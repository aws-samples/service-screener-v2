import botocore

from utils.Tools import _pi
## NOTE: utils.Config.Config is the *global scanner config* and shares its class
## name with this module's Config service class. Alias it on import so the two
## never shadow each other inside this file.
from utils.Config import Config as GlobalConfig
from services.Service import Service

from services.config.drivers.ConfigCommon import ConfigCommon


class Config(Service):
    """
    AWS Config service scanner.

    AWS Config is account/region-level infrastructure rather than a collection of
    per-resource objects: there is at most ONE customer-managed configuration
    recorder and ONE delivery channel per account per region. So discovery here
    produces a single account-scoped descriptor for the region, mirroring the
    existing precedent in services/cloudtrail/drivers/CloudtrailAccount.py.

    Hydration calls (all read-only):
      - describe_configuration_recorders
      - describe_configuration_recorder_status
      - describe_delivery_channels
      - describe_config_rules              (paginated)
      - describe_compliance_by_config_rule (paginated)
      - describe_retention_configurations  (paginated)
      - describe_configuration_aggregators (paginated)
      - describe_remediation_configurations (batched, 25 rule names per call,
                                             for every Config rule)

    API failures are recorded in detail['_errors'] ({api_name: error_code}) so
    checks can report 'Unable to evaluate (<code>)' instead of treating an
    empty (unreadable) list as a real absence.

    The class name MUST be `Config` and the module MUST be
    services/config/Config.py: Screener.getServiceModuleDynamically builds the
    module path as 'services.' + service + '.' + service.title().
    """

    ## Resource types that matter most for a security/compliance baseline. Used by
    ## the driver when the recorder opts out of allSupported and instead lists an
    ## explicit inclusion set.
    KEY_RESOURCE_TYPES = [
        'AWS::EC2::SecurityGroup',
        'AWS::EC2::Instance',
        'AWS::EC2::Volume',
        'AWS::EC2::VPC',
        'AWS::IAM::Role',
        'AWS::IAM::Policy',
        'AWS::IAM::User',
        'AWS::S3::Bucket',
        'AWS::KMS::Key',
        'AWS::RDS::DBInstance',
        'AWS::CloudTrail::Trail',
        'AWS::Lambda::Function',
    ]

    ## describe_remediation_configurations caps ConfigRuleNames at 25 per call.
    REMEDIATION_BATCH_SIZE = 25

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.configClient = ssBoto.client('config', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        """
        Return a single account/region-scoped descriptor, or None when the AWS
        Config endpoint is unreachable in this region.

        Note: tag filtering (--filters) is intentionally NOT applied. The subject
        of every check is the account's regional AWS Config posture, which is not
        a taggable resource, so a tag filter cannot meaningfully include or
        exclude it. Behaving otherwise would silently drop account-level findings.
        """
        self._errors = {}
        try:
            recorders = self._describeConfigurationRecorders()
            detail = {
                '_region': self.region,
                '_accountId': self._currentAccount(),
                '_recorders': recorders,
                '_recorderStatus': self._describeConfigurationRecorderStatus(),
                '_deliveryChannels': self._describeDeliveryChannels(),
                '_configRules': self._describeConfigRules(),
                '_compliance': self._describeComplianceByConfigRule(),
                '_retentionConfigurations': self._describeRetentionConfigurations(),
                '_aggregators': self._describeConfigurationAggregators(),
                '_keyResourceTypes': self.KEY_RESOURCE_TYPES,
            }
            nonCompliant = [
                entry.get('ConfigRuleName')
                for entry in detail['_compliance']
                if (entry.get('Compliance') or {}).get('ComplianceType') == 'NON_COMPLIANT'
                and entry.get('ConfigRuleName')
            ]
            detail['_nonCompliantRules'] = nonCompliant
            ## Remediation is queried for every rule (not just NON_COMPLIANT
            ## ones): configNoRemediationActions filters to the failing rules,
            ## while configRemediationManualOnly needs the account-wide view.
            allRuleNames = [
                r.get('ConfigRuleName') for r in detail['_configRules']
                if r.get('ConfigRuleName')
            ]
            detail['_remediationConfigurations'] = \
                self._describeRemediationConfigurations(allRuleNames)
            detail['_errors'] = dict(self._errors)

            _pi('Config', f"Account posture in {self.region}")
            return detail
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"AWS Config not available in region {self.region}: {e}")
            return None

    def _describeConfigurationRecorders(self):
        try:
            resp = self.configClient.describe_configuration_recorders()
            return resp.get('ConfigurationRecorders', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_configuration_recorders', e)
            return []

    def _describeConfigurationRecorderStatus(self):
        try:
            resp = self.configClient.describe_configuration_recorder_status()
            return resp.get('ConfigurationRecordersStatus', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_configuration_recorder_status', e)
            return []

    def _describeDeliveryChannels(self):
        try:
            resp = self.configClient.describe_delivery_channels()
            return resp.get('DeliveryChannels', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_delivery_channels', e)
            return []

    def _describeConfigRules(self):
        rules = []
        try:
            paginator = self.configClient.get_paginator('describe_config_rules')
            for page in paginator.paginate():
                rules += page.get('ConfigRules', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_config_rules', e)
        return rules

    def _describeComplianceByConfigRule(self):
        entries = []
        try:
            paginator = self.configClient.get_paginator(
                'describe_compliance_by_config_rule')
            for page in paginator.paginate():
                entries += page.get('ComplianceByConfigRules', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_compliance_by_config_rule', e)
        return entries

    def _describeRetentionConfigurations(self):
        configs = []
        try:
            paginator = self.configClient.get_paginator(
                'describe_retention_configurations')
            for page in paginator.paginate():
                configs += page.get('RetentionConfigurations', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_retention_configurations', e)
        return configs

    def _describeConfigurationAggregators(self):
        aggregators = []
        try:
            paginator = self.configClient.get_paginator(
                'describe_configuration_aggregators')
            for page in paginator.paginate():
                aggregators += page.get('ConfigurationAggregators', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_configuration_aggregators', e)
        return aggregators

    def _describeRemediationConfigurations(self, ruleNames):
        """
        Remediation configurations are queried per rule name, max 25 names per
        call, and the API is not paginated. Returns the flat list of
        RemediationConfiguration dicts found across all batches.
        """
        found = []
        if not ruleNames:
            return found

        for i in range(0, len(ruleNames), self.REMEDIATION_BATCH_SIZE):
            batch = ruleNames[i:i + self.REMEDIATION_BATCH_SIZE]
            try:
                resp = self.configClient.describe_remediation_configurations(
                    ConfigRuleNames=batch)
                found += resp.get('RemediationConfigurations', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('describe_remediation_configurations', e)
        return found

    def _currentAccount(self):
        info = GlobalConfig.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        detail = self.getResources()
        if detail is None:
            return objs

        try:
            obj = ConfigCommon(detail, self.configClient)
            obj.run(self.__class__)
            ## Account/region-scoped finding: there is exactly one AWS Config
            ## posture per account per region, so use the aggregate identifier
            ## 'Config::Account'. RemediationResolver treats a trailing
            ## 'Account' segment as an aggregate label and leaves resource
            ## placeholders unsubstituted rather than inventing a resource name
            ## — which is exactly the behaviour we want here.
            objs['Config::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing AWS Config posture in {self.region}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        ## Remember the failure so checks never mistake "unreadable" for "absent".
        if not hasattr(self, '_errors'):
            self._errors = {}
        self._errors.setdefault(where, code)
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Config {where}: {code} - {msg}")

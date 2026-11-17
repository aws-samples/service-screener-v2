import botocore

from utils.Tools import _pi
from services.Service import Service

from services.securityhub.drivers.SecurityhubCommon import SecurityhubCommon


class Securityhub(Service):
    """
    AWS Security Hub service scanner.

    Account/region-scoped, so discovery produces a single
    'SecurityHub::Account' descriptor per region (Config::Account precedent).

    Hydration calls (all read-only):
      - describe_hub                       (enabled? auto-enable? finding gen mode)
      - get_enabled_standards              (which standards are on)
      - list_finding_aggregators           (cross-region aggregation)
      - list_enabled_products_for_import   (integrations)

    Called lazily by the driver, only when the matching check runs:
      - describe_security_hub_v2           (securityHubV2NotEnabled)
      - describe_standards_controls        (shubControlsDisabledNoReason)
      - list_automation_rules, describe_action_targets, ssm.list_documents,
        events.list_rules                  (securityHubNoAutomationRules)

    Deliberately NOT called: get_findings. It paginates over every finding in the
    account (verified: NextToken on page one), which is exactly the unbounded
    enumeration SPEC_04's review flagged as blocking. The finding-count check is
    implemented with a capped page read instead — see FINDINGS_PAGE_CAP.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## describe_hub raises this when Security Hub is not enabled in the region.
    NOT_ENABLED_CODES = ('InvalidAccessException', 'ResourceNotFoundException')

    ## Cap on get_findings pages for the unprocessed-findings check.
    FINDINGS_PAGE_CAP = 4

    ## A CIS standard ARN contains this fragment regardless of version.
    CIS_ARN_FRAGMENT = 'cis-aws-foundations-benchmark'

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.shClient = ssBoto.client('securityhub', config=self.bConfig)
        ## Read-only clients used only by securityHubNoAutomationRules to
        ## recognise response automation that lives outside Security Hub.
        self.ssmClient = ssBoto.client('ssm', config=self.bConfig)
        self.eventsClient = ssBoto.client('events', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        detail = {
            '_region': self.region,
            '_enabled': False,
            '_hub': None,
            '_standards': [],
            '_standardsError': None,
            '_aggregators': [],
            '_products': [],
            '_unprocessedFindings': None,
            '_findingsCapped': False,
        }

        try:
            detail['_hub'] = self.shClient.describe_hub()
            detail['_enabled'] = True
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in self.NOT_ENABLED_CODES:
                ## Not enabled — return the descriptor so shubNotEnabled can FAIL;
                ## every other check will report "not applicable".
                _pi('Securityhub', f"Security Hub not enabled in {self.region}")
                return detail
            self._logClientError('describe_hub', e)
            return detail
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Security Hub not available in region {self.region}: {e}")
            return None

        detail['_standards'], detail['_standardsError'] = \
            self._getEnabledStandards()
        detail['_aggregators'] = self._listFindingAggregators()
        detail['_products'] = self._listProducts()
        detail['_unprocessedFindings'], detail['_findingsCapped'] = \
            self._countUnprocessedFindings()

        _pi('Securityhub', f"Security Hub posture in {self.region}")
        return detail

    def _getEnabledStandards(self):
        """Returns (subscriptions, errorCode). errorCode is None on success so
        standard-specific checks can report 'Unable to evaluate' instead of a
        false FAIL when the list could not be read."""
        standards = []
        try:
            paginator = self.shClient.get_paginator('get_enabled_standards')
            for page in paginator.paginate():
                standards += page.get('StandardsSubscriptions', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('get_enabled_standards', e)
            return [], e.response.get('Error', {}).get('Code', 'Unknown')
        return standards, None

    def _listFindingAggregators(self):
        aggregators = []
        try:
            paginator = self.shClient.get_paginator('list_finding_aggregators')
            for page in paginator.paginate():
                aggregators += page.get('FindingAggregators', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_finding_aggregators', e)
        except botocore.exceptions.OperationNotPageableError:
            try:
                aggregators = self.shClient.list_finding_aggregators().get(
                    'FindingAggregators', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_finding_aggregators', e)
        return aggregators

    def _listProducts(self):
        products = []
        try:
            paginator = self.shClient.get_paginator(
                'list_enabled_products_for_import')
            for page in paginator.paginate():
                products += page.get('ProductSubscriptions', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_enabled_products_for_import', e)
        except botocore.exceptions.OperationNotPageableError:
            try:
                products = self.shClient.list_enabled_products_for_import().get(
                    'ProductSubscriptions', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_enabled_products_for_import', e)
        return products

    def _countUnprocessedFindings(self):
        """
        Count NEW-workflow, ACTIVE findings, capped at FINDINGS_PAGE_CAP pages.
        Returns (count, capped); capped True means "at least count".
        """
        filters = {
            'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}],
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        }
        count, pages, nextToken = 0, 0, None
        try:
            while pages < self.FINDINGS_PAGE_CAP:
                kwargs = {'Filters': filters, 'MaxResults': 100}
                if nextToken:
                    kwargs['NextToken'] = nextToken
                resp = self.shClient.get_findings(**kwargs)
                count += len(resp.get('Findings', []) or [])
                pages += 1
                nextToken = resp.get('NextToken')
                if not nextToken:
                    break
            return count, bool(nextToken)
        except botocore.exceptions.ClientError as e:
            self._logClientError('get_findings', e)
            return None, False

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        detail = self.getResources()
        if detail is None:
            return objs
        try:
            obj = SecurityhubCommon(detail, self.shClient, self.CIS_ARN_FRAGMENT,
                                    ssmClient=self.ssmClient,
                                    eventsClient=self.eventsClient)
            obj.run(self.__class__)
            objs['SecurityHub::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing Security Hub posture in {self.region}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Securityhub {where}: {code} - {msg}")

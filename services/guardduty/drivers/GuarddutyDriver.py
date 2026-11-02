import re
from botocore.exceptions import ClientError, EndpointConnectionError
from services.Evaluator import Evaluator
from utils.Config import Config
from datetime import datetime, timezone
    
class GuarddutyDriver(Evaluator):
    def __init__(self, detector_id, guardduty_client, region, bedrock_client=None, cloudtrail_client=None):
        super().__init__()
        
        self.results = {}
        stsInfo = Config.get('stsInfo')
        
        self.accountId = stsInfo['Account'] 
        self.region = region
        self.detector_id = detector_id
        self.gd_client = guardduty_client
        self.bedrock_client = bedrock_client
        self.cloudtrail_client = cloudtrail_client

        self._resourceName = detector_id

        ## get_detector() response, cached so the settings check and all ten
        ## feature checks share a single API call. Set by _getDetector().
        self._detector = None
        self._detectorFailed = False

        self.init()

    def _checkFindings(self):
        next_token = None
        arr = {}
        while True:
            try:
                if next_token == None:
                    results = self.gd_client.list_findings(
                        DetectorId=self.detector_id,
                        MaxResults=20
                    )
                else: 
                    results = self.gd_client.list_findings(
                        DetectorId=self.detector_id,
                        MaxResults=20,
                        NextToken=next_token
                    )
                    
                finding_ids = results.get('FindingIds', [])

                if finding_ids:
                    findings = self.gd_client.get_findings(
                        DetectorId=self.detector_id,
                        FindingIds=finding_ids
                    )

                    for finding in findings.get('Findings', []):
                        date_str = finding['CreatedAt']
                        given_date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                        current_date = datetime.now(timezone.utc)

                        days_difference = (current_date - given_date).days

                        type_ = finding['Type']
                        sev = self.convertSev(finding['Severity'])

                        if sev not in arr:
                            arr[sev] = {}
                        if type_ not in arr[sev]:
                            arr[sev][type_] = {}
                        if 'res_' not in arr[sev][type_]:
                            arr[sev][type_]['res_'] = []

                        isArchived = finding['Service']['Archived']
                        arr[sev][type_]['res_'].append({
                            'Id': finding['Id'],
                            'Count': finding['Service']['Count'],
                            'Title': finding['Title'],
                            'region': self.region,
                            'failResolvedAfterXDays': self.isFail_cfg_gd_non_archived_findings(sev, days_difference),
                            'days': days_difference,
                            'isArchived': isArchived
                        })

                next_token = results.get('NextToken')
                if not next_token:
                    break
            except ClientError:
                break

        if not arr:
            return
        
        for serv, obj in arr.items():
            for type_, det in obj.items():
                arr[serv][type_]['__'] = self._build_doc_links(type_)

        self.results['Findings'] = [-1, arr]

    # https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html
    def convertSev(self, sev):
        if sev >= 7:
            return 8
        if sev >= 4:
            return 5
        return 2

    def isFail_cfg_gd_non_archived_findings(self, sev, days):
        SEVERITY_TO_DAYS_MAPPING = {
            '2': 30,  # Low severity - 30 days
            '5': 7,   # Medium severity - 7 days
            '8': 1    # High severity - 1 day
        }

        _d = SEVERITY_TO_DAYS_MAPPING[str(sev)]

        if days > _d: 
            self.results['FailMeetingCompliances'] = [-1, None]
            return True

    def _checkUsage_statistics(self):
        try:
            results = self.gd_client.get_usage_statistics(
                DetectorId=self.detector_id,
                MaxResults=50,
                UsageCriteria={
                    'DataSources': [
                        'FLOW_LOGS', 'CLOUD_TRAIL', 'DNS_LOGS', 'S3_LOGS', 'KUBERNETES_AUDIT_LOGS', 'EC2_MALWARE_SCAN'
                    ]
                },
                UsageStatisticType='SUM_BY_DATA_SOURCE'
            )
            tmp = results.get('UsageStatistics')
            arr = tmp['SumByDataSource']
            self.results['UsageStat'] = [-1, arr]
        except ClientError:
            pass

    def _checkFree_trial_remaining(self):
        try:
            results = self.gd_client.get_remaining_free_trial_days(
                AccountIds=[self.accountId],
                DetectorId=self.detector_id
            )

            tmp = results.get('Accounts')
            arr = tmp[0]['DataSources']
            self.results['FreeTrial'] = [-1, arr]
        except ClientError:
            pass

    def _checkGuard_duty_settings(self):
        results = self._getDetector()
        if results is None:
            return

        ## DataSources is deprecated in favour of Features[], but
        ## GuarddutypageBuilder reads detector['Settings']['value']['Settings']
        ## to render the settings table, so it must keep being populated.
        ##
        ## The status is -1 by design, not by mistake: Reporter.process() only
        ## copies a check into self.detail when info[0] == -1, so -1 is the only
        ## way a payload-carrying check reaches the page builder. The feature
        ## checks below are separate, and DO report real pass/fail.
        settings = results.get('DataSources')
        gd_status = results.get('Status')

        self.results['Settings'] = [-1, {'isEnabled': gd_status, 'Settings': settings}]

    # ------------------------------------------------------------------ #
    # Protection feature checks
    #
    # All of these read get_detector().Features[], so they cost NO additional
    # API call beyond the one _checkGuard_duty_settings already makes (the
    # response is cached in _getDetector).
    #
    # Feature names come from the GuardDuty API's own enum:
    #   FLOW_LOGS, CLOUD_TRAIL, DNS_LOGS, S3_DATA_EVENTS, EKS_AUDIT_LOGS,
    #   EBS_MALWARE_PROTECTION, RDS_LOGIN_EVENTS, LAMBDA_NETWORK_LOGS,
    #   EKS_RUNTIME_MONITORING, RUNTIME_MONITORING
    # and AdditionalConfiguration names:
    #   EKS_ADDON_MANAGEMENT, ECS_FARGATE_AGENT_MANAGEMENT, EC2_AGENT_MANAGEMENT
    #
    # NOTE ON MULTI-ACCOUNT SCOPE: the equivalent Security Hub controls
    # (GuardDuty.5-13) evaluate the delegated administrator AND every member
    # account, and report only in the admin account. This scanner deliberately
    # evaluates the LOCAL detector only, so a member account reporting PASS here
    # is not evidence that the organisation as a whole passes.
    # ------------------------------------------------------------------ #

    def _getDetector(self):
        """get_detector(), fetched once and reused by every feature check."""
        if self._detector is not None:
            return self._detector
        if self._detectorFailed:
            return None
        try:
            self._detector = self.gd_client.get_detector(
                DetectorId=self.detector_id
            )
            return self._detector
        except ClientError:
            self._detectorFailed = True
            return None

    def _featureStatus(self, name):
        """
        Return the Status of a named feature, or None when the API does not
        report it. A feature absent from the response is NOT the same as
        disabled -- it usually means this region or account tier does not offer
        it -- so callers must report INFO rather than FAIL.
        """
        detector = self._getDetector()
        if detector is None:
            return None
        for feature in detector.get('Features', []) or []:
            if feature.get('Name') == name:
                return feature.get('Status')
        return None

    def _additionalConfigStatus(self, featureName, configName):
        detector = self._getDetector()
        if detector is None:
            return None
        for feature in detector.get('Features', []) or []:
            if feature.get('Name') != featureName:
                continue
            for cfg in feature.get('AdditionalConfiguration', []) or []:
                if cfg.get('Name') == configName:
                    return cfg.get('Status')
        return None

    def _evaluateFeature(self, checkKey, featureName, label):
        """Standard ENABLED / DISABLED / not-reported handling for one feature."""
        status = self._featureStatus(featureName)
        if status is None:
            self.results[checkKey] = [
                0, f"{label} is not reported by GuardDuty in this region"
            ]
        elif status == 'ENABLED':
            self.results[checkKey] = [1, f"{label} is enabled"]
        else:
            self.results[checkKey] = [
                -1, f"{label} is {status} — GuardDuty is not analysing this source"
            ]

    def _checkS3ProtectionDisabled(self):
        self._evaluateFeature('S3ProtectionDisabled', 'S3_DATA_EVENTS',
                              'S3 Protection (S3 data event monitoring)')

    def _checkEksAuditLogsDisabled(self):
        self._evaluateFeature('EksAuditLogsDisabled', 'EKS_AUDIT_LOGS',
                              'EKS Audit Log Monitoring')

    def _checkMalwareProtectionDisabled(self):
        self._evaluateFeature('MalwareProtectionDisabled',
                              'EBS_MALWARE_PROTECTION',
                              'Malware Protection for EC2 (EBS volume scanning)')

    def _checkRdsProtectionDisabled(self):
        self._evaluateFeature('RdsProtectionDisabled', 'RDS_LOGIN_EVENTS',
                              'RDS Protection (login event monitoring)')

    def _checkLambdaProtectionDisabled(self):
        self._evaluateFeature('LambdaProtectionDisabled', 'LAMBDA_NETWORK_LOGS',
                              'Lambda Protection (network activity monitoring)')

    def _checkRuntimeMonitoringDisabled(self):
        self._evaluateFeature('RuntimeMonitoringDisabled', 'RUNTIME_MONITORING',
                              'Runtime Monitoring')

    def _checkAiProtectionDisabled(self):
        ## AI_PROTECTION is present in the API but has no Security Hub control
        ## yet, so this is a scanner-original check.
        self._evaluateFeature('AiProtectionDisabled', 'AI_PROTECTION',
                              'AI Protection (generative AI workload monitoring)')
        self._recordAiStatus('AiProtectionDisabled')

    def _recordAiStatus(self, key):
        """
        Copy an AI Protection check result into the AiProtectionStatus payload so
        the page builder can show passing and info results too. Like Settings,
        the payload status is -1 by design: Reporter only passes -1 checks on.
        """
        if key not in self.results:
            return
        # setdefault is atomic, checks may run concurrently
        self.results.setdefault('AiProtectionStatus', [-1, {}])[1][key] = self.results[key]

    # ------------------------------------------------------------------ #
    # AI Protection finding type coverage
    #
    # Enabling AI_PROTECTION is not enough on its own to get every AI finding
    # type. Both checks below only run when AI_PROTECTION is ENABLED; the
    # disabled case is already reported by AiProtectionDisabled.
    #   - AnomalousModelInvocation / CostHarvesting need the GuardDuty
    #     service-linked CloudTrail channel streaming Bedrock data events.
    #   - PromptInjection.Direct is only generated when a Bedrock Guardrail
    #     with an active PROMPT_ATTACK filter evaluates the prompt.
    # ------------------------------------------------------------------ #

    def _checkAiProtectionEventChannel(self):
        if self._featureStatus('AI_PROTECTION') != 'ENABLED' or self.cloudtrail_client is None:
            return
        self._evaluateAiProtectionEventChannel()
        self._recordAiStatus('AiProtectionNoEventChannel')

    def _evaluateAiProtectionEventChannel(self):

        try:
            channels = []
            params = {}
            while True:
                results = self.cloudtrail_client.list_channels(**params)
                channels.extend(results.get('Channels', []))
                if not results.get('NextToken'):
                    break
                params['NextToken'] = results['NextToken']

            for channel in channels:
                if not channel.get('Name', '').startswith('aws-service-channel/guardduty/'):
                    continue
                detail = self.cloudtrail_client.get_channel(Channel=channel['ChannelArn'])
                selectors = (detail.get('SourceConfig') or {}).get('AdvancedEventSelectors', [])
                for selector in selectors:
                    for field in selector.get('FieldSelectors', []):
                        if field.get('Field') == 'resources.type' and any(v.startswith('AWS::Bedrock') for v in field.get('Equals', [])):
                            self.results['AiProtectionNoEventChannel'] = [
                                1, f"GuardDuty channel {channel['Name']} streams Bedrock data events"
                            ]
                            return
        except ClientError as e:
            self.results['AiProtectionNoEventChannel'] = [
                0, f"Unable to verify CloudTrail channels: {e.response['Error']['Code']}"
            ]
            return

        self.results['AiProtectionNoEventChannel'] = [
            -1,
            "AI Protection is enabled but no GuardDuty service-linked channel streams "
            "Bedrock data events — AnomalousModelInvocation and CostHarvesting findings "
            "cannot be generated"
        ]

    def _hasActivePromptAttackFilter(self, guardrailId, version=None):
        params = {'guardrailIdentifier': guardrailId}
        if version:
            params['guardrailVersion'] = version
        guardrail = self.bedrock_client.get_guardrail(**params)
        for f in (guardrail.get('contentPolicy') or {}).get('filters', []):
            if f.get('type') == 'PROMPT_ATTACK' and f.get('inputStrength', 'NONE') != 'NONE' \
                    and f.get('inputEnabled', True):
                return guardrail.get('name', guardrailId)
        return None

    def _checkAiProtectionPromptInjection(self):
        if self._featureStatus('AI_PROTECTION') != 'ENABLED' or self.bedrock_client is None:
            return
        self._evaluateAiProtectionPromptInjection()
        self._recordAiStatus('AiProtectionPromptInjectionNotDetected')

    def _evaluateAiProtectionPromptInjection(self):
        key = 'AiProtectionPromptInjectionNotDetected'
        try:
            # 1. Account-level enforced guardrails apply to every model invocation
            enforced = []
            params = {}
            while True:
                results = self.bedrock_client.list_enforced_guardrails_configuration(**params)
                for cfg in results.get('guardrailsConfig', []):
                    name = self._hasActivePromptAttackFilter(
                        cfg.get('guardrailArn') or cfg.get('guardrailId'), cfg.get('guardrailVersion'))
                    if name:
                        enforced.append(name)
                if not results.get('nextToken'):
                    break
                params['nextToken'] = results['nextToken']

            if enforced:
                self.results[key] = [
                    1, f"Enforced guardrail(s) with prompt attack filter: {', '.join(enforced)}"
                ]
                return

            # 2. Guardrails that only cover requests that explicitly apply them
            optIn = []
            params = {}
            while True:
                results = self.bedrock_client.list_guardrails(**params)
                for g in results.get('guardrails', []):
                    name = self._hasActivePromptAttackFilter(g['id'])
                    if name:
                        optIn.append(name)
                if not results.get('nextToken'):
                    break
                params['nextToken'] = results['nextToken']
        except EndpointConnectionError:
            self.results[key] = [0, "Amazon Bedrock is not available in this region"]
            return
        except ClientError as e:
            self.results[key] = [
                0, f"Unable to verify Bedrock guardrails: {e.response['Error']['Code']}"
            ]
            return

        if optIn:
            self.results[key] = [
                -1,
                f"Guardrail(s) with prompt attack filter are not enforced at account level: "
                f"{', '.join(optIn)} — PromptInjection.Direct is only detected for requests "
                "that explicitly apply them"
            ]
        else:
            self.results[key] = [
                -1,
                "No guardrail with an active prompt attack filter — GuardDuty cannot "
                "generate Impact:IAMUser/PromptInjection.Direct findings"
            ]

    def _checkEksRuntimeMonitoringDisabled(self):
        """
        EKS runtime coverage is reported two different ways depending on account
        vintage: the older standalone EKS_RUNTIME_MONITORING feature, or the
        unified RUNTIME_MONITORING feature with an EKS_ADDON_MANAGEMENT
        sub-configuration. Treat either as coverage.
        """
        standalone = self._featureStatus('EKS_RUNTIME_MONITORING')
        unified = self._featureStatus('RUNTIME_MONITORING')
        addon = self._additionalConfigStatus('RUNTIME_MONITORING',
                                            'EKS_ADDON_MANAGEMENT')

        if standalone is None and unified is None:
            self.results['EksRuntimeMonitoringDisabled'] = [
                0, "EKS Runtime Monitoring is not reported in this region"
            ]
            return

        if standalone == 'ENABLED' or (unified == 'ENABLED' and addon == 'ENABLED'):
            self.results['EksRuntimeMonitoringDisabled'] = [
                1, "EKS Runtime Monitoring is enabled"
            ]
            return

        self.results['EksRuntimeMonitoringDisabled'] = [
            -1,
            "EKS Runtime Monitoring is not active (EKS_RUNTIME_MONITORING="
            f"{standalone or 'not reported'}, RUNTIME_MONITORING={unified or 'not reported'}"
            f", EKS_ADDON_MANAGEMENT={addon or 'not reported'}) — container "
            "runtime threats on EKS are not detected"
        ]

    def _checkEcsRuntimeMonitoringDisabled(self):
        self._evaluateRuntimeSubFeature(
            'EcsRuntimeMonitoringDisabled', 'ECS_FARGATE_AGENT_MANAGEMENT',
            'ECS/Fargate Runtime Monitoring')

    def _checkEc2RuntimeMonitoringDisabled(self):
        self._evaluateRuntimeSubFeature(
            'Ec2RuntimeMonitoringDisabled', 'EC2_AGENT_MANAGEMENT',
            'EC2 Runtime Monitoring')

    def _evaluateRuntimeSubFeature(self, checkKey, configName, label):
        """
        ECS and EC2 runtime coverage both require the parent RUNTIME_MONITORING
        feature to be ENABLED *and* the relevant agent-management
        sub-configuration to be ENABLED. If the parent is off, report that as the
        cause rather than blaming the sub-configuration.
        """
        parent = self._featureStatus('RUNTIME_MONITORING')
        if parent is None:
            self.results[checkKey] = [
                0, f"{label} is not reported in this region"
            ]
            return

        if parent != 'ENABLED':
            self.results[checkKey] = [
                -1,
                f"{label} is inactive because the parent Runtime Monitoring "
                f"feature is {parent}"
            ]
            return

        addon = self._additionalConfigStatus('RUNTIME_MONITORING', configName)
        if addon == 'ENABLED':
            self.results[checkKey] = [1, f"{label} is enabled"]
        elif addon is None:
            self.results[checkKey] = [
                0,
                f"{label}: Runtime Monitoring is enabled but {configName} is not "
                "reported"
            ]
        else:
            self.results[checkKey] = [
                -1,
                f"{label} is not active ({configName}={addon}) — automated agent "
                "management is off, so coverage depends on manual agent "
                "deployment"
            ]

    def _build_doc_links(self, topic):
        general_page = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"
        doc_prefix = "https://docs.aws.amazon.com/guardduty/latest/ug/"

        patterns = r"\w+"
        result = re.findall(patterns, topic)

        type_ = result[1]

        # AI Protection, e.g. Impact:IAMUser/PromptInjection.Direct
        aiFindings = {
            'AnomalousModelInvocation': 'ai-protection-anomalousmodelinvocation',
            'CostHarvesting': 'ai-protection-costharvesting',
            'PromptInjection': 'ai-protection-promptinjection-direct'
        }
        if len(result) > 2 and result[2] in aiFindings:
            return f"{doc_prefix}findings-ai-protection.html#{aiFindings[result[2]]}"

        # Malware
        if result[0] == 'Execution':
            type_ = 'Malware'

        # Need to validate if RDS links work properly, no sample.
        types = {
            'EC2': "guardduty_finding-types-ec2",
            'IAMUser': "guardduty_finding-types-iam",
            'Kubernetes': "guardduty_finding-types-kubernetes",
            'S3': "guardduty_finding-types-s3",
            'Malware': "findings-malware-protection",
            'RDS': "findings-rds-protection"
        }

        if type_ in types:
            topic = f"{result[0]}-{result[1]}-{result[2]}"
            return f"{doc_prefix}{types[type_]}.html#{topic.lower()}"
        else:
            return f"{general_page}#suffix?screener=notfound&type={type_}"
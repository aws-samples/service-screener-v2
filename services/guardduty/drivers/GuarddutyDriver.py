import re
from botocore.exceptions import ClientError
from services.Evaluator import Evaluator
from utils.Config import Config
    
class GuarddutyDriver(Evaluator):
    def __init__(self, detector_id, guardduty_client, region):
        super().__init__()
        
        self.results = {}
        stsInfo = Config.get('stsInfo')
        
        self.accountId = stsInfo['Account'] 
        self.region = region
        self.detector_id = detector_id
        self.gd_client = guardduty_client
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
                        type_ = finding['Type']

                        if finding['Severity'] not in arr:
                            arr[finding['Severity']] = {}
                        if type_ not in arr[finding['Severity']]:
                            arr[finding['Severity']][type_] = {}
                        if 'res_' not in arr[finding['Severity']][type_]:
                            arr[finding['Severity']][type_]['res_'] = []

                        arr[finding['Severity']][type_]['res_'].append({
                            'Id': finding['Id'],
                            'Count': finding['Service']['Count'],
                            'Title': finding['Title'],
                            'region': self.region
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
        try:
            results = self.gd_client.get_detector(
                DetectorId=self.detector_id
            )

            settings = results.get('DataSources')
            gd_status = results.get('Status')

            self.results['Settings'] = [-1, {'isEnabled': gd_status, 'Settings': settings}]
        except ClientError:
            pass

    def _build_doc_links(self, topic):
        general_page = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"
        doc_prefix = "https://docs.aws.amazon.com/guardduty/latest/ug/"

        patterns = r"\w+"
        result = re.findall(patterns, topic)

        type_ = result[1]

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
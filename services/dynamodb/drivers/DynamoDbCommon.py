import boto3
import botocore
import datetime
import re
import urllib.parse
from statistics import mean

from services.Service import Service
from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator
from utils import PolicyPrincipal


# Condition keys accepted as organisation scoping for cross-account grants.
_ORG_CONDITION_KEYS = frozenset(('aws:principalorgid', 'aws:principalorgpaths'))
# Positive-match operators (negated / IfExists / ForAllValues forms do not restrict callers).
_POSITIVE_OPERATORS = frozenset(('stringequals', 'stringequalsignorecase', 'stringlike', 'arnequals', 'arnlike'))
_ALL_ORG_KEYS = _ORG_CONDITION_KEYS | frozenset(('aws:sourceorgid', 'aws:sourceorgpaths'))
_ACCOUNT_KEYS = frozenset(('aws:principalaccount', 'aws:sourceaccount', 'aws:sourceowner'))
_ARN_KEYS = frozenset(('aws:principalarn', 'aws:sourcearn'))
_NETWORK_PATH_KEYS = frozenset(('aws:sourcevpc', 'aws:sourcevpce'))
_ORG_ID = re.compile(r'^o-[a-z0-9]{10,32}$')
_ACCOUNT_ID = re.compile(r'^\d{12}$')
# Principal values that carry an account ID: "123456789012", arn:aws:iam::123456789012:..., arn:aws:sts::123456789012:...
_ACCOUNT_IN_PRINCIPAL = re.compile(r'^(?:arn:aws[a-z-]*:(?:iam|sts)::)?(\d{12})(?::|$)')
_OPEN_CIDRS = frozenset(('0.0.0.0/0', '::/0'))
# Replica statuses that can serve traffic. CREATING, CREATION_FAILED, DELETING, REGION_DISABLED,
# INACCESSIBLE_ENCRYPTION_CREDENTIALS, ARCHIVING, ARCHIVED and REPLICATION_NOT_AUTHORIZED do not.
_HEALTHY_REPLICA_STATUSES = frozenset(('ACTIVE', 'UPDATING'))

# Tag keys/values (case-insensitive, '-', '_' and spaces ignored) that mark a table as business critical.
_CRITICALITY_TAG_KEYS = frozenset((
    'criticality', 'critical', 'businesscriticality', 'datacriticality', 'servicecriticality',
    'tier', 'servicetier', 'apptier', 'applicationtier', 'businesstier', 'drtier',
))
_CRITICALITY_TAG_VALUES = frozenset((
    'critical', 'missioncritical', 'businesscritical', 'high', 'tier0', 'tier1', '0', '1',
    'p0', 'p1', 'true', 'yes',
))


def _norm(value):
    return re.sub(r'[\s_-]', '', str(value)).lower()


def _asList(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _hasWildcard(value):
    return '*' in value or '?' in value


def _orgValueIsConcrete(key, value):
    """aws:PrincipalOrgID / SourceOrgID must be a full o-... ID (no wildcards: 'o-*' matches every
    organisation). aws:PrincipalOrgPaths / SourceOrgPaths must start with a concrete o-... segment."""
    if not isinstance(value, str):
        return False
    if key.endswith('orgid'):
        return bool(_ORG_ID.match(value))
    first = value.split('/', 1)[0]
    return bool(_ORG_ID.match(first)) and '/' in value


def _positiveBlocks(condition):
    """Yield (key_lower, values) for positive-match operators that actually restrict callers.
    Negated, IfExists and ForAllValues forms are skipped (they can match callers without the key)."""
    if not isinstance(condition, dict):
        return
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        op = operator.lower()
        if op.startswith('forallvalues:'):
            continue
        if op.startswith('foranyvalue:'):
            op = op[len('foranyvalue:'):]
        if op not in _POSITIVE_OPERATORS:
            continue
        for key, value in block.items():
            values = _asList(value)
            if values:
                yield str(key).lower(), values


def _conditionScopesToOrg(condition, keys=_ORG_CONDITION_KEYS):
    """True if the Condition pins an organisation key to a concrete organisation."""
    for key, values in _positiveBlocks(condition):
        if key in keys and all(_orgValueIsConcrete(key, v) for v in values):
            return True
    return False


def _wildcardScope(condition, ownAccount):
    """
    Classify how a Condition restricts an Allow statement whose principal is "*" / NotPrincipal.
    Returns (scoped, externalAccounts):
      scoped=True  -> limited to a concrete organisation, to this account, to a specific source
                      resource / VPC / VPC endpoint, or to fixed non-open source CIDRs;
      externalAccounts -> other 12-digit accounts the caller is pinned to (cross-account grant,
                      still needs organisation scoping);
      scoped=False and no accounts -> effectively public.
    Wildcards in an account position (e.g. aws:PrincipalArn arn:aws:iam::*:role/x) do not scope.
    """
    if _conditionScopesToOrg(condition, _ALL_ORG_KEYS) or _conditionScopesToNetwork(condition):
        return True, set()
    scoped = False
    external = set()
    for key, values in _positiveBlocks(condition):
        if not all(isinstance(v, str) and v for v in values):
            continue
        if key in _ACCOUNT_KEYS:
            if all(_ACCOUNT_ID.match(v) for v in values):
                others = {v for v in values if v != ownAccount}
                if others:
                    external |= others
                else:
                    scoped = True
        elif key in _ARN_KEYS:
            accounts = set()
            ok = True
            for v in values:
                parts = v.split(':')
                if len(parts) < 6 or not parts[0] == 'arn':
                    ok = False
                    break
                acct = parts[4]
                if acct == '':
                    # Resources without an account segment (e.g. S3 buckets) scope only when fully concrete.
                    if key == 'aws:principalarn' or _hasWildcard(v):
                        ok = False
                        break
                elif _ACCOUNT_ID.match(acct):
                    accounts.add(acct)
                else:
                    ok = False
                    break
            if not ok:
                continue
            others = accounts - {ownAccount}
            if others:
                external |= others
            else:
                scoped = True
        elif key in _NETWORK_PATH_KEYS:
            if not any(_hasWildcard(v) for v in values):
                scoped = True
    if scoped:
        # Any concrete own-account / resource / VPC restriction is ANDed with the others.
        return True, set()
    return False, external


def _conditionScopesToNetwork(condition):
    """True if the Condition pins aws:SourceIp to concrete, non-open CIDRs (IpAddress operator)."""
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        op = operator.lower()
        if op.startswith('foranyvalue:'):
            op = op[len('foranyvalue:'):]
        if op != 'ipaddress':
            continue
        for key, value in block.items():
            if str(key).lower() != 'aws:sourceip':
                continue
            values = _asList(value)
            if values and all(isinstance(v, str) and v.strip() not in _OPEN_CIDRS for v in values):
                return True
    return False


def resourcePolicyIssues(policyDoc, ownAccount):
    """
    Return a list of human-readable issues for a DynamoDB table/stream resource policy:
    - an Allow statement for any principal ("*", {"AWS": ["*"]}, NotPrincipal) that is not
      restricted by a scoping Condition (org / account / source / VPC / fixed source IP), or
    - an Allow statement for a principal in another AWS account without an
      aws:PrincipalOrgID / aws:PrincipalOrgPaths condition.
    Returns None if the policy cannot be parsed. Deny statements are not subtracted.
    """
    if PolicyPrincipal.parsePolicy(policyDoc) is None:
        return None
    issues = []
    for stmt in PolicyPrincipal.iterStatements(policyDoc):
        if str(stmt.get('Effect', '')).lower() != 'allow':
            continue
        sid = stmt.get('Sid')
        label = 'statement ' + (str(sid) if sid else '(no Sid)')
        condition = stmt.get('Condition')
        if PolicyPrincipal.principalIsWildcard(stmt.get('Principal')) or 'NotPrincipal' in stmt:
            scoped, externalAccts = _wildcardScope(condition, ownAccount)
            if scoped:
                continue
            if externalAccts:
                issues.append(label + ' allows any principal in account(s) ' + ', '.join(sorted(externalAccts))
                              + ' without aws:PrincipalOrgID')
            else:
                issues.append(label + ' allows any principal without a restricting condition')
            continue
        principal = stmt.get('Principal')
        awsValues = _asList(principal.get('AWS')) if isinstance(principal, dict) else []
        external = set()
        for value in awsValues:
            m = _ACCOUNT_IN_PRINCIPAL.match(str(value).strip())
            if m and m.group(1) != ownAccount:
                external.add(m.group(1))
        if external and not _conditionScopesToOrg(condition):
            issues.append(label + ' allows cross-account principal(s) ' + ', '.join(sorted(external))
                          + ' without aws:PrincipalOrgID')
    return issues


class DynamoDbCommon(Evaluator):

    def __init__(self, tables, dynamoDbClient, cloudWatchClient, serviceQuotaClient, appScalingPolicyClient, backupClient, cloudTrailClient, tagsResp=None):
        super().__init__()
        self.tables = tables
        self.tablename = self.tables['Table']['TableName']
        self.dynamoDbClient = dynamoDbClient
        self.cloudWatchClient = cloudWatchClient
        self.serviceQuotaClient = serviceQuotaClient
        self.appScalingPolicyClient = appScalingPolicyClient
        self.backupClient = backupClient
        self.cloudTrailClient = cloudTrailClient
        # list_tags_of_resource(ResourceArn=...) response already fetched by
        # Dynamodb.list_tables() when tag filtering is on; None otherwise.
        self._tagsResp = tagsResp

        self._resourceName = self.tablename

    # ---- read-once API helpers shared by several checks ---- #
    def _tagsFirstPage(self, arn):
        """list_tags_of_resource(ResourceArn=arn) - first page, fetched once."""
        if self._tagsResp is not None and arn == self.tables['Table'].get('TableArn'):
            return self._memo(('list_tags_of_resource', arn), lambda: self._tagsResp)
        return self._memo(('list_tags_of_resource', arn),
                          lambda: self.dynamoDbClient.list_tags_of_resource(ResourceArn=arn))

    def _scalingPolicies(self):
        resourceId = 'table/' + self.tables['Table']['TableName']
        return self._memo(('describe_scaling_policies', resourceId),
                          lambda: self.appScalingPolicyClient.describe_scaling_policies(
                              ServiceNamespace='dynamodb', ResourceId=resourceId))

    def _consumedWcu7Days(self):
        """ConsumedWriteCapacityUnits, hourly Average over the past 7 days."""
        def fetch():
            return self.cloudWatchClient.get_metric_statistics(
                Namespace='AWS/DynamoDB',
                MetricName='ConsumedWriteCapacityUnits',
                Dimensions=[{'Name': 'TableName', 'Value': self.tables['Table']['TableName']}],
                StartTime=datetime.datetime.now() - datetime.timedelta(7),
                EndTime=datetime.datetime.now(),
                Period=3600,
                Statistics=['Average'],
                Unit='Count'
            )
        return self._memo(('get_metric_statistics', 'ConsumedWriteCapacityUnits', 3600, 'Average', 7), fetch)

    # logic to check delete protection    
    def _check_delete_protection(self):
        #print('Checking ' + self.tables['Table']['TableName'] + ' delete protection started')
        try:
            if self.tables['Table']['DeletionProtectionEnabled'] == False:
                self.results['deleteTableProtection'] = [-1, '']
                
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
            
    # logic to check resources for tags
    def _check_resources_for_tags(self):
        #print('Checking ' + self.tables['Table']['TableName'] + ' for resource tag started')
        try:
            #retrieve tags for specific table by tableARN
            result = self._tagsFirstPage(self.tables['Table']['TableArn'])
            #check tags
            if not result['Tags']:
                self.results['resourcesWithoutTags'] = [-1, '']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check unused resources GSI - read
    def _check_unused_resources_gsi_read(self):
        if not 'GlobalSecondaryIndexes' in self.tables['Table']:
            return
        
        try:
            #Count the number active reads on the table on the GSIs
            result = self.cloudWatchClient.get_metric_statistics(
                Namespace = 'AWS/DynamoDB',
                MetricName = 'ConsumedReadCapacityUnits',
                Dimensions = [
                       {
                            'Name':'TableName',
                            'Value':self.tables['Table']['TableName']
                        },
                        {
                            'Name':'GlobalSecondaryIndexName',
                            'Value':self.tables['Table']['GlobalSecondaryIndexes'][0]['IndexName']
                        },
                    ],
                StartTime = datetime.datetime.now() - datetime.timedelta(30),
                EndTime = datetime.datetime.now(),
                Period = 86400,
                Statistics = [
                    'Sum',
                ],
                Unit = 'Count'
            )
            
            #Calculate sum of all occurances within the 30 days period
            sumTotal = 0.0    
            for eachSum in result['Datapoints']:
               sumTotal += eachSum['Sum']
        
            #Flag as issue if > 0 issues in the 30 days period.
            if sumTotal == 0:
              self.results['unusedResourcesGSIRead'] = [-1, 'GSI ['+self.tables['Table']['GlobalSecondaryIndexes'][0]['IndexName']+']=0 RCU in past 30 days']
        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
        
    # logic to check unused resource GSI - write
    def _check_unused_resources_gsi_write(self):
        if not 'GlobalSecondaryIndexes' in self.tables['Table']:
            return
        
        try:
            
            #Count the number active reads on the table on the GSIs
            result = self.cloudWatchClient.get_metric_statistics(
                Namespace = 'AWS/DynamoDB',
                MetricName = 'ConsumedWriteCapacityUnits',
                Dimensions = [
                       {
                           'Name':'TableName',
                           'Value':self.tables['Table']['TableName']
                       },
                       {
                            'Name':'GlobalSecondaryIndexName',
                            'Value':self.tables['Table']['GlobalSecondaryIndexes'][0]['IndexName']
                       },
                    ],
                StartTime = datetime.datetime.now() - datetime.timedelta(30),
                EndTime = datetime.datetime.now(),
                Period = 86400,
                Statistics = [
                    'Sum',
                ],
                Unit = 'Count'
            )
            
            #Calculate sum of all occurances within the 30 days period
            sumTotal = 0.0    
            for eachSum in result['Datapoints']:
                sumTotal += eachSum['Sum']
        
            #Flag as issue if > 0 issues in the 30 days period.
            if sumTotal == 0:
                self.results['unusedResourcesGSIWrite'] = [-1, 'GSI ['+self.tables['Table']['GlobalSecondaryIndexes'][0]['IndexName']+']=WCU in past 30 days']
        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
        
    # logic to check attribute length > 15 and >8
    def _check_attribute_length(self):
        try:
            for tableAttributes in self.tables['Table']['AttributeDefinitions']:
                if len(tableAttributes['AttributeName']) > 15:
                    # error attributesNamesXL for length > 15
                    self.results['attributeNamesXL'] = [-1,  tableAttributes['AttributeName']]
                elif len(tableAttributes['AttributeName']) > 8:
                    # error attributesNamesL for length > 8 <= 15
                    self.results['attributeNamesL'] = [-1, tableAttributes['AttributeName']]
        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(ecode)
        
    # logic to check for TTL status
    def _check_time_to_live_status(self):
        try:
            result = self.dynamoDbClient.describe_time_to_live(TableName = self.tables['Table']['TableName'])
        
            #Check result for TimeToLiveStatus (ENABLED/DISABLED)
            if result['TimeToLiveDescription']['TimeToLiveStatus'] == 'DISABLED':
                self.results['disabledTTL'] = [-1, '']
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check Point In Time Recovery backup
    def _check_pitr_backup(self):
        try:
            result = self.dynamoDbClient.describe_continuous_backups(TableName = self.tables['Table']['TableName'])
            #Check results of ContinuousBackupStatus (ENABLED/DISABLED)
            if result['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'DISABLED':                    
                self.results['disabledPointInTimeRecovery'] = [-1, '']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check capacity mode
    def _check_capacity_mode(self):
        try:
            #Count the number active reads on the table on the GSIs
            result = self._consumedWcu7Days()
        
            #Calculate % of write capacity in the given hour
            _percentageWrite = 0  
            for eachDatapoints in result['Datapoints']:
                _percentageWrite += eachDatapoints['Average']
            
            if 'BillingModeSummary' not in self.tables['Table'] or 'BillingMode' not in self.tables['Table']['BillingModeSummary']:
                billingMode = 'PAY_PER_REQUEST' ## Default it
            else:
                billingMode = self.tables['Table']['BillingModeSummary']['BillingMode']
            
            #Check if percentage <= 18 and billingmode is on-demand
            if _percentageWrite <= 0.018 and billingMode == 'PROVISIONED' :
                #Recommended for On-demand capacity
                self.results['capacityModeOnDemand'] = [-1, billingMode]
            elif _percentageWrite > 0.018 and billingMode == 'PAY_PER_REQUEST' :
                #Recommended for Provisioned capacity
                self.results['capacityModeProvisioned'] = [-1, billingMode]
    
    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Code']
            print(ecode, emsg)

    # logic to check provisoned capacity with autoscaling
    def _check_autoscaling_status(self):
        try:

            #Check for autoscaling policy in each table
            results = self._scalingPolicies()
            
            #If results comes back with record, autoscaling is enabled
            if len(results['ScalingPolicies']) == 0:
                if 'BillingModeSummary' in self.tables['Table'] and 'BillingMode' in self.tables['Table']['BillingModeSummary'] and self.tables['Table']['BillingModeSummary']['BillingMode'] == 'PROVISIONED':
                    self.results['autoScalingStatus'] = [-1 , '']
                
        except botocore.exceptions as e:
            ecode = e.response['Error']['Code']
            print(ecode)
    
    # logic to check for any existing backup available
    def _check_backup_status(self):
        try:
            results = self.backupClient.list_recovery_points_by_resource(ResourceArn = self.tables['Table']['TableArn'])

            if len(results['RecoveryPoints']) < 1:
                self.results['disabledBackup'] = [-1, '']
        except botocore.exception as e:
            ecode = e.response['Error']['Code']
            print(ecode)
            
    # logic to check service limits max GSI per table
    def _check_service_limits_max_gsi_table(self):
        if not 'GlobalSecondaryIndexes' in self.tables['Table']:
            return
        
        serviceQuotasResults = Config.get('QuotaCodeDDB', None)
        try:
            #Retrieve quota for DynamoDb = L-F98FE922
            if serviceQuotasResults == None:
                serviceQuotasResults = self.serviceQuotaClient.list_service_quotas(ServiceCode='dynamodb')['Quotas']
                Config.set('QuotaCodeDDB', serviceQuotasResults)
                
            for quotas in serviceQuotasResults:
                #Check for GSI limit / table
                if quotas['QuotaCode'] == 'L-F7858A77':
                    y = int(80 * quotas['Value'] / 100)
                    x = len(self.tables['Table']['GlobalSecondaryIndexes'])
                    
                    if x >= y:
                        self.results['serviceLimitMaxGSIPerTable'] = [-1, str(x) + '/' + str(quotas['Value']) + ' GSI. Exceed 80% recommended GSI in the table']
                        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check CW Sum ConditionalCheckFailedRequests > 0
    def _check_conditional_check_failed_requests(self):
        
        _sumOfConditionalCheckFailedRequest = 0;
        
        try:
            #Count the number active reads on the table on the GSIs
            result = self.cloudWatchClient.get_metric_statistics(
                Namespace = 'AWS/DynamoDB',
                MetricName = 'ConditionalCheckFailedRequests',
                Dimensions = [
                        {
                            'Name':'TableName',
                            'Value':self.tables['Table']['TableName']
                        },
                    ],
                StartTime = datetime.datetime.now() - datetime.timedelta(7),
                EndTime = datetime.datetime.now(),
                Period = 900,
                Statistics = [
                    'SampleCount',
                ],
                Unit = 'Count'
            )
            
            for eachDatapoints in result['Datapoints']:
                _sumOfConditionalCheckFailedRequest += eachDatapoints['SampleCount']
                
            if _sumOfConditionalCheckFailedRequest >= 1.0:
                self.results['conditionalCheckFailedRequests'] = [-1, str(_sumOfConditionalCheckFailedRequest) + ' : errors in past 7 days']
                    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check service limit wcu and rcu
    def _check_service_limit_wcu_rcu(self):
        try:
            
            _startTime = datetime.datetime.now() - datetime.timedelta(7)
            _endTime = datetime.datetime.now()
            
            #Count the number active reads on the table RCU
            rcuResult = self.cloudWatchClient.get_metric_statistics(
                Namespace = 'AWS/DynamoDB',
                MetricName = 'ConsumedReadCapacityUnits',
                Dimensions = [
                        {
                            'Name':'TableName',
                            'Value':self.tables['Table']['TableName']
                        },
                    ],
                StartTime = _startTime,
                EndTime = _endTime,
                Period = 3600,
                Statistics = [
                    'Average',
                ],
                Unit = 'Count'
            )
            
            #Count the number active reads on the table WCU
            wcuResult = self._consumedWcu7Days()
            
            _rcuLimitCount = 0
            _wcuLimitCount = 0
            
            for eachRCUAverage in rcuResult['Datapoints']:
                if eachRCUAverage['Average'] > 0.8:
                    _rcuLimitCount += 1
            
            for eachWCUAverage in wcuResult['Datapoints']:
                if eachWCUAverage['Average'] > 0.8:
                    _wcuLimitCount += 1
                
            if _rcuLimitCount > 0:
                self.results['rcuServiceLimit'] = [-1, 'RCU limit > ' + str(_rcuLimitCount) + ' in past 7 days.']
            
            if _wcuLimitCount > 0:
                self.results['wcuServiceLimit'] = [-1, 'WCU limit > ' + str(_wcuLimitCount) + ' in past 7 days.']
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
            
    # logic to check autoscaling aggresiveness
    def _check_autoscaling_aggresiveness(self):
        try:
            results = self._scalingPolicies()
            
            
            if len(results['ScalingPolicies']) > 0:
            
                _wcuTarget = 0
                _rcuTarget = 0
                
                for eachScalingPolicies in results['ScalingPolicies']:
                    if eachScalingPolicies['ScalableDimension'] == 'dynamodb:table:WriteCapacityUnits':
                        _wcuTarget = eachScalingPolicies['TargetTrackingScalingPolicyConfiguration']['TargetValue']
                    elif eachScalingPolicies['ScalableDimension'] == 'dynamodb:table:ReadCapacityUnits':
                        _rcuTarget = eachScalingPolicies['TargetTrackingScalingPolicyConfiguration']['TargetValue']
                
                if _rcuTarget >= 80.0: 
                    self.results['autoScalingHighUtil'] = [-1, 'RCU = ' + str(_rcuTarget)]
            
                if _rcuTarget <= 50.0:
                    self.results['autoScalingLowUtil'] = [-1, 'RCU = ' + str(_rcuTarget)]
            
                if _wcuTarget >= 80.0:
                    self.results['autoScalingHighUtil'] = [-1, 'WCU = ' + str(_wcuTarget)]
            
                if _wcuTarget <= 50.0:
                    self.results['autoScalingLowUtil'] = [-1, 'WCU = ' + str(_wcuTarget)]
                   
        except botocore.exceptions as e:
            ecode = e.response['Error']['Code']
            print(ecode)
    
    # logic to check CW Sum SystemErrors > 0
    def _check_system_errors(self):
        try:
            #Count the number active reads on the table on the GSIs
            result = self.cloudWatchClient.get_metric_statistics(
                Namespace = 'AWS/DynamoDB',
                MetricName = 'SystemErrors',
                Dimensions = [
                       {
                            'Name':'TableName',
                            'Value':self.tables['Table']['TableName']
                        },
                    ],
                StartTime = datetime.datetime.now() - datetime.timedelta(30),
                EndTime = datetime.datetime.now(),
                Period = 3600,
                Statistics = [
                    'SampleCount',
                ],
                Unit = 'Count'
            )
            
            _systemErrorsCount = 0
            
            for eachDatapoints in result['Datapoints']:
                _systemErrorsCount += eachDatapoints['SampleCount']
            
            if _systemErrorsCount > 0:
                self.results['systemErrors'] = [-1,  '['+ str(_systemErrorsCount)+ '] SystemError in past 7 days']
                    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
     
    # logic to check CW Sum ThrottledRequest > 0
    def _check_throttled_request(self):
        try:
            #Count the number active reads on the table on the GSIs
            result = self.cloudWatchClient.get_metric_statistics(
                Namespace = 'AWS/DynamoDB',
                MetricName = 'ThrottledRequests',
                Dimensions = [
                       {
                            'Name':'TableName',
                            'Value': self.tables['Table']['TableName']
                        },
                    ],
                StartTime = datetime.datetime.now() - datetime.timedelta(30),
                EndTime = datetime.datetime.now(),
                Period = 3600,
                Statistics = [
                    'SampleCount',
                ],
                Unit = 'Count'
            )
            
            _throttledRequestErrors = 0
            
            for eachDatapoints in result['Datapoints']:
                _throttledRequestErrors += eachDatapoints['SampleCount']
            
            if _throttledRequestErrors > 0:
                self.results['throttledRequest'] = [-1, '[' + str(_throttledRequestErrors) + '] request throttled in past 30 days']
                    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check encryption at rest
    def _check_encryption_at_rest(self):
        try:
            # Check if SSEDescription exists and encryption is enabled
            sse_description = self.tables['Table'].get('SSEDescription', {})
            
            if not sse_description:
                # No encryption configured
                self.results['encryptionAtRest'] = [-1, 'Encryption at rest is not enabled']
            else:
                sse_status = sse_description.get('Status')
                sse_type = sse_description.get('SSEType')
                
                # Check if encryption is not enabled or in a transitional state
                if sse_status not in ['ENABLED', 'ENABLING']:
                    self.results['encryptionAtRest'] = [-1, f'Encryption status: {sse_status}']
                # Optionally flag if not using KMS (using default AES256)
                elif sse_type == 'AES256':
                    self.results['encryptionAtRest'] = [-1, 'Using default encryption (AES256), consider KMS for better control']
                    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check global table version
    def _check_global_table_version(self):
        try:
            # Check if table is a global table and verify version
            global_table_version = self.tables['Table'].get('GlobalTableVersion')
            
            # Only flag if it's a global table with legacy version
            if global_table_version == '2017.11.29':
                self.results['globalTableVersion'] = [-1, 'Using legacy global table version (2017.11.29)']
            # Note: If GlobalTableVersion is None, it's not a global table (pass)
            # If it's '2019.11.21', it's using current version (pass)
                    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    # logic to check table class optimization
    def _check_table_class_optimization(self):
        try:
            # Get table class information
            table_class_summary = self.tables['Table'].get('TableClassSummary', {})
            table_class = table_class_summary.get('TableClass', 'STANDARD')
            
            # Only recommend Standard-IA if currently using STANDARD
            if table_class == 'STANDARD':
                # Get table size to determine if recommendation is relevant
                table_size_bytes = self.tables['Table'].get('TableSizeBytes', 0)
                
                # Only recommend for tables with significant storage (>10 GB)
                if table_size_bytes > 10 * 1024 * 1024 * 1024:  # 10 GB in bytes
                    # Check CloudWatch metrics for access patterns (optional enhancement)
                    # For now, flag all large STANDARD tables as potential candidates
                    table_size_gb = table_size_bytes / (1024 * 1024 * 1024)
                    self.results['tableClassOptimization'] = [-1, f'Table size: {table_size_gb:.2f} GB - Consider Standard-IA for infrequent access']
                    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)

    # Resource-based policy on the table (and its stream) must not grant access to any principal
    # or to unscoped cross-account principals.
    def _checkDynamodbResourcePolicyPublic(self):
        table = self.tables['Table']
        tableArn = table.get('TableArn')
        if not tableArn:
            self.results['dynamodbResourcePolicyPublic'] = [0, 'Unable to evaluate (TableArn missing)']
            return
        ownAccount = tableArn.split(':')[4] if len(tableArn.split(':')) > 4 else ''

        targets = [('table', tableArn)]
        if table.get('LatestStreamArn'):
            targets.append(('stream', table['LatestStreamArn']))

        issues = []
        errors = []
        for kind, arn in targets:
            try:
                resp = self.dynamoDbClient.get_resource_policy(ResourceArn=arn)
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', 'Unknown')
                if code == 'PolicyNotFoundException':
                    continue
                # A stream ARN that is no longer readable (stream disabled) has no policy to evaluate.
                if kind == 'stream' and code == 'ResourceNotFoundException':
                    continue
                errors.append(code)
                continue
            found = resourcePolicyIssues(resp.get('Policy'), ownAccount)
            if found is None:
                errors.append('PolicyNotParseable')
                continue
            issues.extend(kind + ' policy ' + i for i in found)

        if issues:
            self.results['dynamodbResourcePolicyPublic'] = [-1, '; '.join(issues)]
        elif errors:
            self.results['dynamodbResourcePolicyPublic'] = [0, 'Unable to evaluate (' + ', '.join(sorted(set(errors))) + ')']
        else:
            self.results['dynamodbResourcePolicyPublic'] = [1, '']

    # Heuristic (tier 3): a table tagged as business critical should have a replica in another
    # Region (global table) for disaster recovery. Untagged tables are reported as INFO only.
    def _checkDynamodbNoMultiRegionReplica(self):
        key = 'dynamodbNoMultiRegionReplica'
        table = self.tables['Table']
        tableArn = table.get('TableArn', '')
        arnParts = tableArn.split(':')
        ownRegion = arnParts[3] if len(arnParts) > 3 else None

        replicaRegions = set()
        unhealthy = []

        def consider(r):
            region = r.get('RegionName')
            if not region or region == ownRegion:
                return
            status = r.get('ReplicaStatus')
            # Allowlist: only replicas that can serve traffic count for DR. A missing (optional)
            # status field is not evidence of an unhealthy replica.
            if status is None or status in _HEALTHY_REPLICA_STATUSES:
                replicaRegions.add(region)
            else:
                unhealthy.append(region + ' (' + str(status) + ')')

        for r in table.get('Replicas') or []:
            if isinstance(r, dict):
                consider(r)

        # Legacy (2017.11.29) global tables report their replicas only via DescribeGlobalTable.
        if not replicaRegions and table.get('GlobalTableVersion') == '2017.11.29':
            try:
                gt = self.dynamoDbClient.describe_global_table(GlobalTableName=self.tablename)
                for r in gt.get('GlobalTableDescription', {}).get('ReplicationGroup', []) or []:
                    if isinstance(r, dict):
                        consider(r)
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', 'Unknown')
                self.results[key] = [0, 'Unable to evaluate (' + code + ')']
                return

        if replicaRegions:
            self.results[key] = [1, 'Replicas: ' + ', '.join(sorted(replicaRegions))]
            return

        try:
            tags = []
            kwargs = {'ResourceArn': tableArn}
            while True:
                # First page is shared with _check_resources_for_tags; later pages are fetched here.
                if 'NextToken' in kwargs:
                    resp = self.dynamoDbClient.list_tags_of_resource(**kwargs)
                else:
                    resp = self._tagsFirstPage(tableArn)
                tags.extend(resp.get('Tags', []) or [])
                if not resp.get('NextToken'):
                    break
                kwargs['NextToken'] = resp['NextToken']
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.results[key] = [0, 'Unable to evaluate (' + code + ')']
            return

        criticalTag = None
        for t in tags:
            if _norm(t.get('Key', '')) in _CRITICALITY_TAG_KEYS and _norm(t.get('Value', '')) in _CRITICALITY_TAG_VALUES:
                criticalTag = str(t.get('Key')) + '=' + str(t.get('Value'))
                break

        note = ''
        if unhealthy:
            note = ' (replicas not serving traffic: ' + ', '.join(sorted(unhealthy)) + ')'
        if criticalTag:
            self.results[key] = [-1, 'Table tagged ' + criticalTag + ' has no active replica in another Region' + note]
        else:
            self.results[key] = [0, 'No active replica in another Region; table is not tagged as critical - review its DR requirements' + note]

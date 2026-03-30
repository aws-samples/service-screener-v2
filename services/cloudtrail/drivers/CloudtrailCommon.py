import botocore
import boto3

from utils.Config import Config
from services.Evaluator import Evaluator

class CloudtrailCommon(Evaluator):
    def __init__(self, trail, ctClient, snsClient, s3Client):
        super().__init__()
        self.trail = trail
        self.ctClient = ctClient
        self.snsClient = snsClient
        self.s3Client = s3Client
        
        self._resourceName = trail['TrailARN']

        r = self.ctClient.describe_trails(
            trailNameList=[self.trail['TrailARN']]
        )
        
        s = self.ctClient.get_event_selectors(
            TrailName=self.trail['TrailARN']
        )
        
        self.trailInfo = r.get('trailList')[0]
        self.trailSelector = {
            'Event': s.get('EventSelectors'), 
            'AdvancedEvent': s.get('AdvancedEventSelectors')
        }
        
        self.init()
    
    ## For General Trail purpose
    def _checkHasGeneralTrailSetup(self):
        if Config.get('CloudTrail_hasOneMultiRegion') == False and self.trailInfo['IsMultiRegionTrail'] == True:
            Config.set('CloudTrail_hasOneMultiRegion', True)
        
        if  self.trailInfo['IncludeGlobalServiceEvents'] == True:
            gList = Config.get('CloudTrail_listGlobalServEnabled')
            gList.append(self.trail['TrailARN'])
            
            Config.set('CloudTrail_hasGlobalServEnabled', True)
            Config.set('CloudTrail_listGlobalServEnabled', gList)
    
    def _checkTrailBestPractices(self):
        if not self.trailInfo['LogFileValidationEnabled'] == True:
            self.results['LogFileValidationEnabled'] = [-1, '']
            
        if (not 'CloudWatchLogsLogGroupArn' in self.trailInfo) or (len(self.trailInfo['CloudWatchLogsLogGroupArn']) == 0):
            self.results['CloudWatchLogsLogGroupArn'] = [-1, '']    
    
        if (not 'KmsKeyId' in self.trailInfo):
            self.results['RequiresKmsKey'] = [-1, '']
            
            
        if (not 'HasInsightSelectors' in self.trailInfo) or (self.trailInfo['HasInsightSelectors'] == False):
            self.results['HasInsightSelectors'] = [-1, '']
            
    def _checkEvents(self):
        e = self.trailSelector['Event']
        if e == None:
            return
        
        if 'IncludeManagementEvents' in e and e['IncludeManagementEvents'] == True:
            Config.set('CloudTrail_hasManagementEventsCaptured', True)
        
        if 'DataResources' in e and len(e['DataResources']) > 0:
            Config.set('CloudTrail_hasDataEventsCaptured', True)
            
    def _checkSNSTopicValid(self):
        if (not 'SnsTopicARN' in self.trailInfo) or (self.trailInfo['SnsTopicARN'] == None):
            self.results['SetupSNSTopicForTrail'] = [-1, '']
            return
        
        snsArn = self.trailInfo['SnsTopicARN']
        try:
            r = self.snsClient.get_topic_attributes(TopicArn = snsArn)
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'NotFoundException':
                self.results['SNSTopicNoLongerValid'] = [-1, self.trail['TrailARN']]
            else:
                print(snsArn, err.response['Error']['Code'])
    
    def _checkTrailStatus(self):
        r = self.ctClient.get_trail_status(
            Name=self.trail['TrailARN']
        )
        
        if not 'IsLogging' in r or r.get('IsLogging') == False:
            self.results['EnableCloudTrailLogging'] = [-1, '']
        
        # Only check for delivery errors if the attribute exists and is not 'None'
        if 'LatestDeliveryError' in r and r.get('LatestDeliveryError') != 'None':
            self.results['TrailDeliverError'] = [-1, r.get('LatestDeliveryError')]
            
    def _checkS3BucketSettings(self):
        ## For safety purpose, though all trails must have bucket
        if 'S3BucketName' in self.trailInfo and len(self.trailInfo['S3BucketName']) > 0:
            s3Bucket = self.trailInfo['S3BucketName']
            # help me retrieve s3 bucket public
            try:
                resp = self.s3Client.get_public_access_block(
                    Bucket=s3Bucket
                )
                
                for param, val in resp['PublicAccessBlockConfiguration'].items():
                    if val == False:
                        self.results['EnableS3PublicAccessBlock'] = [-1, None]
                        break
                    
            except botocore.exceptions.ClientError as e:
                print('-- Unable to capture Public Access Block settings:', e.response['Error']['Code'])
            
            try:
                r = self.s3Client.get_bucket_versioning(
                    Bucket=s3Bucket
                )
                
                mfaDelete = r.get('MFADelete')
                if mfaDelete == None or mfaDelete == 'Disabled':
                    self.results['EnableTrailS3BucketMFADelete'] = [-1, '']
                
                versioning = r.get('Status')
                if versioning == None or versioning == 'Disabled':
                    self.results['EnableTrailS3BucketVersioning'] = [-1, '']
                    
            except botocore.exceptions.ClientError as e:
                print('-- Unable to capture S3 MFA settings:', e.response['Error']['Code'])
        
            try:
                r = self.s3Client.get_bucket_logging(
                    Bucket=s3Bucket
                )
                logEnable = r.get('LoggingEnabled')
                if logEnable == None or not type(logEnable) is dict:
                    self.results['EnableTrailS3BucketLogging'] = [-1, '']
            except botocore.exceptions.ClientError as e:
                print('-- Unable to capture S3 Logging settings:', e.response['Error']['Code'])
                
            try:
                resp = self.s3Client.get_bucket_lifecycle(
                    Bucket=s3Bucket
                )
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] ==  'NoSuchLifecycleConfiguration':
                    self.results['EnableTrailS3BucketLifecycle'] = [-1, 'Off']

    def _checkKMSPolicySourceArn(self):
        """
        Validates that KMS key policies include aws:SourceArn condition
        to ensure keys are only used by specific CloudTrail trails
        """
        # Skip if trail doesn't use KMS encryption
        if 'KmsKeyId' not in self.trailInfo:
            return
        
        kmsKeyId = self.trailInfo['KmsKeyId']
        trailArn = self.trail['TrailARN']
        
        try:
            # Get KMS key policy
            kmsClient = boto3.client('kms')
            response = kmsClient.get_key_policy(
                KeyId=kmsKeyId,
                PolicyName='default'
            )
            
            import json
            policy = json.loads(response['Policy'])
            
            # Check if any statement includes aws:SourceArn condition for this trail
            hasSourceArnCondition = False
            for statement in policy.get('Statement', []):
                conditions = statement.get('Condition', {})
                
                # Check for StringEquals or StringLike conditions
                for conditionType in ['StringEquals', 'StringLike']:
                    if conditionType in conditions:
                        sourceArn = conditions[conditionType].get('aws:SourceArn', '')
                        # Check if condition references this trail or uses wildcard
                        if sourceArn == trailArn or (isinstance(sourceArn, list) and trailArn in sourceArn):
                            hasSourceArnCondition = True
                            break
                        # Also accept wildcard patterns that include trail ARN
                        if isinstance(sourceArn, str) and 'cloudtrail' in sourceArn.lower():
                            hasSourceArnCondition = True
                            break
                
                if hasSourceArnCondition:
                    break
            
            if not hasSourceArnCondition:
                self.results['KMSPolicySourceArn'] = [-1, f'KMS key {kmsKeyId} lacks aws:SourceArn condition']
                
        except botocore.exceptions.ClientError as e:
            print(f'-- Unable to check KMS key policy: {e.response["Error"]["Code"]}')
    
    def _checkCloudWatchAlarmsConfigured(self):
        """
        Validates that CloudWatch metric filters and alarms are configured
        for critical security events in CloudTrail logs
        """
        # Skip if trail doesn't have CloudWatch Logs integration
        if 'CloudWatchLogsLogGroupArn' not in self.trailInfo or not self.trailInfo['CloudWatchLogsLogGroupArn']:
            return
        
        logGroupArn = self.trailInfo['CloudWatchLogsLogGroupArn']
        # Extract log group name from ARN: arn:aws:logs:region:account:log-group:name:*
        logGroupName = logGroupArn.split(':log-group:')[1].rstrip(':*') if ':log-group:' in logGroupArn else None
        
        if not logGroupName:
            return
        
        try:
            logsClient = boto3.client('logs')
            cwClient = boto3.client('cloudwatch')
            
            # Get metric filters for this log group
            response = logsClient.describe_metric_filters(
                logGroupName=logGroupName
            )
            
            metricFilters = response.get('metricFilters', [])
            
            if len(metricFilters) == 0:
                self.results['CloudWatchAlarmsConfigured'] = [-1, 'No metric filters configured']
                return
            
            # Check if alarms exist for the metric filters
            alarmsExist = False
            for metricFilter in metricFilters:
                for transformation in metricFilter.get('metricTransformations', []):
                    metricName = transformation.get('metricName')
                    metricNamespace = transformation.get('metricNamespace')
                    
                    if metricName and metricNamespace:
                        # Check if alarms exist for this metric
                        alarmResponse = cwClient.describe_alarms_for_metric(
                            MetricName=metricName,
                            Namespace=metricNamespace
                        )
                        
                        if len(alarmResponse.get('MetricAlarms', [])) > 0:
                            alarmsExist = True
                            break
                
                if alarmsExist:
                    break
            
            if not alarmsExist:
                self.results['CloudWatchAlarmsConfigured'] = [0, f'{len(metricFilters)} metric filters exist but no alarms configured']
            
        except botocore.exceptions.ClientError as e:
            print(f'-- Unable to check CloudWatch alarms: {e.response["Error"]["Code"]}')

import botocore
import json
from datetime import datetime, timedelta

from utils.Config import Config
from services.Evaluator import Evaluator

class SqsQueueDriver(Evaluator):
    def __init__(self, queue, sqs_client, cloudwatch_client, cloudtrail_client=None):
        super().__init__()
        self.queue = queue
        self.sqs_client = sqs_client
        self.cloudwatch_client = cloudwatch_client
        self.cloudtrail_client = cloudtrail_client
        self.queue_url = queue['QueueUrl']
        self.queue_name = queue['QueueName']
        self.attributes = queue.get('Attributes', {})
        
        # Store resource information for reporting
        self.addII('queueName', self.queue_name)
        self.addII('queueUrl', self.queue_url)
        self.addII('queueType', 'FIFO' if self.queue_name.endswith('.fifo') else 'Standard')
        
        # Resource name is the unique identifier
        self._resourceName = self.queue_name
        
        self.init()
    
    def _checkEncryptionAtRest(self):
        """
        Check if SQS queue has server-side encryption enabled.
        """
        kms_key_id = self.attributes.get('KmsMasterKeyId')
        sse_enabled = self.attributes.get('SqsManagedSseEnabled')
        
        if kms_key_id:
            self.results['EncryptionAtRest'] = [1, f'KMS Encrypted ({kms_key_id})']
        elif sse_enabled == 'true':
            self.results['EncryptionAtRest'] = [1, 'SSE-SQS Enabled']
        else:
            self.results['EncryptionAtRest'] = [-1, 'Not Encrypted']
    
    def _checkEncryptionInTransit(self):
        """
        Check if queue policy enforces HTTPS-only access or VPC endpoint usage.
        """
        policy_str = self.attributes.get('Policy')
        
        if not policy_str:
            self.results['EncryptionInTransit'] = [-1, 'No Policy Set']
            return
        
        try:
            policy = json.loads(policy_str)
            statements = policy.get('Statement', [])
            
            has_secure_transport = False
            has_deny_insecure = False
            has_vpc_endpoint_only = False
            
            for statement in statements:
                condition = statement.get('Condition', {})
                effect = statement.get('Effect', '')
                
                # Check for HTTPS enforcement
                if 'Bool' in condition and 'aws:SecureTransport' in condition['Bool']:
                    secure_transport = condition['Bool']['aws:SecureTransport']
                    if effect.upper() == 'ALLOW' and (secure_transport == 'true' or secure_transport is True):
                        has_secure_transport = True
                    elif effect.upper() == 'DENY' and (secure_transport == 'false' or secure_transport is False):
                        has_deny_insecure = True
                
                # Check for VPC endpoint only access
                if 'StringEquals' in condition and 'aws:sourceVpce' in condition['StringEquals']:
                    if effect.upper() == 'ALLOW':
                        has_vpc_endpoint_only = True
                elif 'StringNotEquals' in condition and 'aws:sourceVpce' in condition['StringNotEquals']:
                    if effect.upper() == 'DENY':
                        has_vpc_endpoint_only = True
            
            if has_vpc_endpoint_only:
                self.results['EncryptionInTransit'] = [1, 'VPC Endpoint Only (Encrypted)']
            elif has_secure_transport and has_deny_insecure:
                self.results['EncryptionInTransit'] = [1, 'HTTPS Enforced (Allow HTTPS & Deny HTTP)']
            elif has_secure_transport:
                self.results['EncryptionInTransit'] = [0, 'HTTPS Required but HTTP not explicitly denied']
            elif has_deny_insecure:
                self.results['EncryptionInTransit'] = [0, 'HTTP Denied but HTTPS not explicitly allowed']
            else:
                self.results['EncryptionInTransit'] = [-1, 'HTTPS Not Enforced']
                
        except (json.JSONDecodeError, KeyError):
            self.results['EncryptionInTransit'] = [-1, 'Invalid Policy']
    
    def _checkDeadLetterQueue(self):
        """
        Check if queue has dead letter queue configured or if it serves as a DLQ.
        """
        # Check if this queue is used as a DLQ by other queues
        dlq_used_by = self.queue.get('DlqUsedBy', [])
        if dlq_used_by:
            source_queues = ', '.join(dlq_used_by)
            self.results['DeadLetterQueue'] = [1, f'DLQ for: {source_queues}']
            return
        
        # Check if this queue has a DLQ configured
        redrive_policy = self.attributes.get('RedrivePolicy')
        
        if redrive_policy:
            try:
                policy = json.loads(redrive_policy)
                dlq_arn = policy.get('deadLetterTargetArn')
                max_receive_count = policy.get('maxReceiveCount', 'Unknown')
                
                if dlq_arn:
                    self.results['DeadLetterQueue'] = [1, f'Configured (Max Rcv: {max_receive_count})']
                else:
                    self.results['DeadLetterQueue'] = [-1, 'Invalid Configuration']
            except json.JSONDecodeError:
                self.results['DeadLetterQueue'] = [-1, 'Invalid Policy']
        else:
            self.results['DeadLetterQueue'] = [-1, 'Not Configured']
    
    def _checkVisibilityTimeout(self):
        """
        Check if visibility timeout is appropriately configured.
        """
        visibility_timeout = int(self.attributes.get('VisibilityTimeout', 30))
        
        if visibility_timeout == 30:
            self.results['VisibilityTimeout'] = [0, 'Default (30s) - Consider Optimization']
        elif visibility_timeout < 30:
            self.results['VisibilityTimeout'] = [-1, f'{visibility_timeout}s (Too Short)']
        elif visibility_timeout > 43199:  # 12 hours - 1 second
            self.results['VisibilityTimeout'] = [-1, f'{visibility_timeout}s (Too Long)']
        else:
            self.results['VisibilityTimeout'] = [1, f'{visibility_timeout}s']
    
    def _checkMessageRetention(self):
        """
        Check message retention period for cost optimization.
        """
        retention_period = int(self.attributes.get('MessageRetentionPeriod', 345600))
        retention_days = retention_period / 86400  # Convert seconds to days
        
        if retention_days == 14:  # 14 days (maximum)
            self.results['MessageRetention'] = [-1, f'{retention_days:.0f} days (Maximum - Consider Reducing)']
        elif retention_days > 7:
            self.results['MessageRetention'] = [-1, f'{retention_days:.0f} days (High Retention)']
        else:
            self.results['MessageRetention'] = [1, f'{retention_days:.0f} days']
    
    def _checkQueueMonitoring(self):
        """
        Check if CloudWatch alarms are configured for key SQS metrics.
        """
        try:
            # Key SQS metrics to monitor
            key_metrics = [
                'ApproximateNumberOfMessages',
                'ApproximateAgeOfOldestMessage',
                'NumberOfMessagesSent',
                'NumberOfMessagesReceived'
            ]
            
            total_alarms = 0
            monitored_metrics = []
            
            for metric_name in key_metrics:
                response = self.cloudwatch_client.describe_alarms_for_metric(
                    Namespace='AWS/SQS',
                    MetricName=metric_name,
                    Dimensions=[
                        {
                            'Name': 'QueueName',
                            'Value': self.queue_name
                        }
                    ]
                )
                
                alarms = response.get('MetricAlarms', [])
                if alarms:
                    total_alarms += len(alarms)
                    monitored_metrics.append(metric_name)
            
            if total_alarms > 0:
                self.results['QueueMonitoring'] = [1, f'{total_alarms} alarms on {len(monitored_metrics)} metrics']
            else:
                self.results['QueueMonitoring'] = [-1, 'No alarms on key metrics']
                
        except botocore.exceptions.ClientError:
            self.results['QueueMonitoring'] = [-1, 'Unable to Check Alarms']
    
    def _checkFifoConfiguration(self):
        """
        Check FIFO queue configuration best practices.
        """
        if not self.queue_name.endswith('.fifo'):
            # Skip check for standard queues
            return
        
        content_dedup = self.attributes.get('ContentBasedDeduplication', 'false')
        fifo_queue = self.attributes.get('FifoQueue', 'false')

        issues = []
        if fifo_queue != 'true':
            issues.append('Not properly configured as FIFO')
        
        if content_dedup == 'false':
            issues.append('Content-based deduplication disabled')
        
        if issues:
            self.results['FifoConfiguration'] = [-1, '; '.join(issues)]
        else:
            self.results['FifoConfiguration'] = [1, 'Properly Configured']
    
    def _checkAccessPolicy(self):
        """
        Check queue access policy for least privilege principles.
        """
        policy_str = self.attributes.get('Policy')
        
        if not policy_str:
            self.results['AccessPolicy'] = [1, 'No Policy (Default Permissions)']
            return
        
        try:
            policy = json.loads(policy_str)
            statements = policy.get('Statement', [])
            
            issues = []
            for statement in statements:
                # Check for overly permissive principals
                principal = statement.get('Principal', {})
                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                    issues.append('Wildcard principal')
                
                # Check for overly permissive actions
                action = statement.get('Action', [])
                if isinstance(action, str):
                    action = [action]

                if any(a.lower() == 'sqs:*' for a in action) or any('*' in a for a in action):
                    issues.append('Wildcard actions')
            
            if issues:
                self.results['AccessPolicy'] = [-1, '; '.join(issues)]
            else:
                self.results['AccessPolicy'] = [1, 'Follows Least Privilege']
                
        except json.JSONDecodeError:
            self.results['AccessPolicy'] = [-1, 'Invalid Policy']
    
    def _checkBatchOperations(self):
        """
        Check if batch operations are being used based on CloudTrail events.
        """
        if not self.cloudtrail_client:
            self.results['BatchOperations'] = [0, 'CloudTrail client not available']
            return
            
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=7)
            
            # Check average message volume over 7 days
            cw_response = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/SQS',
                MetricName='NumberOfMessagesSent',
                Dimensions=[{'Name': 'QueueName', 'Value': self.queue_name}],
                StartTime=start_time,
                EndTime=end_time,
                Period=604800,  # 7 days period
                Statistics=['Sum']
            )
            
            total_messages = sum(point['Sum'] for point in cw_response.get('Datapoints', []))
            avg_per_minute = total_messages / (7 * 24 * 60)  # 7 days in minutes
            
            if avg_per_minute < 1:
                self.results['BatchOperations'] = [1, 'No high volume detected']
                return
            
            # High volume detected, check for batch operations
            batch_events = ['SendMessageBatch', 'DeleteMessageBatch', 'ChangeMessageVisibilityBatch']
            
            for event_name in batch_events:
                response = self.cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'ResourceName',
                            'AttributeValue': self.queue_url
                        },
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': event_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=1
                )
                
                if response.get('Events'):
                    self.results['BatchOperations'] = [1, f'Batch operations detected ({event_name})']
                    return
            
            
            # CloudTrail not capturing SQS data events (not enabled)
            self.results['BatchOperations'] = [-1, 'No batch operations detected']
                
        except botocore.exceptions.ClientError:
            self.results['BatchOperations'] = [0, 'Unable to check CloudTrail events']
    
    def _checkUnusedQueues(self):
        """
        Check for unused queues based on CloudWatch metrics.
        """
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=30)
            
            # Check for any activity in the past 30 days
            metrics = ['NumberOfMessagesSent', 'NumberOfMessagesReceived']
            has_activity = False
            
            for metric in metrics:
                response = self.cloudwatch_client.get_metric_statistics(
                    Namespace='AWS/SQS',
                    MetricName=metric,
                    Dimensions=[{'Name': 'QueueName', 'Value': self.queue_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                
                total = sum(point['Sum'] for point in response.get('Datapoints', []))
                if total > 0:
                    has_activity = True
                    break
            
            if not has_activity:
                self.results['UnusedQueues'] = [-1, 'No Activity in 30 Days']
            else:
                self.results['UnusedQueues'] = [1, 'Active Queue']
                
        except botocore.exceptions.ClientError:
            self.results['UnusedQueues'] = [0, 'Unable to Check Activity']
    
    def _checkTaggingStrategy(self):
        """
        Check if queue has proper tagging for resource management.
        """
        try:
            response = self.sqs_client.list_queue_tags(QueueUrl=self.queue_url)
            tags = response.get('Tags', {})
            
            required_tags = ['Environment', 'Owner', 'Project', 'CostCenter']
            missing_tags = [tag for tag in required_tags if tag not in tags]
            
            if not tags:
                self.results['TaggingStrategy'] = [-1, 'No Tags Applied']
            elif len(missing_tags) > 2:
                self.results['TaggingStrategy'] = [-1, f'Missing: {", ".join(missing_tags)}']
            elif missing_tags:
                self.results['TaggingStrategy'] = [0, f'Missing: {", ".join(missing_tags)}']
            else:
                self.results['TaggingStrategy'] = [1, 'Properly Tagged']
                
        except botocore.exceptions.ClientError:
            self.results['TaggingStrategy'] = [0, 'Unable to Check Tags']
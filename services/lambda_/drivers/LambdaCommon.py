import json
import os
import sys
from datetime import datetime, timedelta

import botocore
import boto3

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator
import constants as _C

class LambdaCommon(Evaluator):
    RUNTIME_PREFIX = [
        'nodejs',
        'python',
        'java',
        'dotnetcore',
        'dotnet',
        'go',
        'ruby'
    ]

    CUSTOM_RUNTIME_PREFIX = [
        'provided'
    ]

    RUNTIME_PATH = _C.BOTOCORE_DIR + '/data/lambda/2015-03-31/service-2.json'
    CW_HISTORY_DAYS = [30, 7]

    def __init__(self, lambda_, lambda_client, iam_client, role_count):
        self.lambda_ = lambda_
        self.function_name = lambda_['FunctionName']
        self.role_count = role_count
        self.lambda_client = lambda_client
        self.iam_client = iam_client

        self._resourceName = self.function_name

        self.results = {}
        self.init()
    
    @staticmethod
    def get_arn_role_name(arn):
        array = arn.split("/")
        role_name = array[-1]
        return role_name

    def get_invocation_count(self, day):
        cw_client = Config.get('CWClient')

        dimensions = [
            {
                'Name': 'FunctionName',
                'Value': self.function_name
            }
        ]

        results = cw_client.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/Lambda',
            MetricName='Invocations',
            StartTime=datetime.utcnow() - timedelta(days=day),
            EndTime=datetime.utcnow(),
            Period=day * 24 * 60 * 60,
            Statistics=['SampleCount']
        )

        if not results['Datapoints']:
            return 0
        else:
            for result in results['Datapoints']:
                return result['SampleCount']

    
    def _check_architectures_is_arm(self):
        if 'arm64' in self.lambda_['Architectures']:
            return
        
        self.results['UseArmArchitecture'] = [-1, ', '.join(self.lambda_['Architectures'])]
    
    def _check_function_url_in_used_and_auth(self):
        try:
            url_config = self.lambda_client.list_function_url_configs(
                FunctionName=self.function_name
            )
            if url_config['FunctionUrlConfigs']:
                self.results['lambdaURLInUsed'] = [-1, "Enabled"]

                for config in url_config['FunctionUrlConfigs']:
                    if config['AuthType'] == 'NONE':
                        self.results['lambdaURLWithoutAuth'] = [-1, config['AuthType']]
                        return

        except botocore.exceptions.ClientError as e:
            print("No permission to access lambda:list_function_url_configs")
        return

    def _check_missing_role(self):
        role_arn = self.lambda_['Role']
        role_name = self.get_arn_role_name(role_arn)

        try:
            role = self.iam_client.get_role(
                RoleName=role_name
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                self.results['lambdaMissingRole'] = [-1, '']
            else:
                raise e
        return

    def _check_code_signing_disabled(self):
        if self.lambda_['PackageType'] != 'Zip':
            return
        try:
            code_sign = self.lambda_client.get_function_code_signing_config(
                FunctionName=self.function_name
            )
            if not code_sign.get('CodeSigningConfigArn'):
                self.results['lambdaCodeSigningDisabled'] = [-1, 'Disabled']
        except botocore.exceptions.ClientError as e:
            print("No permission to access get_function_code_signing_config")

        return

    def _check_dead_letter_queue_disabled(self):
        config = self.lambda_client.get_function_configuration(
            FunctionName=self.function_name
        )

        if not config.get('DeadLetterConfig'):
            self.results['lambdaDeadLetterQueueDisabled'] = [-1, 'Disabled']

        return

    def _check_env_var_default_key(self):
        function_name = self.lambda_['FunctionName']
        if not self.lambda_.get('KMSKeyArn'):
            self.results['lambdaCMKEncryptionDisabled'] = [-1, 'Disabled']
        return

    def _check_enhanced_monitor(self):
        if 'Layers' in self.lambda_:
            layers = self.lambda_['Layers']
            for layer in layers:
                if 'LambdaInsightsExtension' in layer['Arn']:
                    return

        self.results['lambdaEnhancedMonitoringDisabled'] = [-1, 'Disabled']
        return

    def _check_provisioned_concurrency(self):
        concurrency = self.lambda_client.get_function_concurrency(
            FunctionName=self.function_name
        )

        if not concurrency.get('ReservedConcurrentExecutions'):
            self.results['lambdaReservedConcurrencyDisabled'] = [-1, 'Disabled']

        return

    def _check_tracing_enabled(self):
        if 'TracingConfig' in self.lambda_ and 'Mode' in self.lambda_['TracingConfig'] and self.lambda_['TracingConfig']['Mode'] == 'PassThrough':
            self.results['lambdaTracingDisabled'] = [-1, 'Disabled']

        return

    def _check_role_reused(self):
        if self.role_count[self.lambda_['Role']] > 1:
            self.results['lambdaRoleReused'] = [-1, self.lambda_['Role']]
        return
    
    ## <TODO>
    ## Cache the runtime_version and enum instead of looping everytime
    def _check_runtime(self):
        if not os.path.exists(self.RUNTIME_PATH):
            print("Skipped runtime version check due to unable to locate runtime option path")
            return
        
        ## Container based will skip
        if self.lambda_['PackageType'] != 'Zip':
            return

        arr = Config.get('lambdaRunTimeList', False)
        if arr == False:
            with open(self.RUNTIME_PATH, 'r') as f:
                arr = json.load(f)
                
            Config.set('lambdaRunTimeList', arr)

        runtime = self.lambda_['Runtime']

        runtime_prefix = ''
        runtime_version = ''

        for prefix in self.CUSTOM_RUNTIME_PREFIX:
            if runtime.startswith(prefix):
                return

        for prefix in self.RUNTIME_PREFIX:
            if runtime.startswith(prefix):
                runtime_prefix = prefix

                replace_arr = [runtime_prefix]
                if prefix in ['go', 'nodejs']:
                    replace_arr.append('.x')
                if prefix == 'nodejs':
                    replace_arr.append('-edge')

                runtime_version = runtime
                for item in replace_arr:
                    runtime_version = runtime_version.replace(item, '')
                break

        # skip java check
        if runtime_prefix == 'java':
            return

        for option in arr['shapes']['Runtime']['enum']:
            if not option.startswith(runtime_prefix):
                continue
            else:
                option_version = option
                for item in replace_arr:
                    option_version = option_version.replace(item, '')
                if option_version == '':
                    option_version = 0

                if float(option_version) > float(runtime_version):
                    self.results['lambdaRuntimeUpdate'] = [-1, runtime]
                    return

        return
    
    
    def _check_function_in_used(self):
        for day in self.CW_HISTORY_DAYS:
            cnt = self.get_invocation_count(day)

            if cnt == 0:
                self.results['lambdaNotInUsed' + str(day) + 'Days'] = [-1, '']
                return

        return
    
    def _check_function_public_access(self):
        try:
            results = self.lambda_client.get_policy(
                FunctionName=self.function_name
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return
            else:
                raise e
                
        if results.get('Policy'):
            doc = json.loads(results.get('Policy'))
            pObj = Policy(doc)
            pObj.inspectPrinciple()
            
            if pObj.hasPublicAccess() == True:
                self.results['lambdaPublicAccess'] = [-1, 'Enabled']
            
        return
    
    def _check_sqs_visibility_timeout(self):
        """Check if SQS visibility timeout is at least 6x function timeout"""
        try:
            # Get event source mappings
            mappings = self.lambda_client.list_event_source_mappings(
                FunctionName=self.function_name
            )
            
            # Get function timeout
            func_config = self.lambda_client.get_function_configuration(
                FunctionName=self.function_name
            )
            function_timeout = func_config.get('Timeout', 3)
            
            # Check each SQS event source
            sqs_client = Config.get('SQSClient')
            if not sqs_client:
                bconfig = Config.get('bConfig', None)
                sqs_client = boto3.client('sqs') if not bconfig else boto3.client('sqs', config=bconfig)
                Config.set('SQSClient', sqs_client)
            
            for mapping in mappings.get('EventSourceMappings', []):
                event_source_arn = mapping.get('EventSourceArn', '')
                if ':sqs:' in event_source_arn:
                    # Extract queue name from ARN
                    queue_name = event_source_arn.split(':')[-1]
                    
                    try:
                        # Get queue URL
                        queue_url_response = sqs_client.get_queue_url(QueueName=queue_name)
                        queue_url = queue_url_response['QueueUrl']
                        
                        # Get queue attributes
                        attrs = sqs_client.get_queue_attributes(
                            QueueUrl=queue_url,
                            AttributeNames=['VisibilityTimeout']
                        )
                        
                        visibility_timeout = int(attrs['Attributes'].get('VisibilityTimeout', 30))
                        
                        # Check if visibility timeout is at least 6x function timeout
                        if visibility_timeout < (6 * function_timeout):
                            self.results['lambdaSQSVisibilityTimeout'] = [
                                -1, 
                                f"Function timeout: {function_timeout}s, SQS visibility: {visibility_timeout}s"
                            ]
                            return
                    except Exception as e:
                        # Skip if unable to get queue attributes
                        print(f"Unable to check SQS queue {queue_name}: {str(e)}")
                        continue
                        
        except Exception as e:
            print(f"Error checking SQS visibility timeout: {str(e)}")
        
        return
    
    def _check_async_retry_configuration(self):
        """Check if async invocation retry configuration is customized"""
        try:
            config = self.lambda_client.get_function_event_invoke_config(
                FunctionName=self.function_name
            )
            
            # Check if using default values (not customized)
            max_retry = config.get('MaximumRetryAttempts', 2)
            max_age = config.get('MaximumEventAgeInSeconds', 21600)
            
            # If both are defaults, flag as not configured
            if max_retry == 2 and max_age == 21600:
                self.results['lambdaAsyncRetryNotConfigured'] = [-1, 'Using defaults']
                
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                # No custom config means using defaults
                self.results['lambdaAsyncRetryNotConfigured'] = [-1, 'Not configured']
            else:
                print(f"Error checking async retry config: {str(e)}")
        
        return
    
    def _check_cloudwatch_alarms(self):
        """Check if CloudWatch alarms are configured for critical metrics"""
        try:
            cw_client = Config.get('CWClient')
            
            # Key metrics to check
            critical_metrics = ['Errors', 'Duration', 'Throttles']
            has_any_alarm = False
            
            for metric in critical_metrics:
                response = cw_client.describe_alarms_for_metric(
                    MetricName=metric,
                    Namespace='AWS/Lambda',
                    Dimensions=[
                        {'Name': 'FunctionName', 'Value': self.function_name}
                    ]
                )
                
                if response.get('MetricAlarms'):
                    has_any_alarm = True
                    break
            
            if not has_any_alarm:
                self.results['lambdaNoCloudWatchAlarms'] = [-1, 'No alarms configured']
                
        except Exception as e:
            print(f"Error checking CloudWatch alarms: {str(e)}")
        
        return
    
    def _check_partial_batch_response(self):
        """Check if partial batch response is enabled for stream sources"""
        try:
            mappings = self.lambda_client.list_event_source_mappings(
                FunctionName=self.function_name
            )
            
            for mapping in mappings.get('EventSourceMappings', []):
                event_source_arn = mapping.get('EventSourceArn', '')
                
                # Check if source is Kinesis or DynamoDB Streams
                if ':kinesis:' in event_source_arn or ':dynamodb:' in event_source_arn:
                    function_response_types = mapping.get('FunctionResponseTypes', [])
                    
                    if 'ReportBatchItemFailures' not in function_response_types:
                        self.results['lambdaPartialBatchResponseDisabled'] = [
                            -1, 
                            'Stream source without partial batch response'
                        ]
                        return
                        
        except Exception as e:
            print(f"Error checking partial batch response: {str(e)}")
        
        return
    
    def _check_batching_window(self):
        """Check if batching window is configured for stream sources"""
        try:
            mappings = self.lambda_client.list_event_source_mappings(
                FunctionName=self.function_name
            )
            
            for mapping in mappings.get('EventSourceMappings', []):
                event_source_arn = mapping.get('EventSourceArn', '')
                
                # Check if source is Kinesis or DynamoDB Streams
                if ':kinesis:' in event_source_arn or ':dynamodb:' in event_source_arn:
                    batching_window = mapping.get('MaximumBatchingWindowInSeconds', 0)
                    
                    if batching_window == 0:
                        self.results['lambdaBatchingWindowNotConfigured'] = [
                            -1, 
                            'No batching window configured'
                        ]
                        return
                        
        except Exception as e:
            print(f"Error checking batching window: {str(e)}")
        
        return
    
    def _check_iterator_age_alarm(self):
        """Check if IteratorAge alarms are configured for stream consumers"""
        try:
            mappings = self.lambda_client.list_event_source_mappings(
                FunctionName=self.function_name
            )
            
            has_stream_source = False
            for mapping in mappings.get('EventSourceMappings', []):
                event_source_arn = mapping.get('EventSourceArn', '')
                
                # Check if source is Kinesis or DynamoDB Streams
                if ':kinesis:' in event_source_arn or ':dynamodb:' in event_source_arn:
                    has_stream_source = True
                    break
            
            if has_stream_source:
                # Check for IteratorAge alarm
                cw_client = Config.get('CWClient')
                response = cw_client.describe_alarms_for_metric(
                    MetricName='IteratorAge',
                    Namespace='AWS/Lambda',
                    Dimensions=[
                        {'Name': 'FunctionName', 'Value': self.function_name}
                    ]
                )
                
                if not response.get('MetricAlarms'):
                    self.results['lambdaNoIteratorAgeAlarm'] = [-1, 'No IteratorAge alarm']
                    
        except Exception as e:
            print(f"Error checking IteratorAge alarm: {str(e)}")
        
        return
    
    def _check_guardduty_lambda_protection(self):
        """Check if GuardDuty Lambda Protection is enabled (account-level check)"""
        try:
            # This is an account-level check, only run once
            if Config.get('GuardDutyLambdaProtectionChecked', False):
                return
            
            Config.set('GuardDutyLambdaProtectionChecked', True)
            
            guardduty_client = Config.get('GuardDutyClient')
            if not guardduty_client:
                guardduty_client = boto3.client('guardduty', config=Config.get('bConfig'))
                Config.set('GuardDutyClient', guardduty_client)
            
            # List detectors
            detectors = guardduty_client.list_detectors()
            
            if not detectors.get('DetectorIds'):
                # GuardDuty not enabled
                self.results['lambdaGuardDutyProtectionDisabled'] = [-1, 'GuardDuty not enabled']
                return
            
            # Check if Lambda Protection is enabled
            for detector_id in detectors['DetectorIds']:
                detector = guardduty_client.get_detector(DetectorId=detector_id)
                
                # Check DataSources for Lambda protection
                data_sources = detector.get('DataSources', {})
                lambda_protection = data_sources.get('Lambda', {})
                
                if lambda_protection.get('Status') != 'ENABLED':
                    self.results['lambdaGuardDutyProtectionDisabled'] = [
                        -1, 
                        'Lambda Protection not enabled'
                    ]
                    return
                    
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] in ['AccessDeniedException', 'UnauthorizedException']:
                print("No permission to check GuardDuty Lambda Protection")
            else:
                print(f"Error checking GuardDuty Lambda Protection: {str(e)}")
        except Exception as e:
            print(f"Error checking GuardDuty Lambda Protection: {str(e)}")
        
        return

    def _check_environment_variables(self):
        """Check if function has environment variables defined"""
        try:
            if 'Environment' not in self.lambda_ or not self.lambda_['Environment'].get('Variables'):
                self.results['lambdaNoEnvironmentVariables'] = [-1, 'No environment variables']
        except Exception as e:
            print(f"Error checking environment variables: {str(e)}")
        
        return
    
    def _check_memory_optimization(self):
        """Check if memory configuration is optimized based on CloudWatch Logs"""
        try:
            # Get configured memory
            configured_memory = self.lambda_.get('MemorySize', 128)
            
            # Get CloudWatch Logs client
            logs_client = Config.get('LogsClient')
            if not logs_client:
                logs_client = boto3.client('logs', config=Config.get('bConfig'))
                Config.set('LogsClient', logs_client)
            
            # Query CloudWatch Logs Insights for max memory used
            log_group_name = f"/aws/lambda/{self.function_name}"
            
            # Check if log group exists
            try:
                logs_client.describe_log_groups(logGroupNamePrefix=log_group_name, limit=1)
            except Exception:
                # No logs available, skip check
                return
            
            # Query for max memory used in last 7 days
            query = f"""
            fields @maxMemoryUsed
            | filter @type = "REPORT"
            | stats max(@maxMemoryUsed) as maxMemory
            """
            
            from datetime import datetime, timedelta
            start_time = int((datetime.utcnow() - timedelta(days=7)).timestamp())
            end_time = int(datetime.utcnow().timestamp())
            
            response = logs_client.start_query(
                logGroupName=log_group_name,
                startTime=start_time,
                endTime=end_time,
                queryString=query
            )
            
            query_id = response['queryId']
            
            # Wait for query to complete (with timeout)
            import time
            max_wait = 10  # seconds
            waited = 0
            while waited < max_wait:
                result = logs_client.get_query_results(queryId=query_id)
                if result['status'] == 'Complete':
                    if result['results'] and len(result['results']) > 0:
                        max_memory_used = None
                        for field in result['results'][0]:
                            if field['field'] == 'maxMemory':
                                max_memory_used = float(field['value'])
                                break
                        
                        if max_memory_used:
                            # Check if over-provisioned (using < 50% of configured)
                            if max_memory_used < (configured_memory * 0.5):
                                self.results['lambdaMemoryNotOptimized'] = [
                                    -1,
                                    f"Configured: {configured_memory}MB, Max used: {int(max_memory_used)}MB (over-provisioned)"
                                ]
                            # Check if under-provisioned (using > 90% of configured)
                            elif max_memory_used > (configured_memory * 0.9):
                                self.results['lambdaMemoryNotOptimized'] = [
                                    -1,
                                    f"Configured: {configured_memory}MB, Max used: {int(max_memory_used)}MB (under-provisioned)"
                                ]
                    break
                elif result['status'] == 'Failed':
                    break
                time.sleep(0.5)
                waited += 0.5
                
        except Exception as e:
            print(f"Error checking memory optimization: {str(e)}")
        
        return
    
    def _check_timeout_optimization(self):
        """Check if timeout configuration matches execution patterns"""
        try:
            # Get configured timeout
            configured_timeout = self.lambda_.get('Timeout', 3)
            
            # Get CloudWatch metrics for Duration
            cw_client = Config.get('CWClient')
            
            from datetime import datetime, timedelta
            response = cw_client.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Duration',
                Dimensions=[
                    {'Name': 'FunctionName', 'Value': self.function_name}
                ],
                StartTime=datetime.utcnow() - timedelta(days=7),
                EndTime=datetime.utcnow(),
                Period=604800,  # 7 days in seconds
                Statistics=['Maximum', 'Average']
            )
            
            if response['Datapoints']:
                datapoint = response['Datapoints'][0]
                max_duration_ms = datapoint.get('Maximum', 0)
                avg_duration_ms = datapoint.get('Average', 0)
                
                max_duration_sec = max_duration_ms / 1000
                configured_timeout_ms = configured_timeout * 1000
                
                # Check if timeout is too close to max duration (>90%)
                if max_duration_ms > (configured_timeout_ms * 0.9):
                    self.results['lambdaTimeoutNotOptimized'] = [
                        -1,
                        f"Timeout: {configured_timeout}s, Max duration: {max_duration_sec:.1f}s (too close)"
                    ]
                # Check if timeout is much higher than needed (<10% usage)
                elif max_duration_ms < (configured_timeout_ms * 0.1) and configured_timeout > 10:
                    self.results['lambdaTimeoutNotOptimized'] = [
                        -1,
                        f"Timeout: {configured_timeout}s, Max duration: {max_duration_sec:.1f}s (over-configured)"
                    ]
                    
        except Exception as e:
            print(f"Error checking timeout optimization: {str(e)}")
        
        return
    
    def _check_role_permissions(self):
        """Check if execution role has overly broad permissions"""
        try:
            role_arn = self.lambda_['Role']
            role_name = self.get_arn_role_name(role_arn)
            
            # Get role policies
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            
            has_wildcard = False
            has_aws_managed = False
            
            # Check inline policies for wildcards
            for policy_name in inline_policies.get('PolicyNames', []):
                policy = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policy_doc = policy.get('PolicyDocument', {})
                
                # Check for wildcard actions or resources
                for statement in policy_doc.get('Statement', []):
                    if isinstance(statement, dict):
                        actions = statement.get('Action', [])
                        resources = statement.get('Resource', [])
                        
                        # Convert to list if string
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        
                        # Check for wildcard actions (e.g., "*" or "s3:*")
                        if '*' in actions:
                            has_wildcard = True
                            break
                        for action in actions:
                            if action == '*' or (isinstance(action, str) and action.endswith(':*')):
                                has_wildcard = True
                                break
                        
                        # Check for full wildcard resources (not path wildcards like arn:aws:s3:::bucket/*)
                        if '*' in resources:
                            has_wildcard = True
                            break
                        for resource in resources:
                            if resource == '*':
                                has_wildcard = True
                                break
                
                if has_wildcard:
                    break
            
            # Check for AWS managed policies (often too broad)
            for policy in attached_policies.get('AttachedPolicies', []):
                policy_arn = policy['PolicyArn']
                if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                    # Exclude common Lambda execution policies
                    if 'AWSLambdaBasicExecutionRole' not in policy_arn and \
                       'AWSLambdaVPCAccessExecutionRole' not in policy_arn:
                        has_aws_managed = True
                        break
            
            if has_wildcard or has_aws_managed:
                reason = []
                if has_wildcard:
                    reason.append('wildcard permissions')
                if has_aws_managed:
                    reason.append('AWS managed policies')
                
                self.results['lambdaRoleTooPermissive'] = [
                    -1,
                    f"Role has {', '.join(reason)}"
                ]
                
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                print(f"Error checking role permissions: {str(e)}")
        except Exception as e:
            print(f"Error checking role permissions: {str(e)}")
        
        return
    
    def _check_lambda_quotas(self):
        """Check if Lambda service quotas are being monitored (account-level check)"""
        try:
            # This is an account-level check, only run once
            if Config.get('LambdaQuotasChecked', False):
                return
            
            Config.set('LambdaQuotasChecked', True)
            
            # Get service quotas client
            sq_client = Config.get('ServiceQuotasClient')
            if not sq_client:
                sq_client = boto3.client('service-quotas', config=Config.get('bConfig'))
                Config.set('ServiceQuotasClient', sq_client)
            
            # Check concurrent executions quota
            try:
                quota = sq_client.get_service_quota(
                    ServiceCode='lambda',
                    QuotaCode='L-B99A9384'  # Concurrent executions
                )
                
                quota_value = quota['Quota']['Value']
                
                # Get current usage from CloudWatch
                cw_client = Config.get('CWClient')
                from datetime import datetime, timedelta
                
                response = cw_client.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='ConcurrentExecutions',
                    StartTime=datetime.utcnow() - timedelta(days=7),
                    EndTime=datetime.utcnow(),
                    Period=604800,
                    Statistics=['Maximum']
                )
                
                if response['Datapoints']:
                    max_concurrent = response['Datapoints'][0].get('Maximum', 0)
                    usage_percent = (max_concurrent / quota_value) * 100
                    
                    if usage_percent > 80:
                        self.results['lambdaQuotasNotMonitored'] = [
                            -1,
                            f"Concurrent executions at {usage_percent:.1f}% of quota ({int(max_concurrent)}/{int(quota_value)})"
                        ]
                        
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchResourceException':
                    # Quota not found, skip
                    pass
                else:
                    print(f"Error checking Lambda quotas: {str(e)}")
                    
        except Exception as e:
            print(f"Error checking Lambda quotas: {str(e)}")
        
        return
    
    def _check_reserved_concurrency_for_throttling(self):
        """Check if functions with throttling have reserved concurrency"""
        try:
            # Check for throttles in CloudWatch metrics
            cw_client = Config.get('CWClient')
            from datetime import datetime, timedelta
            
            response = cw_client.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Throttles',
                Dimensions=[
                    {'Name': 'FunctionName', 'Value': self.function_name}
                ],
                StartTime=datetime.utcnow() - timedelta(days=7),
                EndTime=datetime.utcnow(),
                Period=604800,
                Statistics=['Sum']
            )
            
            if response['Datapoints']:
                throttle_count = response['Datapoints'][0].get('Sum', 0)
                
                if throttle_count > 0:
                    # Check if reserved concurrency is set
                    concurrency = self.lambda_client.get_function_concurrency(
                        FunctionName=self.function_name
                    )
                    
                    if not concurrency.get('ReservedConcurrentExecutions'):
                        self.results['lambdaNoReservedConcurrencyForThrottling'] = [
                            -1,
                            f"Throttled {int(throttle_count)} times in last 7 days"
                        ]
                        
        except Exception as e:
            print(f"Error checking reserved concurrency for throttling: {str(e)}")
        
        return

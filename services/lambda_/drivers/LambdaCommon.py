import json
import os
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

    ## <TODO>
    # RUNTIME_PATH = os.path.join(os.environ.get("VENDOR_DIR"), 'aws/aws-sdk-php/src/data/lambda/2015-03-31/api-2.json.php')
    RUNTIME_PATH = _C.BOTOCORE_DIR + '/data/lambda/2015-03-31/service-2.json'
    CW_HISTORY_DAYS = [30, 7]

    def __init__(self, lambda_, lambda_client, iam_client, role_count):
        self.lambda_ = lambda_
        self.function_name = lambda_['FunctionName']
        self.role_count = role_count
        self.lambda_client = lambda_client
        self.iam_client = iam_client
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
    
    def _check_function_url_in_used(self):
        url_config = self.lambda_client.list_function_url_configs(
            FunctionName=self.function_name
        )
        if url_config['FunctionUrlConfigs']:
            self.results['lambdaURLInUsed'] = [-1, "Enabled"]
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

    def _check_url_without_auth(self):
        url_configs = self.lambda_client.list_function_url_configs(
            FunctionName=self.function_name
        )

        if url_configs['FunctionUrlConfigs']:
            for config in url_configs['FunctionUrlConfigs']:
                if config['AuthType'] == 'NONE':
                    self.results['lambdaURLWithoutAuth'] = [-1, config['AuthType']]
                    return

        return

    def _check_code_signing_disabled(self):
        if self.lambda_['PackageType'] != 'Zip':
            return
        
        code_sign = self.lambda_client.get_function_code_signing_config(
            FunctionName=self.function_name
        )
        if not code_sign.get('CodeSigningConfigArn'):
            self.results['lambdaCodeSigningDisabled'] = [-1, 'Disabled']

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
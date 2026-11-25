import urllib.parse
from datetime import date

import boto3
import botocore

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class S3Control(Evaluator):
    def __init__(self, s3Control):
        super().__init__()
        self.s3Control = s3Control

        self._resourceName = 'S3AccountLevel'
        
        self.init()
    
    def _checkAccountPublicAccessBlock(self):
        stsInfo = Config.get('stsInfo') or {}
        accountId = stsInfo.get('Account')
        if not accountId:
            self.results['S3AccountPublicAccessBlock'] = [0, 'Unable to evaluate (account id unavailable)']
            return

        try:
            resp = self.s3Control.get_public_access_block(
                AccountId = accountId
            )
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code == 'NoSuchPublicAccessBlockConfiguration':
                self.results['S3AccountPublicAccessBlock'] = [-1, 'Off']
            else:
                # AccessDenied etc. is not evidence that BPA is off.
                self.results['S3AccountPublicAccessBlock'] = [0, f'Unable to evaluate ({code})']
            return
        except botocore.exceptions.BotoCoreError as e:
            self.results['S3AccountPublicAccessBlock'] = [0, f'Unable to evaluate ({type(e).__name__})']
            return
        
        for param, val in resp['PublicAccessBlockConfiguration'].items():
            if val == False:
                self.results['S3AccountPublicAccessBlock'] = [-1, 'Off']
                return
            
        self.results['S3AccountPublicAccessBlock'] = [1,'On'] 

    def _checkStorageLens(self):
        """
        Check if S3 Storage Lens is enabled for the account.
        Storage Lens provides organization-wide visibility into storage usage,
        cost optimization opportunities, and security posture.
        """
        self.results['StorageLens'] = [-1, 'Not enabled']
        
        try:
            stsInfo = Config.get('stsInfo')
            if not stsInfo:
                print("Unable to retrieve account information for Storage Lens check")
                self.results['StorageLens'] = [0, 'Unable to evaluate (account id unavailable)']
                return
        except Exception as e:
            print(f'Unable to get account info for Storage Lens: {e}')
            self.results['StorageLens'] = [0, 'Unable to evaluate (account id unavailable)']
            return
        
        try:
            # List all Storage Lens configurations for the account
            resp = self.s3Control.list_storage_lens_configurations(
                AccountId=stsInfo['Account']
            )
            
            configs = resp.get('StorageLensConfigurationList', [])
            
            # Check if any configuration is enabled
            enabled_configs = []
            for config in configs:
                config_id = config.get('Id', '')
                is_enabled = config.get('IsEnabled', False)
                
                if is_enabled:
                    enabled_configs.append(config_id)
            
            if enabled_configs:
                config_count = len(enabled_configs)
                self.results['StorageLens'] = [1, f'{config_count} configuration(s) enabled']
            # else: remains as 'Not enabled'
                
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchConfiguration':
                # No configurations exist
                self.results['StorageLens'] = [-1, 'Not enabled']
            else:
                # An API error is not evidence that Storage Lens is disabled.
                print(f"Unable to check Storage Lens: {error_code}")
                self.results['StorageLens'] = [0, f'Unable to evaluate ({error_code})']
        except botocore.exceptions.BotoCoreError as e:
            self.results['StorageLens'] = [0, f'Unable to evaluate ({type(e).__name__})']

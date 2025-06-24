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
        self.results['S3AccountPublicAccessBlock'] = [-1,'Off']
        try:
            stsInfo = Config.get('stsInfo')
            if not stsInfo:
                print("Unable to retrieve account information")
                self.results['S3AccountPublicAccessBlock'] = [-1,'Insufficient info']
                return
        except botocore.exceptions.ClientError as e:
            print('Unable to capture S3 Logging settings:', e.response['Error']['Code'])
            # self.results['S3AccountPublicAccessBlock'] = [-1,'Insufficient info']
            
        try:
            resp = self.s3Control.get_public_access_block(
                AccountId = stsInfo['Account']
            )
        except botocore.exceptions.ClientError as e:
            print("Public access configuration not set")
            return
        
        for param, val in resp['PublicAccessBlockConfiguration'].items():
            if val == False:
                return
            
        self.results['S3AccountPublicAccessBlock'] = [1,'On'] 

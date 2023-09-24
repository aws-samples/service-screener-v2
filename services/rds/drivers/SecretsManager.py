import boto3

import time
from datetime import datetime, timedelta
from dateutil.tz import tzlocal

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import aws_parseInstanceFamily
from utils.Tools import _warn
from services.Evaluator import Evaluator

class SecretsManager(Evaluator):
    def __init__(self, secret, smClient, ctClient):
        super().__init__()
        self.secret = secret
        self.smClient = smClient
        self.ctClient = ctClient
        
        self.init()
    
    def _checkHasRotation(self):
        if not 'RotationEnabled' in self.secret or self.secret['RotationEnabled']==False:
            self.results['Secret__NoRotation'] = [-1, None]
            
    def _checkSecretUsage(self):
        LookupAttributes=[
            {
                'AttributeKey': 'ResourceName',
                'AttributeValue': self.secret['ARN']
            },
            {
                'AttributeKey': 'Eventname',
                'AttributeValue': 'GetSecretValue'
            }
        ]
        
        StartTime=datetime.today() - timedelta(days=7)
        EndTime=datetime.today() - timedelta(days=1)
        
        result = self.ctClient.lookup_events(
            LookupAttributes=LookupAttributes,
            StartTime=StartTime,
            EndTime=EndTime,
            MaxResults=1
        )
        
        ee = result.get('Events')
        if len(ee) == 0:
            self.results['Secret__NotUsed7days'] = [-1, None]
        
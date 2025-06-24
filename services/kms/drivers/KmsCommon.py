import boto3

import time
from datetime import datetime, tzinfo

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import _warn
# from utils.Tools import aws_parseInstanceFamily
from utils.Policy import Policy
from services.Evaluator import Evaluator

class KmsCommon(Evaluator):
    def __init__(self, kms, kmsClient):
        self.dbParams = {}
        self.results = {}
        self.kms = kms
        self.kmsClient = kmsClient

        self._resourceName = kms['Arn']

        # self.__configPrefix = 'kms::' +  + '::' + db['EngineVersion'] + '::'
        self.init()

    def _checkKeyInfo(self):
        if self.kms['KeyRotationEnabled'] == False:
            self.results['KeyRotationEnabled'] = [-1, False]
            
        if self.kms['KeyState'] == 'PendingDeletion':
            self.results['KeyInPendingDeletion'] = [-1, self.kms['DeletionDate'].strftime("%Y-%m-%d %H:%M:%S %Z")]
            
        if self.kms['KeyState'] == 'Disabled':
            self.results['DisabledKey'] = [-1, None]
            
            
    def _checkPolicyAdminUser(self):
        resp = self.kmsClient.get_key_policy(
            KeyId = self.kms['KeyId'],
            PolicyName = 'default'
        )
        
        pDoc = resp.get('Policy')
        pObj = Policy(pDoc)
        pObj.parseDocumentToJson()
        parseInfo = pObj.extractPolicyInfo()
        
        admins = []
        users = []
        
        ## <TODO> Add one more checks for "cross accounts user using the loops below"
        ## https://www.trendmicro.com/cloudoneconformity-staging/knowledge-base/aws/KMS/kms-cross-account-access.html
        
        ## <TODO> Check any Principal is *
        ## https://www.trendmicro.com/cloudoneconformity-staging/knowledge-base/aws/KMS/key-exposed.html
        if 'allow' in parseInfo:
            ## Build Admin List
            for sid, arr in parseInfo['allow'].items():
                if 'Service' in arr['Principal']:
                    continue
                
                if not 'AWS' in arr['Principal']:
                    continue
                
                principals = arr['Principal']['AWS']
                if isinstance(principals, str):
                    principals = [principals]
                
                if isinstance(arr['Action'], str):
                    arr['Action'] = [arr['Action']]
                
                for action in arr['Action']:
                    if action.startswith('kms:Enable'):
                        for principal in principals:
                            if principal not in admins:
                                admins.append(principal)
                        break
            
                    if action.startswith('kms:Encrypt'):
                        for principal in principals:
                            if principal not in users:
                                users.append(principal)
                        break
                    
                    if action.startswith('kms:CreateGrant'):
                        for principal in principals:
                            if principal not in users:
                                users.append(principal)
                        break
        
        findMatches = []
        if admins and users:
            findMatches = set(admins) & set(users)
            
        if findMatches:
            self.results['AdminIsGrantor'] = [-1, "<br>".join(findMatches)]
            
    
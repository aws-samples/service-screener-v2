import os
import json
import boto3
import botocore
from botocore.config import Config as bConfig

from utils.Config import Config
from utils.Tools import _warn, _info
import constants as _C

class CrossAccountsValidator():
    DEFAULT_ROLENAME = 'ServiceScreenerAutomationRole'
    DEFAULT_ROLESESSIONNAME = 'ServiceScreenerCrossAcct'    #For CloudTrail tracking purpose, does not impact any logic
    DEFAULT_DURATIONSECONDS = 7200
    ROLEARN_PREFIX = 'arn:aws:iam::{accountId}:role/{roleName}'
    
    ## Remove sample in future
    CONFIGJSON = _C.ROOT_DIR + '/crossAccounts.json'
    ROLEINFO = {}
    
    VALIDATED = False
    IncludeThisAccount = True
    
    def __init__(self):
        fileValidation = self.readConfig()
        
        if fileValidation == True:
            roleValidation = self.validateRoles()
            
        if fileValidation == True and roleValidation == True:
            self.VALIDATED = True
        else:
            print('Cross Account Roles failed, script end')
            exit()
            
    def isValidated(self):
        return self.VALIDATED
        
    def getCred(self):
        return self.ROLEINFO
        
    def validateRoles(self):
        canProceedFlag = True
        sts = boto3.client('sts')
        
        generalDicts = self.crossAccountsDict['general']
        for acct, cfg in self.crossAccountsDict['accountLists'].items():
            params = {**generalDicts, **cfg}
            res = {k: v for k, v in params.items() if v}
            
            res['RoleSessionName'] = self.DEFAULT_ROLESESSIONNAME    
            res['RoleArn'] = self.getRoleArn(acct, None if not 'RoleName' in res else res['RoleName'])
            res['DurationSeconds'] = self.DEFAULT_DURATIONSECONDS
            res.pop('RoleName')
            
            try:
                resp = sts.assume_role(**res)
                cred = resp.get('Credentials')
                if 'AccessKeyId' in cred and 'SecretAccessKey' in cred and 'SessionToken' in cred:
                    print('[\u2714] {}, assume_role passed'.format(acct))
                    
                    self.ROLEINFO[acct] = {
                        'aws_access_key_id': cred['AccessKeyId'],
                        'aws_secret_access_key': cred['SecretAccessKey'],
                        'aws_session_token': cred['SessionToken']
                    }
                    
            except botocore.exceptions.ClientError as err:
                canProceedFlag = False
                _warn("Unable to assume role, read more below")
                print('AcctId: {}'.format(acct), str(err))
                print(res)
                
                break
          
        return canProceedFlag
    
    def getRoleArn(self, acctId, roleName):
        if roleName == None:
            roleName = self.DEFAULT_ROLENAME
        
        return self.ROLEARN_PREFIX.format(accountId=acctId, roleName=roleName)
        
    def checkIfIncludeThisAccount(self):
        return self.IncludeThisAccount
    
    def readConfig(self):
        if os.path.exists(self.CONFIGJSON) == False:
            _warn('{} is not found, multiple accounts scan halted'.format(self.CONFIGJSON))
            return False
        
        generalErrMsg = "Unable to process {}, encounters error: {}"
        try:
            f = open(self.CONFIGJSON)
            data = json.load(f)
            f.close()
            
            self.IncludeThisAccount = True
            if 'general' in data and 'IncludeThisAccount' in data['general']:
                self.IncludeThisAccount = data['general']['IncludeThisAccount']
                del data['general']['IncludeThisAccount']
            
            self.crossAccountsDict = data
            if 'general' not in self.crossAccountsDict:
                _warn( generalErrMsg.format(self.CONFIGJSON, 'Missing <general> key') )
                return False
            if 'accountLists' not in self.crossAccountsDict:
                _warn( generalErrMsg.format(self.CONFIGJSON, 'Missing <accountLists> key') )
                return False
            
            return True
        except json.decoder.JSONDecodeError as err:
            _warn( generalErrMsg.format(self.CONFIGJSON, str(err)) )
            return False
        except Exception as err:
            _warn( generalErrMsg.format(self.CONFIGJSON, str(err)) )
            return False
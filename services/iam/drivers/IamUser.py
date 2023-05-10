import boto3
import datetime
from dateutil.tz import tzlocal

from .IamCommon import IamCommon
 
class IamUser(IamCommon):
    ENUM_NO_INFO = ['not_supported', 'no_information']
    
    def __init__(self, user, iamClient):
        super().__init__()
        self.user = user
        self.iamClient = iamClient
        
        self.init()

    def _checkHasMFA(self):
        xkey = "rootMfaActive" if self.user['user'] == "<root_account>" else "mfaActive"
        if self.user['mfa_active'] == 'false':
            self.results[xkey] = [-1, 'Inactive']

    def _checkConsoleLastAccess(self):
        key = ''
        
        ##<TODO>
        ##Created new Iam users, wait for this info to populate
        if self.user['password_last_used'] in self.ENUM_NO_INFO:
            return

        daySinceLastAccess = self.getAgeInDay(self.user['password_last_used'])

        if daySinceLastAccess > 365:
            key = "consoleLastAccess365"
        elif daySinceLastAccess > 90:
            key = "consoleLastAccess90"
        else:
            key = False
            
        if key != False:
            self.results[key] = [-1, daySinceLastAccess]
            
    def _checkPasswordLastChange(self):
        if self.user['password_last_changed'] in self.ENUM_NO_INFO:
            return
        
        daySinceLastChange = self.getAgeInDay(self.user['password_last_changed'])

        if daySinceLastChange > 365:
            key = "passwordLastChange365"
        elif daySinceLastChange > 90:
            key = "passwordLastChange90"
        else:
            key = False
            
        if key != False:
            self.results[key] = [-1, daySinceLastChange]
    
    def _checkUserInGroup(self):
        user = self.user['user']
        if user == '<root_account>':
            return
        
        resp = self.iamClient.list_groups_for_user(UserName = user)
        groups = resp.get('Groups')
        if not groups:
            self.results['userNotUsingGroup'] = [-1, '-']
            
    def _checkUserPolicy(self):
        user = self.user['user']
        if user == '<root_account>':
            return
            
        ## Managed Policy   
        resp = self.iamClient.list_attached_user_policies(UserName = user)
        policies = resp.get('AttachedPolicies')
        self.evaluateManagePolicy(policies) ## code in iam_common.class.php
        
        ## Inline Policy
        resp = self.iamClient.list_user_policies(UserName = user)
        inlinePolicies = resp.get('PolicyNames')
        self.evaluateInlinePolicy(inlinePolicies, user, 'user')
        
    def _checkAccessKeyRotate(self):
        user = self.user
        if user['user'] == '<root_account>':
            if user['access_key_1_active'] == 'false' and user['access_key_2_active'] == 'false':
                pass 
            else:
                self.results['rootHasAccessKey'] = [-1, '']
        else:
            ## <TODO>
            ## GenerateReport api will cache results, waiting it to refresh
            if user['access_key_1_active'] == 'false':
                return
            
            days = self.getAgeInDay(user['access_key_1_last_rotated'])
            
            if days >= 90:
                k = 'hasAccessKeyNoRotate90days'
            elif days >= 30:
                k = 'hasAccessKeyNoRotate30days'
            else:
                return
            
            self.results[k] = [-1, str(days)]
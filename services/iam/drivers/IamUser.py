import boto3, botocore
import datetime
from dateutil.tz import tzlocal

from .IamCommon import IamCommon
 
class IamUser(IamCommon):
    ENUM_NO_INFO = ['not_supported', 'no_information']
    
    BEDROCK_API_KEY_USER_PREFIX = 'bedrockapikey'

    def __init__(self, user, iamClient, authDetails=None, policyDocumentMap=None, bedrockCredentialMap=None):
        super().__init__()
        self.user = user
        self.iamClient = iamClient
        self._authDetails = authDetails
        self._policyDocumentMap = policyDocumentMap or {}
        self._bedrockCredentialMap = bedrockCredentialMap or {}
        self._prefetchedUserDetail = None
        
        # Look up prefetched user detail by username
        if authDetails and user['user'] != '<root_account>':
            for u in authDetails.get('users', []):
                if u.get('UserName') == user['user']:
                    self._prefetchedUserDetail = u
                    break

        self._resourceName = user['user']
        
        self.init()

    def _checkHasMFA(self):
        xkey = "rootMfaActive" if self.user['user'] == "<root_account>" else "mfaActive"
        if self.user['mfa_active'] == 'false' and (self.user['user'] == "<root_account>" or self.user['password_enabled'] == 'true'):
            self.results[xkey] = [-1, 'Inactive']
            
    def _checkConsoleLastAccess(self):
        key = ''
        
        ##<TODO>
        ##Created new Iam users, wait for this info to populate
        if self.user['password_last_used'] in self.ENUM_NO_INFO:
            return
        
        if self.user['password_enabled'] == 'false':
            return
        
        if self.user == '<root_account>':
            return

        daySinceLastAccess = self.getAgeInDay(self.user['password_last_used'])

        if daySinceLastAccess > 365:
            key = "consoleLastAccess365"
        elif daySinceLastAccess > 90:
            key = "consoleLastAccess90"
        elif daySinceLastAccess > 45:
            key = "consoleLastAccess45"
        else:
            key = False
            
        if key != False:
            self.results[key] = [-1, daySinceLastAccess]
    
    def _checkUserInGroup(self):
        user = self.user['user']
        if user == '<root_account>':
            return
        
        if self._prefetchedUserDetail:
            groups = self._prefetchedUserDetail.get('GroupList', [])
            if not groups:
                self.results['userNotUsingGroup'] = [-1, '-']
        else:
            try:
                resp = self.iamClient.list_groups_for_user(UserName=user)
                groups = resp.get('Groups')
                if not groups:
                    self.results['userNotUsingGroup'] = [-1, '-']
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'], e.response['Error']['Message'])
                
    def _checkUserPolicy(self):
        user = self.user['user']
        if user == '<root_account>':
            return
        
        if self._prefetchedUserDetail:
            policies = self._prefetchedUserDetail.get('AttachedManagedPolicies', [])
            self.evaluateManagePolicy(policies, self._policyDocumentMap)
            
            inlinePolicies = self._prefetchedUserDetail.get('UserPolicyList', [])
            if inlinePolicies:
                self.evaluateInlinePolicyFromDocs(inlinePolicies)
        else:
            try:
                resp = self.iamClient.list_attached_user_policies(UserName=user)
                policies = resp.get('AttachedPolicies')
                self.evaluateManagePolicy(policies)
                
                resp = self.iamClient.list_user_policies(UserName=user)
                inlinePolicies = resp.get('PolicyNames')
                self.evaluateInlinePolicy(inlinePolicies, user, 'user')
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'], e.response['Error']['Message'])
        
    def _checkAccessKeyRotate(self):
        user = self.user
        if user['password_last_changed'] in self.ENUM_NO_INFO:
            return
        
        if user['password_enabled'] == 'true':
            daySinceLastChange = self.getAgeInDay(self.user['password_last_changed'])
    
            if daySinceLastChange > 365:
                key = "passwordLastChange365"
            elif daySinceLastChange > 90:
                key = "passwordLastChange90"
            else:
                key = False
                
            if key != False:
                self.results[key] = [-1, daySinceLastChange]
            
        daysAccesskey = 0
        if user['user'] == '<root_account>':
            if user['access_key_1_active'] == 'false' and user['access_key_2_active'] == 'false':
                pass 
            else:
                self.results['rootHasAccessKey'] = [-1, '']
        else:
            if user['access_key_1_active'] == 'false':
                pass
            else:
                if user['access_key_2_active'] == 'false':
                    daysAccesskey = self.getAgeInDay(user['access_key_1_last_used_date'])
                    daysAccesskeyLastRotated = self.getAgeInDay(user['access_key_1_last_rotated'])
                else:
                    daysAccesskey = max(self.getAgeInDay(user['access_key_1_last_used_date']), self.getAgeInDay(user['access_key_2_last_used_date']))
                    daysAccesskeyLastRotated = max(self.getAgeInDay(user['access_key_1_last_rotated']), self.getAgeInDay(user['access_key_2_last_rotated']))
                
                if daysAccesskeyLastRotated >= 90:
                    k = 'hasAccessKeyNoRotate90days'
                elif daysAccesskeyLastRotated >= 30:
                    k = 'hasAccessKeyNoRotate30days'
                else:
                    return
                
                self.results[k] = [-1, str(daysAccesskey)]
        
            daySinceLastLogin = 0
            field = 'password_last_used'
            if user['password_last_used'] in self.ENUM_NO_INFO:
                field = 'user_creation_time'
                
            daySinceLastLogin = self.getAgeInDay(user[field])
                    
            if daysAccesskey >= 90 and daySinceLastLogin >= 90:
                self.results['userNoActivity90days'] = [-1, '']

    def _checkBedrockLongTermApiKey(self):
        user = self.user['user']
        if user == '<root_account>':
            return

        # Bedrock console creates the IAM user as BedrockAPIKey-xxxx; keys created via the API can use any user name
        isBedrockKeyUser = self.BEDROCK_API_KEY_USER_PREFIX in user.lower()
        creds = self._bedrockCredentialMap.get(user, [])
        if not isBedrockKeyUser and not creds:
            return

        now = datetime.datetime.now(tzlocal())
        activeKeys = []
        for cred in creds:
            if cred.get('Status') != 'Active':
                continue
            expiry = cred.get('ExpirationDate')
            if expiry and expiry <= now:
                continue
            activeKeys.append(cred)

        # Deleting or expiring a key leaves the IAM user and its Bedrock permissions in place
        if not activeKeys:
            self.results['bedrockApiKeyUnusedUser'] = [-1, 'No active key (unused Bedrock API key user)']
            return

        details = []
        noExpiry = 0
        for cred in activeKeys:
            ageDays = (now - cred['CreateDate']).days
            expiry = cred.get('ExpirationDate')
            if expiry:
                details.append('{}: {} days old, expires {}'.format(cred['ServiceSpecificCredentialId'], ageDays, expiry.strftime('%Y-%m-%d')))
            else:
                noExpiry += 1
                details.append('{}: {} days old, never expires'.format(cred['ServiceSpecificCredentialId'], ageDays))

        self.results['bedrockLongTermApiKey'] = [-1, '; '.join(details)]
        if noExpiry > 0:
            self.results['bedrockApiKeyNoExpiry'] = [-1, '{} active key(s) without expiry'.format(noExpiry)]

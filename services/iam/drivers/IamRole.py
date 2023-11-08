import datetime
from dateutil.tz import tzlocal

from .IamCommon import IamCommon

class IamRole(IamCommon):
    MAXSESSIONDURATION = 3600
    MAXROLENOTUSEDDAYS = 14
    def __init__(self, role, iamClient):
        super().__init__()
        self.role = role
        self.iamClient = iamClient
        self._configPrefix = 'iam::role::'

        self.init()
        self.retrieveRoleDetail()
        
    def retrieveRoleDetail(self):
        c = self.iamClient
        result = c.get_role(RoleName=self.role['RoleName'])
        
        detail = result.get('Role')
        self.role['RoleLastUsed'] = detail['RoleLastUsed']
        
    #def _checkMocktest(self):
    #    self.results['Mocktest'] = [-1, 'GG']
    
    #def _checkMocktest2(self):    
    #    self.results['Mocktest2'] = [-1, 'GG']
        
    def _checkRoleOldAge(self):
        c = self.iamClient
        now = datetime.datetime.today().date()
        
        if not self.role['RoleLastUsed'] or not self.role['RoleLastUsed']['LastUsedDate']:
            cdate = self.role['CreateDate'].date()
            diff = now - cdate
            days = diff.days
            
            if days > self.MAXROLENOTUSEDDAYS:
                self.results['unusedRole'] = [-1, "<b>{}</b> days passed".format(days)]
                
            return
        
        lastDate = self.role['RoleLastUsed']['LastUsedDate'].date()
        diff = now - lastDate
        days = diff.days
        
        if days > 30:
            self.results['unusedRole'] = [-1, "{} days".format(days)]
    
    def _checkLongSessionDuration(self):
        if self.role['MaxSessionDuration'] > self.MAXSESSIONDURATION:
            self.results['roleLongSession'] = [-1, self.role['MaxSessionDuration']]
            
    def _checkRolePolicy(self):
        role = self.role['RoleName']
        ## Managed Policy
        resp = self.iamClient.list_attached_role_policies(RoleName=role)
        policies = resp.get('AttachedPolicies')
        self.evaluateManagePolicy(policies)  ## code in iam_common.class.php
        
        ## Inline Policy
        resp = self.iamClient.list_role_policies(RoleName=role)
        inlinePolicies = resp.get('PolicyNames')
        self.evaluateInlinePolicy(inlinePolicies, role, 'role') 
        
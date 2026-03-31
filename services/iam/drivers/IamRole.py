import datetime
from dateutil.tz import tzlocal

from .IamCommon import IamCommon

class IamRole(IamCommon):
    MAXSESSIONDURATION = 3600
    MAXROLENOTUSEDDAYS = 14
    def __init__(self, role, iamClient, authDetails=None, policyDocumentMap=None):
        super().__init__()
        self.role = role
        self.iamClient = iamClient
        self._configPrefix = 'iam::role::'
        self._authDetails = authDetails
        self._policyDocumentMap = policyDocumentMap or {}

        self._resourceName = self.role['RoleName']

        self.init()
        self._enrichRoleDetail()
        
    def _enrichRoleDetail(self):
        """Ensure RoleLastUsed is populated, using prefetched data or API fallback"""
        if 'RoleLastUsed' in self.role:
            return
        
        # Fallback to API if not in prefetched data
        result = self.iamClient.get_role(RoleName=self.role['RoleName'])
        self.role['RoleLastUsed'] = result.get('Role', {}).get('RoleLastUsed', {})
        
    def _checkRoleOldAge(self):
        now = datetime.datetime.today().date()
        
        if not self.role['RoleLastUsed'] or not self.role['RoleLastUsed'].get('LastUsedDate'):
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
        if self.role.get('MaxSessionDuration', self.MAXSESSIONDURATION) > self.MAXSESSIONDURATION:
            self.results['roleLongSession'] = [-1, self.role['MaxSessionDuration']]
            
    def _checkRolePolicy(self):
        role = self.role['RoleName']
        
        # Use prefetched data if available
        if 'AttachedManagedPolicies' in self.role:
            policies = self.role['AttachedManagedPolicies']
            self.evaluateManagePolicy(policies, self._policyDocumentMap)
            
            inlinePolicies = self.role.get('RolePolicyList', [])
            if inlinePolicies:
                self.evaluateInlinePolicyFromDocs(inlinePolicies)
        else:
            # Fallback to API calls
            resp = self.iamClient.list_attached_role_policies(RoleName=role)
            policies = resp.get('AttachedPolicies')
            self.evaluateManagePolicy(policies)
            
            resp = self.iamClient.list_role_policies(RoleName=role)
            inlinePolicies = resp.get('PolicyNames')
            self.evaluateInlinePolicy(inlinePolicies, role, 'role')

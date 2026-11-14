import datetime
from dateutil.tz import tzlocal

from .IamCommon import IamCommon

class IamRole(IamCommon):
    MAXSESSIONDURATION = 3600
    MAXROLENOTUSEDDAYS = 14
    def __init__(self, role, iamClient, authDetails=None, policyDocumentMap=None, roleLastUsedCache=None):
        super().__init__()
        self.role = role
        self.iamClient = iamClient
        self._configPrefix = 'iam::role::'
        self._authDetails = authDetails
        self._policyDocumentMap = policyDocumentMap or {}
        self._roleLastUsedCache = roleLastUsedCache

        self._resourceName = self.role['RoleName']

        self.init()
        self._enrichRoleDetail()

    def _enrichRoleDetail(self):
        """Ensure RoleLastUsed is populated, using prefetched data, a persistent
        cross-run cache, or the get_role() API as a last resort."""
        if 'RoleLastUsed' in self.role:
            return

        # A role younger than MAXROLENOTUSEDDAYS can't trigger the age-based
        # unusedRole flag regardless of RoleLastUsed, so there's nothing this
        # call could change for it - skip it and the cache entirely.
        roleAgeDays = (datetime.datetime.today().date() - self.role['CreateDate'].date()).days
        if roleAgeDays <= self.MAXROLENOTUSEDDAYS:
            self.role['RoleLastUsed'] = {}
            return

        roleName = self.role['RoleName']
        if self._roleLastUsedCache is not None and roleName in self._roleLastUsedCache:
            self.role['RoleLastUsed'] = self._roleLastUsedCache[roleName]
            return

        # Cache miss / no cache - fall back to the API.
        result = self.iamClient.get_role(RoleName=roleName)
        roleLastUsed = result.get('Role', {}).get('RoleLastUsed', {})
        self.role['RoleLastUsed'] = roleLastUsed

        if self._roleLastUsedCache is not None:
            self._roleLastUsedCache[roleName] = roleLastUsed
        
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

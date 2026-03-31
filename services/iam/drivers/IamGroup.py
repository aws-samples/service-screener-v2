import datetime
from dateutil.tz import tzlocal

from .IamCommon import IamCommon
 
class IamGroup(IamCommon):
    def __init__(self, group, iamClient, authDetails=None, policyDocumentMap=None):
        super().__init__()
        self.group = group
        self.iamClient = iamClient
        self.__configPrefix = 'iam::group::'
        self._authDetails = authDetails
        self._policyDocumentMap = policyDocumentMap or {}

        self._resourceName = group['GroupName']

        self.init()
        
    def _checkGroupHasUsers(self):
        group = self.group['GroupName']
        
        # Use prefetched data if available
        if self._authDetails and 'users' in self._authDetails:
            has_users = any(
                group in u.get('GroupList', [])
                for u in self._authDetails['users']
            )
            if not has_users:
                self.results['groupEmptyUsers'] = [-1, 'No users']
        else:
            resp = self.iamClient.get_group(GroupName=group)
            users = resp.get('Users')
            if len(users) == 0:
                self.results['groupEmptyUsers'] = [-1, 'No users']
            
    def _checkGroupPolicyPermission(self):
        group = self.group['GroupName']
        
        # Use prefetched data if available
        if 'AttachedManagedPolicies' in self.group:
            policies = self.group['AttachedManagedPolicies']
            self.evaluateManagePolicy(policies, self._policyDocumentMap)
            
            inlinePolicies = self.group.get('GroupPolicyList', [])
            if inlinePolicies:
                self.evaluateInlinePolicyFromDocs(inlinePolicies)
        else:
            results = self.iamClient.list_attached_group_policies(GroupName=group)
            policies = results.get('AttachedPolicies')
            self.evaluateManagePolicy(policies)
            
            resp = self.iamClient.list_group_policies(GroupName=group)
            inlinePolicies = resp.get('PolicyNames')
            self.evaluateInlinePolicy(inlinePolicies, group, 'group')

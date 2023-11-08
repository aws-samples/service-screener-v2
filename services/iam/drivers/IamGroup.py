import datetime
from dateutil.tz import tzlocal

from .IamCommon import IamCommon
 
class IamGroup(IamCommon):
    def __init__(self, group, iamClient):
        super().__init__()
        self.group = group
        self.iamClient = iamClient
        self.__configPrefix = 'iam::group::'
        self.init()
        
    def _checkGroupHasUsers(self):
        group = self.group['GroupName']
        resp = self.iamClient.get_group(GroupName = group)
        users = resp.get('Users')
        if len(users) == 0:
            self.results['groupEmptyUsers'] = [-1, 'No users']
            
    def _checkGroupPolicyPermission(self):
        group = self.group['GroupName']
        results = self.iamClient.list_attached_group_policies(GroupName = group)
        policies = results.get('AttachedPolicies')
        self.evaluateManagePolicy(policies)
        
        resp = self.iamClient.list_group_policies(GroupName = group)
        inlinePolicies = resp.get('PolicyNames')
        self.evaluateInlinePolicy(inlinePolicies, group, 'group')
        
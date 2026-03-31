# import urllib.parse
from datetime import datetime
from datetime import date
from dateutil.parser import parse

import boto3

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class IamCommon(Evaluator):
    def getAgeInDay(self, dateTime):
        return self.getAge(dateTime, 60*60*24)
    
    def getAge(self, dateTime, div=60*60*24):
        if dateTime == 'N/A':
            return 999
        
        datediff = datetime.today() - parse(dateTime).replace(tzinfo=None)
        return datediff.days
        
    def evaluateManagePolicy(self, policies, policyDocumentMap=None):
        cachePrefix = 'iam::mpolicy::'
        
        policyWithFullAccess = []
        policyWithWildcards = []
        
        if policies:
            hasFullAccess = -1 # instead of false/true, easier handling on cache checking using !empty
            for policy in policies:
                if policy['PolicyName'] == 'AdministratorAccess':
                    self.results['FullAdminAccess'] = [-1, 'AdministratorAccess']
                    continue

                cache = Config.get(cachePrefix + policy['PolicyArn'], "")
                if cache == 1:
                    hasFullAccess = 1
                    policyWithFullAccess.append(policy['PolicyName'])
                    continue
                
                # Try prefetched document first, then fall back to API
                doc = None
                if policyDocumentMap and policy['PolicyArn'] in policyDocumentMap:
                    doc = policyDocumentMap[policy['PolicyArn']]
                else:
                    versInfo = self.iamClient.get_policy(PolicyArn=policy['PolicyArn'])
                    vers = versInfo.get('Policy')
                    verId = vers['DefaultVersionId']

                    detail = self.iamClient.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=verId
                    )
                    doc = detail.get('PolicyVersion')['Document']

                pObj = Policy(doc)
                pObj.inspectAccess()

                if pObj.hasFullAccessToOneResource() == True:
                    hasFullAccess = 1
                    policyWithFullAccess.append(policy['PolicyName'])
                
                # Check for wildcard actions (excluding full admin)
                if pObj.hasWildcardActions() == True:
                    wildcards = pObj.getWildcardActions()
                    policyWithWildcards.append(f"{policy['PolicyName']} ({', '.join(wildcards)})")
                    
            Config.set(cachePrefix + policy['PolicyArn'], hasFullAccess)

        if policyWithFullAccess:
            self.results['ManagedPolicyFullAccessOneServ'] = [-1, '<br>'.join(policyWithFullAccess)]
        
        if policyWithWildcards:
            self.results['wildcardActionsDetection'] = [-1, '<br>'.join(policyWithWildcards)]
    
    def evaluateInlinePolicyFromDocs(self, policyDocs):
        """Evaluate inline policies from prefetched documents (list of {PolicyName, PolicyDocument})"""
        if not policyDocs:
            return
        
        policyNames = [p['PolicyName'] for p in policyDocs]
        self.results['InlinePolicy'] = [-1, '<br>'.join(policyNames)]
        
        inlinePoliciesWithAdminAccess = []
        inlinePoliciesWithFullAccess = []
        inlinePoliciesWithWildcards = []
        
        for p in policyDocs:
            doc = p['PolicyDocument']
            pObj = Policy(doc)
            pObj.inspectAccess()
            
            if pObj.hasFullAccessToOneResource() == True:
                inlinePoliciesWithFullAccess.append(p['PolicyName'])
                
            if pObj.hasFullAccessAdmin() == True:
                inlinePoliciesWithAdminAccess.append(p['PolicyName'])
            
            if pObj.hasWildcardActions() == True:
                wildcards = pObj.getWildcardActions()
                inlinePoliciesWithWildcards.append(f"{p['PolicyName']} ({', '.join(wildcards)})")
            
        if inlinePoliciesWithFullAccess:
            self.results['InlinePolicyFullAccessOneServ'] = [-1, '<br>'.join(inlinePoliciesWithFullAccess)]
        
        if inlinePoliciesWithAdminAccess:
            self.results['InlinePolicyFullAdminAccess'] = [-1, '<br>'.join(inlinePoliciesWithAdminAccess)]
        
        if inlinePoliciesWithWildcards:
            self.results['wildcardActionsDetection'] = [-1, '<br>'.join(inlinePoliciesWithWildcards)]
            
    def evaluateInlinePolicy(self, inlinePolicies, identifier, entityType):
        if inlinePolicies is None or not inlinePolicies:
            return
        
        self.results['InlinePolicy'] = [-1, '<br>'.join(inlinePolicies)]
        inlinePoliciesWithAdminAccess = []
        inlinePoliciesWithFullAccess = []
        inlinePoliciesWithWildcards = []
        
        for policy in inlinePolicies:
            if entityType == 'user':
                resp = self.iamClient.get_user_policy(PolicyName=policy, UserName=identifier)
            elif entityType == 'group':
                resp = self.iamClient.get_group_policy(PolicyName=policy, GroupName=identifier)
            else:
                resp = self.iamClient.get_role_policy(PolicyName=policy, RoleName=identifier)
            
            doc = resp.get('PolicyDocument')
            # doc = urllib.parse.unquote(doc)
            
            pObj = Policy(doc)
            pObj.inspectAccess()
            if pObj.hasFullAccessToOneResource() == True:
                inlinePoliciesWithFullAccess.append(policy)
                
            if pObj.hasFullAccessAdmin() == True:
                inlinePoliciesWithAdminAccess.append(policy)
            
            # Check for wildcard actions (excluding full admin)
            if pObj.hasWildcardActions() == True:
                wildcards = pObj.getWildcardActions()
                inlinePoliciesWithWildcards.append(f"{policy} ({', '.join(wildcards)})")
            
        if inlinePoliciesWithFullAccess:
            self.results['InlinePolicyFullAccessOneServ'] = [-1, '<br>'.join(inlinePoliciesWithFullAccess)]
        
        if inlinePoliciesWithAdminAccess:
            self.results['InlinePolicyFullAdminAccess'] = [-1, '<br>'.join(inlinePoliciesWithAdminAccess)]
        
        if inlinePoliciesWithWildcards:
            self.results['wildcardActionsDetection'] = [-1, '<br>'.join(inlinePoliciesWithWildcards)]
# import urllib.parse
import copy
import json
from datetime import datetime
from datetime import date
from dateutil.parser import parse

import boto3

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class _PageLog:
    """Pages of one paginated read, plus the exception that ended it (if
    any). replay() yields the pages and then re-raises that exception, so a
    consumer sees exactly what iterating the paginator itself would give."""
    def __init__(self, pages, error):
        self.pages = pages
        self.error = error

    def __deepcopy__(self, memo):
        # Evaluator._memo hands every caller a deep copy; copy the pages but
        # keep the original exception object.
        return _PageLog(copy.deepcopy(self.pages, memo), self.error)

    def replay(self):
        for page in self.pages:
            yield page
        if self.error is not None:
            raise self.error


class IamCommon(Evaluator):
    # ------------------------------------------------------------------ #
    # Read-once API helpers: several checks need the same response.
    # ------------------------------------------------------------------ #
    def _pages(self, client, op, **kw):
        """Pages of client.get_paginator(op).paginate(**kw), fetched once per
        (service, region, op, args) for this driver. Iterate the result as
        the paginator itself: pages are yielded in order and an error raised
        while paginating is re-raised after the pages read before it."""
        meta = getattr(client, 'meta', None)
        where = (meta.service_model.service_name, meta.region_name) if meta is not None else (id(client),)
        key = ('pages',) + where + (op, json.dumps(kw, sort_keys=True, default=str))

        def fetch():
            pages = []
            try:
                for page in client.get_paginator(op).paginate(**kw):
                    pages.append(page)
            except Exception as e:  # replayed to every consumer
                return _PageLog(pages, e)
            return _PageLog(pages, None)
        return self._memo(key, fetch).replay()

    def _iamPolicy(self, arn):
        """iam.get_policy(PolicyArn=arn): account-level, read once per scan
        (many users / roles / groups attach the same managed policy)."""
        return self._sharedMemo(('iam.get_policy', self.iamClient.meta.region_name, arn),
                                lambda: self.iamClient.get_policy(PolicyArn=arn))

    def _iamPolicyVersion(self, arn, versionId):
        """iam.get_policy_version(PolicyArn=arn, VersionId=versionId), read once per scan."""
        return self._sharedMemo(('iam.get_policy_version', self.iamClient.meta.region_name, arn, versionId),
                                lambda: self.iamClient.get_policy_version(PolicyArn=arn, VersionId=versionId))

    def _inlinePolicy(self, entityType, entity, policyName):
        """get_<entity>_policy(<Entity>Name=entity, PolicyName=policyName), read
        once per driver (inline policy checks and the policy-document helpers
        of IamUser / IamRole both need it)."""
        op, arg = {'user': ('get_user_policy', 'UserName'), 'group': ('get_group_policy', 'GroupName'),
                   'role': ('get_role_policy', 'RoleName')}[entityType]
        return self._memo(('iam.' + op, entity, policyName),
                          lambda: getattr(self.iamClient, op)(**{arg: entity, 'PolicyName': policyName}))

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
            for policy in policies:
                if policy['PolicyName'] == 'AdministratorAccess':
                    self.results['FullAdminAccess'] = [-1, 'AdministratorAccess']
                    continue

                # Per-policy cache: the analysis result for a given policy ARN is the
                # same no matter which role/user/group it's attached to, so cache it
                # by ARN instead of recomputing for every entity that has it attached.
                cache = Config.get(cachePrefix + policy['PolicyArn'], None)
                if cache is not None:
                    if cache['fullAccess']:
                        policyWithFullAccess.append(policy['PolicyName'])
                    if cache['wildcards']:
                        policyWithWildcards.append(f"{policy['PolicyName']} ({', '.join(cache['wildcards'])})")
                    continue

                # Try prefetched document first, then fall back to API
                doc = None
                if policyDocumentMap and policy['PolicyArn'] in policyDocumentMap:
                    doc = policyDocumentMap[policy['PolicyArn']]
                else:
                    versInfo = self._iamPolicy(policy['PolicyArn'])
                    vers = versInfo.get('Policy')
                    verId = vers['DefaultVersionId']

                    detail = self._iamPolicyVersion(policy['PolicyArn'], verId)
                    doc = detail.get('PolicyVersion')['Document']

                pObj = Policy(doc)
                pObj.inspectAccess()

                policyFullAccess = pObj.hasFullAccessToOneResource() == True
                if policyFullAccess:
                    policyWithFullAccess.append(policy['PolicyName'])

                # Check for wildcard actions (excluding full admin)
                policyWildcards = pObj.getWildcardActions() if pObj.hasWildcardActions() == True else []
                if policyWildcards:
                    policyWithWildcards.append(f"{policy['PolicyName']} ({', '.join(policyWildcards)})")

                Config.set(cachePrefix + policy['PolicyArn'], {'fullAccess': policyFullAccess, 'wildcards': policyWildcards})

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
            resp = self._inlinePolicy(entityType if entityType in ('user', 'group') else 'role', identifier, policy)
            
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
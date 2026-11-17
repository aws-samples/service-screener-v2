import datetime
from dateutil.tz import tzlocal

import botocore

from .IamCommon import IamCommon
from .IamTrust import crossAccountTrusts, isAdminLevelDocument, parseDocument

class IamRole(IamCommon):
    MAXSESSIONDURATION = 3600
    MAXROLENOTUSEDDAYS = 14
    def __init__(self, role, iamClient, authDetails=None, policyDocumentMap=None, roleLastUsedCache=None, trustContext=None):
        super().__init__()
        self.role = role
        self.iamClient = iamClient
        self._configPrefix = 'iam::role::'
        self._authDetails = authDetails
        self._policyDocumentMap = policyDocumentMap or {}
        self._roleLastUsedCache = roleLastUsedCache
        self._trustContext = trustContext

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

    # ------------------------------------------------------------------ #
    # Third-party (outside the organization) trust checks (WAFS2027).
    # Roles with no cross-account trust get no result. When the org account
    # list is unreadable a trusted account cannot be told apart from an
    # intra-org account, so the result is [0, ...] - never a FAIL.
    # ------------------------------------------------------------------ #
    ADMIN_MANAGED_POLICY_NAMES = {'AdministratorAccess', 'IAMFullAccess'}

    def _thirdPartyTrusts(self):
        if self._trustContext is None:
            return None
        return crossAccountTrusts(self.role.get('AssumeRolePolicyDocument'), self._trustContext)

    def _unknownNote(self, accounts):
        reason = (self._trustContext or {}).get('reason') or 'organization account list not readable'
        return 'Trusts account(s) {} that may be outside the organization; unable to classify ({})'.format(
            ', '.join(sorted(accounts)), reason)

    def _checkThirdPartyRoleNoExternalId(self):
        key = 'thirdPartyRoleNoExternalId'
        trusts = self._thirdPartyTrusts()
        if not trusts:
            return
        bad, unknown, ok = [], set(), []
        for t in trusts:
            if t['orgConditioned'] or t['externalIdWeakness'] is None:
                ok.append(t['account'])
                continue
            if t['class'] == 'unknown':
                unknown.add(t['account'])
            else:
                bad.append('{}: {}'.format(t['account'], t['externalIdWeakness']))
        if bad:
            self.results[key] = [-1, 'External account trust without a strong sts:ExternalId:<br>' + '<br>'.join(bad)]
        elif unknown:
            self.results[key] = [0, self._unknownNote(unknown)]
        else:
            self.results[key] = [1, 'Cross-account trust(s) to {} require a strong sts:ExternalId or aws:PrincipalOrgID'.format(
                ', '.join(sorted(set(ok))))]

    def _adminLevelPolicies(self):
        """(names, errors) of attached/inline policies granting admin-level access."""
        found, errors = [], []
        attached = self.role.get('AttachedManagedPolicies')
        inline = self.role.get('RolePolicyList')
        try:
            if attached is None:
                attached = []
                for page in self.iamClient.get_paginator('list_attached_role_policies').paginate(RoleName=self.role['RoleName']):
                    attached.extend(page.get('AttachedPolicies', []))
            for p in attached:
                if p.get('PolicyName') in self.ADMIN_MANAGED_POLICY_NAMES:
                    found.append(p['PolicyName'])
                    continue
                doc = self._policyDocumentMap.get(p.get('PolicyArn'))
                if doc is None:
                    pol = self.iamClient.get_policy(PolicyArn=p['PolicyArn'])['Policy']
                    doc = self.iamClient.get_policy_version(PolicyArn=p['PolicyArn'],
                                                            VersionId=pol['DefaultVersionId'])['PolicyVersion']['Document']
                if isAdminLevelDocument(parseDocument(doc)):
                    found.append(p['PolicyName'])
            if inline is None:
                inline = []
                for page in self.iamClient.get_paginator('list_role_policies').paginate(RoleName=self.role['RoleName']):
                    for name in page.get('PolicyNames', []):
                        doc = self.iamClient.get_role_policy(RoleName=self.role['RoleName'], PolicyName=name)['PolicyDocument']
                        inline.append({'PolicyName': name, 'PolicyDocument': doc})
            for p in inline:
                if isAdminLevelDocument(parseDocument(p.get('PolicyDocument'))):
                    found.append('{} (inline)'.format(p.get('PolicyName')))
        except botocore.exceptions.ClientError as e:
            errors.append(e.response['Error']['Code'])
        return found, errors

    def _checkThirdPartyRoleOverprivileged(self):
        key = 'thirdPartyRoleOverprivileged'
        trusts = self._thirdPartyTrusts()
        if not trusts:
            return
        # aws:PrincipalOrgID-conditioned trusts only admit org principals.
        external = sorted({t['account'] for t in trusts if t['class'] == 'external' and not t['orgConditioned']})
        unknown = sorted({t['account'] for t in trusts if t['class'] == 'unknown' and not t['orgConditioned']})
        admin, errors = self._adminLevelPolicies()
        if admin and external:
            self.results[key] = [-1, 'Role trusted by external account(s) {} has admin-level permissions: {}'.format(
                ', '.join(external), ', '.join(admin))]
        elif errors:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(errors[0])]
        elif admin and unknown:
            self.results[key] = [0, self._unknownNote(unknown) + '; role has admin-level permissions: {}'.format(', '.join(admin))]
        elif admin:
            # Every cross-account trust is restricted by aws:PrincipalOrgID.
            self.results[key] = [1, 'Admin-level role is not trusted by accounts outside the organization']
        else:
            self.results[key] = [1, 'No AdministratorAccess, *:* or iam:* permissions']

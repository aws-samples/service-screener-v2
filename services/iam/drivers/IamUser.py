import boto3, botocore
import datetime
import json
import urllib.parse
from dateutil.tz import tzlocal
from dateutil.parser import parse

from .IamCommon import IamCommon
from . import IamPolicyHelpers
 
class IamUser(IamCommon):
    ENUM_NO_INFO = ['not_supported', 'no_information']
    ACCESS_KEY_UNUSED_DAYS = 90
    ACCESS_KEY_NEVER_USED_GRACE_DAYS = 7

    BEDROCK_API_KEY_USER_PREFIX = 'bedrockapikey'

    def __init__(self, user, iamClient, authDetails=None, policyDocumentMap=None, bedrockCredentialMap=None):
        super().__init__()
        self.user = user
        self.iamClient = iamClient
        self._authDetails = authDetails
        self._policyDocumentMap = policyDocumentMap or {}
        self._bedrockCredentialMap = bedrockCredentialMap or {}
        self._prefetchedUserDetail = None
        
        # Look up prefetched user detail by username. Build the name->detail
        # index once and cache it on the shared authDetails dict so the next
        # IamUser construction gets an O(1) lookup instead of re-scanning the
        # full user list (this constructor runs once per user).
        if authDetails and user['user'] != '<root_account>':
            usersByName = authDetails.get('_usersByName')
            if usersByName is None:
                usersByName = {u.get('UserName'): u for u in authDetails.get('users', [])}
                authDetails['_usersByName'] = usersByName
            self._prefetchedUserDetail = usersByName.get(user['user'])

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
                # First page of the list_groups_for_user paginator (same request),
                # shared with _userPolicyDocs().
                resp = next(self._pages(self.iamClient, 'list_groups_for_user', UserName=user))
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
                # First pages of the paginators shared with _userPolicyDocs() (same requests).
                resp = next(self._pages(self.iamClient, 'list_attached_user_policies', UserName=user))
                policies = resp.get('AttachedPolicies')
                self.evaluateManagePolicy(policies)
                
                resp = next(self._pages(self.iamClient, 'list_user_policies', UserName=user))
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

    def _isCredentialReportRow(self):
        # Placeholder rows built for Bedrock API key users missing from the
        # credential report carry no real credential data - never evaluate them.
        return 'user_creation_time' in self.user and self.user['user'] != '<root_account>'

    @staticmethod
    def _reportDate(value):
        if not value or value in ('N/A', 'not_supported', 'no_information'):
            return None
        try:
            dt = parse(value)
        except (ValueError, OverflowError, TypeError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    def _checkIamActiveKeyUnused(self):
        """Each active access key must have been used in the last
        ACCESS_KEY_UNUSED_DAYS days; a key never used must not be older than
        ACCESS_KEY_NEVER_USED_GRACE_DAYS. Evaluated per key, independently of
        console activity (userNoActivity90days covers fully dormant users)."""
        if not self._isCredentialReportRow():
            return

        now = datetime.datetime.now(datetime.timezone.utc)
        activeKeys = 0
        stale = []
        unknown = []
        for n in ('1', '2'):
            if self.user.get('access_key_{}_active'.format(n)) != 'true':
                continue
            activeKeys += 1
            lastUsedRaw = self.user.get('access_key_{}_last_used_date'.format(n), 'N/A')
            lastUsed = self._reportDate(lastUsedRaw)
            created = self._reportDate(self.user.get('access_key_{}_last_rotated'.format(n)))
            if lastUsed is not None:
                days = (now - lastUsed).days
                if days > self.ACCESS_KEY_UNUSED_DAYS:
                    stale.append('access key {}: last used {} days ago'.format(n, days))
            elif lastUsedRaw == 'N/A' and created is not None:
                days = (now - created).days
                if days > self.ACCESS_KEY_NEVER_USED_GRACE_DAYS:
                    stale.append('access key {}: never used, created {} days ago'.format(n, days))
            else:
                unknown.append('access key {}'.format(n))

        if activeKeys == 0:
            return
        if stale:
            self.results['iamActiveKeyUnused'] = [-1, '<br>'.join(stale)]
        elif unknown:
            self.results['iamActiveKeyUnused'] = [0, 'Unable to evaluate (no usable last-used/created date for {})'.format(', '.join(unknown))]
        else:
            self.results['iamActiveKeyUnused'] = [1, '{} active key(s), each used in the last {} days or created in the last {} days'.format(
                activeKeys, self.ACCESS_KEY_UNUSED_DAYS, self.ACCESS_KEY_NEVER_USED_GRACE_DAYS)]

    def _checkIamUserHumanAndMachineCreds(self):
        """A user with both a console password and an active access key mixes
        human and programmatic credentials on one identity."""
        if not self._isCredentialReportRow():
            return

        activeKeys = [n for n in ('1', '2') if self.user.get('access_key_{}_active'.format(n)) == 'true']
        if self.user.get('password_enabled') == 'true' and activeKeys:
            self.results['iamUserHumanAndMachineCreds'] = [-1, 'Console password and active access key(s) {}'.format(', '.join(activeKeys))]
        else:
            self.results['iamUserHumanAndMachineCreds'] = [1, 'Single credential type']

    def _checkIamUserTwoActiveKeys(self):
        """CIS 1.13: an IAM user should have at most one active access key.
        Two active keys are expected only briefly during a rotation."""
        if not self._isCredentialReportRow():
            return
        active = [n for n in ('1', '2') if self.user.get('access_key_{}_active'.format(n)) == 'true']
        if len(active) == 2:
            self.results['iamUserTwoActiveKeys'] = [-1, 'Access keys 1 and 2 are both active']
        elif active:
            self.results['iamUserTwoActiveKeys'] = [1, 'One active access key']

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

    # ------------------------------------------------------------------ #
    # WAFS2027 identity checks (chunk 3)
    # ------------------------------------------------------------------ #
    # Tag an IAM user with this key (any value except "false") to record an
    # approved exception for iamUserLongTermAccessKey.
    LONG_TERM_KEY_EXCEPTION_TAG = 'ServiceScreener:LongTermKeyException'

    def _activeAccessKeys(self):
        return [n for n in ('1', '2') if self.user.get('access_key_{}_active'.format(n)) == 'true']

    def _userTags(self):
        """(tags, error) for the user: prefetched authorization details first,
        list_user_tags otherwise."""
        if self._prefetchedUserDetail is not None:
            return self._prefetchedUserDetail.get('Tags', []) or [], None
        tags = []
        try:
            for page in self.iamClient.get_paginator('list_user_tags').paginate(UserName=self.user['user']):
                tags.extend(page.get('Tags', []))
        except botocore.exceptions.ClientError as e:
            return [], e.response['Error']['Code']
        return tags, None

    def _checkIamUserLongTermAccessKey(self):
        """Non-root IAM user with an active long-term access key. Workloads
        should use IAM roles (instance profiles, task roles, IAM Roles
        Anywhere) and people should use federation / IAM Identity Center."""
        if not self._isCredentialReportRow():
            return
        active = self._activeAccessKeys()
        if not active:
            return
        key = 'iamUserLongTermAccessKey'
        kind = ('console + programmatic user' if self.user.get('password_enabled') == 'true'
                else 'programmatic-only user (machine identity)')
        tags, err = self._userTags()
        for t in tags:
            if t.get('Key') == self.LONG_TERM_KEY_EXCEPTION_TAG and str(t.get('Value', '')).strip().lower() != 'false':
                self.results[key] = [0, 'Exception recorded by tag {}={} ({}, active key(s) {})'.format(
                    t.get('Key'), t.get('Value', ''), kind, ', '.join(active))]
                return
        note = ' (tags not readable: {})'.format(err) if err else ''
        self.results[key] = [-1, '{} with active access key(s) {}{}'.format(kind, ', '.join(active), note)]

    def _userPolicyDocs(self):
        """(docs, unreadable) - identity policies that apply to the user
        (inline, attached, and those of its groups)."""
        detail = self._prefetchedUserDetail
        docs, unreadable = [], []
        attached = []
        if detail is not None:
            docs.extend(p.get('PolicyDocument') for p in detail.get('UserPolicyList', []) or [])
            attached.extend(detail.get('AttachedManagedPolicies', []) or [])
            groupsByName = {g.get('GroupName'): g for g in (self._authDetails or {}).get('groups', [])}
            for gname in detail.get('GroupList', []) or []:
                g = groupsByName.get(gname)
                if g is None:
                    unreadable.append('group {}'.format(gname))
                    continue
                docs.extend(p.get('PolicyDocument') for p in g.get('GroupPolicyList', []) or [])
                attached.extend(g.get('AttachedManagedPolicies', []) or [])
        else:
            user = self.user['user']
            try:
                for page in self._pages(self.iamClient, 'list_user_policies', UserName=user):
                    for name in page.get('PolicyNames', []):
                        docs.append(self._inlinePolicy('user', user, name)['PolicyDocument'])
                for page in self._pages(self.iamClient, 'list_attached_user_policies', UserName=user):
                    attached.extend(page.get('AttachedPolicies', []))
                for page in self._pages(self.iamClient, 'list_groups_for_user', UserName=user):
                    for g in page.get('Groups', []):
                        gname = g['GroupName']
                        for gp in self.iamClient.get_paginator('list_group_policies').paginate(GroupName=gname):
                            for name in gp.get('PolicyNames', []):
                                docs.append(self.iamClient.get_group_policy(GroupName=gname, PolicyName=name)['PolicyDocument'])
                        for gp in self.iamClient.get_paginator('list_attached_group_policies').paginate(GroupName=gname):
                            attached.extend(gp.get('AttachedPolicies', []))
            except botocore.exceptions.ClientError as e:
                return None, [e.response['Error']['Code']]

        seen = set()
        for p in attached:
            arn = p.get('PolicyArn')
            if not arn or arn in seen:
                continue
            seen.add(arn)
            doc = self._policyDocumentMap.get(arn)
            if doc is None:
                try:
                    ver = self._iamPolicy(arn)['Policy']['DefaultVersionId']
                    doc = self._iamPolicyVersion(arn, ver)['PolicyVersion']['Document']
                except (botocore.exceptions.ClientError, KeyError):
                    unreadable.append(p.get('PolicyName') or arn)
                    continue
            docs.append(doc)
        return docs, unreadable

    def _permissionsBoundary(self):
        if self._prefetchedUserDetail is not None:
            return (self._prefetchedUserDetail.get('PermissionsBoundary') or {}).get('PermissionsBoundaryArn'), None
        try:
            user = self.iamClient.get_user(UserName=self.user['user'])['User']
        except botocore.exceptions.ClientError as e:
            return None, e.response['Error']['Code']
        return (user.get('PermissionsBoundary') or {}).get('PermissionsBoundaryArn'), None

    @staticmethod
    def _parseDoc(doc):
        """Policy document as a dict (JSON / URL-encoded JSON strings
        accepted), or None when it cannot be parsed."""
        if isinstance(doc, dict):
            return doc
        if isinstance(doc, (str, bytes)):
            if isinstance(doc, bytes):
                doc = doc.decode('utf-8', 'replace')
            for text in (doc, urllib.parse.unquote(doc)):
                try:
                    parsed = json.loads(text)
                except (ValueError, TypeError):
                    continue
                if isinstance(parsed, dict):
                    return parsed
        return None

    def _boundaryDocument(self, arn):
        """(document, errorCode) of the permissions boundary policy."""
        doc = self._policyDocumentMap.get(arn)
        if doc is None:
            try:
                ver = self._iamPolicy(arn)['Policy']['DefaultVersionId']
                doc = self._iamPolicyVersion(arn, ver)['PolicyVersion']['Document']
            except botocore.exceptions.ClientError as e:
                return None, e.response['Error']['Code']
            except KeyError:
                return None, 'NoDefaultVersion'
        parsed = self._parseDoc(doc)
        if parsed is None:
            return None, 'unparseable document'
        return parsed, None

    def _checkLongTermKeyNotContained(self):
        """A user that keeps an active access key should limit where the key
        can be used: a permissions boundary or identity policies that only
        allow requests from known networks (aws:SourceIp / aws:SourceVpc /
        aws:SourceVpce / aws:VpcSourceIp). Effective permissions are the
        intersection of the boundary and the identity policies, so either one
        being network-contained contains the key. A boundary is read and
        evaluated like the identity policies - its mere presence (e.g.
        AdministratorAccess as boundary) contains nothing. SCP/RCP network
        perimeters are not visible from here."""
        if not self._isCredentialReportRow():
            return
        active = self._activeAccessKeys()
        if not active:
            return
        key = 'longTermKeyNotContained'
        boundary, err = self._permissionsBoundary()
        if err:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(err)]
            return
        boundaryName = boundary.split('/')[-1] if boundary else None
        boundaryErr, boundaryReason = None, None
        if boundary:
            bdoc, boundaryErr = self._boundaryDocument(boundary)
            if bdoc is not None:
                bContained, bReason = IamPolicyHelpers.networkContainment([bdoc])
                if bContained:
                    self.results[key] = [1, 'Permissions boundary {}: {}'.format(boundaryName, bReason)]
                    return
                if bContained is None:
                    self.results[key] = [1, 'Active key(s) {}, but permissions boundary {} grants no permissions'.format(
                        ', '.join(active), boundaryName)]
                    return
                boundaryReason = 'permissions boundary {} has no network restriction ({})'.format(boundaryName, bReason)

        docs, unreadable = self._userPolicyDocs()
        if docs is None:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(', '.join(unreadable))]
            return
        parsedDocs = []
        for d in docs:
            pd = self._parseDoc(d)
            if pd is None:
                unreadable.append('unparseable policy document')
            else:
                parsedDocs.append(pd)
        contained, reason = IamPolicyHelpers.networkContainment(parsedDocs)
        # A Deny guard holds whatever an unreadable policy allows; "every
        # Allow is network-restricted" cannot be proven with one unread.
        denyGuard = any(IamPolicyHelpers.isNetworkDenyGuard(st) for d in parsedDocs
                        for st in IamPolicyHelpers.PolicyPrincipal.iterStatements(d))
        if contained and (denyGuard or not unreadable):
            self.results[key] = [1, 'Identity policies: {}'.format(reason)]
        elif boundaryErr:
            self.results[key] = [0, 'Unable to evaluate (permissions boundary {} not readable: {})'.format(
                boundaryName, boundaryErr)]
        elif unreadable:
            self.results[key] = [0, 'Unable to evaluate (policy not readable: {})'.format(', '.join(unreadable))]
        elif contained is None:
            self.results[key] = [1, 'Active key(s) {}, but identity policies {}'.format(', '.join(active), reason)]
        else:
            self.results[key] = [-1, 'Active key(s) {}: {}; identity policies: {}'.format(
                ', '.join(active), boundaryReason or 'no permissions boundary', reason)]

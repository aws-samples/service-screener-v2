import re

import boto3
import botocore

import time
from datetime import datetime, timedelta, timezone, tzinfo

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import _warn
# from utils.Tools import aws_parseInstanceFamily
from utils.Policy import Policy
from utils import PolicyPrincipal
from services.Evaluator import Evaluator

# Condition keys that confine a cross-account principal to the caller's AWS
# Organization. aws:PrincipalAccount is deliberately NOT accepted: the Principal
# element already names the external account, so a matching PrincipalAccount
# condition adds no boundary.
ORG_SCOPING_KEYS = ('aws:principalorgid', 'aws:principalorgpaths')
_POSITIVE_OPERATORS = ('stringequals', 'stringequalsignorecase', 'stringlike')
_ACCOUNT_ARN_RE = re.compile(r'^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):')


def principalAccountId(principal):
    """Account ID of an AWS principal given as an IAM/STS ARN or a bare
    12-digit account ID; None when it cannot be determined."""
    if not isinstance(principal, str):
        return None
    if re.fullmatch(r'\d{12}', principal):
        return principal
    m = _ACCOUNT_ARN_RE.match(principal)
    return m.group(1) if m else None


def orgConditionScopes(condition):
    """True if the Condition restricts callers to an AWS Organization (or OU
    path) with a positive-match operator and a concrete value. IfExists,
    negated and ForAllValues operators are not accepted because they also
    match callers that carry no organization at all."""
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        op = operator.lower()
        if op.startswith('forallvalues:'):
            continue
        if op.startswith('foranyvalue:'):
            op = op[len('foranyvalue:'):]
        if op not in _POSITIVE_OPERATORS:
            continue
        for key, value in block.items():
            if str(key).lower() not in ORG_SCOPING_KEYS:
                continue
            values = value if isinstance(value, list) else [value]
            if values and all(isinstance(v, str) and v and set(v) - {'*', '?'} for v in values):
                return True
    return False


# Condition keys that identify the CALLER's account (directly or through the
# caller ARN). If any of them confines the caller to the key's own account the
# wildcard statement cannot grant cross-account access (condition keys are AND-ed).
_CALLER_ACCOUNT_KEYS = ('kms:calleraccount', 'aws:principalaccount')
_CALLER_ARN_KEYS = ('aws:principalarn',)
# Keys that identify the account of the SOURCE resource a service acts for.
_SOURCE_ACCOUNT_KEYS = ('aws:sourceaccount', 'aws:sourceowner')
_SOURCE_ARN_KEYS = ('aws:sourcearn',)


def wildcardConditionAccounts(condition):
    """Accounts named by the scoping condition of a wildcard-principal statement.

    Mirrors PolicyPrincipal.conditionScopes: only positive-match operators
    whose every value is concrete are considered (IfExists / negated /
    ForAllValues and wildcarded values do not restrict anything).

    Returns (callerSets, otherAccounts):
      callerSets    -- list of account sets, one per caller-identity key
                       (kms:CallerAccount, aws:PrincipalAccount, aws:PrincipalArn)
      otherAccounts -- accounts named by source keys (aws:SourceAccount,
                       aws:SourceOwner, aws:SourceArn)
    """
    callerSets, otherAccounts = [], set()
    if not isinstance(condition, dict):
        return callerSets, otherAccounts
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        op = operator.lower()
        if op.startswith('forallvalues:'):
            continue
        if op.startswith('foranyvalue:'):
            op = op[len('foranyvalue:'):]
        if op not in PolicyPrincipal.SCOPING_OPERATORS:
            continue
        for key, value in block.items():
            k = str(key).lower()
            values = value if isinstance(value, list) else [value]
            if not values or not all(PolicyPrincipal._valueScopes(k, v) for v in values):
                continue
            if k in _CALLER_ACCOUNT_KEYS or k in _SOURCE_ACCOUNT_KEYS:
                accounts = set(values)
            elif k in _CALLER_ARN_KEYS or k in _SOURCE_ARN_KEYS:
                accounts = {v.split(':', 5)[4] for v in values if v.split(':', 5)[4]}
                if len(accounts) != len(values):
                    ## An account-less ARN (S3 bucket) does not name an account.
                    accounts = None
            else:
                continue
            if accounts is None:
                continue
            if k in _CALLER_ACCOUNT_KEYS or k in _CALLER_ARN_KEYS:
                callerSets.append(accounts)
            else:
                otherAccounts |= accounts
    return callerSets, otherAccounts


def wildcardAccountScope(condition, keyAccount):
    """Classify the account boundary of a condition-scoped wildcard principal.

    Returns (external, ownOnly):
      external -- accounts other than keyAccount named by an account-bearing
                  scoping key (empty when the caller is confined to keyAccount)
      ownOnly  -- True when a caller-identity key confines the caller to
                  keyAccount, or every account named is keyAccount
    Both empty/False means the condition names no account at all (for
    example only aws:SourceVpce or an S3 aws:SourceArn)."""
    callerSets, otherAccounts = wildcardConditionAccounts(condition)
    if any(s and s <= {keyAccount} for s in callerSets):
        return set(), True
    named = set(otherAccounts)
    for s in callerSets:
        named |= s
    external = {a for a in named if a != keyAccount}
    return external, bool(named) and not external


def wildcardExternalAccounts(condition, keyAccount):
    """External accounts a condition-scoped wildcard principal is opened to."""
    return wildcardAccountScope(condition, keyAccount)[0]


class KmsCommon(Evaluator):
    def __init__(self, kms, kmsClient):
        self.dbParams = {}
        self.results = {}
        self.kms = kms
        self.kmsClient = kmsClient

        self._resourceName = kms['Arn']

        # self.__configPrefix = 'kms::' +  + '::' + db['EngineVersion'] + '::'
        self.init()

    ## Read-once helpers: several checks need the same key policy / grants.
    def _keyPolicy(self):
        return self._memo(('get_key_policy', self.kms['KeyId'], 'default'),
                          lambda: self.kmsClient.get_key_policy(KeyId=self.kms['KeyId'], PolicyName='default'))

    def _grantsFirstPage(self):
        """First list_grants page (Limit=100), shared by the grant checks."""
        return self._memo(('list_grants', self.kms['KeyId'], 100),
                          lambda: self.kmsClient.list_grants(KeyId=self.kms['KeyId'], Limit=100))

    def _checkKeyInfo(self):
        if self.kms['KeyRotationEnabled'] == False:
            self.results['KeyRotationEnabled'] = [-1, False]
            
        if self.kms['KeyState'] == 'PendingDeletion':
            self.results['KeyInPendingDeletion'] = [-1, self.kms['DeletionDate'].strftime("%Y-%m-%d %H:%M:%S %Z")]
            
        if self.kms['KeyState'] == 'Disabled':
            self.results['DisabledKey'] = [-1, None]
            
            
    def _checkGrantPermissions(self):
        """Check grant permissions for security issues (Tier 1 + Tier 2)"""
        try:
            resp = self._grantsFirstPage()
            
            grants = resp.get('Grants', [])
            
            # Handle pagination if needed
            while 'NextMarker' in resp:
                resp = self.kmsClient.list_grants(
                    KeyId = self.kms['KeyId'],
                    Marker = resp['NextMarker'],
                    Limit = 100
                )
                grants.extend(resp.get('Grants', []))
            
            if not grants:
                return
            
            # Tier 1 Check 1: Overly permissive grants
            overly_permissive = []
            for grant in grants:
                operations = grant.get('Operations', [])
                grant_id = grant.get('GrantId', 'Unknown')
                
                # Flag if >5 operations
                if len(operations) > 5:
                    overly_permissive.append(f"Grant {grant_id}: {len(operations)} operations")
                    continue
                
                # Flag dangerous combinations
                has_decrypt = 'Decrypt' in operations
                has_encrypt = 'Encrypt' in operations
                has_generate = 'GenerateDataKey' in operations
                has_create_grant = 'CreateGrant' in operations
                
                if has_decrypt and has_encrypt and has_generate:
                    overly_permissive.append(f"Grant {grant_id}: Full crypto operations")
                elif has_create_grant:
                    overly_permissive.append(f"Grant {grant_id}: Can delegate grants")
            
            if overly_permissive:
                self.results['GrantOverlyPermissive'] = [-1, "<br>".join(overly_permissive)]
            
            # Tier 1 Check 2: Wildcard or broad principals
            wildcard_principals = []
            for grant in grants:
                principal = grant.get('GranteePrincipal', '')
                grant_id = grant.get('GrantId', 'Unknown')
                
                # Check for wildcards
                if '*' in principal:
                    wildcard_principals.append(f"Grant {grant_id}: Wildcard principal")
                # Check for account-level principals (root)
                elif ':root' in principal:
                    wildcard_principals.append(f"Grant {grant_id}: Account-level principal")
            
            if wildcard_principals:
                self.results['GrantWildcardPrincipal'] = [-1, "<br>".join(wildcard_principals)]
            
            # Tier 1 Check 3: Duplicate grants
            grant_signatures = {}
            duplicates = []
            
            for grant in grants:
                # Create signature from principal + operations + constraints
                principal = grant.get('GranteePrincipal', '')
                operations = tuple(sorted(grant.get('Operations', [])))
                constraints = str(grant.get('Constraints', {}))
                signature = f"{principal}|{operations}|{constraints}"
                
                if signature in grant_signatures:
                    grant_id = grant.get('GrantId', 'Unknown')
                    original_id = grant_signatures[signature]
                    duplicates.append(f"Grant {grant_id} duplicates {original_id}")
                else:
                    grant_signatures[signature] = grant.get('GrantId', 'Unknown')
            
            if duplicates:
                self.results['GrantDuplicate'] = [-1, "<br>".join(duplicates)]
            
            # Tier 2 Check 1: Missing encryption context constraints
            missing_encryption_context = []
            for grant in grants:
                grant_id = grant.get('GrantId', 'Unknown')
                constraints = grant.get('Constraints', {})
                
                # Check if grant has encryption context constraints
                has_encryption_context = (
                    'EncryptionContextEquals' in constraints or 
                    'EncryptionContextSubset' in constraints
                )
                
                if not has_encryption_context:
                    missing_encryption_context.append(f"Grant {grant_id}: No encryption context constraint")
            
            if missing_encryption_context:
                self.results['GrantMissingEncryptionContext'] = [-1, "<br>".join(missing_encryption_context)]
            
            # Tier 2 Check 2: Old grants (>180 days)
            old_grants = []
            current_time = datetime.now(grants[0].get('CreationDate').tzinfo) if grants else datetime.now()
            threshold_days = 180
            
            for grant in grants:
                grant_id = grant.get('GrantId', 'Unknown')
                creation_date = grant.get('CreationDate')
                
                if creation_date:
                    age_days = (current_time - creation_date).days
                    if age_days > threshold_days:
                        old_grants.append(f"Grant {grant_id}: {age_days} days old")
            
            if old_grants:
                self.results['GrantOldAge'] = [-1, "<br>".join(old_grants)]
                
        except Exception as e:
            # Log error but don't fail the check
            pass
    
    def _checkPolicyAdminUser(self):
        """Check key policy for security issues (Tier 1 + Tier 2)"""
        resp = self._keyPolicy()
        
        pDoc = resp.get('Policy')
        pObj = Policy(pDoc)
        pObj.parseDocumentToJson()
        parseInfo = pObj.extractPolicyInfo()
        
        admins = []
        users = []
        cross_account_principals = []
        org_scoped_cross_account = []
        wildcard_principals = []
        wildcard_actions = []
        has_root_access = False
        sensitive_actions_not_restricted = []
        statements_without_conditions = []
        
        # Extract account ID from key ARN
        key_account = self.kms['Arn'].split(':')[4]
        
        # Tier 2: Track if sensitive actions are in key policy
        has_put_key_policy = False
        has_schedule_key_deletion = False
        
        undetermined_wildcards = []

        def addScopedWildcard(sid, condition):
            ## A wildcard principal scoped by kms:CallerAccount / aws:PrincipalAccount /
            ## aws:SourceAccount (or an ARN key) to ANOTHER account is cross-account access.
            external, ownOnly = wildcardAccountScope(condition, key_account)
            if ownOnly:
                return
            orgScoped = orgConditionScopes(condition)
            for acct in sorted(external):
                entry = f"Statement {sid}: * (condition-scoped to account {acct})"
                if orgScoped:
                    org_scoped_cross_account.append(entry)
                else:
                    cross_account_principals.append(entry)
            if external:
                return
            if orgScoped:
                ## Open to every account in the organization.
                org_scoped_cross_account.append(f"Statement {sid}: * (organization-scoped)")
            else:
                ## Scoped only by network path / account-less source ARN: the
                ## caller's account cannot be determined from the policy.
                undetermined_wildcards.append(f"Statement {sid}: *")

        if 'allow' in parseInfo:
            ## Build Admin List and perform security checks
            for sid, arr in parseInfo['allow'].items():
                condition = arr.get('Condition') or {}
                # A wildcard principal restricted to a known account / org /
                # source (e.g. kms:CallerAccount, aws:PrincipalOrgID) is not open.
                wildcard_scoped = PolicyPrincipal.conditionScopes(condition, extraKeys=['kms:CallerAccount'])
                
                # Tier 1: Check for wildcard principals (KeyPolicyWildcardPrincipal)
                if 'Principal' in arr:
                    if arr['Principal'] == '*':
                        if not wildcard_scoped:
                            wildcard_principals.append(f"Statement {sid}: Principal is *")
                        else:
                            addScopedWildcard(sid, condition)
                    elif isinstance(arr['Principal'], dict):
                        if 'AWS' in arr['Principal']:
                            aws_principals = arr['Principal']['AWS']
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            org_scoped = orgConditionScopes(condition)
                            for principal in aws_principals:
                                if not isinstance(principal, str):
                                    continue
                                if principal == '*':
                                    if not wildcard_scoped:
                                        wildcard_principals.append(f"Statement {sid}: AWS Principal is *")
                                    else:
                                        addScopedWildcard(sid, condition)
                                # Check for root access ("arn:...:root" or the bare account ID form)
                                elif f":iam::{key_account}:root" in principal or principal == key_account:
                                    has_root_access = True
                                # Tier 1: Check for cross-account access (KeyPolicyCrossAccount)
                                else:
                                    principal_account = principalAccountId(principal)
                                    if principal_account and principal_account != key_account:
                                        if org_scoped:
                                            # aws:PrincipalOrgID / aws:PrincipalOrgPaths keeps the
                                            # grant inside the organization boundary.
                                            org_scoped_cross_account.append(f"Statement {sid}: {principal}")
                                        else:
                                            cross_account_principals.append(f"Statement {sid}: {principal}")
                
                # Tier 1: Check for wildcard actions (KeyPolicyWildcardAction)
                # Tier 2: Check for sensitive actions and missing conditions
                if 'Action' in arr:
                    actions = arr['Action']
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    # Tier 2: Check for sensitive actions
                    for action in actions:
                        if action == 'kms:PutKeyPolicy' or action == 'kms:*' or action == '*':
                            has_put_key_policy = True
                        if action == 'kms:ScheduleKeyDeletion' or action == 'kms:*' or action == '*':
                            has_schedule_key_deletion = True
                    
                    # Tier 1: Check for wildcard actions
                    for action in actions:
                        if action == '*' or action == 'kms:*':
                            # Check if there are conditions that might limit the wildcard
                            if not condition:
                                wildcard_actions.append(f"Statement {sid}: Action {action} without conditions")
                    
                    # Tier 2: Check for statements without conditions (KeyPolicyNoConditions)
                    # Only flag for non-root principals and non-service principals
                    if not condition:
                        # Skip if it's a service principal or root with full access (common pattern)
                        is_service = 'Service' in arr.get('Principal', {})
                        is_root_full_access = False
                        
                        if 'Principal' in arr and isinstance(arr['Principal'], dict):
                            if 'AWS' in arr['Principal']:
                                aws_principals = arr['Principal']['AWS']
                                if isinstance(aws_principals, str):
                                    aws_principals = [aws_principals]
                                # Check if it's root with kms:* or *
                                for principal in aws_principals:
                                    if f":iam::{key_account}:root" in principal:
                                        if 'kms:*' in actions or '*' in actions:
                                            is_root_full_access = True
                        
                        if not is_service and not is_root_full_access:
                            statements_without_conditions.append(f"Statement {sid}: No conditions")
                
                # Continue with existing admin/user checks
                if 'Service' in arr.get('Principal', {}):
                    continue
                
                if 'AWS' not in arr.get('Principal', {}):
                    continue
                
                principals = arr['Principal']['AWS']
                if isinstance(principals, str):
                    principals = [principals]
                
                if isinstance(arr['Action'], str):
                    arr['Action'] = [arr['Action']]
                
                for action in arr['Action']:
                    if action.startswith('kms:Enable'):
                        for principal in principals:
                            if principal not in admins:
                                admins.append(principal)
                        break
            
                    if action.startswith('kms:Encrypt'):
                        for principal in principals:
                            if principal not in users:
                                users.append(principal)
                        break
                    
                    if action.startswith('kms:CreateGrant'):
                        for principal in principals:
                            if principal not in users:
                                users.append(principal)
                        break
        
        # Tier 1: Existing AdminIsGrantor check
        findMatches = []
        if admins and users:
            findMatches = set(admins) & set(users)
            
        if findMatches:
            self.results['AdminIsGrantor'] = [-1, "<br>".join(findMatches)]
        
        # Tier 1: New security checks
        if cross_account_principals:
            self.results['KeyPolicyCrossAccount'] = [-1, "<br>".join(cross_account_principals)]
        elif undetermined_wildcards:
            self.results['KeyPolicyCrossAccount'] = [0, "Unable to evaluate (wildcard principal scoped without an account condition; caller account cannot be determined): " + "<br>".join(undetermined_wildcards + org_scoped_cross_account)]
        elif org_scoped_cross_account:
            self.results['KeyPolicyCrossAccount'] = [1, "Cross-account access restricted by aws:PrincipalOrgID/aws:PrincipalOrgPaths: " + "<br>".join(org_scoped_cross_account)]
        else:
            self.results['KeyPolicyCrossAccount'] = [1, "No cross-account principals in key policy"]
        
        if wildcard_principals:
            self.results['KeyPolicyWildcardPrincipal'] = [-1, "<br>".join(wildcard_principals)]
        
        if wildcard_actions:
            self.results['KeyPolicyWildcardAction'] = [-1, "<br>".join(wildcard_actions)]
        
        if not has_root_access:
            self.results['KeyPolicyMissingRootAccess'] = [-1, f"Root account arn:aws:iam::{key_account}:root not found in policy"]
        
        # Tier 2: Check if sensitive actions are properly restricted
        if not has_put_key_policy or not has_schedule_key_deletion:
            missing = []
            if not has_put_key_policy:
                missing.append("kms:PutKeyPolicy")
            if not has_schedule_key_deletion:
                missing.append("kms:ScheduleKeyDeletion")
            sensitive_actions_not_restricted.append(f"Missing in key policy: {', '.join(missing)}")
        
        if sensitive_actions_not_restricted:
            self.results['KeyPolicySensitiveActionsNotRestricted'] = [-1, "<br>".join(sensitive_actions_not_restricted)]
        
        # Tier 2: Check for statements without conditions
        if statements_without_conditions:
            self.results['KeyPolicyNoConditions'] = [-1, "<br>".join(statements_without_conditions)]
    
    def _checkKeyUsage(self):
        """Check if key appears to be unused (Tier 2)"""
        try:
            # Heuristics for unused keys:
            # 1. Key is disabled
            # 2. Key has no grants
            # 3. Key has minimal policy (only root access)
            # 4. Key is old (>365 days) with no grants
            
            unused_indicators = []
            
            # Check 1: Disabled state
            if self.kms.get('KeyState') == 'Disabled':
                unused_indicators.append("Key is disabled")
            
            # Check 2: No grants
            try:
                ## Any grant on the first page means the key has grants; reuse
                ## the page the other grant checks read instead of a Limit=1 call.
                resp = self._grantsFirstPage()
                has_grants = len(resp.get('Grants', [])) > 0
                
                if not has_grants:
                    unused_indicators.append("No grants")
            except:
                pass
            
            # Check 3: Check key age
            creation_date = self.kms.get('CreationDate')
            if creation_date:
                current_time = datetime.now(creation_date.tzinfo)
                age_days = (current_time - creation_date).days
                
                if age_days > 365 and not has_grants:
                    unused_indicators.append(f"Key is {age_days} days old with no grants")
            
            # Only flag if multiple indicators suggest it's unused
            if len(unused_indicators) >= 2:
                self.results['KeyUnused'] = [-1, "<br>".join(unused_indicators)]
                
        except Exception as e:
            # Log error but don't fail the check
            pass
    
    def _checkKeyManagementPattern(self):
        """Check for centralized key management patterns (Tier 3)"""
        try:
            # This is an informational check to detect cross-account usage patterns
            # indicating centralized key management
            
            cross_account_usage = []
            
            # Extract account ID from key ARN
            key_account = self.kms['Arn'].split(':')[4]
            
            # Check 1: Cross-account principals in key policy
            resp = self._keyPolicy()
            
            pDoc = resp.get('Policy')
            pObj = Policy(pDoc)
            pObj.parseDocumentToJson()
            parseInfo = pObj.extractPolicyInfo()
            
            external_accounts = set()
            
            if 'allow' in parseInfo:
                for sid, arr in parseInfo['allow'].items():
                    if 'Principal' in arr and isinstance(arr['Principal'], dict):
                        if 'AWS' in arr['Principal']:
                            aws_principals = arr['Principal']['AWS']
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for principal in aws_principals:
                                if principal == '*':
                                    external_accounts |= wildcardExternalAccounts(arr.get('Condition'), key_account)
                                elif ':iam::' in principal:
                                    principal_account = principal.split(':')[4]
                                    if principal_account != key_account:
                                        external_accounts.add(principal_account)
                    elif arr.get('Principal') == '*':
                        external_accounts |= wildcardExternalAccounts(arr.get('Condition'), key_account)
            
            # Check 2: Cross-account grants
            try:
                resp = self._grantsFirstPage()
                
                grants = resp.get('Grants', [])
                
                for grant in grants:
                    principal = grant.get('GranteePrincipal', '')
                    if ':iam::' in principal:
                        principal_account = principal.split(':')[4]
                        if principal_account != key_account:
                            external_accounts.add(principal_account)
            except:
                pass
            
            # If we have cross-account usage, report it as informational
            if external_accounts:
                cross_account_usage.append(f"Cross-account access from {len(external_accounts)} account(s): {', '.join(list(external_accounts)[:3])}")
                cross_account_usage.append("This may indicate centralized key management")
                self.results['KeyCentralizedManagement'] = [-1, "<br>".join(cross_account_usage)]
                
        except Exception as e:
            # Log error but don't fail the check
            pass

    # ------------------------------------------------------------------ #
    # WAFS2027 checks
    # ------------------------------------------------------------------ #
    ## Imported key material that expires within this many days is reported.
    IMPORTED_MATERIAL_WARN_DAYS = 30

    ## AWS default (and most common compliance baseline) automatic rotation period.
    MAX_ROTATION_PERIOD_DAYS = 365

    ## Normalised (lowercase, separators removed) tag-key fragments.
    OWNERSHIP_TAG_HINTS = ('owner', 'team', 'contact', 'custodian', 'steward')
    CLASSIFICATION_TAG_HINTS = ('classification', 'confidentiality', 'sensitivity')

    @staticmethod
    def _errorCode(e):
        return e.response.get('Error', {}).get('Code', 'ClientError')

    def _checkImportedKeyMaterialExpiring(self):
        """EXTERNAL-origin key whose imported key material is missing or expires
        within IMPORTED_MATERIAL_WARN_DAYS. When imported material expires KMS
        deletes it and every ciphertext under that material is undecryptable
        until the same material is re-imported."""
        if self.kms.get('Origin') != 'EXTERNAL':
            return
        state = self.kms.get('KeyState')
        if state == 'PendingDeletion':
            return

        if state == 'PendingImport':
            self.results['ImportedKeyMaterialExpiring'] = [-1, 'Key state is PendingImport: no key material is imported (never imported, expired or deleted); the key cannot be used']
            return

        now = datetime.now(timezone.utc)
        threshold = now + timedelta(days=self.IMPORTED_MATERIAL_WARN_DAYS)

        ## Current key material from describe_key, plus every imported key
        ## material version (on-demand rotation of imported keys keeps older
        ## material, which can expire independently).
        materials = {}
        if self.kms.get('ExpirationModel') == 'KEY_MATERIAL_EXPIRES':
            materials[self.kms.get('CurrentKeyMaterialId') or 'current'] = self.kms.get('ValidTo')

        note = ''
        try:
            paginator = self.kmsClient.get_paginator('list_key_rotations')
            for page in paginator.paginate(KeyId=self.kms['KeyId'], IncludeKeyMaterial='ALL_KEY_MATERIAL'):
                for rot in page.get('Rotations', []) or []:
                    if rot.get('ImportState') != 'IMPORTED':
                        continue
                    if rot.get('ExpirationModel') != 'KEY_MATERIAL_EXPIRES':
                        continue
                    materials[rot.get('KeyMaterialId') or 'unknown'] = rot.get('ValidTo')
        except botocore.exceptions.ClientError as e:
            note = f" (non-current key material not checked: {self._errorCode(e)})"

        expiring = []
        for materialId, validTo in materials.items():
            if not isinstance(validTo, datetime):
                continue
            if validTo.tzinfo is None:
                validTo = validTo.replace(tzinfo=timezone.utc)
            if validTo < threshold:
                days = (validTo - now).days
                expiring.append(f"Key material {materialId} expires {validTo.strftime('%Y-%m-%d %H:%M:%S %Z')} ({days} days)")

        if expiring:
            self.results['ImportedKeyMaterialExpiring'] = [-1, "<br>".join(expiring) + note]
        elif materials:
            self.results['ImportedKeyMaterialExpiring'] = [1, f"Imported key material valid for more than {self.IMPORTED_MATERIAL_WARN_DAYS} days" + note]
        else:
            self.results['ImportedKeyMaterialExpiring'] = [1, 'Imported key material does not expire' + note]

    def _checkRotationPeriodTooLong(self):
        """Automatic rotation is enabled but RotationPeriodInDays exceeds 365.
        Keys without rotation are reported by KeyRotationEnabled instead."""
        if self.kms.get('KeyState') == 'PendingDeletion':
            return
        err = self.kms.get('_rotationError')
        if self.kms.get('KeyRotationEnabled') is None:
            ## Asymmetric, HMAC, imported and custom key store keys do not
            ## support automatic rotation: not applicable.
            if err and err not in ('UnsupportedOperationException',):
                self.results['RotationPeriodTooLong'] = [0, f'Unable to evaluate ({err})']
            return
        if self.kms.get('KeyRotationEnabled') is not True:
            return

        period = self.kms.get('_rotationPeriodInDays')
        if period is None:
            self.results['RotationPeriodTooLong'] = [0, 'Unable to evaluate (RotationPeriodInDays not returned)']
        elif period > self.MAX_ROTATION_PERIOD_DAYS:
            self.results['RotationPeriodTooLong'] = [-1, f'Rotation period is {period} days (> {self.MAX_ROTATION_PERIOD_DAYS})']
        else:
            self.results['RotationPeriodTooLong'] = [1, f'Rotation period is {period} days']

    @staticmethod
    def _normTagKey(key):
        return re.sub(r'[^a-z0-9]', '', str(key).lower())

    def _checkKeyMissingOwnershipTags(self):
        """Customer managed key without an ownership tag (owner/team/contact...)
        or a data classification tag. Heuristic: tag conventions are
        organisation specific, so this is low criticality."""
        if self.kms.get('KeyState') == 'PendingDeletion':
            return
        if '_resourceTags' in self.kms:
            ## Complete tag list already read by the service class (tag filter).
            tags = list(self.kms['_resourceTags'])
        else:
            tags = []
            try:
                paginator = self.kmsClient.get_paginator('list_resource_tags')
                for page in paginator.paginate(KeyId=self.kms['KeyId']):
                    tags.extend(page.get('Tags', []) or [])
            except botocore.exceptions.ClientError as e:
                self.results['KeyMissingOwnershipTags'] = [0, f'Unable to evaluate ({self._errorCode(e)})']
                return

        keys = [self._normTagKey(t.get('TagKey', '')) for t in tags]
        hasOwner = any(h in k for k in keys for h in self.OWNERSHIP_TAG_HINTS)
        hasClass = any(h in k for k in keys for h in self.CLASSIFICATION_TAG_HINTS)

        missing = []
        if not hasOwner:
            missing.append('ownership (e.g. Owner, Team)')
        if not hasClass:
            missing.append('data classification (e.g. DataClassification)')

        if missing:
            self.results['KeyMissingOwnershipTags'] = [-1, 'Missing tag: ' + ', '.join(missing)]
        else:
            self.results['KeyMissingOwnershipTags'] = [1, 'Ownership and classification tags present']

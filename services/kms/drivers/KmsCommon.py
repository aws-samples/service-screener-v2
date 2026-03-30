import boto3

import time
from datetime import datetime, tzinfo

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import _warn
# from utils.Tools import aws_parseInstanceFamily
from utils.Policy import Policy
from services.Evaluator import Evaluator

class KmsCommon(Evaluator):
    def __init__(self, kms, kmsClient):
        self.dbParams = {}
        self.results = {}
        self.kms = kms
        self.kmsClient = kmsClient

        self._resourceName = kms['Arn']

        # self.__configPrefix = 'kms::' +  + '::' + db['EngineVersion'] + '::'
        self.init()

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
            resp = self.kmsClient.list_grants(
                KeyId = self.kms['KeyId'],
                Limit = 100
            )
            
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
        resp = self.kmsClient.get_key_policy(
            KeyId = self.kms['KeyId'],
            PolicyName = 'default'
        )
        
        pDoc = resp.get('Policy')
        pObj = Policy(pDoc)
        pObj.parseDocumentToJson()
        parseInfo = pObj.extractPolicyInfo()
        
        # Also parse the raw policy for condition checks
        import json
        rawPolicy = json.loads(pDoc)
        
        admins = []
        users = []
        cross_account_principals = []
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
        
        # Create a mapping of Sid to raw statement for condition checking
        sid_to_statement = {}
        for statement in rawPolicy.get('Statement', []):
            sid = statement.get('Sid', 'noSid')
            sid_to_statement[sid] = statement
        
        if 'allow' in parseInfo:
            ## Build Admin List and perform security checks
            for sid, arr in parseInfo['allow'].items():
                # Get the raw statement for condition checking
                raw_statement = sid_to_statement.get(sid, {})
                
                # Tier 1: Check for wildcard principals (KeyPolicyWildcardPrincipal)
                if 'Principal' in arr:
                    if arr['Principal'] == '*':
                        wildcard_principals.append(f"Statement {sid}: Principal is *")
                    elif isinstance(arr['Principal'], dict):
                        if 'AWS' in arr['Principal']:
                            aws_principals = arr['Principal']['AWS']
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for principal in aws_principals:
                                if principal == '*':
                                    wildcard_principals.append(f"Statement {sid}: AWS Principal is *")
                                # Check for root access
                                elif f":iam::{key_account}:root" in principal:
                                    has_root_access = True
                                # Tier 1: Check for cross-account access (KeyPolicyCrossAccount)
                                elif ':iam::' in principal:
                                    principal_account = principal.split(':')[4]
                                    if principal_account != key_account:
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
                            if 'Condition' not in raw_statement or not raw_statement.get('Condition'):
                                wildcard_actions.append(f"Statement {sid}: Action {action} without conditions")
                    
                    # Tier 2: Check for statements without conditions (KeyPolicyNoConditions)
                    # Only flag for non-root principals and non-service principals
                    if 'Condition' not in raw_statement or not raw_statement.get('Condition'):
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
                resp = self.kmsClient.list_grants(
                    KeyId = self.kms['KeyId'],
                    Limit = 1
                )
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
            resp = self.kmsClient.get_key_policy(
                KeyId = self.kms['KeyId'],
                PolicyName = 'default'
            )
            
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
                                if ':iam::' in principal:
                                    principal_account = principal.split(':')[4]
                                    if principal_account != key_account:
                                        external_accounts.add(principal_account)
            
            # Check 2: Cross-account grants
            try:
                resp = self.kmsClient.list_grants(
                    KeyId = self.kms['KeyId'],
                    Limit = 100
                )
                
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

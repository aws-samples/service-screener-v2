import botocore
from botocore.config import Config as bConfig

import json
from datetime import datetime, timedelta
from dateutil.tz import tzlocal

from utils.Config import Config
from utils.Tools import _warn, _pr
from .IamCommon import IamCommon
from .IamOrgData import OrgData, SCP, RCP, TAG, FULL_AWS_ACCESS_ID, statements, denyCoversAction, conditionKeys, scpGuardrails, SCP_GUARDRAILS
 
class IamAccount(IamCommon):
    PASSWORD_POLICY_MIN_SCORE = 4
    ROOT_LOGIN_MAX_COUNT = 3
    
    def __init__(self, none, awsClients, users, roles, ssBoto, authDetails=None, policyDocumentMap=None):
        super().__init__()
        
        self.ssBoto = ssBoto
        self.iamClient = awsClients['iamClient']
        self.accClient = awsClients['accClient']
        self.sppClient = awsClients['sppClient']
        # self.gdClient = awsClients['gdClient']
        self.budgetClient = awsClients['budgetClient']
        self.orgClient = awsClients['orgClient']
        
        
        self.curClient = awsClients['curClient']
        self.ctClient = awsClients['ctClient']
        self.backupClient = awsClients['backupClient']
        
        self.noOfUsers = len(users)
        self.roles = roles
        
        self._resourceName = 'General'

        # self.__configPrefix = 'iam::settings::'

        # Assuming AWS Organization is disabled at first
        self.organizationIsEnabled = False

        # Use prefetched data if available, otherwise lazy-load
        self._authDetails = authDetails
        self._policyDocumentMap = policyDocumentMap or {}
        self._customerPoliciesCache = None
        if authDetails and 'policies' in authDetails:
            self._customerPoliciesCache = [
                p for p in authDetails['policies'] 
                if not p.get('Arn', '').startswith('arn:aws:iam::aws:')
            ]
        self._policyDocumentsCache = dict(self._policyDocumentMap)

        # Check if AWS Organization is enabled
        orgResp, orgErr = None, None
        try:
            orgResp = self.orgClient.describe_organization()
            self.organizationIsEnabled = True
        except botocore.exceptions.ClientError as e:
            orgErr = e.response['Error']['Code']

        callerAccountId = (Config.get('stsInfo', {}) or {}).get('Account')
        self.orgData = OrgData(self.orgClient, callerAccountId, orgResp, orgErr)

        self.init()
    
    def _getCustomerPolicies(self):
        """Cached fetch of all customer managed policies with preloaded documents"""
        if self._customerPoliciesCache is not None:
            return self._customerPoliciesCache
        
        self._customerPoliciesCache = []
        paginator = self.iamClient.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            self._customerPoliciesCache.extend(page.get('Policies', []))
        
        return self._customerPoliciesCache
    
    def _getPolicyDocument(self, policyArn, versionId):
        """Cached fetch of policy document by ARN and version"""
        key = f"{policyArn}:{versionId}"
        if key not in self._policyDocumentsCache:
            # Check prefetched map by ARN only
            if policyArn in self._policyDocumentMap:
                self._policyDocumentsCache[key] = self._policyDocumentMap[policyArn]
            else:
                resp = self.iamClient.get_policy_version(
                    PolicyArn=policyArn,
                    VersionId=versionId
                )
                self._policyDocumentsCache[key] = resp['PolicyVersion']['Document']
        return self._policyDocumentsCache[key]
        
    def passwordPolicyScoring(self, policies):
        score = 0
        for policy, value in policies.items():
            ## no score for this:
            if policy in ['AllowUsersToChangePassword', 'ExpirePasswords']:
                continue
            
            if policy == 'MinimumPasswordLength':
                if value >= 12:
                    score += 1
                else:
                    self.results['passwordPolicyLength'] = [-1, value]
                continue

            if policy == 'MaxPasswordAge' and value <= 90:
                score += 1
                continue

            if policy == 'PasswordReusePrevention' and value >= 6:
                score += 1
                self.results['passwordPolicyReuse'] = [-1, value]
                continue
            
            if not value is None and value > 0:
                score += 1
                
        return score
    
    def _checkPasswordPolicy(self):
        try:
            resp = self.iamClient.get_account_password_policy()
            policies = resp.get('PasswordPolicy')
            
            score = self.passwordPolicyScoring(policies)
            
            currVal = []
            if score <= self.PASSWORD_POLICY_MIN_SCORE:
                for policy, num in policies.items():
                    currVal.append(f"{policy}={num}")
                    
                output = '<br>'.join(currVal)
                self.results['passwordPolicyWeak'] = [-1, output]
                
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(ecode)
            if ecode == 'NoSuchEntity':
                self.results['passwordPolicy'] = [-1, ecode]
    
    def _checkRootLoginActivity(self):
        c = 0
        LookupAttributes=[
            {
                'AttributeKey': 'Username',
                'AttributeValue': 'root'
            },
            {
                'AttributeKey': 'Eventname',
                'AttributeValue': 'ConsoleLogin'
            }
        ]
        StartTime=datetime.today() - timedelta(days=30)
        EndTime=datetime.today() + timedelta(days=1)
        
        resp = self.ctClient.lookup_events(
            LookupAttributes=LookupAttributes,
            StartTime=StartTime,
            EndTime=EndTime,
            MaxResults=50,
        )
        
        ee = resp.get('Events')
        if len(ee) == 0:
            return
        
        self.results['rootConsoleLogin30days'] = [-1, '']
        
        for e in ee:
            o = e.get('CloudTrailEvent')
            o = json.loads(o)
            
            if 'errorMessage' in o:
                c += 1
                
            if c >= self.ROOT_LOGIN_MAX_COUNT:
                self.results['rootConsoleLoginFail3x'] = [-1, '']
                return
        
        while resp.get('NextToken') != None:
            resp = self.ctClient.lookup_events(
                LookupAttributes=LookupAttributes,
                StartTime=StartTime,
                EndTime=EndTime,
                MaxResults=50,
                NextToken = resp.get('NextToken')
            )
            
            ee = resp.get('Events')
            for e in ee:
                o = e.get('CloudTrailEvent')
                o = json.loads(o)
                
                if 'errorMessage' in o:
                    c += 1
                    
                if c >= self.ROOT_LOGIN_MAX_COUNT:
                    self.results['rootConsoleLoginFail3x'] = [-1, '']
                return
    
    def _checkHasRole_AWSReservedSSO(self):
        hasReservedRole = False
        for role in self.roles:
            if role['RoleName'].startswith('AWSReservedSSO_'):
                hasReservedRole = True
                break 
            
        if hasReservedRole == False:
            self.results['hasSSORoles'] = [-1, '']
    
    def _checkHasExternalProvider(self):
        hasOpID = False
        hasSaml = False
        resp = self.iamClient.list_open_id_connect_providers()
        if 'OpenIDConnectProviderList' in resp:
            if len(resp['OpenIDConnectProviderList']) > 0:
                hasOpID = True
        
        resp = self.iamClient.list_saml_providers()
        if 'SAMLProviderList' in resp:
            if len(resp['SAMLProviderList']) > 0:
                hasSaml = True
        
        if hasOpID == False and hasSaml == False:
            self.results['hasExternalIdentityProvider'] = [-1, '']
    
    def _checkHasGuardDuty(self):
        ssBoto = self.ssBoto
        regions = Config.get("REGIONS_SELECTED")
        
        results = {}
        badResults = []
        cnt = 0
        for region in regions:
            if region == 'GLOBAL':
                continue
            
            conf = bConfig(region_name = region)
            gdClient = ssBoto.client('guardduty', config=conf)
        
            resp = gdClient.list_detectors()
            if 'DetectorIds' in resp:
                ids = resp.get('DetectorIds')
                if len(ids) > 0:
                    return
            
        self.results["enableGuardDuty"] = [-1, ""]
        
    def _checkHasCostBudget(self):
        stsInfo = Config.get('stsInfo')
        
        budgetClient = self.budgetClient
        
        try:
            resp = budgetClient.describe_budgets(AccountId=stsInfo['Account'])
        
            if 'Budgets' in resp:
                return 
        
            self.results['enableCostBudget'] = [-1, ""]
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    def _checkSupportPlan(self):
        sppClient = self.sppClient
        try:
            resp = sppClient.describe_severity_levels()
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'SubscriptionRequiredException':
                self.results['supportPlanLowTier'] = [-1, '']
    
    def _checkHasUsers(self):
        # has at least 1 for all account (root)
        if self.noOfUsers < 2:
            self.results['noUsersFound'] = [-1, 'No IAM User found']
                
    def _checkHasAlternateContact(self):
        CONTACT_TYP = ['BILLING', 'SECURITY', 'OPERATIONS']
        cnt = 0
        for typ in CONTACT_TYP:
            res = self.getAlternateContactByType(typ)
            if res == None:
                res = 0
            cnt += res
        
        if cnt == 0:
            self.results['hasAlternateContact'] = [-1, 'No alternate contacts']
    
    def getAlternateContactByType(self, typ):
        try:
            resp = self.accClient.get_alternate_contact(
                AlternateContactType = typ
            )
            return 1
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'ResourceNotFoundException':
                return 0

    def _checkHasOrganization(self):
        if (self.organizationIsEnabled == False):
                self.results['hasOrganization'] = [-1, '']
    
    def _checkCURReport(self):
        try:
            results = self.curClient.describe_report_definitions()
            if len(results.get('ReportDefinitions')) == 0:
                self.results['enableCURReport'] = [-1, '']
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if e.response['Error']['Code'] == 'AccessDeniedException':
               _warn('Unable to describe the CUR report. It is likely that this account is part of AWS Organizations')
            else:
                print(e)
        
        return

    def _checkConfigEnabled(self):
        ssBoto = self.ssBoto
        regions = Config.get("REGIONS_SELECTED")
        
        results = {}
        badResults = []
        cnt = 0
        for region in regions:
            if region == 'GLOBAL':
                continue
            
            conf = bConfig(region_name = region)
            cfg = ssBoto.client('config', config=conf)
            
            resp = cfg.describe_configuration_recorders()
            recorders = resp.get('ConfigurationRecorders')
            r = 1
            if len(recorders) == 0:
                r = 0
                badResults.append(region)
            
            cnt = cnt + r
            results[region] = r
        
        if cnt == 0:
            self.results['EnableConfigService'] = [-1, None]
        elif cnt < len(regions):
            self.results['PartialEnableConfigService'] = [-1, ', '.join(badResults)]
        else:
            return

    def _checkAWSBackupPlans(self):
        """Check if AWS Backup plans are configured (FTR BAR-001.1)"""
        try:
            resp = self.backupClient.list_backup_plans()
            plans = resp.get('BackupPlansList', [])
            
            if len(plans) == 0:
                self.results['hasAWSBackupPlans'] = [-1, 'No AWS Backup plans configured']
                
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            if ecode == 'AccessDeniedException':
                _warn('Unable to check AWS Backup plans. Insufficient permissions.')
            else:
                print(f'Error checking AWS Backup: {ecode}')
    
    def _checkUnusedCustomerManagedPolicy(self):
        """Check for customer managed policies not attached to any users, groups, or roles"""
        try:
            unused_policies = []
            for policy in self._getCustomerPolicies():
                if policy.get('AttachmentCount', 0) == 0:
                    unused_policies.append(policy['PolicyName'])
            
            if unused_policies:
                self.results['unusedCustomerManagedPolicy'] = [
                    len(unused_policies), 
                    '<br>'.join(unused_policies)
                ]
                
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(f'Error checking unused policies: {ecode}')
    
    def _checkIamUsersWithFederationAvailable(self):
        """Check for IAM users with credentials when federation is configured"""
        try:
            # Check if federation is configured
            has_federation = False
            
            # Check for SAML providers
            saml_resp = self.iamClient.list_saml_providers()
            if len(saml_resp.get('SAMLProviderList', [])) > 0:
                has_federation = True
            
            # Check for OIDC providers
            oidc_resp = self.iamClient.list_open_id_connect_providers()
            if len(oidc_resp.get('OpenIDConnectProviderList', [])) > 0:
                has_federation = True
            
            # Only proceed if federation is configured
            if not has_federation:
                return
            
            # Get credential report to check for users with credentials
            users_with_credentials = []
            
            try:
                report = self.iamClient.get_credential_report()
                rows = report.get('Content').decode('UTF-8').split("\n")
                
                # Skip header and root account
                for row in rows[1:]:
                    if not row:
                        continue
                    
                    fields = row.split(',')
                    if len(fields) < 4:
                        continue
                    
                    username = fields[0]
                    
                    # Skip root account
                    if username == '<root_account>':
                        continue
                    
                    # Check if user has password or access keys
                    password_enabled = fields[3] if len(fields) > 3 else 'false'
                    access_key_1_active = fields[8] if len(fields) > 8 else 'false'
                    access_key_2_active = fields[13] if len(fields) > 13 else 'false'
                    
                    if (password_enabled == 'true' or 
                        access_key_1_active == 'true' or 
                        access_key_2_active == 'true'):
                        users_with_credentials.append(username)
                
                if users_with_credentials:
                    self.results['iamUsersWithFederationAvailable'] = [
                        len(users_with_credentials),
                        '<br>'.join(users_with_credentials)
                    ]
                    
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] in ['ReportNotPresent', 'ReportExpired']:
                    # Report will be generated by getUsers() method
                    pass
                    
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(f'Error checking federation: {ecode}')
    
    def _checkUnnecessaryCustomPolicies(self):
        """Check for customer managed policies that may duplicate AWS managed policies"""
        try:
            # Common AWS managed policies that are often duplicated
            common_aws_managed = {
                'ReadOnlyAccess': ['read', 'get', 'list', 'describe'],
                'PowerUserAccess': ['full access except IAM'],
                'ViewOnlyAccess': ['read', 'get', 'list', 'describe'],
                'SecurityAudit': ['security', 'audit', 'read'],
            }
            
            potentially_unnecessary = []
            paginator = self.iamClient.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):
                for policy in page.get('Policies', []):
                    policy_name = policy['PolicyName']
                    
                    # Simple heuristic: check if policy name suggests it might duplicate AWS managed
                    name_lower = policy_name.lower()
                    
                    # Check for common patterns that suggest AWS managed alternatives exist
                    if any(keyword in name_lower for keyword in [
                        'readonly', 'read-only', 'viewonly', 'view-only',
                        'poweruser', 'power-user', 'securityaudit', 'security-audit'
                    ]):
                        potentially_unnecessary.append(policy_name)
            
            if potentially_unnecessary:
                self.results['unnecessaryCustomPolicies'] = [
                    len(potentially_unnecessary),
                    '<br>'.join(potentially_unnecessary)
                ]
                
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(f'Error checking custom policies: {ecode}')
    
    def _checkMissingPolicyConditions(self):
        """
        Check for policies with sensitive operations missing security conditions.
        
        This check analyzes customer managed policies to identify sensitive operations
        (IAM modifications, security config changes, privilege escalation actions) that
        lack appropriate security conditions such as MFA enforcement, IP restrictions,
        or secure transport requirements.
        
        Validates Requirements: 1.2, 1.3, 1.4, 1.6, 4.1, 4.2, 4.3, 5.1
        """
        try:
            from utils.Policy import Policy, ALL_SENSITIVE_ACTIONS
            
            policies_with_issues = []
            
            for policy in self._getCustomerPolicies():
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                
                try:
                    policy_document = self._getPolicyDocument(policy_arn, policy['DefaultVersionId'])
                    
                    # Parse policy using Policy class
                    policy_obj = Policy(policy_document)
                    
                    # Check for missing conditions on sensitive actions
                    missing_conditions = policy_obj.getMissingConditions(ALL_SENSITIVE_ACTIONS)
                    
                    if missing_conditions:
                        # Format the missing conditions for this policy
                        missing_details = []
                        for item in missing_conditions:
                            action = item['action']
                            missing_types = ', '.join(item['missing'])
                            missing_details.append(f"{action} (missing: {missing_types})")
                        
                        policy_issue = f"{policy_name}: {'; '.join(missing_details)}"
                        policies_with_issues.append(policy_issue)
                
                except botocore.exceptions.ClientError as e:
                    ecode = e.response['Error']['Code']
                    print(f'Error getting policy version for {policy_name}: {ecode}')
                    continue
            
            # Store results if any policies have issues
            if policies_with_issues:
                self.results['missingPolicyConditions'] = [
                    len(policies_with_issues),
                    '<br>'.join(policies_with_issues)
                ]
                
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(f'Error checking policy conditions: {ecode}')


    def _checkMissingPermissionsBoundaries(self):
        """
        Check for IAM entities without permissions boundaries in delegated administration scenarios.
        
        This check identifies IAM users and roles that have delegated administration capabilities
        (such as IAM management permissions) but lack permissions boundaries. Permissions boundaries
        set the maximum permissions an entity can have, providing an additional layer of security
        for delegated administrators.
        
        Delegated admins are identified using heuristics:
        - Roles/users with IAM management permissions (iam:CreateUser, iam:CreateRole, etc.)
        - Roles with admin-related name patterns (admin, administrator, delegated, manager)
        
        Validates Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 4.1, 4.2, 4.3, 5.1
        """
        try:
            entities_without_boundaries = []
            
            DELEGATED_ADMIN_ACTIONS = [
                'iam:CreateUser', 'iam:CreateRole',
                'iam:AttachUserPolicy', 'iam:AttachRolePolicy',
                'iam:PutUserPolicy', 'iam:PutRolePolicy'
            ]
            
            ADMIN_NAME_PATTERNS = ['admin', 'administrator', 'delegated', 'manager']
            
            def has_admin_name_pattern(name):
                name_lower = name.lower()
                return any(pattern in name_lower for pattern in ADMIN_NAME_PATTERNS)
            
            def has_iam_management_permissions(policy_docs):
                for policy_doc in policy_docs:
                    if isinstance(policy_doc, str):
                        import json
                        try:
                            policy_doc = json.loads(policy_doc)
                        except (json.JSONDecodeError, TypeError):
                            continue
                    if not isinstance(policy_doc, dict):
                        continue
                    statements = policy_doc.get('Statement', [])
                    if isinstance(statements, str):
                        continue
                    for statement in statements:
                        if not isinstance(statement, dict):
                            continue
                        if statement.get('Effect') != 'Allow':
                            continue
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        for action in actions:
                            if action in DELEGATED_ADMIN_ACTIONS or action in ('iam:*', '*'):
                                return True
                return False
            
            def get_entity_policies(entity_type, entity):
                """Get all policy documents for a role or user dict already in
                hand, using its prefetched fields when present instead of
                re-searching authDetails by name."""
                import json as _json
                docs = []

                key_field = 'RoleName' if entity_type == 'role' else 'UserName'
                policy_list_field = 'RolePolicyList' if entity_type == 'role' else 'UserPolicyList'
                entity_name = entity.get(key_field, '')

                # Use the entity's own prefetched fields directly - no need to
                # re-scan authDetails, this dict came from there (or an
                # equivalent bulk fetch) already.
                if policy_list_field in entity or 'AttachedManagedPolicies' in entity:
                    for p in entity.get(policy_list_field, []):
                        doc = p.get('PolicyDocument', {})
                        if isinstance(doc, str):
                            doc = _json.loads(doc)
                        docs.append(doc)
                    for p in entity.get('AttachedManagedPolicies', []):
                        arn = p['PolicyArn']
                        if arn in self._policyDocumentMap:
                            doc = self._policyDocumentMap[arn]
                            if isinstance(doc, str):
                                doc = _json.loads(doc)
                            docs.append(doc)
                    return docs

                # Fallback to API calls
                try:
                    if entity_type == 'role':
                        inline_names = self.iamClient.list_role_policies(RoleName=entity_name).get('PolicyNames', [])
                        for pn in inline_names:
                            resp = self.iamClient.get_role_policy(RoleName=entity_name, PolicyName=pn)
                            doc = resp.get('PolicyDocument', {})
                            if isinstance(doc, str):
                                doc = _json.loads(doc)
                            docs.append(doc)
                        attached = self.iamClient.list_attached_role_policies(RoleName=entity_name).get('AttachedPolicies', [])
                    else:
                        inline_names = self.iamClient.list_user_policies(UserName=entity_name).get('PolicyNames', [])
                        for pn in inline_names:
                            resp = self.iamClient.get_user_policy(UserName=entity_name, PolicyName=pn)
                            doc = resp.get('PolicyDocument', {})
                            if isinstance(doc, str):
                                doc = _json.loads(doc)
                            docs.append(doc)
                        attached = self.iamClient.list_attached_user_policies(UserName=entity_name).get('AttachedPolicies', [])
                    
                    for p in attached:
                        policy_info = self.iamClient.get_policy(PolicyArn=p['PolicyArn'])
                        doc = self._getPolicyDocument(p['PolicyArn'], policy_info['Policy']['DefaultVersionId'])
                        if isinstance(doc, str):
                            doc = _json.loads(doc)
                        docs.append(doc)
                except botocore.exceptions.ClientError:
                    pass
                return docs
            
            # Check IAM roles - check name pattern first (cheap), then policies only if needed
            for role in self.roles:
                role_name = role.get('RoleName', '')
                if role.get('PermissionsBoundary'):
                    continue
                
                # Skip AWS service-linked roles - they can't have permissions boundaries
                role_path = role.get('Path', '')
                if role_path.startswith('/aws-service-role/'):
                    continue
                
                if has_admin_name_pattern(role_name):
                    entities_without_boundaries.append(f"Role: {role_name}")
                    continue
                
                if has_iam_management_permissions(get_entity_policies('role', role)):
                    entities_without_boundaries.append(f"Role: {role_name}")

            # Check IAM users - use prefetched data when available instead of
            # a fresh list_users() enumeration, same as the role loop above.
            try:
                if self._authDetails and self._authDetails.get('users'):
                    users_source = self._authDetails['users']
                else:
                    users_source = []
                    paginator = self.iamClient.get_paginator('list_users')
                    for page in paginator.paginate():
                        users_source.extend(page.get('Users', []))

                for user in users_source:
                    user_name = user.get('UserName', '')
                    if user.get('PermissionsBoundary'):
                        continue

                    if has_admin_name_pattern(user_name):
                        entities_without_boundaries.append(f"User: {user_name}")
                        continue

                    if has_iam_management_permissions(get_entity_policies('user', user)):
                        entities_without_boundaries.append(f"User: {user_name}")
            except botocore.exceptions.ClientError as e:
                print(f'Error listing users: {e.response["Error"]["Code"]}')
            
            if entities_without_boundaries:
                self.results['missingPermissionsBoundaries'] = [
                    len(entities_without_boundaries),
                    '<br>'.join(entities_without_boundaries)
                ]
        
        except botocore.exceptions.ClientError as e:
            print(f'Error checking permissions boundaries: {e.response["Error"]["Code"]}')

    # ------------------------------------------------------------------ #
    # AWS Organizations checks (WAFS2027). All reads go through self.orgData
    # (cached, thread-safe). Org-level reads that fail from a member account
    # record [0, 'Not evaluable from member account'] - never a silent PASS.
    # ------------------------------------------------------------------ #
    MAX_DETAIL_LINES = 50
    WORKLOAD_EXEMPT_LAMBDA_PREFIXES = (
        'aws-controltower-', 'awscontroltower', 'awsaccelerator', 'aws-accelerator',
        'aws-quicksetup', 'customizations-for-aws-control-tower',
    )
    RCP_PERIMETER_KEYS = {
        'aws:principalorgid', 'aws:principalorgpaths', 'aws:resourceorgid', 'aws:resourceorgpaths',
        'aws:sourceorgid', 'aws:sourceorgpaths',
    }
    BACKUP_TAMPER_ACTIONS = [
        'backup:DeleteBackupVault', 'backup:DeleteBackupVaultAccessPolicy',
        'backup:DeleteBackupVaultLockConfiguration', 'backup:DeleteRecoveryPoint',
        'backup:PutBackupVaultAccessPolicy', 'backup:UpdateRecoveryPointLifecycle',
    ]
    CLASSIFICATION_KEYWORDS = ('classif', 'sensitiv', 'confidential')

    def _detail(self, lines):
        if len(lines) > self.MAX_DETAIL_LINES:
            extra = len(lines) - self.MAX_DETAIL_LINES
            lines = lines[:self.MAX_DETAIL_LINES] + ['... and {} more'.format(extra)]
        return '<br>'.join(lines)

    def _orgPrecondition(self, key, requireAllFeatures=False, featureMsg=None):
        """Record [0, ...] for `key` and return False when the org check cannot run."""
        pre = self.orgData.preconditionResult()
        if pre:
            self.results[key] = pre
            return False
        if requireAllFeatures:
            org, _ = self.orgData.organization()
            if org.get('FeatureSet') != 'ALL':
                self.results[key] = [0, featureMsg or 'Not applicable: organization does not use All Features (see orgNotAllFeatures)']
                return False
        return True

    def _customerAttached(self, pols):
        return [p for p in pols if not p['AwsManaged'] and p['Id'] != FULL_AWS_ACCESS_ID and p['Targets']]

    @staticmethod
    def _targetLabel(t):
        return '{} {} ({})'.format(t.get('Type', ''), t.get('Name', ''), t.get('TargetId', '')).strip()

    def _policyGate(self, key, policyType, disabledResult):
        """Common gate for policy-type checks. Returns the policy list or None
        (after recording a result)."""
        status, err = self.orgData.policyTypeStatus(policyType)
        if err:
            self.results[key] = self.orgData.notEvaluable(err)
            return None
        if status != 'ENABLED':
            self.results[key] = disabledResult
            return None
        pols, err = self.orgData.policies(policyType)
        if err:
            self.results[key] = self.orgData.notEvaluable(err)
            return None
        return pols

    def _checkOrgNotAllFeatures(self):
        key = 'orgNotAllFeatures'
        if not self._orgPrecondition(key):
            return
        org, _ = self.orgData.organization()
        fs = org.get('FeatureSet')
        if fs != 'ALL':
            self.results[key] = [-1, 'Organization FeatureSet is {}'.format(fs)]
        else:
            self.results[key] = [1, 'Organization FeatureSet is ALL']

    def _checkOrgMgmtAccountHostsWorkloads(self):
        key = 'orgMgmtAccountHostsWorkloads'
        if not self._orgPrecondition(key):
            return
        if not self.orgData.isManagementAccount():
            self.results[key] = [1, 'This account is not the organization management account']
            return

        counts = {'EC2 instances': 0, 'Lambda functions': 0, 'RDS DB instances': 0, 'EKS clusters': 0}
        errors = []
        regions = [r for r in (Config.get('REGIONS_SELECTED', []) or []) if r != 'GLOBAL']
        if not regions:
            self.results[key] = [0, 'Unable to evaluate (no regions selected)']
            return
        probes = [
            ('EC2 instances', 'ec2', 'describe_instances', 'Reservations',
             {'Filters': [{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}]}),
            ('Lambda functions', 'lambda', 'list_functions', 'Functions', {}),
            ('RDS DB instances', 'rds', 'describe_db_instances', 'DBInstances', {}),
            ('EKS clusters', 'eks', 'list_clusters', 'clusters', {}),
        ]
        for region in regions:
            conf = bConfig(region_name=region)
            for label, svc, op, rkey, kw in probes:
                try:
                    client = self.ssBoto.client(svc, config=conf)
                    for page in client.get_paginator(op).paginate(**kw):
                        items = page.get(rkey, [])
                        if svc == 'ec2':
                            counts[label] += sum(len(r.get('Instances', [])) for r in items)
                        elif svc == 'lambda':
                            # Control Tower / Landing Zone Accelerator / Quick Setup
                            # deploy their own functions into the management account.
                            counts[label] += len([f for f in items if not str(f.get('FunctionName', '')).lower()
                                                  .startswith(self.WORKLOAD_EXEMPT_LAMBDA_PREFIXES)])
                        else:
                            counts[label] += len(items)
                except botocore.exceptions.ClientError as e:
                    errors.append('{} {}: {}'.format(region, label, e.response['Error']['Code']))

        found = ['{}: {}'.format(k, v) for k, v in counts.items() if v > 0]
        if found:
            self.results[key] = [-1, 'Management account hosts workload resources in scanned regions ({}):<br>{}'.format(
                ', '.join(regions), '<br>'.join(found))]
        elif errors:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(self._detail(errors))]
        else:
            self.results[key] = [1, 'No EC2/Lambda/RDS/EKS workloads found in scanned regions ({})'.format(', '.join(regions))]

    def _checkSCPEnabled(self):
        key = 'SCPEnabled'
        if not self._orgPrecondition(key, True, 'Not applicable: SCPs require All Features (see orgNotAllFeatures)'):
            return
        pols = self._policyGate(key, SCP, [-1, 'Service control policy type is not enabled on the organization root'])
        if pols is None:
            return
        attached = self._customerAttached(pols)
        if not attached:
            self.results[key] = [-1, 'No SCP other than FullAWSAccess is attached to the root, any OU or any account']
        else:
            self.results[key] = [1, '{} customer SCP(s) attached: {}'.format(
                len(attached), ', '.join(p['Name'] for p in attached[:20]))]

    def _checkScpBestPractices(self):
        """Evaluate the EFFECTIVE SCP set (directly attached + inherited from
        every parent) of each OU and active member account for best-practice
        guardrails: root user denial, region restriction and privilege
        escalation prevention. A guardrail provided by any SCP in the path
        counts, so guardrails split across several SCPs are not flagged.
        The management account is skipped (SCPs never apply to it)."""
        key = 'scpBestPractices'
        if not self._orgPrecondition(key, True, 'Not applicable: SCPs require All Features (see orgNotAllFeatures)'):
            return
        pols = self._policyGate(key, SCP, [0, 'Not applicable: SCPs are not enabled (see SCPEnabled)'])
        if pols is None:
            return
        if not self._customerAttached(pols):
            self.results[key] = [0, 'Not applicable: no customer SCP is attached (see SCPEnabled)']
            return
        tree, err = self.orgData.tree()
        if err:
            self.results[key] = self.orgData.notEvaluable(err)
            return

        byTarget = {}
        for p in pols:
            for t in p['Targets']:
                byTarget.setdefault(t.get('TargetId'), []).append(p)

        org, _ = self.orgData.organization()
        mgmtId = org.get('MasterAccountId')
        nodes = tree['nodes']
        evaluated, missing, unknown = 0, [], []
        for nid, node in nodes.items():
            if node['Type'] == 'ROOT':
                continue
            if node['Type'] == 'ACCOUNT' and (nid == mgmtId or (node.get('State') or 'ACTIVE') != 'ACTIVE'):
                continue
            evaluated += 1
            have, unparsed, cur, seen = set(), False, nid, set()
            while cur and cur not in seen:
                seen.add(cur)
                for p in byTarget.get(cur, []):
                    if p['AwsManaged'] or p['Id'] == FULL_AWS_ACCESS_ID:
                        continue
                    if p['Content'] is None:
                        unparsed = True
                    have |= scpGuardrails(p['Content'])
                cur = nodes.get(cur, {}).get('Parent')
            lacking = [SCP_GUARDRAILS[g] for g in SCP_GUARDRAILS if g not in have]
            if lacking:
                label = '{} {} ({}): missing {}'.format(
                    'OU' if node['Type'] == 'ORGANIZATIONAL_UNIT' else 'Account', node['Name'], nid, ', '.join(lacking))
                (unknown if unparsed else missing).append(label)

        if missing:
            self.results[key] = [-1, '{} of {} OUs/member accounts lack effective SCP guardrails:<br>{}'.format(
                len(missing), evaluated, self._detail(missing))]
        elif unknown:
            self.results[key] = [0, 'Unable to evaluate (unparseable SCP content):<br>{}'.format(self._detail(unknown))]
        elif evaluated == 0:
            self.results[key] = [0, 'No OUs or member accounts to evaluate (SCPs do not apply to the management account)']
        else:
            self.results[key] = [1, 'All {} OUs/member accounts have effective root-denial, region and privilege-escalation guardrails'.format(evaluated)]

    def _checkOrgOuStructureFlat(self):
        key = 'orgOuStructureFlat'
        if not self._orgPrecondition(key):
            return
        roots, err = self.orgData.roots()
        if err or not roots:
            self.results[key] = self.orgData.notEvaluable(err or 'NoRoot')
            return
        rootId = roots[0]['Id']
        try:
            ous = []
            for page in self.orgClient.get_paginator('list_organizational_units_for_parent').paginate(ParentId=rootId):
                ous.extend(page.get('OrganizationalUnits', []))
        except botocore.exceptions.ClientError as e:
            self.results[key] = self.orgData.notEvaluable(e.response['Error']['Code'])
            return
        if not ous:
            self.results[key] = [-1, 'No organizational units exist under the organization root']
            return
        org, _ = self.orgData.organization()
        try:
            direct = []
            for page in self.orgClient.get_paginator('list_accounts_for_parent').paginate(ParentId=rootId):
                direct.extend(a for a in page.get('Accounts', []) if a.get('Id') != org.get('MasterAccountId'))
        except botocore.exceptions.ClientError as e:
            self.results[key] = self.orgData.notEvaluable(e.response['Error']['Code'])
            return
        if direct:
            self.results[key] = [-1, '{} member account(s) attached directly to the root:<br>{}'.format(
                len(direct), self._detail(['{} ({})'.format(a.get('Name', ''), a['Id']) for a in direct]))]
        else:
            self.results[key] = [1, '{} top-level OU(s); no member accounts attached directly to the root'.format(len(ous))]

    def _checkOrgMemberAlternateContactsMissing(self):
        """Alternate contacts of every other ACTIVE account in the org. The
        scanned account itself is covered by hasAlternateContact."""
        key = 'orgMemberAlternateContactsMissing'
        if not self._orgPrecondition(key):
            return
        accounts, err = self.orgData.accounts()
        if err:
            self.results[key] = self.orgData.notEvaluable(err)
            return
        caller = self.orgData.callerAccountId
        members = [a for a in accounts
                   if a.get('Id') != caller and (a.get('State') or a.get('Status')) == 'ACTIVE']
        if not members:
            self.results[key] = [1, 'No other active member accounts in the organization']
            return

        missing, errors, ok = [], [], 0
        for a in members:
            gaps = []
            for typ in ['SECURITY', 'BILLING', 'OPERATIONS']:
                try:
                    self.accClient.get_alternate_contact(AccountId=a['Id'], AlternateContactType=typ)
                    ok += 1
                except botocore.exceptions.ClientError as e:
                    code = e.response['Error']['Code']
                    if code == 'ResourceNotFoundException':
                        gaps.append(typ)
                        ok += 1
                    else:
                        errors.append('{} {}: {}'.format(a['Id'], typ, code))
            if gaps:
                missing.append('{} ({}): missing {}'.format(a.get('Name', ''), a['Id'], ', '.join(gaps)))
            if ok == 0 and errors:
                # Trusted access for AWS Account Management not enabled (or no
                # permission): every further call would fail the same way.
                break

        if missing:
            msg = '{} of {} member account(s) missing alternate contacts:<br>{}'.format(
                len(missing), len(members), self._detail(missing))
            if errors:
                msg += '<br>Unable to read {} contact(s)'.format(len(errors))
            self.results[key] = [-1, msg]
        elif errors:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(errors[0].split(': ')[-1])]
        else:
            self.results[key] = [1, 'All {} member account(s) have SECURITY, BILLING and OPERATIONS contacts'.format(len(members))]

    def _checkOrgNoResourceControlPolicies(self):
        key = 'orgNoResourceControlPolicies'
        if not self._orgPrecondition(key, True):
            return
        pols = self._policyGate(key, RCP, [-1, 'Resource control policy type is not enabled on the organization root'])
        if pols is None:
            return
        attached = self._customerAttached(pols)
        if not attached:
            self.results[key] = [-1, 'No RCP other than RCPFullAWSAccess is attached']
            return
        perimeter, unparsed = [], []
        for p in attached:
            if p['Content'] is None:
                unparsed.append(p['Name'])
                continue
            for s in statements(p['Content']):
                if s.get('Effect') == 'Deny' and any(k in self.RCP_PERIMETER_KEYS for (_, k) in conditionKeys(s)):
                    perimeter.append(p)
                    break
        if perimeter:
            self.results[key] = [1, 'Org data-perimeter RCP(s) attached: {}'.format('; '.join(
                '{} -> {}'.format(p['Name'], ', '.join(self._targetLabel(t) for t in p['Targets'][:5])) for p in perimeter))]
        elif unparsed:
            self.results[key] = [0, 'Unable to evaluate (unparseable RCP content: {})'.format(', '.join(unparsed))]
        else:
            self.results[key] = [-1, 'Customer RCP(s) attached ({}) but none Deny on aws:PrincipalOrgID / aws:ResourceOrgID / aws:SourceOrgID'.format(
                ', '.join(p['Name'] for p in attached))]

    def _checkOrgNoTagPolicy(self):
        key = 'orgNoTagPolicy'
        if not self._orgPrecondition(key, True):
            return
        pols = self._policyGate(key, TAG, [-1, 'Tag policy type is not enabled on the organization root'])
        if pols is None:
            return
        attached = self._customerAttached(pols)
        if not attached:
            self.results[key] = [-1, 'No tag policy is attached to the root, any OU or any account']
            return
        classKeys = []
        for p in attached:
            tags = p['Content'].get('tags', {}) if isinstance(p['Content'], dict) else {}
            for name, spec in (tags.items() if isinstance(tags, dict) else []):
                tagKey = name
                if isinstance(spec, dict) and isinstance(spec.get('tag_key'), dict):
                    tagKey = spec['tag_key'].get('@@assign', name)
                if any(w in str(tagKey).lower() for w in self.CLASSIFICATION_KEYWORDS):
                    classKeys.append('{} ({})'.format(tagKey, p['Name']))
        detail = 'data-classification tag key(s): {}'.format(', '.join(classKeys)) if classKeys \
            else 'no tag policy defines a data-classification-like tag key'
        self.results[key] = [1, '{} tag policy(ies) attached ({}); {}'.format(
            len(attached), ', '.join(p['Name'] for p in attached), detail)]

    def _checkRootCentralizedAccessNotEnabled(self):
        key = 'rootCentralizedAccessNotEnabled'
        if not self._orgPrecondition(key, True):
            return
        try:
            enabled = self.iamClient.list_organizations_features().get('EnabledFeatures', []) or []
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code == 'ServiceAccessNotEnabledException' and self.orgData.isManagementAccount():
                self.results[key] = [-1, 'Trusted access for IAM is not enabled in AWS Organizations; centralized root access is off']
            elif code in ('AccountNotManagementOrDelegatedAdministratorException', 'AccessDenied', 'AccessDeniedException') \
                    and not self.orgData.isManagementAccount():
                self.results[key] = [0, 'Not evaluable from member account']
            elif code == 'OrganizationNotInAllFeaturesModeException':
                self.results[key] = [0, 'Not applicable: organization does not use All Features (see orgNotAllFeatures)']
            else:
                self.results[key] = [0, 'Unable to evaluate ({})'.format(code)]
            return
        lacking = [f for f in ('RootCredentialsManagement', 'RootSessions') if f not in enabled]
        if lacking:
            self.results[key] = [-1, 'Centralized root access feature(s) not enabled: {}'.format(', '.join(lacking))]
        else:
            self.results[key] = [1, 'RootCredentialsManagement and RootSessions are enabled']

    def _checkScpNoBackupTamperProtection(self):
        key = 'scpNoBackupTamperProtection'
        if not self._orgPrecondition(key, True, 'Not applicable: SCPs require All Features (see orgNotAllFeatures)'):
            return
        pols = self._policyGate(key, SCP, [0, 'Not applicable: SCPs are not enabled (see SCPEnabled)'])
        if pols is None:
            return
        covered, protecting, unparsed = set(), set(), []
        for p in self._customerAttached(pols):
            if p['Content'] is None:
                unparsed.append(p['Name'])
                continue
            for s in statements(p['Content']):
                for a in self.BACKUP_TAMPER_ACTIONS:
                    if denyCoversAction(s, a):
                        covered.add(a)
                        protecting.add(p['Name'])
        uncovered = [a for a in self.BACKUP_TAMPER_ACTIONS if a not in covered]
        if not uncovered:
            self.results[key] = [1, 'Attached SCP(s) deny backup tampering actions: {}'.format(', '.join(sorted(protecting)))]
        elif unparsed:
            self.results[key] = [0, 'Unable to evaluate (unparseable SCP content: {})'.format(', '.join(unparsed))]
        else:
            self.results[key] = [-1, 'No attached SCP denies: {}'.format(', '.join(uncovered))]

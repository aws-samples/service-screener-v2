import botocore
from botocore.config import Config as bConfig

import json
from datetime import datetime, timedelta
from dateutil.tz import tzlocal

from utils.Config import Config
from utils.Tools import _warn, _pr
from .IamCommon import IamCommon
 
class IamAccount(IamCommon):
    PASSWORD_POLICY_MIN_SCORE = 4
    ROOT_LOGIN_MAX_COUNT = 3
    
    def __init__(self, none, awsClients, users, roles, ssBoto):
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

        # Cache for customer managed policies (populated lazily)
        self._customerPoliciesCache = None
        self._policyDocumentsCache = {}

        # Check if AWS Organization is enabled
        try:
            resp = self.orgClient.describe_organization()
            self.organizationIsEnabled = True
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code'] 

        
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
    
    def _preloadPolicyDocuments(self):
        """Preload all customer managed policy documents into cache"""
        for policy in self._getCustomerPolicies():
            arn = policy['Arn']
            vid = policy['DefaultVersionId']
            key = f"{arn}:{vid}"
            if key not in self._policyDocumentsCache:
                try:
                    resp = self.iamClient.get_policy_version(PolicyArn=arn, VersionId=vid)
                    self._policyDocumentsCache[key] = resp['PolicyVersion']['Document']
                except botocore.exceptions.ClientError:
                    pass
    
    def _getPolicyDocument(self, policyArn, versionId):
        """Cached fetch of policy document by ARN and version"""
        key = f"{policyArn}:{versionId}"
        if key not in self._policyDocumentsCache:
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

    def _checkSCPEnabled(self):
        # Run this check only when AWS Organization is activated in the account
        if self.organizationIsEnabled == True:
            try:
                # Get organization root ID
                roots = self.orgClient.list_roots()
                root_id = roots['Roots'][0]['Id']
                
                policies = self.orgClient.list_policies_for_target(
                    TargetId=root_id,
                    Filter='SERVICE_CONTROL_POLICY'
                )
                
                # If no SCPs are attached, add to results
                if len(policies.get('Policies', [])) == 0:
                    self.results['SCPEnabled'] = [-1, '']
                                    
            except botocore.exceptions.ClientError as e:
                ecode = e.response['Error']['Code']
    
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
            
            self._preloadPolicyDocuments()
            
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
            
            def get_entity_policies(entity_type, entity_name):
                """Get all policy documents for a role or user using cached lookups"""
                import json as _json
                docs = []
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
                
                if has_iam_management_permissions(get_entity_policies('role', role_name)):
                    entities_without_boundaries.append(f"Role: {role_name}")
            
            # Check IAM users
            try:
                paginator = self.iamClient.get_paginator('list_users')
                for page in paginator.paginate():
                    for user in page.get('Users', []):
                        user_name = user.get('UserName', '')
                        if user.get('PermissionsBoundary'):
                            continue
                        
                        if has_admin_name_pattern(user_name):
                            entities_without_boundaries.append(f"User: {user_name}")
                            continue
                        
                        if has_iam_management_permissions(get_entity_policies('user', user_name)):
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

    def _checkScpBestPractices(self):
        """
        Validate Service Control Policy (SCP) content against best practices.
        
        This check analyzes SCPs in AWS Organizations to ensure they follow security
        best practices including:
        - Denying root user actions to prevent use of root credentials
        - Restricting access to specific AWS regions
        - Preventing privilege escalation through IAM actions
        
        Only runs when AWS Organizations is enabled. If Organizations is not enabled,
        the check is skipped.
        
        Validates Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 4.2, 4.3, 5.1
        """
        # Skip check if AWS Organizations is not enabled
        if not self.organizationIsEnabled:
            return
        
        try:
            from utils.Policy import Policy
            
            scps_with_issues = []
            
            # List all Service Control Policies
            try:
                paginator = self.orgClient.get_paginator('list_policies')
                
                for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
                    for policy in page.get('Policies', []):
                        policy_name = policy['Name']
                        policy_id = policy['Id']
                        
                        # Skip AWS managed default policies
                        if policy.get('AwsManaged', False):
                            continue
                        
                        try:
                            # Get the policy document
                            policy_detail = self.orgClient.describe_policy(PolicyId=policy_id)
                            policy_content = policy_detail['Policy']['Content']
                            
                            # Parse the policy document (it's a JSON string)
                            import json
                            policy_document = json.loads(policy_content)
                            
                            # Create Policy object and validate
                            policy_obj = Policy(policy_document)
                            validation_results = policy_obj.validateScpBestPractices()
                            
                            # Check which best practices are missing
                            missing_practices = []
                            if not validation_results['denyRoot']:
                                missing_practices.append('Missing root user denial')
                            if not validation_results['restrictRegions']:
                                missing_practices.append('Missing region restrictions')
                            if not validation_results['preventPrivEscalation']:
                                missing_practices.append('Missing privilege escalation prevention')
                            
                            # If any best practices are missing, add to issues list
                            if missing_practices:
                                issue_detail = f"{policy_name}: {', '.join(missing_practices)}"
                                scps_with_issues.append(issue_detail)
                        
                        except botocore.exceptions.ClientError as e:
                            ecode = e.response['Error']['Code']
                            print(f'Error getting policy details for {policy_name}: {ecode}')
                            continue
                        except json.JSONDecodeError as e:
                            print(f'Error parsing policy document for {policy_name}: {e}')
                            continue
            
            except botocore.exceptions.ClientError as e:
                ecode = e.response['Error']['Code']
                if ecode == 'AccessDeniedException':
                    print(f'Access denied when listing SCPs: {ecode}')
                    return
                else:
                    print(f'Error listing SCPs: {ecode}')
                    return
            
            # Store results if any SCPs have issues
            if scps_with_issues:
                self.results['scpBestPractices'] = [
                    len(scps_with_issues),
                    '<br>'.join(scps_with_issues)
                ]
        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(f'Error checking SCP best practices: {ecode}')

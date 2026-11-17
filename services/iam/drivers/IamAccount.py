import botocore
from botocore.config import Config as bConfig

import json
import re
from datetime import datetime, timedelta
from dateutil.tz import tzlocal

from utils.Config import Config
from utils.Tools import _warn, _pr
from .IamCommon import IamCommon
from . import IamPolicyHelpers
from . import IamX509
 
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
        self.healthClient = awsClients.get('healthClient')
        
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
        self.orgInfo = None
        try:
            resp = self.orgClient.describe_organization()
            self.organizationIsEnabled = True
            self.orgInfo = resp.get('Organization', {})
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
        
            # An empty 'Budgets' list means no budget is configured.
            if resp.get('Budgets'):
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

    SERVER_CERT_EXPIRY_WARN_DAYS = 30

    def _checkIamServerCertificates(self):
        """IAM server certificates are renewed manually: flag expired ones and
        ones expiring within SERVER_CERT_EXPIRY_WARN_DAYS; any other IAM
        server certificate is informational (prefer ACM)."""
        certs = []
        try:
            paginator = self.iamClient.get_paginator('list_server_certificates')
            for page in paginator.paginate():
                certs.extend(page.get('ServerCertificateMetadataList', []))
        except botocore.exceptions.ClientError as e:
            self.results['iamServerCertificates'] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
            return

        if not certs:
            self.results['iamServerCertificates'] = [1, 'No IAM server certificates']
            return

        now = datetime.now(tzlocal())
        expired, expiring, others = [], [], []
        for cert in certs:
            name = cert.get('ServerCertificateName', cert.get('Arn', '?'))
            exp = cert.get('Expiration')
            if exp is None:
                others.append('{} (no expiration date)'.format(name))
                continue
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=tzlocal())
            days = (exp - now).days
            if exp <= now:
                expired.append('{} (expired {})'.format(name, exp.strftime('%Y-%m-%d')))
            elif days < self.SERVER_CERT_EXPIRY_WARN_DAYS:
                expiring.append('{} (expires in {} days)'.format(name, days))
            else:
                others.append('{} (expires {})'.format(name, exp.strftime('%Y-%m-%d')))

        if expired or expiring:
            self.results['iamServerCertificates'] = [-1, '<br>'.join(expired + expiring)]
        else:
            self.results['iamServerCertificates'] = [0, 'IAM server certificate(s) need manual renewal; consider ACM: ' + '<br>'.join(others)]

    def _checkBroadSecretReadAccess(self):
        """Customer managed (attached) or inline identity policies that allow
        reading every secret / SSM parameter (Resource "*" or an ARN wildcard
        covering all secrets/parameters, without a resource-tag or secret-ID
        condition). Full-administrator statements (Action "*") are left to the
        administrator-access checks."""
        if not self._authDetails:
            self.results['broadSecretReadAccess'] = [0, 'Unable to evaluate (authorization details not available)']
            return

        offenders = []

        for policy in self._authDetails.get('policies', []):
            arn = policy.get('Arn', '')
            if ':iam::aws:policy/' in arn:
                continue
            if policy.get('AttachmentCount', 0) == 0:
                continue
            doc = self._policyDocumentMap.get(arn)
            if doc is None:
                for ver in policy.get('PolicyVersionList', []):
                    if ver.get('IsDefaultVersion'):
                        doc = ver.get('Document')
            actions = IamPolicyHelpers.broadSecretReadActions(doc)
            if actions:
                offenders.append('managed policy {} ({})'.format(policy.get('PolicyName', arn), ', '.join(actions)))

        inlineSources = (
            ('users', 'UserName', 'UserPolicyList', 'user'),
            ('groups', 'GroupName', 'GroupPolicyList', 'group'),
            ('roles', 'RoleName', 'RolePolicyList', 'role'),
        )
        for key, nameField, listField, label in inlineSources:
            for entity in self._authDetails.get(key, []):
                if key == 'roles' and str(entity.get('Path', '')).startswith('/aws-service-role/'):
                    continue
                for p in entity.get(listField, []) or []:
                    actions = IamPolicyHelpers.broadSecretReadActions(p.get('PolicyDocument'))
                    if actions:
                        offenders.append('{} {} inline policy {} ({})'.format(
                            label, entity.get(nameField, '?'), p.get('PolicyName', '?'), ', '.join(actions)))

        if offenders:
            self.results['broadSecretReadAccess'] = [-1, '<br>'.join(offenders)]
        else:
            self.results['broadSecretReadAccess'] = [1, 'No identity policy grants secret reads on all resources']

    def _isOrgManagementAccount(self):
        if not self.organizationIsEnabled or not self.orgInfo:
            return False
        account = (Config.get('stsInfo', {}) or {}).get('Account')
        return bool(account) and account == self.orgInfo.get('MasterAccountId')

    def _controlTowerClient(self, region):
        return self.ssBoto.client('controltower', config=bConfig(region_name=region))

    def _checkControlTowerLandingZoneDrift(self):
        """AWS Control Tower landing zone (and its enabled controls) must be in
        sync. Only evaluable from the Organizations management account (where
        Control Tower runs). No landing zone is a design choice - INFO only."""
        if not self.organizationIsEnabled:
            self.results['controlTowerLandingZoneDrift'] = [0, 'No AWS Organization - AWS Control Tower not in use']
            return
        if not self._isOrgManagementAccount():
            self.results['controlTowerLandingZoneDrift'] = [0, 'Not evaluable from member account']
            return

        regions = [r for r in (Config.get('REGIONS_SELECTED') or []) if r != 'GLOBAL'] or ['us-east-1']
        landingZoneArn = None
        homeClient = None
        errors = []
        for region in regions:
            client = self._controlTowerClient(region)
            try:
                arns = []
                paginator = client.get_paginator('list_landing_zones')
                for page in paginator.paginate():
                    arns.extend(lz.get('arn') for lz in page.get('landingZones', []) if lz.get('arn'))
            except botocore.exceptions.ClientError as e:
                errors.append('{}: {}'.format(region, e.response['Error']['Code']))
                continue
            except botocore.exceptions.EndpointConnectionError:
                continue
            if arns:
                landingZoneArn = arns[0]
                parts = landingZoneArn.split(':')
                lzRegion = parts[3] if len(parts) > 3 and parts[3] else region
                homeClient = client if lzRegion == region else self._controlTowerClient(lzRegion)
                break

        if landingZoneArn is None:
            if errors:
                self.results['controlTowerLandingZoneDrift'] = [0, 'Unable to evaluate ({})'.format(', '.join(errors))]
            else:
                self.results['controlTowerLandingZoneDrift'] = [0, 'No AWS Control Tower landing zone found in scanned region(s): {}'.format(', '.join(regions))]
            return

        issues = []
        try:
            lz = homeClient.get_landing_zone(landingZoneIdentifier=landingZoneArn).get('landingZone', {})
        except botocore.exceptions.ClientError as e:
            self.results['controlTowerLandingZoneDrift'] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
            return
        status = lz.get('status')
        drift = (lz.get('driftStatus') or {}).get('status')
        if status == 'FAILED':
            issues.append('Landing zone status FAILED')
        if drift == 'DRIFTED':
            issues.append('Landing zone drifted')

        controlNotes = []
        for flt, label in (({'statuses': ['FAILED']}, 'failed'), ({'driftStatuses': ['DRIFTED']}, 'drifted')):
            try:
                bad = []
                paginator = homeClient.get_paginator('list_enabled_controls')
                for page in paginator.paginate(filter=flt):
                    bad.extend(page.get('enabledControls', []))
            except botocore.exceptions.ClientError as e:
                controlNotes.append('{} controls: unable to evaluate ({})'.format(label, e.response['Error']['Code']))
                continue
            if bad:
                names = sorted({str(c.get('controlIdentifier', '?')).split('/')[-1] for c in bad})
                issues.append('{} enabled control(s) {}: {}'.format(
                    len(bad), label, ', '.join(names[:10]) + (' ...' if len(names) > 10 else '')))

        if issues:
            self.results['controlTowerLandingZoneDrift'] = [-1, '<br>'.join(issues + controlNotes)]
        elif controlNotes:
            self.results['controlTowerLandingZoneDrift'] = [0, 'Landing zone {} / {}; {}'.format(status, drift, '; '.join(controlNotes))]
        else:
            self.results['controlTowerLandingZoneDrift'] = [1, 'Landing zone {} / {}'.format(status, drift or 'drift status n/a')]

    # Scheduled-change event type codes that announce end of life / end of
    # support / deprecation (no more security patches). Other scheduled
    # changes (maintenance windows, instance retirement) are not security
    # findings and are ignored here.
    HEALTH_LIFECYCLE_EVENT_RE = re.compile(
        r'LIFECYCLE|END_OF_(LIFE|SUPPORT|STANDARD_SUPPORT|EXTENDED_SUPPORT)|(^|_)EOL(_|$)|DEPRECAT', re.I)

    def _healthClientForPartition(self):
        if self.healthClient is not None:
            return self.healthClient
        arn = (Config.get('stsInfo', {}) or {}).get('Arn', '')
        parts = arn.split(':')
        partition = parts[1] if len(parts) > 1 and parts[1] else 'aws'
        region = {'aws-cn': 'cn-northwest-1', 'aws-us-gov': 'us-gov-west-1'}.get(partition, 'us-east-1')
        self.healthClient = self.ssBoto.client('health', config=bConfig(region_name=region))
        return self.healthClient

    def _checkHealthLifecycleEventsOpen(self):
        """Open or upcoming AWS Health scheduled-change events announcing end of
        life / end of support of engines, runtimes or platforms in use."""
        client = self._healthClientForPartition()
        events = []
        try:
            paginator = client.get_paginator('describe_events')
            for page in paginator.paginate(filter={
                'eventTypeCategories': ['scheduledChange'],
                'eventStatusCodes': ['open', 'upcoming'],
            }):
                events.extend(page.get('events', []))
        except botocore.exceptions.ClientError as e:
            self.results['healthLifecycleEventsOpen'] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
            return

        lifecycle = [ev for ev in events if self.HEALTH_LIFECYCLE_EVENT_RE.search(ev.get('eventTypeCode') or '')]
        if not lifecycle:
            self.results['healthLifecycleEventsOpen'] = [1, 'No open/upcoming lifecycle events ({} other scheduled change(s) ignored)'.format(len(events))]
            return

        summary = {}
        for ev in lifecycle:
            k = '{} ({})'.format(ev.get('eventTypeCode', '?'), ev.get('region', 'global'))
            summary[k] = summary.get(k, 0) + 1
        self.results['healthLifecycleEventsOpen'] = [-1, '<br>'.join('{} x{}'.format(k, v) for k, v in sorted(summary.items()))]

    # ------------------------------------------------------------------ #
    # WAFS2027 identity checks (chunk 2)
    # ------------------------------------------------------------------ #
    def _scanRegions(self):
        return [r for r in (Config.get('REGIONS_SELECTED') or []) if r != 'GLOBAL'] or ['us-east-1']

    def _regionalClient(self, service, region):
        return self.ssBoto.client(service, config=bConfig(region_name=region))

    def _checkHealthOrgViewDisabled(self):
        """AWS Health organizational view aggregates Health events of every
        member account. Only the management account (or a Health delegated
        administrator, which can only exist once the view is enabled) can
        read the status."""
        if not self.organizationIsEnabled:
            self.results['healthOrgViewDisabled'] = [0, 'No AWS Organization - organizational view not applicable']
            return
        isMgmt = self._isOrgManagementAccount()
        try:
            resp = self._healthClientForPartition().describe_health_service_status_for_organization()
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if not isMgmt:
                self.results['healthOrgViewDisabled'] = [0, 'Not evaluable from member account']
            else:
                self.results['healthOrgViewDisabled'] = [0, 'Unable to evaluate ({})'.format(code)]
            return
        status = resp.get('healthServiceAccessStatusForOrganization')
        if status == 'ENABLED':
            self.results['healthOrgViewDisabled'] = [1, 'AWS Health organizational view enabled']
        elif not isMgmt:
            # A member account (not a delegated admin) cannot see the real status.
            self.results['healthOrgViewDisabled'] = [0, 'Not evaluable from member account']
        elif status is None:
            self.results['healthOrgViewDisabled'] = [0, 'Unable to evaluate (no status returned)']
        else:
            self.results['healthOrgViewDisabled'] = [-1, 'AWS Health organizational view is {}'.format(status)]

    ROOT_MFA_SERIAL_SUFFIX = ':mfa/root-account-mfa-device'

    def _checkRootVirtualMfaOnly(self):
        """Root user MFA should be a FIDO2 security key / passkey or hardware
        TOTP token rather than a virtual (authenticator app) device."""
        try:
            summary = self.iamClient.get_account_summary().get('SummaryMap', {})
        except botocore.exceptions.ClientError as e:
            self.results['rootVirtualMfaOnly'] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
            return
        if summary.get('AccountMFAEnabled') != 1:
            # No root MFA at all is reported by rootMfaActive.
            self.results['rootVirtualMfaOnly'] = [0, 'Root user MFA not enabled (see rootMfaActive)']
            return

        rootDevices = []
        try:
            paginator = self.iamClient.get_paginator('list_virtual_mfa_devices')
            for page in paginator.paginate(AssignmentStatus='Assigned'):
                for dev in page.get('VirtualMFADevices', []):
                    serial = dev.get('SerialNumber', '')
                    userArn = (dev.get('User') or {}).get('Arn', '')
                    if userArn.endswith(':root') or serial.endswith(self.ROOT_MFA_SERIAL_SUFFIX):
                        rootDevices.append(serial)
        except botocore.exceptions.ClientError as e:
            self.results['rootVirtualMfaOnly'] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
            return

        if rootDevices:
            self.results['rootVirtualMfaOnly'] = [-1, 'Root user has virtual MFA device(s): {}'.format(', '.join(rootDevices))]
        else:
            self.results['rootVirtualMfaOnly'] = [1, 'Root user MFA is not a virtual device']

    ROLES_ANYWHERE_EXPIRY_WARN_DAYS = 30

    def _checkRolesAnywhereTrustAnchorCertExpiring(self):
        """Enabled IAM Roles Anywhere trust anchors whose CA certificate has
        expired or expires within ROLES_ANYWHERE_EXPIRY_WARN_DAYS, and
        imported CRLs that are disabled (revoked certificates still accepted).
        Disabled trust anchors cannot authenticate anyone and are only noted."""
        now = datetime.now(tzlocal())
        issues, notes, errors = [], [], []
        anchorCount = 0
        pcaClients = {}

        for region in self._scanRegions():
            client = self._regionalClient('rolesanywhere', region)
            try:
                anchors = []
                for page in client.get_paginator('list_trust_anchors').paginate():
                    anchors.extend(page.get('trustAnchors', []))
                crls = []
                for page in client.get_paginator('list_crls').paginate():
                    crls.extend(page.get('crls', []))
            except botocore.exceptions.ClientError as e:
                errors.append('{}: {}'.format(region, e.response['Error']['Code']))
                continue
            except botocore.exceptions.EndpointConnectionError:
                continue

            enabledArns = set()
            for ta in anchors:
                anchorCount += 1
                name = '{} ({})'.format(ta.get('name') or ta.get('trustAnchorId', '?'), region)
                if ta.get('enabled') is False:
                    notes.append('{}: trust anchor disabled'.format(name))
                    continue
                enabledArns.add(ta.get('trustAnchorArn'))
                source = ta.get('source') or {}
                stype = source.get('sourceType')
                data = source.get('sourceData') or {}
                if stype == 'CERTIFICATE_BUNDLE':
                    certs = IamX509.pemCertificates(data.get('x509CertificateData'))
                    if not certs:
                        notes.append('{}: no certificate found in bundle'.format(name))
                    for idx, (_nb, notAfter, err) in enumerate(certs):
                        label = '{} certificate #{}'.format(name, idx + 1)
                        if err:
                            notes.append('{}: unable to evaluate ({})'.format(label, err))
                            continue
                        self._raExpiry(label, notAfter, now, issues)
                elif stype == 'AWS_ACM_PCA':
                    pcaArn = data.get('acmPcaArn', '')
                    parts = pcaArn.split(':')
                    pcaRegion = parts[3] if len(parts) > 3 and parts[3] else region
                    if pcaRegion not in pcaClients:
                        pcaClients[pcaRegion] = self._regionalClient('acm-pca', pcaRegion)
                    try:
                        ca = pcaClients[pcaRegion].describe_certificate_authority(
                            CertificateAuthorityArn=pcaArn).get('CertificateAuthority', {})
                    except botocore.exceptions.ClientError as e:
                        notes.append('{}: unable to evaluate ACM PCA {} ({})'.format(name, pcaArn, e.response['Error']['Code']))
                        continue
                    caStatus = ca.get('Status')
                    if caStatus in ('EXPIRED', 'DELETED'):
                        issues.append('{}: ACM PCA {}'.format(name, caStatus))
                    elif ca.get('NotAfter') is not None:
                        self._raExpiry('{} ACM PCA'.format(name), ca['NotAfter'], now, issues)
                    else:
                        notes.append('{}: ACM PCA status {} (no validity date)'.format(name, caStatus))
                else:
                    notes.append('{}: source {} not evaluated'.format(name, stype))

            for crl in crls:
                if crl.get('enabled') is False and crl.get('trustAnchorArn') in enabledArns:
                    issues.append('CRL {} ({}) is disabled - revoked certificates are still accepted'.format(
                        crl.get('name') or crl.get('crlId', '?'), region))

        key = 'rolesAnywhereTrustAnchorCertExpiring'
        if issues:
            self.results[key] = [-1, '<br>'.join(issues + notes)]
        elif errors and anchorCount == 0:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(', '.join(errors))]
        elif anchorCount == 0:
            self.results[key] = [1, 'No IAM Roles Anywhere trust anchors in scanned region(s)']
        elif any('unable to evaluate' in n for n in notes) or errors:
            self.results[key] = [0, 'Unable to evaluate all trust anchors: ' + '<br>'.join(notes + errors)]
        else:
            self.results[key] = [1, '{} trust anchor(s) valid for more than {} days{}'.format(
                anchorCount, self.ROLES_ANYWHERE_EXPIRY_WARN_DAYS, ('<br>' + '<br>'.join(notes)) if notes else '')]

    def _raExpiry(self, label, notAfter, now, issues):
        if notAfter.tzinfo is None:
            notAfter = notAfter.replace(tzinfo=tzlocal())
        if notAfter <= now:
            issues.append('{}: expired {}'.format(label, notAfter.strftime('%Y-%m-%d')))
        elif (notAfter - now).days < self.ROLES_ANYWHERE_EXPIRY_WARN_DAYS:
            issues.append('{}: expires in {} days'.format(label, (notAfter - now).days))

    def _roleIdentityPolicyDocs(self, role):
        """(docs, unreadable) for a role from the authorization details."""
        docs = [p.get('PolicyDocument') for p in role.get('RolePolicyList', []) or []]
        unreadable = []
        for p in role.get('AttachedManagedPolicies', []) or []:
            doc = self._managedPolicyDoc(p.get('PolicyArn'))
            if doc is None:
                unreadable.append(p.get('PolicyName') or p.get('PolicyArn'))
            else:
                docs.append(doc)
        return docs, unreadable

    def _managedPolicyDoc(self, arn):
        if not arn:
            return None
        if arn in self._policyDocumentMap:
            return self._policyDocumentMap[arn]
        try:
            ver = self.iamClient.get_policy(PolicyArn=arn)['Policy']['DefaultVersionId']
            doc = self._getPolicyDocument(arn, ver)
        except (botocore.exceptions.ClientError, KeyError):
            return None
        self._policyDocumentMap[arn] = doc
        return doc

    def _checkWorkloadRoleCanEscalate(self):
        """Roles assumable by a workload service (Lambda, ECS tasks, EC2,
        CodeBuild, Step Functions) that can modify IAM policies / trust or
        pass any role, i.e. code running in the workload can escalate to
        administrator. Full-administrator roles are left to FullAdminAccess /
        InlinePolicyFullAdminAccess."""
        key = 'workloadRoleCanEscalate'
        if not self._authDetails:
            self.results[key] = [0, 'Unable to evaluate (authorization details not available)']
            return

        offenders, unknown = [], []
        for role in self._authDetails.get('roles', []):
            if str(role.get('Path', '')).startswith('/aws-service-role/'):
                continue
            services = IamPolicyHelpers.workloadServicesTrusted(role.get('AssumeRolePolicyDocument'))
            if not services:
                continue
            name = role.get('RoleName', '?')
            docs, unreadable = self._roleIdentityPolicyDocs(role)
            if any(IamPolicyHelpers.isFullAdmin(d) for d in docs):
                continue
            actions = IamPolicyHelpers.escalationActions(docs)

            boundaryArn = (role.get('PermissionsBoundary') or {}).get('PermissionsBoundaryArn')
            if actions and boundaryArn:
                bdoc = self._managedPolicyDoc(boundaryArn)
                if bdoc is None:
                    unknown.append('{} (permissions boundary not readable)'.format(name))
                    continue
                permitted = set(IamPolicyHelpers.escalationActions([bdoc], ignoreResource=True))
                actions = [a for a in actions if a in permitted]

            if actions:
                offenders.append('{} [{}]: {}'.format(name, ', '.join(services), ', '.join(actions)))
            elif unreadable:
                unknown.append('{} (policy not readable: {})'.format(name, ', '.join(unreadable)))

        if offenders:
            self.results[key] = [-1, '<br>'.join(offenders)]
        elif unknown:
            self.results[key] = [0, 'Unable to evaluate: ' + '<br>'.join(unknown)]
        else:
            self.results[key] = [1, 'No workload role can modify IAM policies or pass any role']

    # Tag keys commonly used to label the deployment environment (compared lower-case).
    ENVIRONMENT_TAG_KEYS = frozenset((
        'environment', 'env', 'stage', 'environment-type', 'environmenttype', 'environment_type',
        'env-type', 'envtype', 'env_type', 'environment-name', 'environmentname', 'environment_name',
        'aws:environment'))
    _PROD_TOKENS = frozenset(('prod', 'production', 'prd', 'prdn', 'live'))
    _NONPROD_TOKENS = frozenset((
        'dev', 'develop', 'development', 'test', 'testing', 'tst', 'qa', 'uat', 'sit', 'staging', 'stage',
        'stg', 'sandbox', 'sbx', 'nonprod', 'nonproduction', 'notprod', 'preprod', 'preproduction', 'demo', 'poc',
        'lab', 'perf', 'int', 'integration', 'beta', 'alpha', 'gamma'))

    @classmethod
    def classifyEnvironmentValue(cls, value):
        """'prod', 'nonprod' or None for an environment tag value."""
        tokens = [t for t in re.split(r'[^a-z0-9]+', str(value).lower()) if t]
        if any(t in cls._NONPROD_TOKENS for t in tokens):
            return 'nonprod'
        for i, t in enumerate(tokens):
            if t in cls._PROD_TOKENS:
                # "non-prod", "pre prod", "not_prod"
                return 'nonprod' if i > 0 and tokens[i - 1] in ('non', 'pre', 'not') else 'prod'
        return None

    def _checkAccountMixesEnvironments(self):
        """Resources tagged as production and as non-production in the same
        account: environments should be separated by account."""
        key = 'accountMixesEnvironments'
        seen = {'prod': set(), 'nonprod': set()}
        errors, evaluated = [], 0
        for region in self._scanRegions():
            client = self._regionalClient('resourcegroupstaggingapi', region)
            try:
                keys = []
                for page in client.get_paginator('get_tag_keys').paginate():
                    keys.extend(page.get('TagKeys', []))
                for tagKey in keys:
                    if str(tagKey).lower() not in self.ENVIRONMENT_TAG_KEYS:
                        continue
                    for page in client.get_paginator('get_tag_values').paginate(Key=tagKey):
                        for value in page.get('TagValues', []):
                            cls = self.classifyEnvironmentValue(value)
                            if cls:
                                seen[cls].add('{}={}'.format(tagKey, value))
                evaluated += 1
            except botocore.exceptions.ClientError as e:
                errors.append('{}: {}'.format(region, e.response['Error']['Code']))
            except botocore.exceptions.EndpointConnectionError:
                continue

        if seen['prod'] and seen['nonprod']:
            self.results[key] = [-1, 'Production tags: {}<br>Non-production tags: {}'.format(
                ', '.join(sorted(seen['prod'])[:10]), ', '.join(sorted(seen['nonprod'])[:10]))]
        elif evaluated == 0 and errors:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(', '.join(errors))]
        elif errors:
            self.results[key] = [0, 'Unable to evaluate all regions ({})'.format(', '.join(errors))]
        else:
            found = sorted(seen['prod'] | seen['nonprod'])
            self.results[key] = [1, 'Single environment tagged: {}'.format(', '.join(found[:10])) if found
                                 else 'No environment tags found']

    def _checkAuditManagerNoActiveAssessment(self):
        """Audit Manager is enabled but no assessment is ACTIVE, so no evidence
        is being collected. Not using Audit Manager at all is informational
        (it is an optional, paid service)."""
        key = 'auditManagerNoActiveAssessment'
        enabled, withActive, errors = [], [], []
        for region in self._scanRegions():
            client = self._regionalClient('auditmanager', region)
            try:
                status = client.get_account_status().get('status')
                if status != 'ACTIVE':
                    continue
                enabled.append(region)
                token = None
                count = 0
                while True:
                    params = {'status': 'ACTIVE'}
                    if token:
                        params['nextToken'] = token
                    resp = client.list_assessments(**params)
                    count += len(resp.get('assessmentMetadata', []))
                    token = resp.get('nextToken')
                    if count or not token:
                        break
                if count:
                    withActive.append(region)
            except botocore.exceptions.ClientError as e:
                errors.append('{}: {}'.format(region, e.response['Error']['Code']))
            except botocore.exceptions.EndpointConnectionError:
                continue

        idle = [r for r in enabled if r not in withActive]
        if idle:
            self.results[key] = [-1, 'Audit Manager enabled without an active assessment in: {}'.format(', '.join(idle))]
        elif errors:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(', '.join(errors))]
        elif not enabled:
            self.results[key] = [0, 'Audit Manager not enabled in scanned region(s)']
        else:
            self.results[key] = [1, 'Active assessment(s) in: {}'.format(', '.join(withActive))]

    def _checkBudgetNoActions(self):
        """Budgets exist but none has a budget action (automatic IAM/SCP
        policy or instance stop when a threshold is crossed). Accounts with
        no budget at all are reported by enableCostBudget."""
        key = 'budgetNoActions'
        account = (Config.get('stsInfo', {}) or {}).get('Account')
        if not account:
            self.results[key] = [0, 'Unable to evaluate (account ID unknown)']
            return
        try:
            budgets = []
            for page in self.budgetClient.get_paginator('describe_budgets').paginate(AccountId=account):
                budgets.extend(page.get('Budgets', []))
            if not budgets:
                self.results[key] = [0, 'No budgets configured (see enableCostBudget)']
                return
            actions = []
            for page in self.budgetClient.get_paginator('describe_budget_actions_for_account').paginate(AccountId=account):
                actions.extend(page.get('Actions', []))
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
            return
        if actions:
            self.results[key] = [1, '{} budget action(s) configured'.format(len(actions))]
        else:
            self.results[key] = [-1, '{} budget(s), none with a budget action'.format(len(budgets))]

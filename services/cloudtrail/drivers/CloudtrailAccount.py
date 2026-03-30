import botocore

from utils.Config import Config
from services.Evaluator import Evaluator

class CloudtrailAccount(Evaluator):
    def __init__(self, ctClient, sizeofTrail):
        super().__init__()
        self.ctClient = ctClient
        self.sizeofTrail = sizeofTrail
        
        self._resourceName = 'General'

        self.init()
    
    ## For General Trail purpose
    def _checkHasOneTrailConfiguredCorrectly(self):
        if self.sizeofTrail == 0:
            self.results['NeedToEnableCloudTrail'] = [-1, '']
        
        if Config.get('CloudTrail_hasOneMultiRegion') == False:
            self.results['HasOneMultiRegionTrail'] = [-1, '']
            
        if Config.get('CloudTrail_hasGlobalServEnabled') == False:
            self.results['HasCoverGlobalServices'] = [-1, '']
            
        if Config.get('CloudTrail_hasManagementEventsCaptured') == False:
            self.results['HasManagementEventsCaptured'] = [-1, '']
        
        if Config.get('CloudTrail_hasDataEventsCaptured') == False:
            self.results['HasDataEventsCaptured'] = [-1, '']
            
        lists = Config.get('CloudTrail_listGlobalServEnabled')
        if len(lists) > 1:
            self.results['DuplicateGlobalTrail'] = [-1, '<br>'.join(lists)]

    def _checkGuardDutyIntegration(self):
        """
        Validates that Amazon GuardDuty is enabled for threat detection
        leveraging CloudTrail logs
        """
        try:
            import boto3
            gdClient = boto3.client('guardduty')
            
            # List all detectors in the region
            response = gdClient.list_detectors()
            detectorIds = response.get('DetectorIds', [])
            
            if len(detectorIds) == 0:
                self.results['GuardDutyIntegration'] = [-1, 'No GuardDuty detectors enabled']
                return
            
            # Check if at least one detector is active
            hasActiveDetector = False
            disabledDetectors = []
            
            for detectorId in detectorIds:
                detectorResponse = gdClient.get_detector(DetectorId=detectorId)
                status = detectorResponse.get('Status')
                
                if status == 'ENABLED':
                    hasActiveDetector = True
                    break
                elif status == 'DISABLED':
                    disabledDetectors.append(detectorId)
            
            # Only report if no active detectors found
            if not hasActiveDetector:
                if len(disabledDetectors) > 0:
                    self.results['GuardDutyIntegration'] = [0, f'GuardDuty detector {disabledDetectors[0]} is disabled']
                else:
                    self.results['GuardDutyIntegration'] = [-1, 'All GuardDuty detectors are disabled']
                
        except Exception as e:
            print(f'-- Unable to check GuardDuty integration: {str(e)}')
    
    def _checkSecurityHubIntegration(self):
        """
        Validates that AWS Security Hub is enabled for centralized
        security posture management and CloudTrail monitoring
        """
        try:
            import boto3
            import botocore
            shClient = boto3.client('securityhub')
            
            # Check if Security Hub is enabled
            try:
                response = shClient.describe_hub()
                hubArn = response.get('HubArn')
                
                if not hubArn:
                    self.results['SecurityHubIntegration'] = [-1, 'Security Hub not enabled']
                    return
                
                # Check if any standards are enabled
                standardsResponse = shClient.get_enabled_standards()
                enabledStandards = standardsResponse.get('StandardsSubscriptions', [])
                
                if len(enabledStandards) == 0:
                    self.results['SecurityHubIntegration'] = [0, 'Security Hub enabled but no standards subscribed']
                
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code in ['InvalidAccessException', 'ResourceNotFoundException']:
                    self.results['SecurityHubIntegration'] = [-1, 'Security Hub not enabled']
                else:
                    raise
                
        except Exception as e:
            print(f'-- Unable to check Security Hub integration: {str(e)}')
    
    def _checkIAMFullAccessRestriction(self):
        """
        Identifies IAM users and roles with AWSCloudTrail_FullAccess
        managed policy attached, recommending least privilege access
        """
        try:
            import boto3
            iamClient = boto3.client('iam')
            
            principalsWithFullAccess = []
            fullAccessPolicyArn = 'arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess'
            
            # Check IAM users
            usersPaginator = iamClient.get_paginator('list_users')
            for usersPage in usersPaginator.paginate():
                for user in usersPage.get('Users', []):
                    userName = user['UserName']
                    
                    # Get attached policies for user
                    policiesResponse = iamClient.list_attached_user_policies(UserName=userName)
                    for policy in policiesResponse.get('AttachedPolicies', []):
                        if policy['PolicyArn'] == fullAccessPolicyArn:
                            principalsWithFullAccess.append(f'User: {userName}')
                            break
            
            # Check IAM roles (exclude service-linked roles)
            rolesPaginator = iamClient.get_paginator('list_roles')
            for rolesPage in rolesPaginator.paginate():
                for role in rolesPage.get('Roles', []):
                    roleName = role['RoleName']
                    rolePath = role.get('Path', '/')
                    
                    # Skip service-linked roles
                    if rolePath.startswith('/aws-service-role/'):
                        continue
                    
                    # Get attached policies for role
                    policiesResponse = iamClient.list_attached_role_policies(RoleName=roleName)
                    for policy in policiesResponse.get('AttachedPolicies', []):
                        if policy['PolicyArn'] == fullAccessPolicyArn:
                            principalsWithFullAccess.append(f'Role: {roleName}')
                            break
            
            # Evaluate results
            count = len(principalsWithFullAccess)
            if count >= 5:
                self.results['IAMFullAccessRestriction'] = [-1, f'{count} principals with full access: {", ".join(principalsWithFullAccess[:5])}...']
            elif count > 0:
                self.results['IAMFullAccessRestriction'] = [0, f'{count} principals with full access: {", ".join(principalsWithFullAccess)}']
            
        except Exception as e:
            print(f'-- Unable to check IAM full access restriction: {str(e)}')
    
    def _checkOrganizationTrailEnabled(self):
        """
        Validates that organization trails are configured for centralized
        multi-account logging in AWS Organizations
        """
        try:
            import boto3
            
            # Check if account is in an organization
            try:
                orgClient = boto3.client('organizations')
                orgResponse = orgClient.describe_organization()
                organization = orgResponse.get('Organization')
                
                if not organization:
                    # Not in an organization, skip check
                    return
                
                # Check if this is the management account
                stsClient = boto3.client('sts')
                identity = stsClient.get_caller_identity()
                currentAccountId = identity['Account']
                managementAccountId = organization.get('MasterAccountId')
                
                if currentAccountId != managementAccountId:
                    # Member account, skip check (organization trails are managed by management account)
                    return
                
            except orgClient.exceptions.AWSOrganizationsNotInUseException:
                # Not in an organization, skip check
                return
            except Exception as e:
                if 'AccessDenied' in str(e):
                    # Cannot determine organization status, skip check
                    return
                raise
            
            # Check if any trail is an organization trail
            response = self.ctClient.describe_trails()
            trails = response.get('trailList', [])
            
            hasOrgTrail = False
            for trail in trails:
                if trail.get('IsOrganizationTrail', False):
                    hasOrgTrail = True
                    break
            
            if not hasOrgTrail:
                self.results['OrganizationTrailEnabled'] = [-1, 'No organization trail configured for AWS Organizations']
            
        except Exception as e:
            print(f'-- Unable to check organization trail: {str(e)}')

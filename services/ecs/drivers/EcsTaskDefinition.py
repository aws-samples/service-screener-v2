import boto3
import botocore
import re
import constants as _C
from services.Evaluator import Evaluator
from utils.Policy import Policy

class EcsTaskDefinition(Evaluator):

    def __init__(self, taskDefName, ecsClient, iamClient):
        super().__init__()
        self.taskDefName = taskDefName
        self.ecsClient = ecsClient
        self.iamClient = iamClient
        self.init()
    
    def _checkReadOnlyRootFileSystem(self):
        """
        Checks if ECS Task definition JSON (latest revision) has enabled readonlyRootFilesystem
        If ENABLED, readonlyRootFilesystem = TRUE
        Otherwise, if FALSE or did not specify the parameter, flag as DISABLED
        """
        try:
            response = self.ecsClient.describe_task_definition(
                taskDefinition = self.taskDefName,
            )

            containerDefJSON = response.get('taskDefinition').get('containerDefinitions')[0]

            if 'readonlyRootFilesystem' in containerDefJSON:
                readOnlyFlag = containerDefJSON['readonlyRootFilesystem']
                if readOnlyFlag is False:
                    self.results['ecsTaskDefinitionReadOnlyRootFilesystem'] = [-1, "Disabled"]
                    
            else:
                self.results['ecsTaskDefinitionReadOnlyRootFilesystem'] = [-1, "Disabled"]

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)

    def getIamRoleName(self, roleArn):
        match = re.match(r"arn:aws:iam::\d+:role/(.+)", roleArn)
        if match:
            return match.group(1)
        else:
            return None         

    def check_if_role_exist(self, roleName):
        try:
            self.iamClient.get_role(RoleName=roleName)
            return True
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            if ecode == 'NoSuchEntity':
                print(ecode, emsg)
                print("Skipping the check for IAM role(s) which does not exist...")
                return False

    def verifyIamRolePermissions(self, iamRoleName, check):
        """
        Verifies if the IAM Role have policies that are overly permissive.
        1 Role may have more than one policies (list)
        2 lists in this function - managedPolicyList and inlinePolicyList
        """
        iamManagedPolicyList = []
        # Get ManagedPolicies of an IAM Role
        try:
            paginator = self.iamClient.get_paginator('list_attached_role_policies')
            page_iterator = paginator.paginate(RoleName=iamRoleName)

            for page in page_iterator:
                iamManagedPolicyList.extend(page['AttachedPolicies'])

            # Check if there are any AdministratorAccess policy attached to the role
            for iamManagedPolicy in iamManagedPolicyList:
                if iamManagedPolicy.get('PolicyName') == "AdministratorAccess":
                    self.results[check] = [-1, "AdministratorAccess"]
        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)

        # Check for overpermissive inline policies
        # Get InlinePolicies of an IAM role
        iamInlinePolicyList = []
        try:
            paginator = self.iamClient.get_paginator('list_role_policies')
            page_iterator = paginator.paginate(RoleName=iamRoleName)
            for page in page_iterator:
                iamInlinePolicyList.extend(page['PolicyNames'])

            # Check each Inline Policy, based on Policy JSON document, is there any "*" being used for Service/Permissions
            for iamInlinePolicy in iamInlinePolicyList:
                policyDocument = self.iamClient.get_role_policy(
                    RoleName = iamRoleName,
                    PolicyName = iamInlinePolicy
                ).get('PolicyDocument')

                pObj = Policy(policyDocument)
                pObj.inspectAccess()

                if pObj.hasFullAccessToOneResource() is True:
                    self.results[check] = [-1, "Full Access to One Resource IAM Role Name: " + iamInlinePolicy]

                elif pObj.hasFullAccessAdmin() is True:
                    self.results[check] = [-1, "Full Admin Access IAM Role Name: " + iamInlinePolicy]


        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)

    def _checkTaskDefinitionTaskIamRole(self):
        try:
            taskDetails = self.ecsClient.describe_task_definition(
                taskDefinition = self.taskDefName
            ).get('taskDefinition')
            
            self.taskRoleArn = taskDetails.get('taskRoleArn')

            if self.taskRoleArn is None:
                self.results['ecsTaskDefinitionTaskIAMRole'] = [-1, "No task role defined"]
            
            else: #continue to check taskRole for the permissions
                # check if taskRole exists
                taskRoleName = self.getIamRoleName(self.taskRoleArn)
                if self.check_if_role_exist(taskRoleName):
                    self.verifyIamRolePermissions(taskRoleName,'ecsTaskDefinitionTaskIAMRole')

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
    
    def _checkTaskDefinitionTaskExecutionRole(self):
        try:
            taskDetails = self.ecsClient.describe_task_definition(
                taskDefinition = self.taskDefName
            ).get('taskDefinition')
            
            self.taskExecutionRoleArn = taskDetails.get('executionRoleArn')

            if self.taskExecutionRoleArn is None:
                self.results['ecsTaskDefinitionTaskExecutionIAMRole'] = [-1, "No task execution role defined"]
            
            else: #continue to check taskRole for the permissions
                # check if exists
                taskRoleName = self.getIamRoleName(self.taskExecutionRoleArn)
                if self.check_if_role_exist(taskRoleName):
                    self.verifyIamRolePermissions(taskRoleName,'ecsTaskDefinitionTaskExecutionIAMRole')

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)

    # def _checkTaskDefinitionIamRoles(self):
    #     """
    #     Checks that both the Task Execution and Task IAM roles are least privilege 
    #     and are restricted to specific resources where possible (avoid using "*" if possible)
    #     - ManagedPolicies - check whether AdministratorAccess policy is attached
    #     - InlinePolicies - check if "*" is used for Permissions OR Service in IAM policy document

    #     If there are no Task Roles or Task Execution Roles, flag as non-compliant
    #     """ 
    #     try:
    #         taskDetails = self.ecsClient.describe_task_definition(
    #             taskDefinition = self.taskDefName
    #         ).get('taskDefinition')
            
    #         self.taskRoleArn = taskDetails.get('taskRoleArn')
    #         self.taskExecutionRoleArn = taskDetails.get('executionRoleArn')

    #         # A task definition can be defined without roles, flag those as non-compliant
    #         if self.taskRoleArn is None:
    #             self.results['ecsTaskDefinitionIAMRoles'] = [-1, "No task role defined"]

    #         elif self.taskExecutionRoleArn is None:
    #             self.results['ecsTaskDefinitionIAMRoles'] = [-1, "No task execution role defined"]

    #         else:
    #             # check if the taskRole and taskExecutionRole is overly permissive
    #             taskRoleName = self.getIamRoleName(self.taskRoleArn)
    #             taskExecutionRoleName = self.getIamRoleName(self.taskExecutionRoleArn)

    #             print(taskRoleName)
    #             print(taskExecutionRoleName)

    #             # check if the IAM role exist (might be deleted sometimes but still defined in Task Definition)
    #             # if taskRoleName exist or taskExecutionRoleName exist, verify the IAM permissions for it
    #             if self.check_if_role_exist(taskRoleName) and self.check_if_role_exist(taskExecutionRoleName):
    #                 self.verifyIamRolePermissions(taskRoleName)
    #                 self.verifyIamRolePermissions(taskExecutionRoleName)
    #                 print("A")
                
    #             elif self.check_if_role_exist(taskRoleName):
    #                 self.verifyIamRolePermissions(taskRoleName)
    #                 print("B")

    #             elif self.check_if_role_exist(taskExecutionRoleName):
    #                 self.verifyIamRolePermissions(taskExecutionRoleName)
    #                 print("C")
                                                  
    #             else:
    #                 print("Both task role and task execution role does not exist...")

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
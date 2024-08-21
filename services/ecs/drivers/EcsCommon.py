import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

###### TO DO #####
## Import modules that needed for this driver
## Example
## from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

###### TO DO #####
## Replace ServiceDriver with

class EcsCommon(Evaluator):
    
    ###### TO DO #####
    ## Replace resource variable to meaningful name
    ## Modify based on your need
    def __init__(self, clusterName, clusterInfo,ecsClient):
        super().__init__()
        self.clusterName = clusterName
        self.clusterInfo = clusterInfo
        #self.taskDefinitionsArn = taskDefinitionsArn
        self.ecsClient = ecsClient
        self.init()
    

    def _checkTaskExecutionRole(self):
        # check the list of task definitions within in ECS account, whether it contains task execution role of AdministratorAccess and ECSFullAccess
        
        print("test")

        self.results['ecsTaskExecutionRole'] = [-1, "roleArn"]
        return
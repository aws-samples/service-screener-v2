import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

class EcsCommon(Evaluator):
    
    def __init__(self, clusterName, clusterInfo,ecsClient):
        super().__init__()
        self.clusterName = clusterName
        self.clusterInfo = clusterInfo
        self.ecsClient = ecsClient
        self.init()

    def _checkECSGraviton(self):
        """
        Notes:
        If list_container_instances is called and returns a result - typically means that they are using EC2 or external ECS Anywhere service

        """
        # containerInstances = []
        # response = self.ecsClient.list_container_instances(
        #     cluster = self.clusterName,
        # )
        # containerInstances += response.get('containerInstanceArns')
        # while response.get('nextToken') is not None:
        #     containerInstances += response.get('containerInstanceArns')
        #     response = self.ecsClient.list_container_instances(
        #         cluster = self.clusterName,
        #         nextToken = response.get('nextToken')
        #     )
        # print("Hi",containerInstances)
        #response = self.ecsClient.

        #print(self.clusterInfo.get('capacityProviders'))
        clusterCapacityProviderList = self.clusterInfo.get('capacityProviders')
        ec2CapacityProviders = []

        if len(clusterCapacityProviderList) > 0:
            for capacityProviderName in clusterCapacityProviderList:
                if capacityProviderName != 'FARGATE_SPOT' and capacityProviderName != 'FARGATE':
                    ec2CapacityProviders.append(capacityProviderName)
                    # TODO: Probably can refactor and get the capacityProviderName's associated Auto Scaling Group ARN
        # check capacity provider of the cluster

        #print(ec2CapacityProviders)
        for ec2CapacityProvider in ec2CapacityProviders:
            response = self.ecsClient.describe_capacity_providers(
                capacityProviders=[ec2CapacityProvider]
            ).get('capacityProviders')[0]
            #print(response['autoScalingGroupProvider']['autoScalingGroupArn'])
        
        # TODO: Continue writing logic for this

        # self.results['ecsGraviton'] = [-1, "TODO: InstanceType here"]
        return
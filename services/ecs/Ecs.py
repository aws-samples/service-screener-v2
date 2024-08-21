import boto3
import botocore
import requests

from utils.Config import Config
from services.Service import Service
from services.ecs.drivers.EcsCommon import EcsCommon

class Ecs(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.ecsClient = ssBoto.client('ecs', config=self.bConfig)
    
    def getTaskDefinitions(self):
        arr = []
        nextToken = None
        while True:
            if nextToken:
                arr += self.ecsClient.list_task_definitions(nextToken=nextToken)

            else:
                arr = self.ecsClient.list_task_definitions()
            nextToken = arr.get('nextToken')
            if not nextToken:
                break 
        return arr

    def getResources(self):
        clustersArns = []                       # stores list of Clusters ARNs
        clustersInfoList = []                   # stores list of Clusters Information

        results = self.ecsClient.list_clusters()    #load the first 100 results into results list
        clustersArns += results.get('clusterArns')  # append first 100 cluster ARNs 

        # append first 100 clusters Information
        clustersInfoList += self.ecsClient.describe_clusters(
            clusters = clustersArns,
            include = ['ATTACHMENTS','CONFIGURATIONS','SETTINGS','STATISTICS']
        ).get('clusters')

        # Ensure paginated results is included to go to the next 100 clusters (if available)
        while results.get('nextToken') is not None:
            results = self.ecsClient.list_clusters(
                nextToken = results.get('nextToken')
            )
            clustersArns += results.get('clusterArns') # next 100 results appended
            clustersInfoList += self.describe_clusters(
                clusters = results.get('clusterArns'),
                include = ['ATTACHMENTS','CONFIGURATIONS','SETTINGS','STATISTICS']
            ).get('clusters') # next 100 results appended
        return clustersInfoList


    def advise(self):
        objs = {}

        clusterInfoList = self.getResources()
        print("test",clusterInfoList)

        taskDefinitionsList = self.getTaskDefinitions()

        for clusterInfo in clusterInfoList:
            clusterName = clusterInfo.get('clusterName')
            obj = EcsCommon(clusterName, clusterInfo, taskDefinitionsList, self.ecsClient)
            obj.run(self.__class__)
            objs['ECSCluster::' + clusterName] = obj.getInfo()

        return objs
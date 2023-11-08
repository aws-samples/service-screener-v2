## https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html

import boto3
import botocore

from botocore.config import Config as AWSConfig
from utils.Config import Config
from services.Service import Service
from services.eks.drivers.EksCommon import EksCommon

class Eks(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.eksClient = ssBoto.client('eks', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self.iamClient = ssBoto.client('iam')
        
    def getClusters(self):
        arr = []
        results = self.eksClient.list_clusters()
        arr = results.get('clusters')
        
        while results.get('nextToken') is not None:
            results = self.eksClient.list_clusters(
                nextToken = results.get('nextToken')
            )
            arr = arr + results.get('clusters')
        
        return arr
        
    def describeCluster(self, clusterName):
        response = self.eksClient.describe_cluster(
            name = clusterName
        )
        
        return response.get('cluster')
        
    def advise(self):
        objs = {}
        clusters = self.getClusters()
        
        for cluster in clusters:
            print('...(EKS:Cluster) inspecting ' + cluster)
            clusterInfo = self.describeCluster(cluster)
            if clusterInfo.get('status') == 'CREATING':
                print(cluster + " cluster is creating. Skipped")
                continue
            
            obj = EksCommon(cluster, clusterInfo, self.eksClient, self.ec2Client, self.iamClient)
            obj.run(self.__class__)
            objs['Cluster::' + cluster] = obj.getInfo()
            
        return objs
        
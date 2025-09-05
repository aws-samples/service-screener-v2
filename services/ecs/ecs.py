import boto3
from botocore.config import Config as AWSConfig
from utils.Config import Config
from services.Service import Service
from services.ecs.drivers.EcsCommon import EcsCommon
from utils.Tools import _pi

class Ecs(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.ecsClient = ssBoto.client('ecs', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self.iamClient = ssBoto.client('iam')

    def getClusters(self):
        arr = []
        results = self.ecsClient.list_clusters()
        arr = results.get('clusterArns')
        while results.get('nextToken') is not None:
            results = self.ecsClient.list_clusters(nextToken=results.get('nextToken'))
            arr += results.get('clusterArns')
        return arr

    def describeCluster(self, clusterArn):
        resp = self.ecsClient.describe_clusters(clusters=[clusterArn])
        return resp.get('clusters', [{}])[0]

    def advise(self):
        objs = {}
        clusters = self.getClusters()
        for clusterArn in clusters:
            _pi('ECS:Cluster', clusterArn)
            clusterInfo = self.describeCluster(clusterArn)
            if self.tags:
                resp = self.ecsClient.list_tags_for_resource(resourceArn=clusterInfo['clusterArn'])
                nTags = self.convertKeyPairTagToTagFormat(resp.get('tags'))
                if self.resourceHasTags(nTags) == False:
                    continue
            obj = EcsCommon(clusterArn, clusterInfo, self.ecsClient, self.ec2Client, self.iamClient)
            obj.run(self.__class__)
            objs['Cluster::' + clusterArn] = obj.getInfo()
        return objs

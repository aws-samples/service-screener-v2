import boto3
import botocore
import requests

from utils.Config import Config
from services.Service import Service
from services.redshift.drivers.RedshiftCluster import RedshiftCluster

from utils.Tools import _pi

class Redshift(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.rsClient = ssBoto.client('redshift', config=self.bConfig)
        
        self.redshifts = []
        return
    
    ## method to get resources for the services
    ## return the array of the resources
    def getClusterResources(self):
        """Get all cluster resources with tag filtering"""
        self.getClusters()
        
        if not self.tags:
            return self.redshifts
        
        # Filter clusters by tags
        filtered_clusters = []
        for cluster in self.redshifts:
            try:
                # Get cluster tags
                resp = self.rsClient.describe_tags(
                    ResourceName=cluster['ClusterIdentifier'],
                    ResourceType='cluster'
                )
                tagged_resources = resp.get('TaggedResources', [])
                tags = tagged_resources[0].get('Tags', []) if tagged_resources else []
                
                if self.resourceHasTags(tags):
                    filtered_clusters.append(cluster)
            except botocore.exceptions.ClientError:
                # Skip clusters we can't access tags for
                continue
        
        return filtered_clusters
        
    def getClusters(self):
        """Efficiently paginate through all clusters"""
        try:
            paginator = self.rsClient.get_paginator('describe_clusters')
            for page in paginator.paginate():
                clusters = page.get('Clusters', [])
                self.redshifts.extend(clusters)
        except botocore.exceptions.ClientError as e:
            print(f"Error fetching Redshift clusters: {e}")
            return
        
    
    def advise(self):
        objs = {}
        
        clusters = self.getClusterResources()
        for cluster in clusters:
            _pi('Redshift', cluster['ClusterIdentifier'])
            obj = RedshiftCluster(cluster, self.rsClient)
            obj.run(self.__class__)
            objs[f"Redshift::{cluster['ClusterIdentifier']}"] = obj.getInfo()
            del obj
        
        return objs
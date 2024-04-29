import boto3
import botocore
import requests

from utils.Config import Config
from services.Service import Service
from services.redshift.drivers.RedshiftCluster import RedshiftCluster

###### TO DO #####
## Import required service module below
## Example
## from services.ec2.drivers.Ec2Instance import Ec2Instance


###### TO DO #####
## Replace ServiceName with
## getResources and advise method is default method that must have
## Feel free to develop method to support your checks
class Redshift(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.rsClient = ssBoto.client('redshift', config=self.bConfig)
        
        ###### TO DO #####
        ## Initiate clients required for the check
        ## Example
        ## self.rdsClient = ssBoto.client('rds', config=self.bConfig)
        self.redshifts = []
        return
    
    ## method to get resources for the services
    ## return the array of the resources
    def getClusterResources(self):
        arr = []
        
        self.getClusters()
        '''
        filters = []
        if self.tags:
            filters = self.tags
        '''
        return arr
        
    def getClusters(self, Marker=None):
        ###### TO DO #####
        ## To implement TAGS later
        args = {}
        if Marker:
            args['Marker'] = Marker
        
        resp = self.rsClient.describe_clusters()
        for cluster in resp.get('Clusters'):
            self.redshifts.append(cluster)
        
        if resp.get('Marker'):
            self.getClusters(Marker=resp.get('Marker'))
        
    
    def advise(self):
        objs = {}
        
        ###### TO DO #####
        ## call getResources method
        ## loop through the resources and run the checks in drivers
        ## Example
        self.getClusterResources()
        for cluster in self.redshifts:
            print('... (Redshift) inspecting ' + cluster['ClusterIdentifier'])
            obj = RedshiftCluster(cluster, self.rsClient)
            obj.run(self.__class__)
            objs[f"Redshift::{cluster['ClusterIdentifier']}"] = obj.getInfo()
            del obj
        
        return objs
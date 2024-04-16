import boto3
import botocore
import requests

from utils.Config import Config
from services.Service import Service

###### TO DO #####
## Import required service module below
## Example
## from services.ec2.drivers.Ec2Instance import Ec2Instance


###### TO DO #####
## Replace ServiceName with
## getResources and advise method is default method that must have
## Feel free to develop method to support your checks
class ServiceName(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        
        ###### TO DO #####
        ## Initiate clients required for the check
        ## Example
        ## self.rdsClient = ssBoto.client('rds', config=self.bConfig)
        
        return
    
    ## method to get resources for the services
    ## return the array of the resources
    def getResources(self):
        arr = {}
        
        filters = []
        if self.tags:
            filters = self.tags
        
        ###### TO DO #####
        ## list the resources
        ## make sure filter by tagging is supported
        ## make sure pagination is supoprted
        ## Example
        # results = self.ec2Client.describe_instances(
        #     Filters = filters
        # )
        
            
        # arr = results.get('Reservations')
        # while results.get('NextToken') is not None:
        #     results = self.ec2Client.describe_instances(
        #         Filters = filters,
        #         NextToken = results.get('NextToken')
        #     )    
        #     arr = arr + results.get('Reservations')
        
        return arr
        
    
    def advise(self):
        objs = {}
        
        ###### TO DO #####
        ## call getResources method
        ## loop through the resources and run the checks in drivers
        ## Example
        # instances = self.getResources()
        # for instance in instances:
        #     instanceData = instance['Instances'][0]
        #     print('... (EC2) inspecting ' + instanceData['InstanceId'])
        #     obj = Ec2Instance(instanceData,self.ec2Client, self.cwClient)
        #     obj.run(self.__class__)
            
        #     objs[f"EC2::{instanceData['InstanceId']}"] = obj.getInfo()
        #.    del obj
        
        return objs
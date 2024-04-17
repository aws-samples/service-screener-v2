import boto3
import botocore
import requests

from utils.Config import Config
from services.Service import Service

###### TO DO #####
## Import required service module below
## Example
from services.cloudwatch.drivers.CloudwatchCommon import CloudwatchCommon
from services.cloudwatch.drivers.CloudwatchTrails import CloudwatchTrails


###### TO DO #####
## Replace ServiceName with
## getResources and advise method is default method that must have
## Feel free to develop method to support your checks
class Cloudwatch(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        self.cwLogClient = ssBoto.client('logs', config=self.bConfig)
        self.ctClient = ssBoto.client('cloudtrail', config=self.bConfig)
        
        self.ctLogs = []
        
        return
    
    ## method to get resources for the services
    ## return the array of the resources
    def loopTrail(self, NextToken=None):
        args = {}
        if NextToken:
            args['NextToken'] = NextToken
        
        resp = self.ctClient.list_trails(**args)
        trails = resp.get('Trails')
        for trail in trails:
            if trail['HomeRegion'] == self.region:
                info = self.ctClient.describe_trails(trailNameList=[trail['TrailARN']])
                tl = info.get('trailList')[0]
                if 'CloudWatchLogsLogGroupArn' in tl:
                    logGroupName = tl['CloudWatchLogsLogGroupArn'].split(':')[6]
                    self.ctLogs.append([trail['TrailARN'], tl['CloudWatchLogsLogGroupArn'], logGroupName])
                else:
                    self.ctLogs.append([trail['TrailARN'], None, None])
           
        if resp.get('NextToken'):
            self.loopTrail(resp.get('NextToken'))
    
    def advise(self):
        objs = {}
        
        self.loopTrail()
        for log in self.ctLogs:
            print("... (Cloudwatch Logs) inspecting CloudTrail's related LogGroup [{}]".format(log[0]))
            obj = CloudwatchTrails(log, self.cwLogClient)
            obj.run(self.__class__)
            
            objs[f"Log::{log[0]}"] = obj.getInfo()
            
            print(obj.getInfo())
            del obj
        
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
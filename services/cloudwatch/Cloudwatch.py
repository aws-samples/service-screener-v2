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

from utils.Tools import _pi

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
        self.logGroups = []
        
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
    
    def getAllLogs(self, nextToken=None):
        args = {}
        if nextToken:
            args['nextToken'] = nextToken
        
        resp = self.cwLogClient.describe_log_groups(**args)
        logGroups = resp.get('logGroups')
        for lg in logGroups:
            self.logGroups.append({
                'logGroupName': lg['logGroupName'],
                'storedBytes': lg['storedBytes'],
                'retentionInDays': lg['retentionInDays'] if 'retentionInDays' in lg else -1,
                'dataProtectionStatus': lg['dataProtectionStatus'] if 'dataProtectionStatus' in lg else ''
            })
        
        if resp.get('nextToken'):
            self.getAllLogs(resp.get('nextToken'))
    
    def advise(self):
        objs = {}
        
        self.loopTrail()
        for log in self.ctLogs:
            _pi("CloudTrail's CloudWatch Logs", log[0])
            obj = CloudwatchTrails(log, log[2], self.cwLogClient)
            obj.run(self.__class__)
            
            objs[f"ctLog::{log[0]}"] = obj.getInfo()
            del obj
        
        self.getAllLogs()
        for log in self.logGroups:
            _pi('Cloudwatch Logs', log['logGroupName'])
            obj = CloudwatchCommon(log, self.cwLogClient)
            obj.run(self.__class__)
            
            objs[f"Log::{log['logGroupName']}"] = obj.getInfo()
            del obj
            
        return objs
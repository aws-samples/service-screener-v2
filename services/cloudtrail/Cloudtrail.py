import boto3
import botocore

import json
import time

from utils.Config import Config
from services.Service import Service
from services.cloudtrail.drivers.CloudtrailCommon import CloudtrailCommon
from services.cloudtrail.drivers.CloudtrailAccount import CloudtrailAccount

class Cloudtrail(Service):
    def __init__(self, region):
        super().__init__(region)
        self.ctClient = boto3.client('cloudtrail', config=self.bConfig)
        self.snsClient = boto3.client('sns', config=self.bConfig)
        self.s3Client = boto3.client('s3')
        
    def getTrails(self):
        results = []
        ctClient = self.ctClient
        resp = ctClient.list_trails()
        results += resp.get('Trails')
        
        while True:
            if resp.get('NextToken') == None:
                break
            
            resp = ctClient.list_trails(NextToken = resp.get('NextToken'))
            results += resp.get('Trails')
        
        return results
    
    def advise(self):
        ## Will loop through all trail, and set to True if any has MultiRegion
        Config.set('CloudTrail_hasOneMultiRegion', False)
        Config.set('CloudTrail_hasGlobalServEnabled', False)
        Config.set('CloudTrail_listGlobalServEnabled', [])
        Config.set('CloudTrail_hasManagementEventsCaptured', False)
        
        objs = {}
        trails = self.getTrails()
        
        for trail in trails:
            print("... [Cloudtrail] inspecting " + trail['Name'])
            obj = CloudtrailCommon(trail, self.ctClient, self.snsClient, self.s3Client)
            obj.run()
            objs['Cloudtrail::' + trail['Name']] = obj.getInfo()
            del obj
        
        print('... (CloudTrail:Common) inspecting')
        obj = CloudtrailAccount(self.ctClient, len(trails))
        objs['Cloudtrail::General'] = obj.getInfo()
        del obj
        
        # print(objs)
        
        return objs
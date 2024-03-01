import botocore

import json
import time

from utils.Config import Config
from botocore.config import Config as bConfig
from services.Service import Service
from services.cloudtrail.drivers.CloudtrailCommon import CloudtrailCommon
from services.cloudtrail.drivers.CloudtrailAccount import CloudtrailAccount

class Cloudtrail(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.ctClient = ssBoto.client('cloudtrail', config=self.bConfig)
        self.snsClient = ssBoto.client('sns', config=self.bConfig)
        self.s3Client = ssBoto.client('s3')
        
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
        
        
        if not self.tags:
            return results    
        
        finalArr = []
        for i, detail in enumerate(results):
            ctInfo = detail['TrailARN'].split(':')
            
            ## despite cloudtrail seems like a "global api", for list_tags, need to call based on region tho.
            ## need to create separate boto instance for that region
            myTmpCtClient = self.ssBoto.client('cloudtrail', config=bConfig(region_name=ctInfo[3]))
            tags = myTmpCtClient.list_tags(ResourceIdList=[detail['TrailARN']])
            
            if self.resourceHasTags(tags.get('ResourceTagList')[0]['TagsList']):
                finalArr.append(results[i])
        
        return finalArr
        
    
    def advise(self):
        ## Will loop through all trail, and set to True if any has MultiRegion
        Config.set('CloudTrail_hasOneMultiRegion', False)
        Config.set('CloudTrail_hasGlobalServEnabled', False)
        Config.set('CloudTrail_listGlobalServEnabled', [])
        Config.set('CloudTrail_hasManagementEventsCaptured', False)
        Config.set('CloudTrail_hasDataEventsCaptured', False)
        
        objs = {}
        trails = self.getTrails()
        
        ctRanList = Config.get('CloudTrail_ranList', [])
        
        for trail in trails:
            if trail['TrailARN'] in ctRanList:
                print('... [Cloudtrail::SKIPPED] ' + trail['Name'] + ', executed in other regions')
                continue
            
            print("... [Cloudtrail] inspecting " + trail['Name'])
            ctRanList.append(trail['TrailARN'])
            
            obj = CloudtrailCommon(trail, self.ctClient, self.snsClient, self.s3Client)
            obj.run(self.__class__)
            objs['Cloudtrail::' + trail['Name']] = obj.getInfo()
            del obj
        
        Config.set('CloudTrail_ranList', ctRanList)
        
        print('... (CloudTrail:Common) inspecting')
        obj = CloudtrailAccount(self.ctClient, len(trails))
        objs['Cloudtrail::General'] = obj.getInfo()
        del obj
        
        # print(objs)
        
        return objs
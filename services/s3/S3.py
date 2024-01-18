import botocore

import json
import time


from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
from botocore.config import Config as bConfig

# import drivers here
from services.s3.drivers.S3Bucket import S3Bucket
from services.s3.drivers.S3Control import S3Control
from services.s3.drivers.S3Macie import S3Macie

class S3(Service):
    def __init__(self, region):
        super().__init__(region)
        self.region = region
        # conf = bConfig(region_name=region)
        # print(self.bConfig)
        
        ssBoto = self.ssBoto
        self.s3Client = ssBoto.client('s3', config=self.bConfig)
        self.s3Control = ssBoto.client('s3control', config=self.bConfig)
        self.macieV2Client = ssBoto.client('macie2', config=self.bConfig)
        
        # buckets = Config.get('s3::buckets', [])
    
    def getResources(self):
        buckets = Config.get('s3::buckets', {})
        unableToListBucket = Config.get('s3::bucketUnableToList', False)
        if not buckets and not unableToListBucket:
            try:
                buckets = {}
                results = self.s3Client.list_buckets()
                
                arr = results.get('Buckets')
                while results.get('Maker') is not None:
                    results = self.s3Client.list_buckets(
                        Maker = results.get('Maker')
                    )    
                    arr = arr + results.get('Buckets')
                
                for ind, bucket in enumerate(arr):
                    loc = self.s3Client.get_bucket_location(
                        Bucket = bucket['Name']
                    )
                    reg = loc.get('LocationConstraint')
                    
                    if reg == None:
                        reg = 'us-east-1'
                        
                    if not reg in buckets:
                        buckets[reg] = []
                    buckets[reg].append(arr[ind])
                
            except botocore.exceptions.ClientError as e:
                Config.set('s3::bucketUnableToList', True)
                ecode = e.response['Error']['Code']
                emsg = e.response['Error']['Message']
                print('s3', ecode, emsg)
                
            Config.set('s3::buckets', buckets)
            
        if self.region in buckets:
            _buckets = buckets[self.region]
        else:
            return []
            
        if not self.tags:
            return _buckets
        
        filteredBuckets = []
        '''
        # <TODO> to support tagging
        for bucket in _buckets:
            try:
                result = self.s3Client.get_bucket_tagging(Bucket = bucket['Name'])
                tags =result.get('TagSet')
            
                if self.resourceHasTags(tags):
                    filteredBuckets.append(bucket)
            except S3E as e:
                ## Do nothing, no tags has been define;clear
                pass
        '''    
        return filteredBuckets    
    
    def advise(self):
        objs = {}
        accountScanned = Config.get('S3_HasAccountScanned', False)
        if accountScanned == False:
            print('... (S3Account) inspecting ')
            obj = S3Control(self.s3Control)
            obj.run(self.__class__)
            
            objs["Account::Control"] = obj.getInfo()
            
            globalKey = 'GLOBALRESOURCES_s3'
            Config.set(globalKey, objs)
            
            Config.set('S3_HasAccountScanned', True)
            del obj
        
        objs = {}
        buckets = self.getResources()
        for bucket in buckets:
            print('... (S3Bucket) inspecting ' + bucket['Name'])
            obj = S3Bucket(bucket['Name'], self.s3Client)
            obj.run(self.__class__)
            
            objs["Bucket::" + bucket['Name']] = obj.getInfo()
            del obj
        
        obj = S3Macie(self.macieV2Client)
        obj.run(self.__class__)
        objs["Macie"] = obj.getInfo()
        return objs

        
if __name__ == "__main__":
    Config.init()
    o = S3('ap-southeast-1')
    o.advise()
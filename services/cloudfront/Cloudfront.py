import boto3
import botocore

import json
import time

from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
from services.cloudfront.drivers.cloudfrontDist import cloudfrontDist


class Cloudfront(Service):
    def __init__(self, region):
        super().__init__(region)
        self.cloudfrontClient = boto3.client('cloudfront')
        
    def getDistributions(self):
        
        response = self.cloudfrontClient.list_distributions()
        arr = []
        
        while True:
            if "DistributionList" in response and "Items" in response["DistributionList"]:
                for dist in response["DistributionList"]["Items"]:
                    arr.append(dist["Id"])
                if "NextMarker" not in response["DistributionList"]:
                    break
    
                response = self.cloudfrontClient.list_distributions(Marker=response["DistributionList"]["NextMarker"])
            else:
                break
        return arr
        
    
    def advise(self):
        objs = {}
        
        dists = self.getDistributions()
        for dist in dists:
            print('... (CloudFront::Distribution) inspecting ' + dist)
            obj = cloudfrontDist(dist, self.cloudfrontClient)
            obj.run()
            
            objs['Cloudfront::' + dist] = obj.getInfo()
            del obj
        
        return objs
    

if __name__ == "__main__":
    Config.init()
    o = CloudFront('us-east-1')
    out = o.advise()
    _pr(out)

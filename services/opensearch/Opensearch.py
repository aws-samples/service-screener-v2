import boto3
import botocore

from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
##import drivers here
from services.opensearch.drivers.OpensearchCommon import OpensearchCommon

class Opensearch(Service):
    def __init__(self, region):
        super().__init__(region)
        self.osClient = boto3.client('opensearch', config=self.bConfig)
        
        # o = Config.get('stsInfo')
    
    def getResources(self):
        arr = []
        results = self.osClient.list_domain_names()
        return results.get('DomainNames')
        
    def advise(self):
        domains = self.getResources()
        objs = {}
        
        for domain in domains:
            domain_name = domain["DomainName"]
            print("... (OpenSearch) inspecting " + domain_name)
            
            obj = OpensearchCommon(self.bConfig, domain_name, self.osClient)
            obj.run(self.__class__)
            
            #objs["OpenSearch::Common"] = obj.getInfo()
            objs["OpenSearch::" + domain_name] = obj.getInfo()
        
        return objs
import botocore

from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
##import drivers here
from services.opensearch.drivers.OpensearchCommon import OpensearchCommon

from utils.Tools import _pi

class Opensearch(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.osClient = ssBoto.client('opensearch', config=self.bConfig)
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        
        # o = Config.get('stsInfo')
    
    def getResources(self):
        arr = []
        fArr = []
        results = self.osClient.list_domain_names()
        
        arr = results.get('DomainNames')
        for domain in arr:
            r = self.osClient.describe_domain(DomainName=domain['DomainName'])
            info = r.get('DomainStatus')
            if info['Processing'] == True or info['Deleted'] == True:
                continue
            
            t = domain
            t['info'] = info
            if not self.tags:
                fArr.append(t)
            else:
                tags = self.osClient.list_tags(ARN=info['ARN'])
                nTags = tags.get('TagList')
                if self.resourceHasTags(nTags):
                    fArr.append(t)
        
        return fArr
        
    def advise(self):
        domains = self.getResources()
        objs = {}
        
        for domain in domains:
            domain_name = domain["DomainName"]
            _pi("OpenSearch", domain_name)
            
            obj = OpensearchCommon(self.bConfig, domain_name, domain['info'], self.osClient, self.cwClient)
            obj.run(self.__class__)
            
            #objs["OpenSearch::Common"] = obj.getInfo()
            objs["OpenSearch::" + domain_name] = obj.getInfo()
        
        return objs
import botocore

from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
##import drivers here
from services.kms.drivers.KmsCommon import KmsCommon

from utils.Tools import _pi

class Kms(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.kmsClient = ssBoto.client('kms', config=self.bConfig)
        self.kmsCustomerManagedKeys = []
    
    def getResources(self):
        resp = self.kmsClient.list_keys(Limit=10)
        self.checkKmsKey(resp)
        NextMarker = resp.get('NextMarker')
        while NextMarker != None:
            resp = self.kmsClient.list_keys(Limit=10, Marker=NextMarker)
            NextMarker = resp.get('NextMarker')
            
            self.checkKmsKey(resp)
        
    def checkKmsKey(self, resp):
        for key in resp['Keys']:
            res = self.kmsClient.describe_key(KeyId = key['KeyId'])
            metadata = res.get('KeyMetadata')
            if metadata['KeyManager'] != 'AWS':
                rr = self.kmsClient.get_key_rotation_status(KeyId = key['KeyId'])
                metadata['KeyRotationEnabled'] = rr.get('KeyRotationEnabled')
                
                if self.tags:
                    tags = self.kmsClient.list_resource_tags(KeyId = key['KeyId'])
                    nTags = self.convertTagKeyTagValueIntoKeyValue(tags.get('Tags'))
                    if self.resourceHasTags(nTags) == False:
                        continue
                
                self.kmsCustomerManagedKeys.append(metadata)
        
        return []
        
    def advise(self):
        objs = {}
        self.getResources()
        
        for key in self.kmsCustomerManagedKeys:
            _pi('KMS', key['KeyId'] + ' (' + key['Arn'] +')')
            
            obj = KmsCommon(key, self.kmsClient)        
            obj.run(self.__class__)
            
            objs[key['KeyId']] = obj.getInfo()
            del obj
           
        return objs
    
if __name__ == "__main__":
    Config.init()
    o = Kms('ap-southeast-1')
    out = o.advise()

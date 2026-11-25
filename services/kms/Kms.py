import botocore

from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
##import drivers here
from services.kms.drivers.KmsCommon import KmsCommon
from services.kms.drivers.KmsAccount import KmsAccount

from utils.Tools import _pi

class Kms(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.kmsClient = ssBoto.client('kms', config=self.bConfig)
        self.kmsCustomerManagedKeys = []
        ## Every listed key in list order -> describe_key KeyMetadata (None when
        ## not described, e.g. checkpointed). Reused by KmsAccount.
        self.kmsKeyMetadata = {}
    
    def getResources(self):
        resp = self.kmsClient.list_keys(Limit=10)
        self.checkKmsKey(resp)
        NextMarker = resp.get('NextMarker')
        while NextMarker != None:
            resp = self.kmsClient.list_keys(Limit=10, Marker=NextMarker)
            NextMarker = resp.get('NextMarker')
            
            self.checkKmsKey(resp)
        
    def checkKmsKey(self, resp):
        keys = resp['Keys']
        pendingArns = {k['KeyArn'] for k in self.registerItems(
            'KmsCommon', keys, idFn=lambda k: k['KeyArn']
        )}

        for key in keys:
            self.kmsKeyMetadata.setdefault(key['KeyId'], None)
            if key['KeyArn'] not in pendingArns:
                ## Already checkpointed - keep a minimal placeholder so advise() still
                ## builds the driver; Evaluator.run() serves the cached result.
                self.kmsCustomerManagedKeys.append({
                    'KeyId': key['KeyId'],
                    'Arn': key['KeyArn'],
                })
                continue

            res = self.kmsClient.describe_key(KeyId = key['KeyId'])
            metadata = res.get('KeyMetadata')
            self.kmsKeyMetadata[key['KeyId']] = dict(metadata)
            if metadata['KeyManager'] != 'AWS':
                try:
                    rr = self.kmsClient.get_key_rotation_status(KeyId = key['KeyId'])
                    metadata['KeyRotationEnabled'] = rr.get('KeyRotationEnabled')
                    metadata['_rotationPeriodInDays'] = rr.get('RotationPeriodInDays')
                except botocore.exceptions.ClientError as e:
                    metadata['KeyRotationEnabled'] = None
                    metadata['_rotationError'] = e.response.get('Error', {}).get('Code', 'ClientError')
                
                if self.tags:
                    tags = self.kmsClient.list_resource_tags(KeyId = key['KeyId'])
                    ## Only the first page is needed for filtering; the driver
                    ## re-reads all pages unless this first page is complete.
                    nTags = self.convertTagKeyTagValueIntoKeyValue(tags.get('Tags'))
                    if self.resourceHasTags(nTags) == False:
                        continue
                    if not tags.get('Truncated'):
                        ## Complete tag list: the driver reuses it instead of re-reading.
                        metadata['_resourceTags'] = list(tags.get('Tags') or [])
                
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

        ## Region-scoped checks (custom key stores, cross-service key reuse).
        ## Always evaluated, even when the region has no customer managed keys.
        ssBoto = self.ssBoto
        bConfig = self.bConfig
        obj = KmsAccount(self.kmsClient, lambda name: ssBoto.client(name, config=bConfig),
                         keyMetadata=self.kmsKeyMetadata)
        obj.run(self.__class__)
        objs['KMS::Account'] = obj.getInfo()
        del obj
           
        return objs
    
if __name__ == "__main__":
    Config.init()
    o = Kms('ap-southeast-1')
    out = o.advise()

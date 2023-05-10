import urllib.parse
from datetime import date
import boto3

from utils.Config import Config
from services.Evaluator import Evaluator

class cloudfrontDist(Evaluator):
    def __init__(self, dist, cloudfrontClient):
        super().__init__()
        self.dist = dist
        self.cloudfrontClient = cloudfrontClient
        self._configPrefix = 'cloudfront::distribution::'
        self.init()
        
    def _checkAccessLogsEnabled(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        logging = str(resp['DistributionConfig']['Logging']['Enabled'])
        # print('Logging : ' + str(logging))
        if logging == 'False':
            self.results['accessLogging'] = [-1, 'Not Enabled']
            
    def _checkWAFAssociation(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        webACL = resp['DistributionConfig']['WebACLId']
        # print('WebACL : ' + str(webACL))
        if webACL == '':
            self.results['WAFAssociation'] = [-1, 'Not Associated']
            
    def _checkDefaultRootObject(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        rootObj = resp['DistributionConfig']['DefaultRootObject']
        # print('Default Root Object : ' + str(rootObj))
        if rootObj == '':
            self.results['defaultRootObject'] = [-1, 'Not Configured']
            
    def _checkCompressedObjects(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        compress = resp['DistributionConfig']['DefaultCacheBehavior']['Compress']
        # print('Serving compressed files : ' + str(compress))
        if compress == False:
            self.results['compressObjectsAutomatically'] = [-1, 'No']
            
    def _xcheckDeprecatedSSL(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        
        deprecatedSSL = resp['DistributionConfig']['Origins']['Items'][0]['CustomOriginConfig']['OriginSslProtocols']['Items']
        # print('Protocols : ' + str(deprecatedSSL))
        if 'SSLv3' in deprecatedSSL:
            self.results['DeprecatedSSLProtocol'] = [-1, 'Yes']
    
    def _xcheckOriginFailover(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        originQuantity = resp['DistributionConfig']['Origins']['Quantity']
        # print('Origins : ' + str(originQuantity))
        if originQuantity <= 1:
            self.results['originFailover'] = [-1, 'No']
            
    def _checkFieldLevelEncryption(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        encryption = resp['DistributionConfig']['DefaultCacheBehavior']['FieldLevelEncryptionId']
        # print('fieldLevelEncryptionId : ' + str(encryption))
        if encryption == '':
            self.results['fieldLevelEncryption'] = [-1, 'No']
            
    def _checkViewerPolicyHttps(self):
        dist = self.dist
        resp = self.cloudfrontClient.get_distribution_config(Id=dist)
        policy = resp['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy']
       # print('viewerPolicy : ' + str(policy))
        if policy == 'allow-all':
            self.results['viewerPolicyHttps'] = [-1, 'No']
    
    
    
if __name__ == "__main__":
    c = boto3.client('cloudfront')
    o = cloudfrontDist('ok', c)
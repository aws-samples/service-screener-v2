import urllib.parse
from datetime import date

from utils.Config import Config
from services.Evaluator import Evaluator

class cloudfrontDist(Evaluator):
    def __init__(self, dist, cloudfrontClient, s3Client):
        super().__init__()
        self.dist = dist
        self.cloudfrontClient = cloudfrontClient
        self.s3Client = s3Client
        self._configPrefix = 'cloudfront::distribution::'
        
        self.distConfig = cloudfrontClient.get_distribution_config(Id=dist)
        
        self._resourceName = dist

        self.init()
        
    def _checkAccessLogsEnabled(self):
        dist = self.dist
        resp = self.distConfig
        logging = str(resp['DistributionConfig']['Logging']['Enabled'])
        if logging == 'False':
            self.results['accessLogging'] = [-1, '']
            
    def _checkWAFAssociation(self):
        dist = self.dist
        resp = self.distConfig
        webACL = resp['DistributionConfig']['WebACLId']
        if webACL == '':
            self.results['WAFAssociation'] = [-1, '']
            
    def _checkDefaultRootObject(self):
        dist = self.dist
        resp = self.distConfig
        rootObj = resp['DistributionConfig']['DefaultRootObject']
        if rootObj == '':
            self.results['defaultRootObject'] = [-1, '']
            
    def _checkCompressedObjects(self):
        dist = self.dist
        resp = self.distConfig
        compress = resp['DistributionConfig']['DefaultCacheBehavior']['Compress']
        if compress == False:
            self.results['compressObjectsAutomatically'] = [-1, '']
            
    def _checkDeprecatedSSL(self):
        dist = self.dist
        resp = self.distConfig
        
        for y in resp['DistributionConfig']['Origins']['Items']:
            if not 'CustomOriginConfig' in y:
                continue
            
            if y['CustomOriginConfig']['OriginProtocolPolicy'] == 'http-only':
                continue
            
            if 'SSLv3' in y['CustomOriginConfig']['OriginSslProtocols']['Items']:
                self.results['DeprecatedSSLProtocol'] = [-1, '']
                break
    
    def _checkOriginFailover(self):
        dist = self.dist
        resp = self.distConfig
        origin = resp['DistributionConfig']['OriginGroups']['Quantity']
        if origin < 1:
            self.results['originFailover'] = [-1, '']
            
    def _checkFieldLevelEncryption(self):
        dist = self.dist
        resp = self.distConfig
        encryption = resp['DistributionConfig']['DefaultCacheBehavior']['FieldLevelEncryptionId']
        if encryption == '':
            self.results['fieldLevelEncryption'] = [-1, '']
            
    def _checkViewerPolicyHttps(self):
        dist = self.dist
        resp = self.distConfig
        policy = resp['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy']
        if policy == 'allow-all':
            self.results['viewerPolicyHttps'] = [-1, '']
    
    def _checkS3OriginAccessControl(self):
        """Check if S3 origins have OAC or OAI configured"""
        resp = self.distConfig
        origins = resp['DistributionConfig']['Origins']['Items']
        
        for origin in origins:
            # Check if this is an S3 origin
            domain_name = origin.get('DomainName', '')
            if '.s3.' in domain_name or '.s3-' in domain_name:
                # Check for OAC (new method)
                has_oac = origin.get('OriginAccessControlId', '') != ''
                
                # Check for OAI (legacy method)
                has_oai = False
                if 'S3OriginConfig' in origin:
                    has_oai = origin['S3OriginConfig'].get('OriginAccessIdentity', '') != ''
                
                # FAIL if neither OAC nor OAI is configured
                if not has_oac and not has_oai:
                    self.results['S3OriginAccessControl'] = [-1, origin['Id']]
                    break
    
    def _checkOriginTrafficEncryption(self):
        """Check if custom origins enforce HTTPS"""
        resp = self.distConfig
        origins = resp['DistributionConfig']['Origins']['Items']
        
        for origin in origins:
            # Only check custom origins (non-S3)
            if 'CustomOriginConfig' in origin:
                protocol_policy = origin['CustomOriginConfig'].get('OriginProtocolPolicy', '')
                
                # FAIL if origin allows HTTP
                if protocol_policy not in ['https-only']:
                    # If match-viewer, need to check viewer protocol policy
                    if protocol_policy == 'match-viewer':
                        viewer_policy = resp['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy']
                        if viewer_policy == 'allow-all':
                            self.results['OriginTrafficEncryption'] = [-1, origin['Id']]
                            break
                    elif protocol_policy == 'http-only':
                        self.results['OriginTrafficEncryption'] = [-1, origin['Id']]
                        break
    
    def _checkCustomSSLCertificate(self):
        """Check if distribution uses custom SSL certificate"""
        resp = self.distConfig
        viewer_cert = resp['DistributionConfig'].get('ViewerCertificate', {})
        
        # Check if using default CloudFront certificate
        using_default = viewer_cert.get('CloudFrontDefaultCertificate', False)
        
        if using_default:
            self.results['CustomSSLCertificate'] = [-1, 'Using default *.cloudfront.net certificate']
    
    def _checkSNIConfiguration(self):
        """Check if custom certificates use SNI instead of dedicated IPs"""
        resp = self.distConfig
        viewer_cert = resp['DistributionConfig'].get('ViewerCertificate', {})
        
        # Only check if using custom certificate
        using_default = viewer_cert.get('CloudFrontDefaultCertificate', False)
        if not using_default:
            ssl_support_method = viewer_cert.get('SSLSupportMethod', '')
            
            # FAIL if using dedicated IPs (vip or static-ip)
            if ssl_support_method in ['vip', 'static-ip']:
                self.results['SNIConfiguration'] = [-1, f'Using {ssl_support_method} ($600/month)']
    
    def _checkS3OriginBucketExists(self):
        """Check if S3 origin buckets exist and are accessible"""
        resp = self.distConfig
        origins = resp['DistributionConfig']['Origins']['Items']
        
        for origin in origins:
            # Check if this is an S3 origin
            domain_name = origin.get('DomainName', '')
            if '.s3.' in domain_name or '.s3-' in domain_name:
                # Extract bucket name from domain
                # Format: bucket-name.s3.region.amazonaws.com or bucket-name.s3.amazonaws.com
                bucket_name = domain_name.split('.s3')[0]
                
                try:
                    # Use head_bucket to check if bucket exists and is accessible
                    self.s3Client.head_bucket(Bucket=bucket_name)
                except Exception as e:
                    # Check if it's a NoSuchBucket error (404)
                    error_code = e.response.get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''
                    if error_code == '404' or 'NoSuchBucket' in str(type(e).__name__):
                        self.results['S3OriginBucketExists'] = [-1, f'{bucket_name} (does not exist)']
                        break
                    # For other errors (like 403 Forbidden), we don't fail
                    # The bucket exists but we don't have permission to verify
    
    def _checkOriginShieldEnabled(self):
        """Check if Origin Shield is enabled for origins"""
        resp = self.distConfig
        origins = resp['DistributionConfig']['Origins']['Items']
        
        has_origin_without_shield = False
        for origin in origins:
            # Check if Origin Shield is configured
            origin_shield = origin.get('OriginShield', {})
            if not origin_shield.get('Enabled', False):
                has_origin_without_shield = True
                break
        
        # FAIL if any origin doesn't have Origin Shield enabled (advisory check)
        if has_origin_without_shield:
            self.results['OriginShieldEnabled'] = [-1, 'Consider enabling Origin Shield']
    
    def _checkGeoRestrictionsConfigured(self):
        """Check if geographic restrictions are configured"""
        resp = self.distConfig
        geo_restriction = resp['DistributionConfig'].get('Restrictions', {}).get('GeoRestriction', {})
        restriction_type = geo_restriction.get('RestrictionType', 'none')
        
        # FAIL if no geographic restrictions configured (advisory check)
        if restriction_type == 'none':
            self.results['GeoRestrictionsConfigured'] = [-1, 'No geographic restrictions configured']
    
    def _checkPriceClassOptimization(self):
        """Check if price class can be optimized"""
        resp = self.distConfig
        price_class = resp['DistributionConfig'].get('PriceClass', 'PriceClass_All')
        
        # FAIL if using all edge locations (advisory check for cost optimization)
        if price_class == 'PriceClass_All':
            self.results['PriceClassOptimization'] = [-1, 'Using all edge locations - consider PriceClass_200 or PriceClass_100']
    
    
    
if __name__ == "__main__":
    ssBoto = Config.get('ssBoto')
    c = ssBoto.client('cloudfront')
    o = cloudfrontDist('ok', c)
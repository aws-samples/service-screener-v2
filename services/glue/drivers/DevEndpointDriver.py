import boto3
import botocore

from services.Evaluator import Evaluator


class DevEndpointDriver(Evaluator):
    """
    Driver for checking AWS Glue development endpoint security configurations.
    
    This driver evaluates development endpoint security settings:
    - CloudWatch logs encryption
    - Job bookmark encryption
    - S3 encryption
    """
    
    def __init__(self, endpoint, glueClient):
        """
        Initialize DevEndpointDriver.
        
        Args:
            endpoint (dict): Development endpoint configuration from get_dev_endpoints()
            glueClient: Boto3 Glue client for API calls
        """
        super().__init__()
        self.endpoint = endpoint
        self.glueClient = glueClient
        
        # Set resource name to unique identifier
        self._resourceName = f"DevEndpoint::{endpoint['EndpointName']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('endpointName', endpoint['EndpointName'])
        self.addII('roleArn', endpoint.get('RoleArn'))
        self.addII('createdTimestamp', str(endpoint.get('CreatedTimestamp', 'N/A')))
        self.addII('lastModifiedTimestamp', str(endpoint.get('LastModifiedTimestamp', 'N/A')))
        self.addII('securityConfiguration', endpoint.get('SecurityConfiguration', 'None'))
        
        # Cache security configuration details
        self._securityConfig = None
        self._securityConfigFetched = False
    
    def _getSecurityConfiguration(self):
        """
        Fetch and cache the security configuration details.
        
        Returns:
            dict: Security configuration details or None if not configured
        """
        if self._securityConfigFetched:
            return self._securityConfig
        
        self._securityConfigFetched = True
        
        securityConfigName = self.endpoint.get('SecurityConfiguration')
        if not securityConfigName:
            return None
        
        try:
            response = self.glueClient.get_security_configuration(Name=securityConfigName)
            self._securityConfig = response.get('SecurityConfiguration', {})
            return self._securityConfig
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'EntityNotFoundException':
                print(f"Security configuration '{securityConfigName}' not found for dev endpoint {self.endpoint['EndpointName']}")
            elif error_code != 'AccessDenied':
                print(f"Error fetching security configuration: {error_code}")
            return None
        except Exception as e:
            print(f"Unexpected error fetching security configuration: {e}")
            return None
    
    def _checkCloudWatchLogsEncryption(self):
        """
        Check if CloudWatch logs encryption is enabled for the development endpoint.
        
        Validates: Requirements 4.5
        Reporter JSON key: DevEndpointCloudWatchLogsEncryption
        """
        try:
            securityConfig = self._getSecurityConfiguration()
            
            if not securityConfig:
                self.results['DevEndpointCloudWatchLogsEncryption'] = [-1, 'No Security Configuration']
                return
            
            encryptionConfig = securityConfig.get('EncryptionConfiguration', {})
            cloudWatchEncryption = encryptionConfig.get('CloudWatchEncryption', {})
            
            encryptionMode = cloudWatchEncryption.get('CloudWatchEncryptionMode', 'DISABLED')
            
            if encryptionMode == 'SSE-KMS':
                kmsKeyArn = cloudWatchEncryption.get('KmsKeyArn', 'N/A')
                self.results['DevEndpointCloudWatchLogsEncryption'] = [1, f'Enabled (Mode: {encryptionMode}, KMS Key: {kmsKeyArn})']
            elif encryptionMode == 'DISABLED':
                self.results['DevEndpointCloudWatchLogsEncryption'] = [-1, 'CloudWatch Logs Encryption Disabled']
            else:
                self.results['DevEndpointCloudWatchLogsEncryption'] = [0, f'Unknown mode: {encryptionMode}']
            
        except Exception as e:
            print(f"Error checking CloudWatch logs encryption for dev endpoint {self.endpoint['EndpointName']}: {e}")
            self.results['DevEndpointCloudWatchLogsEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkBookmarkEncryption(self):
        """
        Check if job bookmark encryption is enabled for the development endpoint.
        
        Validates: Requirements 4.6
        Reporter JSON key: DevEndpointBookmarkEncryption
        """
        try:
            securityConfig = self._getSecurityConfiguration()
            
            if not securityConfig:
                self.results['DevEndpointBookmarkEncryption'] = [-1, 'No Security Configuration']
                return
            
            encryptionConfig = securityConfig.get('EncryptionConfiguration', {})
            bookmarkEncryption = encryptionConfig.get('JobBookmarksEncryption', {})
            
            encryptionMode = bookmarkEncryption.get('JobBookmarksEncryptionMode', 'DISABLED')
            
            if encryptionMode == 'CSE-KMS':
                kmsKeyArn = bookmarkEncryption.get('KmsKeyArn', 'N/A')
                self.results['DevEndpointBookmarkEncryption'] = [1, f'Enabled (Mode: {encryptionMode}, KMS Key: {kmsKeyArn})']
            elif encryptionMode == 'DISABLED':
                self.results['DevEndpointBookmarkEncryption'] = [-1, 'Job Bookmark Encryption Disabled']
            else:
                self.results['DevEndpointBookmarkEncryption'] = [0, f'Unknown mode: {encryptionMode}']
            
        except Exception as e:
            print(f"Error checking bookmark encryption for dev endpoint {self.endpoint['EndpointName']}: {e}")
            self.results['DevEndpointBookmarkEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkS3Encryption(self):
        """
        Check if S3 encryption is enabled for the development endpoint.
        
        Validates: Requirements 4.7
        Reporter JSON key: DevEndpointS3Encryption
        """
        try:
            securityConfig = self._getSecurityConfiguration()
            
            if not securityConfig:
                self.results['DevEndpointS3Encryption'] = [-1, 'No Security Configuration']
                return
            
            encryptionConfig = securityConfig.get('EncryptionConfiguration', {})
            s3Encryption = encryptionConfig.get('S3Encryption', [])
            
            if not s3Encryption:
                self.results['DevEndpointS3Encryption'] = [-1, 'S3 Encryption Not Configured']
                return
            
            # Check if any S3 encryption is enabled (not DISABLED)
            for s3Config in s3Encryption:
                encryptionMode = s3Config.get('S3EncryptionMode', 'DISABLED')
                if encryptionMode != 'DISABLED':
                    kmsKeyArn = s3Config.get('KmsKeyArn', 'N/A')
                    self.results['DevEndpointS3Encryption'] = [1, f'Enabled (Mode: {encryptionMode}, KMS Key: {kmsKeyArn})']
                    return
            
            # All encryption modes are DISABLED
            self.results['DevEndpointS3Encryption'] = [-1, 'S3 Encryption Disabled']
            
        except Exception as e:
            print(f"Error checking S3 encryption for dev endpoint {self.endpoint['EndpointName']}: {e}")
            self.results['DevEndpointS3Encryption'] = [0, f'Error: {str(e)}']

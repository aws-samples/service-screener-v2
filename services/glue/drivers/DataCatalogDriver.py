import boto3
import botocore

from services.Evaluator import Evaluator


class DataCatalogDriver(Evaluator):
    """
    Driver for checking AWS Glue Data Catalog encryption settings.
    
    This driver evaluates account-level data catalog security configurations:
    - Connection password encryption
    - Metadata encryption
    - Public accessibility
    """
    
    def __init__(self, catalogSettings, glueClient):
        """
        Initialize DataCatalogDriver.
        
        Args:
            catalogSettings (dict): Data catalog encryption settings from get_data_catalog_encryption_settings()
            glueClient: Boto3 Glue client for API calls
        """
        super().__init__()
        self.catalogSettings = catalogSettings
        self.glueClient = glueClient
        
        # Set resource name to a unique identifier for account-level settings
        self._resourceName = 'DataCatalog::Settings'
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('catalogSettings', catalogSettings)
    
    def _checkConnectionPasswordEncryption(self):
        """
        Check if connection password encryption is enabled.
        
        Validates: Requirements 4.1
        Reporter JSON key: ConnectionPasswordEncryption
        """
        try:
            connectionPasswordEncryption = self.catalogSettings.get('ConnectionPasswordEncryption', {})
            isEncrypted = connectionPasswordEncryption.get('ReturnConnectionPasswordEncrypted', False)
            
            if isEncrypted:
                kmsKeyId = connectionPasswordEncryption.get('AwsKmsKeyId', 'N/A')
                self.results['ConnectionPasswordEncryption'] = [1, f'Enabled (KMS Key: {kmsKeyId})']
            else:
                self.results['ConnectionPasswordEncryption'] = [-1, 'Disabled']
                
        except Exception as e:
            print(f"Error checking connection password encryption: {e}")
            self.results['ConnectionPasswordEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkMetadataEncryption(self):
        """
        Check if metadata encryption is enabled.
        
        Validates: Requirements 4.2
        Reporter JSON key: MetadataEncryption
        """
        try:
            encryptionAtRest = self.catalogSettings.get('EncryptionAtRest', {})
            catalogEncryptionMode = encryptionAtRest.get('CatalogEncryptionMode', 'DISABLED')
            
            if catalogEncryptionMode == 'SSE-KMS':
                kmsKeyId = encryptionAtRest.get('SseAwsKmsKeyId', 'N/A')
                self.results['MetadataEncryption'] = [1, f'Enabled (Mode: {catalogEncryptionMode}, KMS Key: {kmsKeyId})']
            elif catalogEncryptionMode == 'DISABLED':
                self.results['MetadataEncryption'] = [-1, 'Disabled']
            else:
                # Unknown mode - flag as informational
                self.results['MetadataEncryption'] = [0, f'Unknown mode: {catalogEncryptionMode}']
                
        except Exception as e:
            print(f"Error checking metadata encryption: {e}")
            self.results['MetadataEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkPublicAccessibility(self):
        """
        Check if data catalog is publicly accessible.
        
        This check verifies that the data catalog resource policy does not allow
        public access (Principal: "*" or Principal.AWS: "*").
        
        Validates: Requirements 4.3
        Reporter JSON key: PublicAccessibility
        """
        try:
            # Get the data catalog resource policy
            response = self.glueClient.get_resource_policy()
            policyInJson = response.get('PolicyInJson')
            
            if not policyInJson:
                # No policy means no public access
                self.results['PublicAccessibility'] = [1, 'Not Publicly Accessible (No Policy)']
                return
            
            # Parse the policy to check for public access
            import json
            policy = json.loads(policyInJson)
            
            # Check each statement for public principal
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Check if principal allows public access
                if effect == 'Allow':
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        self.results['PublicAccessibility'] = [-1, 'Publicly Accessible']
                        return
            
            # No public access found
            self.results['PublicAccessibility'] = [1, 'Not Publicly Accessible']
            
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'EntityNotFoundException':
                # No resource policy means no public access
                self.results['PublicAccessibility'] = [1, 'Not Publicly Accessible (No Policy)']
            elif error_code == 'AccessDenied':
                # Skip check silently if access denied
                return
            else:
                print(f"Error checking public accessibility: {error_code}")
                self.results['PublicAccessibility'] = [0, f'Error: {error_code}']
                
        except Exception as e:
            print(f"Error checking public accessibility: {e}")
            self.results['PublicAccessibility'] = [0, f'Error: {str(e)}']

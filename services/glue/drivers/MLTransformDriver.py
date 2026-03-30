import boto3
import botocore

from services.Evaluator import Evaluator


class MLTransformDriver(Evaluator):
    """
    Driver for checking AWS Glue ML transform security configurations.
    
    This driver evaluates ML transform security settings:
    - Encryption at rest for ML user data
    """
    
    def __init__(self, transform, glueClient):
        """
        Initialize MLTransformDriver.
        
        Args:
            transform (dict): ML transform configuration from get_ml_transforms()
            glueClient: Boto3 Glue client for API calls
        """
        super().__init__()
        self.transform = transform
        self.glueClient = glueClient
        
        # Set resource name to unique identifier
        transformName = transform.get('Name', transform['TransformId'])
        self._resourceName = f"MLTransform::{transformName}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('transformId', transform['TransformId'])
        self.addII('name', transform.get('Name', 'N/A'))
        self.addII('createdOn', str(transform.get('CreatedOn', 'N/A')))
        self.addII('lastModifiedOn', str(transform.get('LastModifiedOn', 'N/A')))
    
    def _checkEncryptionAtRest(self):
        """
        Check if encryption at rest is enabled for the ML transform.
        
        This checks if MlUserDataEncryption is configured with SSE-KMS mode.
        
        Validates: Requirements 4.12, 6.1, 6.3, 6.4
        Reporter JSON key: MLTransformEncryptionAtRest
        """
        try:
            transformEncryption = self.transform.get('TransformEncryption', {})
            mlUserDataEncryption = transformEncryption.get('MlUserDataEncryption', {})
            
            encryptionMode = mlUserDataEncryption.get('MlUserDataEncryptionMode', 'DISABLED')
            
            if encryptionMode == 'SSE-KMS':
                kmsKeyId = mlUserDataEncryption.get('KmsKeyId', 'N/A')
                self.results['MLTransformEncryptionAtRest'] = [1, f'Enabled (Mode: {encryptionMode}, KMS Key: {kmsKeyId})']
            elif encryptionMode == 'DISABLED':
                self.results['MLTransformEncryptionAtRest'] = [-1, 'Encryption at Rest Disabled']
            else:
                self.results['MLTransformEncryptionAtRest'] = [0, f'Unknown mode: {encryptionMode}']
            
        except Exception as e:
            transformName = self.transform.get('Name', self.transform['TransformId'])
            print(f"Error checking encryption at rest for ML transform {transformName}: {e}")
            self.results['MLTransformEncryptionAtRest'] = [0, f'Error: {str(e)}']

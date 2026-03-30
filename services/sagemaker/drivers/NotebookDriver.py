import boto3
import botocore

from services.Evaluator import Evaluator


class NotebookDriver(Evaluator):
    """
    Driver for checking AWS SageMaker notebook instance security configurations.
    
    This driver evaluates notebook instance security settings:
    - Volume encryption with KMS
    - Root access disabled
    - VPC configuration
    - Direct internet access disabled
    """
    
    def __init__(self, notebook, sagemakerClient):
        """
        Initialize NotebookDriver.
        
        Args:
            notebook (dict): Notebook instance configuration from describe_notebook_instance()
            sagemakerClient: Boto3 SageMaker client for API calls
        """
        super().__init__()
        self.notebook = notebook
        self.sagemakerClient = sagemakerClient
        
        # Set resource name to unique identifier
        self._resourceName = f"Notebook::{notebook['NotebookInstanceName']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('notebookInstanceName', notebook['NotebookInstanceName'])
        self.addII('instanceType', notebook.get('InstanceType', 'N/A'))
        self.addII('notebookInstanceArn', notebook.get('NotebookInstanceArn', 'N/A'))
        self.addII('roleArn', notebook.get('RoleArn', 'N/A'))
        self.addII('creationTime', str(notebook.get('CreationTime', 'N/A')))
        self.addII('lastModifiedTime', str(notebook.get('LastModifiedTime', 'N/A')))
        self.addII('kmsKeyId', notebook.get('KmsKeyId', 'None'))
        self.addII('directInternetAccess', notebook.get('DirectInternetAccess', 'N/A'))
        self.addII('rootAccess', notebook.get('RootAccess', 'N/A'))
    
    def _checkEncryptionEnabled(self):
        """
        Check if KMS encryption is enabled for the notebook instance volume.
        
        Validates: Requirements 5.4
        Reporter JSON key: EncryptionEnabled
        """
        try:
            kmsKeyId = self.notebook.get('KmsKeyId')
            
            if kmsKeyId:
                self.results['EncryptionEnabled'] = [1, f'Enabled (KMS Key: {kmsKeyId})']
            else:
                self.results['EncryptionEnabled'] = [-1, 'KMS Encryption Not Configured']
            
        except Exception as e:
            notebookName = self.notebook.get('NotebookInstanceName', 'Unknown')
            print(f"Error checking encryption for notebook {notebookName}: {e}")
            self.results['EncryptionEnabled'] = [0, f'Error: {str(e)}']
    
    def _checkRootAccessDisabled(self):
        """
        Check if root access is disabled for the notebook instance.
        
        Validates: Requirements 5.5
        Reporter JSON key: RootAccessDisabled
        """
        try:
            rootAccess = self.notebook.get('RootAccess', 'Enabled')
            
            if rootAccess == 'Disabled':
                self.results['RootAccessDisabled'] = [1, 'Root Access Disabled']
            else:
                self.results['RootAccessDisabled'] = [-1, f'Root Access Enabled (Current: {rootAccess})']
            
        except Exception as e:
            notebookName = self.notebook.get('NotebookInstanceName', 'Unknown')
            print(f"Error checking root access for notebook {notebookName}: {e}")
            self.results['RootAccessDisabled'] = [0, f'Error: {str(e)}']
    
    def _checkVpcSettings(self):
        """
        Check if VPC settings are configured for the notebook instance.
        
        Validates: Requirements 5.6
        Reporter JSON key: NotebookVpcSettings
        """
        try:
            subnetId = self.notebook.get('SubnetId')
            securityGroups = self.notebook.get('SecurityGroups', [])
            
            if subnetId:
                sgInfo = f", Security Groups: {', '.join(securityGroups)}" if securityGroups else ""
                self.results['NotebookVpcSettings'] = [1, f'VPC Configured (Subnet: {subnetId}{sgInfo})']
            else:
                self.results['NotebookVpcSettings'] = [-1, 'VPC Not Configured']
            
        except Exception as e:
            notebookName = self.notebook.get('NotebookInstanceName', 'Unknown')
            print(f"Error checking VPC settings for notebook {notebookName}: {e}")
            self.results['NotebookVpcSettings'] = [0, f'Error: {str(e)}']
    
    def _checkDirectInternetAccessDisabled(self):
        """
        Check if direct internet access is disabled for the notebook instance.
        
        Validates: Requirements 5.7
        Reporter JSON key: DirectInternetAccess
        """
        try:
            directInternetAccess = self.notebook.get('DirectInternetAccess', 'Enabled')
            
            if directInternetAccess == 'Disabled':
                self.results['DirectInternetAccess'] = [1, 'Direct Internet Access Disabled']
            else:
                self.results['DirectInternetAccess'] = [-1, f'Direct Internet Access Enabled (Current: {directInternetAccess})']
            
        except Exception as e:
            notebookName = self.notebook.get('NotebookInstanceName', 'Unknown')
            print(f"Error checking direct internet access for notebook {notebookName}: {e}")
            self.results['DirectInternetAccess'] = [0, f'Error: {str(e)}']
    
    def _checkLifecycleConfigAttached(self):
        """
        Check if lifecycle configuration is attached to the notebook instance.
        
        Lifecycle configurations enable:
        - Automated setup and teardown
        - Consistent environment configuration
        - Package installation automation
        
        PASS: NotebookInstanceLifecycleConfigName is configured
        INFO: No lifecycle config attached (advisory)
        """
        try:
            lifecycleConfigName = self.notebook.get('NotebookInstanceLifecycleConfigName')
            
            if lifecycleConfigName:
                self.results['NotebookLifecycleConfigAttached'] = [
                    1,
                    f'Lifecycle configuration attached: {lifecycleConfigName}'
                ]
            else:
                self.results['NotebookLifecycleConfigAttached'] = [
                    -1,
                    'No lifecycle configuration attached. Consider using lifecycle configs for automation'
                ]
            
        except Exception as e:
            notebookName = self.notebook.get('NotebookInstanceName', 'Unknown')
            print(f"Error checking lifecycle config for notebook {notebookName}: {e}")
            self.results['NotebookLifecycleConfigAttached'] = [0, f'Error: {str(e)}']


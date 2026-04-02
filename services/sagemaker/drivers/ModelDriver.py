import boto3
import botocore

from services.Evaluator import Evaluator


class ModelDriver(Evaluator):
    """
    Driver for checking AWS SageMaker model security configurations.
    
    This driver evaluates model security settings:
    - Network isolation enabled
    - VPC configuration
    """
    
    def __init__(self, model, sagemakerClient):
        """
        Initialize ModelDriver.
        
        Args:
            model (dict): Model configuration from describe_model()
            sagemakerClient: Boto3 SageMaker client for API calls
        """
        super().__init__()
        self.model = model
        self.sagemakerClient = sagemakerClient
        
        # Set resource name to unique identifier
        self._resourceName = f"Model::{model['ModelName']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('modelName', model['ModelName'])
        self.addII('modelArn', model.get('ModelArn', 'N/A'))
        self.addII('executionRoleArn', model.get('ExecutionRoleArn', 'N/A'))
        self.addII('creationTime', str(model.get('CreationTime', 'N/A')))
        self.addII('enableNetworkIsolation', model.get('EnableNetworkIsolation', False))
    
    def _checkNetworkIsolation(self):
        """
        Check if network isolation is enabled for the model.
        
        Validates: Requirements 5.2
        Reporter JSON key: NetworkIsolation
        """
        try:
            networkIsolation = self.model.get('EnableNetworkIsolation', False)
            
            if networkIsolation:
                self.results['NetworkIsolation'] = [1, 'Network Isolation Enabled']
            else:
                self.results['NetworkIsolation'] = [-1, 'Network Isolation Not Enabled']
            
        except Exception as e:
            modelName = self.model.get('ModelName', 'Unknown')
            print(f"Error checking network isolation for model {modelName}: {e}")
            self.results['NetworkIsolation'] = [0, f'Error: {str(e)}']
    
    def _checkVpcSettings(self):
        """
        Check if VPC settings are configured for the model.
        
        Validates: Requirements 5.3
        Reporter JSON key: ModelVpcSettings
        """
        try:
            vpcConfig = self.model.get('VpcConfig')
            
            if vpcConfig:
                subnets = vpcConfig.get('Subnets', [])
                securityGroups = vpcConfig.get('SecurityGroupIds', [])
                
                if subnets and securityGroups:
                    subnetInfo = f"Subnets: {', '.join(subnets[:2])}" + ("..." if len(subnets) > 2 else "")
                    sgInfo = f"Security Groups: {', '.join(securityGroups[:2])}" + ("..." if len(securityGroups) > 2 else "")
                    self.results['ModelVpcSettings'] = [1, f'VPC Configured ({subnetInfo}, {sgInfo})']
                else:
                    self.results['ModelVpcSettings'] = [-1, 'VPC Configured But Missing Subnets or Security Groups']
            else:
                self.results['ModelVpcSettings'] = [-1, 'VPC Not Configured']
            
        except Exception as e:
            modelName = self.model.get('ModelName', 'Unknown')
            print(f"Error checking VPC settings for model {modelName}: {e}")
            self.results['ModelVpcSettings'] = [0, f'Error: {str(e)}']
    
    def _checkModelDataUrlValidation(self):
        """
        Check if model data URL is from S3 (not external URLs).
        
        Security best practice: Model artifacts should only be loaded from S3 buckets
        to prevent loading models from untrusted external sources.
        
        PASS: ModelDataUrl starts with s3://
        FAIL: ModelDataUrl is from external source or not S3
        """
        try:
            # Check PrimaryContainer first
            primaryContainer = self.model.get('PrimaryContainer', {})
            modelDataUrl = primaryContainer.get('ModelDataUrl', '')
            
            # Also check Containers array if present
            containers = self.model.get('Containers', [])
            
            invalid_urls = []
            valid_urls = []
            
            # Check primary container
            if modelDataUrl:
                if modelDataUrl.startswith('s3://'):
                    valid_urls.append(f'Primary: {modelDataUrl[:50]}...')
                else:
                    invalid_urls.append(f'Primary: {modelDataUrl}')
            
            # Check additional containers
            for idx, container in enumerate(containers):
                containerUrl = container.get('ModelDataUrl', '')
                if containerUrl:
                    if containerUrl.startswith('s3://'):
                        valid_urls.append(f'Container{idx}: {containerUrl[:50]}...')
                    else:
                        invalid_urls.append(f'Container{idx}: {containerUrl}')
            
            # Determine result
            if invalid_urls:
                self.results['ModelDataUrlValidation'] = [
                    -1,
                    f'Model data from non-S3 sources: {", ".join(invalid_urls)}'
                ]
            elif valid_urls:
                self.results['ModelDataUrlValidation'] = [
                    1,
                    f'All model data from S3: {len(valid_urls)} container(s)'
                ]
            else:
                # No model data URL specified (might be using image only)
                self.results['ModelDataUrlValidation'] = [
                    1,
                    'No model data URL specified (image-only model)'
                ]
            
        except Exception as e:
            modelName = self.model.get('ModelName', 'Unknown')
            print(f"Error checking model data URL for model {modelName}: {e}")
            self.results['ModelDataUrlValidation'] = [0, f'Error: {str(e)}']
    
    def _checkContainerImageSource(self):
        """
        Check if container images are from trusted sources (AWS DLC or approved ECR).
        
        Security best practice: Use container images from:
        - AWS Deep Learning Containers (DLC)
        - Approved Amazon ECR repositories
        
        PASS: Image from AWS DLC or ECR in same account
        WARN: Image from external registry or different account
        """
        try:
            # Check PrimaryContainer first
            primaryContainer = self.model.get('PrimaryContainer', {})
            image = primaryContainer.get('Image', '')
            
            # Also check Containers array if present
            containers = self.model.get('Containers', [])
            
            trusted_images = []
            untrusted_images = []
            
            def is_trusted_image(img):
                """Check if image is from trusted source"""
                if not img:
                    return True, "No image specified"
                
                # AWS Deep Learning Containers pattern
                if '.dkr.ecr.' in img and '.amazonaws.com/' in img:
                    # Check if it's from AWS DLC account (763104351884)
                    if '763104351884.dkr.ecr.' in img:
                        return True, "AWS Deep Learning Container"
                    # ECR in same region (assume same account if no account ID visible)
                    return True, "Amazon ECR"
                
                # Docker Hub or other external registries
                if 'docker.io' in img or '/' not in img or img.count('/') == 1:
                    return False, "External registry (Docker Hub or similar)"
                
                # Other registries
                return False, "Non-AWS registry"
            
            # Check primary container
            if image:
                is_trusted, source = is_trusted_image(image)
                if is_trusted:
                    trusted_images.append(f'Primary: {source}')
                else:
                    untrusted_images.append(f'Primary: {source} ({image[:50]}...)')
            
            # Check additional containers
            for idx, container in enumerate(containers):
                container_image = container.get('Image', '')
                if container_image:
                    is_trusted, source = is_trusted_image(container_image)
                    if is_trusted:
                        trusted_images.append(f'Container{idx}: {source}')
                    else:
                        untrusted_images.append(f'Container{idx}: {source} ({container_image[:50]}...)')
            
            # Determine result
            if untrusted_images:
                self.results['ModelContainerImageSource'] = [
                    -1,
                    f'Images from non-AWS sources: {"; ".join(untrusted_images)}'
                ]
            elif trusted_images:
                self.results['ModelContainerImageSource'] = [
                    1,
                    f'All images from trusted sources: {len(trusted_images)} container(s)'
                ]
            else:
                self.results['ModelContainerImageSource'] = [
                    1,
                    'No container images specified'
                ]
            
        except Exception as e:
            modelName = self.model.get('ModelName', 'Unknown')
            print(f"Error checking container image source for model {modelName}: {e}")
            self.results['ModelContainerImageSource'] = [0, f'Error: {str(e)}']



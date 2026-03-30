import boto3
import botocore

from services.Evaluator import Evaluator


class EndpointConfigDriver(Evaluator):
    """
    Driver for checking AWS SageMaker endpoint configuration settings.
    
    This driver evaluates endpoint configuration for high availability:
    - Production variant instance count (at least 2 for HA)
    """
    
    def __init__(self, endpointConfig, sagemakerClient):
        """
        Initialize EndpointConfigDriver.
        
        Args:
            endpointConfig (dict): Endpoint configuration from describe_endpoint_config()
            sagemakerClient: Boto3 SageMaker client for API calls
        """
        super().__init__()
        self.endpointConfig = endpointConfig
        self.sagemakerClient = sagemakerClient
        
        # Set resource name to unique identifier
        self._resourceName = f"EndpointConfig::{endpointConfig['EndpointConfigName']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('endpointConfigName', endpointConfig['EndpointConfigName'])
        self.addII('endpointConfigArn', endpointConfig.get('EndpointConfigArn', 'N/A'))
        self.addII('creationTime', str(endpointConfig.get('CreationTime', 'N/A')))
        
        # Store production variant information
        productionVariants = endpointConfig.get('ProductionVariants', [])
        if productionVariants:
            variantInfo = []
            for variant in productionVariants:
                variantInfo.append(f"{variant.get('VariantName', 'Unknown')}:{variant.get('InitialInstanceCount', 0)}")
            self.addII('productionVariants', ', '.join(variantInfo))
    
    def _checkProductionVariantInstanceCount(self):
        """
        Check if production variants have at least 2 instances for high availability.
        
        Validates: Requirements 5.1, 6.2, 6.3, 6.4
        Reporter JSON key: ProductionVariantInstanceCount
        """
        try:
            productionVariants = self.endpointConfig.get('ProductionVariants', [])
            
            if not productionVariants:
                self.results['ProductionVariantInstanceCount'] = [0, 'No Production Variants Configured']
                return
            
            # Check each production variant for instance count
            lowInstanceVariants = []
            haVariants = []
            
            for variant in productionVariants:
                variantName = variant.get('VariantName', 'Unknown')
                instanceCount = variant.get('InitialInstanceCount', 0)
                
                if instanceCount < 2:
                    lowInstanceVariants.append(f"{variantName}({instanceCount})")
                else:
                    haVariants.append(f"{variantName}({instanceCount})")
            
            if lowInstanceVariants:
                variantList = ', '.join(lowInstanceVariants)
                self.results['ProductionVariantInstanceCount'] = [
                    -1, 
                    f'Variants with <2 instances: {variantList}'
                ]
            else:
                variantList = ', '.join(haVariants)
                self.results['ProductionVariantInstanceCount'] = [
                    1, 
                    f'All variants have ≥2 instances: {variantList}'
                ]
            
        except Exception as e:
            configName = self.endpointConfig.get('EndpointConfigName', 'Unknown')
            print(f"Error checking production variant instance count for endpoint config {configName}: {e}")
            self.results['ProductionVariantInstanceCount'] = [0, f'Error: {str(e)}']
    
    def _checkDataCaptureEnabled(self):
        """
        Check if data capture is enabled for model monitoring.
        
        Data capture enables:
        - Model quality monitoring
        - Data drift detection
        - Model performance analysis
        
        PASS: DataCaptureConfig is configured with destination S3 URI
        INFO: No data capture configured (advisory)
        """
        try:
            dataCaptureConfig = self.endpointConfig.get('DataCaptureConfig', {})
            
            if dataCaptureConfig:
                enabled = dataCaptureConfig.get('EnableCapture', False)
                destinationS3Uri = dataCaptureConfig.get('DestinationS3Uri', '')
                capturePercentage = dataCaptureConfig.get('InitialSamplingPercentage', 0)
                
                if enabled and destinationS3Uri:
                    self.results['EndpointDataCaptureEnabled'] = [
                        1,
                        f'Data capture enabled ({capturePercentage}% sampling to {destinationS3Uri[:50]}...)'
                    ]
                else:
                    self.results['EndpointDataCaptureEnabled'] = [
                        -1,
                        'Data capture configured but not enabled or missing destination'
                    ]
            else:
                self.results['EndpointDataCaptureEnabled'] = [
                    -1,
                    'No data capture configured. Consider enabling for model monitoring and drift detection'
                ]
            
        except Exception as e:
            configName = self.endpointConfig.get('EndpointConfigName', 'Unknown')
            print(f"Error checking data capture for endpoint config {configName}: {e}")
            self.results['EndpointDataCaptureEnabled'] = [0, f'Error: {str(e)}']
    
    def _checkInstanceTypeConsistency(self):
        """
        Check if all production variants use the same instance type.
        
        Using consistent instance types ensures:
        - Predictable performance across variants
        - Easier capacity planning
        - Simplified cost analysis
        
        PASS: All variants use same instance type or only one variant
        INFO: Multiple instance types used (advisory)
        """
        try:
            productionVariants = self.endpointConfig.get('ProductionVariants', [])
            
            if not productionVariants:
                self.results['EndpointInstanceTypeConsistency'] = [0, 'No Production Variants Configured']
                return
            
            if len(productionVariants) == 1:
                instanceType = productionVariants[0].get('InstanceType', 'Unknown')
                self.results['EndpointInstanceTypeConsistency'] = [
                    1,
                    f'Single variant using {instanceType}'
                ]
                return
            
            # Check if all variants use same instance type
            instanceTypes = set()
            variantsByType = {}
            
            for variant in productionVariants:
                variantName = variant.get('VariantName', 'Unknown')
                instanceType = variant.get('InstanceType', 'Unknown')
                instanceTypes.add(instanceType)
                
                if instanceType not in variantsByType:
                    variantsByType[instanceType] = []
                variantsByType[instanceType].append(variantName)
            
            if len(instanceTypes) == 1:
                instanceType = list(instanceTypes)[0]
                self.results['EndpointInstanceTypeConsistency'] = [
                    1,
                    f'All {len(productionVariants)} variants use consistent instance type: {instanceType}'
                ]
            else:
                typeInfo = [f"{itype}: {', '.join(variants)}" for itype, variants in variantsByType.items()]
                self.results['EndpointInstanceTypeConsistency'] = [
                    -1,
                    f'Multiple instance types used: {"; ".join(typeInfo)}'
                ]
            
        except Exception as e:
            configName = self.endpointConfig.get('EndpointConfigName', 'Unknown')
            print(f"Error checking instance type consistency for endpoint config {configName}: {e}")
            self.results['EndpointInstanceTypeConsistency'] = [0, f'Error: {str(e)}']


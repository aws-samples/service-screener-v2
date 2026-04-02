import boto3
import botocore

from services.Evaluator import Evaluator


class TrainingJobDriver(Evaluator):
    """
    Driver for checking AWS SageMaker training job security configurations.
    
    This driver evaluates training job security settings:
    - Inter-container traffic encryption
    - Network isolation
    - Volume encryption with KMS
    - Output encryption with KMS
    - VPC configuration
    """
    
    def __init__(self, trainingJob, sagemakerClient):
        """
        Initialize TrainingJobDriver.
        
        Args:
            trainingJob (dict): Training job configuration from describe_training_job()
            sagemakerClient: Boto3 SageMaker client for API calls
        """
        super().__init__()
        self.trainingJob = trainingJob
        self.sagemakerClient = sagemakerClient
        
        # Set resource name to unique identifier
        self._resourceName = f"TrainingJob::{trainingJob['TrainingJobName']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('trainingJobName', trainingJob['TrainingJobName'])
        self.addII('trainingJobArn', trainingJob.get('TrainingJobArn', 'N/A'))
        self.addII('roleArn', trainingJob.get('RoleArn', 'N/A'))
        self.addII('creationTime', str(trainingJob.get('CreationTime', 'N/A')))
        self.addII('trainingJobStatus', trainingJob.get('TrainingJobStatus', 'N/A'))

    
    def _checkInterContainerEncryption(self):
        """
        Check if inter-container traffic encryption is enabled for the training job.
        
        Validates: Requirements 5.8
        Reporter JSON key: InterContainerEncryption
        """
        try:
            interContainerEncryption = self.trainingJob.get('EnableInterContainerTrafficEncryption', False)
            
            if interContainerEncryption:
                self.results['InterContainerEncryption'] = [1, 'Inter-Container Traffic Encryption Enabled']
            else:
                self.results['InterContainerEncryption'] = [-1, 'Inter-Container Traffic Encryption Not Enabled']
            
        except Exception as e:
            jobName = self.trainingJob.get('TrainingJobName', 'Unknown')
            print(f"Error checking inter-container encryption for training job {jobName}: {e}")
            self.results['InterContainerEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkNetworkIsolation(self):
        """
        Check if network isolation is enabled for the training job.
        
        Validates: Requirements 5.9
        Reporter JSON key: TrainingNetworkIsolation
        """
        try:
            networkIsolation = self.trainingJob.get('EnableNetworkIsolation', False)
            
            if networkIsolation:
                self.results['TrainingNetworkIsolation'] = [1, 'Network Isolation Enabled']
            else:
                self.results['TrainingNetworkIsolation'] = [-1, 'Network Isolation Not Enabled']
            
        except Exception as e:
            jobName = self.trainingJob.get('TrainingJobName', 'Unknown')
            print(f"Error checking network isolation for training job {jobName}: {e}")
            self.results['TrainingNetworkIsolation'] = [0, f'Error: {str(e)}']
    
    def _checkVolumeEncryption(self):
        """
        Check if volume encryption with KMS is enabled for the training job.
        
        Validates: Requirements 5.10
        Reporter JSON key: VolumeAndOutputEncryption (combined with output encryption)
        """
        try:
            resourceConfig = self.trainingJob.get('ResourceConfig', {})
            volumeKmsKeyId = resourceConfig.get('VolumeKmsKeyId')
            
            # Store volume encryption status for combined check
            self._volumeEncrypted = bool(volumeKmsKeyId)
            self._volumeKmsKeyId = volumeKmsKeyId
            
            # Run combined check if output encryption has been checked
            if hasattr(self, '_outputEncrypted'):
                self._checkVolumeAndOutputEncryption()
            
        except Exception as e:
            jobName = self.trainingJob.get('TrainingJobName', 'Unknown')
            print(f"Error checking volume encryption for training job {jobName}: {e}")
            self.results['VolumeAndOutputEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkOutputEncryption(self):
        """
        Check if output encryption with KMS is enabled for the training job.
        
        Validates: Requirements 5.11
        Reporter JSON key: VolumeAndOutputEncryption (combined with volume encryption)
        """
        try:
            outputDataConfig = self.trainingJob.get('OutputDataConfig', {})
            outputKmsKeyId = outputDataConfig.get('KmsKeyId')
            
            # Store output encryption status for combined check
            self._outputEncrypted = bool(outputKmsKeyId)
            self._outputKmsKeyId = outputKmsKeyId
            
            # Run combined check if volume encryption has been checked
            if hasattr(self, '_volumeEncrypted'):
                self._checkVolumeAndOutputEncryption()
            
        except Exception as e:
            jobName = self.trainingJob.get('TrainingJobName', 'Unknown')
            print(f"Error checking output encryption for training job {jobName}: {e}")
            self.results['VolumeAndOutputEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkVolumeAndOutputEncryption(self):
        """
        Combined check for volume and output encryption.
        This is called after both _checkVolumeEncryption and _checkOutputEncryption have run.
        """
        if not hasattr(self, '_volumeEncrypted') or not hasattr(self, '_outputEncrypted'):
            return  # Wait for both checks to complete
        
        if self._volumeEncrypted and self._outputEncrypted:
            volumeInfo = f"Volume KMS: {self._volumeKmsKeyId}"
            outputInfo = f"Output KMS: {self._outputKmsKeyId}"
            self.results['VolumeAndOutputEncryption'] = [1, f'Both Encrypted ({volumeInfo}, {outputInfo})']
        elif self._volumeEncrypted:
            self.results['VolumeAndOutputEncryption'] = [-1, f'Only Volume Encrypted (Output Not Encrypted)']
        elif self._outputEncrypted:
            self.results['VolumeAndOutputEncryption'] = [-1, f'Only Output Encrypted (Volume Not Encrypted)']
        else:
            self.results['VolumeAndOutputEncryption'] = [-1, 'Neither Volume Nor Output Encrypted']
    
    def _checkVpcSettings(self):
        """
        Check if VPC settings are configured for the training job.
        
        Validates: Requirements 6.2, 6.3, 6.4
        Reporter JSON key: TrainingVpcSettings
        """
        try:
            vpcConfig = self.trainingJob.get('VpcConfig')
            
            if vpcConfig:
                subnets = vpcConfig.get('Subnets', [])
                securityGroups = vpcConfig.get('SecurityGroupIds', [])
                
                if subnets and securityGroups:
                    subnetInfo = f"Subnets: {', '.join(subnets[:2])}" + ("..." if len(subnets) > 2 else "")
                    sgInfo = f"Security Groups: {', '.join(securityGroups[:2])}" + ("..." if len(securityGroups) > 2 else "")
                    self.results['TrainingVpcSettings'] = [1, f'VPC Configured ({subnetInfo}, {sgInfo})']
                else:
                    self.results['TrainingVpcSettings'] = [-1, 'VPC Configured But Missing Subnets or Security Groups']
            else:
                self.results['TrainingVpcSettings'] = [-1, 'VPC Not Configured']
            
        except Exception as e:
            jobName = self.trainingJob.get('TrainingJobName', 'Unknown')
            print(f"Error checking VPC settings for training job {jobName}: {e}")
            self.results['TrainingVpcSettings'] = [0, f'Error: {str(e)}']
    
    def _checkSpotInstancesEnabled(self):
        """
        Check if managed spot instances are enabled for cost savings.
        
        Managed spot training can reduce training costs by up to 90% by using
        spare EC2 capacity. Best practice for fault-tolerant training workloads.
        
        PASS: EnableManagedSpotTraining is True
        INFO: EnableManagedSpotTraining is False (advisory - not a failure)
        """
        try:
            spotEnabled = self.trainingJob.get('EnableManagedSpotTraining', False)
            
            if spotEnabled:
                # Get max wait time and training time for cost analysis
                maxWaitTime = self.trainingJob.get('StoppingCondition', {}).get('MaxWaitTimeInSeconds', 0)
                maxRunTime = self.trainingJob.get('StoppingCondition', {}).get('MaxRuntimeInSeconds', 0)
                
                self.results['TrainingSpotInstancesEnabled'] = [
                    1,
                    f'Managed spot training enabled (MaxWait: {maxWaitTime}s, MaxRun: {maxRunTime}s)'
                ]
            else:
                # Not using spot instances - advisory message
                self.results['TrainingSpotInstancesEnabled'] = [
                    -1,
                    'Managed spot training not enabled. Consider using spot instances for up to 90% cost savings'
                ]
            
        except Exception as e:
            jobName = self.trainingJob.get('TrainingJobName', 'Unknown')
            print(f"Error checking spot instances for training job {jobName}: {e}")
            self.results['TrainingSpotInstancesEnabled'] = [0, f'Error: {str(e)}']
    
    def _checkCheckpointConfigured(self):
        """
        Check if checkpoint configuration is set for training job resumption.
        
        Checkpoints enable:
        - Resuming interrupted training jobs (especially important for spot instances)
        - Saving training progress periodically
        - Reducing costs by not restarting from scratch
        
        PASS: CheckpointConfig with S3Uri is configured
        FAIL: No checkpoint configuration
        """
        try:
            checkpointConfig = self.trainingJob.get('CheckpointConfig', {})
            s3Uri = checkpointConfig.get('S3Uri', '')
            
            if s3Uri:
                localPath = checkpointConfig.get('LocalPath', '/opt/ml/checkpoints')
                self.results['TrainingCheckpointConfigured'] = [
                    1,
                    f'Checkpoint configured (S3: {s3Uri[:50]}..., Local: {localPath})'
                ]
            else:
                # Check if spot training is enabled - checkpoints are more critical for spot
                spotEnabled = self.trainingJob.get('EnableManagedSpotTraining', False)
                if spotEnabled:
                    self.results['TrainingCheckpointConfigured'] = [
                        -1,
                        'No checkpoint configured. Highly recommended for spot training to resume interrupted jobs'
                    ]
                else:
                    self.results['TrainingCheckpointConfigured'] = [
                        -1,
                        'No checkpoint configured. Recommended to enable resumption of interrupted training'
                    ]
            
        except Exception as e:
            jobName = self.trainingJob.get('TrainingJobName', 'Unknown')
            print(f"Error checking checkpoint config for training job {jobName}: {e}")
            self.results['TrainingCheckpointConfigured'] = [0, f'Error: {str(e)}']


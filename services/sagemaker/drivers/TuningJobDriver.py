import botocore

from services.Evaluator import Evaluator


class TuningJobDriver(Evaluator):
    """
    Driver for checking AWS SageMaker hyperparameter tuning job configurations.
    
    This driver evaluates tuning job cost optimization settings:
    - Early stopping enabled
    """
    
    def __init__(self, tuningJob, sagemakerClient):
        """
        Initialize TuningJobDriver.
        
        Args:
            tuningJob (dict): Tuning job configuration from describe_hyper_parameter_tuning_job()
            sagemakerClient: Boto3 SageMaker client for API calls
        """
        super().__init__()
        self.tuningJob = tuningJob
        self.sagemakerClient = sagemakerClient
        
        # Set resource name to unique identifier
        self._resourceName = f"TuningJob::{tuningJob['HyperParameterTuningJobName']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('tuningJobName', tuningJob['HyperParameterTuningJobName'])
        self.addII('tuningJobArn', tuningJob.get('HyperParameterTuningJobArn', 'N/A'))
        self.addII('tuningJobStatus', tuningJob.get('HyperParameterTuningJobStatus', 'N/A'))
        self.addII('creationTime', str(tuningJob.get('CreationTime', 'N/A')))
    
    def _checkEarlyStoppingEnabled(self):
        """
        Check if early stopping is enabled for hyperparameter tuning job.
        
        Early stopping:
        - Stops underperforming training jobs automatically
        - Reduces training costs significantly
        - Speeds up hyperparameter search
        
        PASS: TrainingJobEarlyStoppingType is 'Auto'
        INFO: Early stopping not enabled (advisory)
        """
        try:
            earlyStoppingType = self.tuningJob.get('TrainingJobEarlyStoppingType', 'Off')
            
            if earlyStoppingType == 'Auto':
                # Get additional info about the tuning job
                strategy = self.tuningJob.get('HyperParameterTuningJobConfig', {}).get('Strategy', 'Unknown')
                maxJobs = self.tuningJob.get('HyperParameterTuningJobConfig', {}).get('ResourceLimits', {}).get('MaxNumberOfTrainingJobs', 0)
                
                self.results['HyperparameterTuningEarlyStopping'] = [
                    1,
                    f'Early stopping enabled (Strategy: {strategy}, MaxJobs: {maxJobs})'
                ]
            else:
                # Not using early stopping - advisory message
                maxJobs = self.tuningJob.get('HyperParameterTuningJobConfig', {}).get('ResourceLimits', {}).get('MaxNumberOfTrainingJobs', 0)
                self.results['HyperparameterTuningEarlyStopping'] = [
                    -1,
                    f'Early stopping not enabled (MaxJobs: {maxJobs}). Consider enabling to reduce training costs'
                ]
            
        except Exception as e:
            jobName = self.tuningJob.get('HyperParameterTuningJobName', 'Unknown')
            print(f"Error checking early stopping for tuning job {jobName}: {e}")
            self.results['HyperparameterTuningEarlyStopping'] = [0, f'Error: {str(e)}']

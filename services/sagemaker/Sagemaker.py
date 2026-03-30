import boto3
import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

# Driver imports - will be uncommented when drivers are implemented (Task 8)
from services.sagemaker.drivers.NotebookDriver import NotebookDriver
from services.sagemaker.drivers.TrainingJobDriver import TrainingJobDriver
from services.sagemaker.drivers.ModelDriver import ModelDriver
from services.sagemaker.drivers.EndpointConfigDriver import EndpointConfigDriver
from services.sagemaker.drivers.EndpointDriver import EndpointDriver
from services.sagemaker.drivers.TuningJobDriver import TuningJobDriver


class Sagemaker(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        
        # Initialize SageMaker client
        self.sagemakerClient = ssBoto.client('sagemaker', config=self.bConfig)
        
        # Initialize Application Auto Scaling client for endpoint auto-scaling checks
        self.autoscalingClient = ssBoto.client('application-autoscaling', config=self.bConfig)
        
        return
    
    ## method to get resources for the services
    ## return the array of the resources
    def getResources(self):
        resources = {
            'notebooks': [],
            'trainingJobs': [],
            'models': [],
            'endpointConfigs': [],
            'endpoints': [],
            'tuningJobs': []
        }
        
        # Get notebook instances with pagination
        try:
            paginator = self.sagemakerClient.get_paginator('list_notebook_instances')
            for page in paginator.paginate():
                for notebook in page.get('NotebookInstances', []):
                    notebookName = notebook['NotebookInstanceName']
                    
                    # Get detailed notebook configuration
                    try:
                        notebookDetails = self.sagemakerClient.describe_notebook_instance(
                            NotebookInstanceName=notebookName
                        )
                        
                        # Handle tag filtering if configured
                        if self.tags:
                            try:
                                notebookArn = notebookDetails['NotebookInstanceArn']
                                tagsResponse = self.sagemakerClient.list_tags(ResourceArn=notebookArn)
                                tags = tagsResponse.get('Tags', [])
                                if not self.resourceHasTags(tags):
                                    continue
                            except botocore.exceptions.ClientError:
                                continue
                        
                        _pi('SageMaker', f"Notebook: {notebookName}")
                        resources['notebooks'].append(notebookDetails)
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] != 'AccessDenied':
                            print(f"Error describing notebook {notebookName}: {e}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing notebook instances: {e}")
        
        # Get training jobs with pagination
        try:
            paginator = self.sagemakerClient.get_paginator('list_training_jobs')
            for page in paginator.paginate():
                for job in page.get('TrainingJobSummaries', []):
                    jobName = job['TrainingJobName']
                    
                    # Get detailed training job configuration
                    try:
                        jobDetails = self.sagemakerClient.describe_training_job(
                            TrainingJobName=jobName
                        )
                        
                        # Handle tag filtering if configured
                        if self.tags:
                            try:
                                jobArn = jobDetails['TrainingJobArn']
                                tagsResponse = self.sagemakerClient.list_tags(ResourceArn=jobArn)
                                tags = tagsResponse.get('Tags', [])
                                if not self.resourceHasTags(tags):
                                    continue
                            except botocore.exceptions.ClientError:
                                continue
                        
                        _pi('SageMaker', f"Training Job: {jobName}")
                        resources['trainingJobs'].append(jobDetails)
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] != 'AccessDenied':
                            print(f"Error describing training job {jobName}: {e}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing training jobs: {e}")
        
        # Get models with pagination
        try:
            paginator = self.sagemakerClient.get_paginator('list_models')
            for page in paginator.paginate():
                for model in page.get('Models', []):
                    modelName = model['ModelName']
                    
                    # Get detailed model configuration
                    try:
                        modelDetails = self.sagemakerClient.describe_model(
                            ModelName=modelName
                        )
                        
                        # Handle tag filtering if configured
                        if self.tags:
                            try:
                                modelArn = modelDetails['ModelArn']
                                tagsResponse = self.sagemakerClient.list_tags(ResourceArn=modelArn)
                                tags = tagsResponse.get('Tags', [])
                                if not self.resourceHasTags(tags):
                                    continue
                            except botocore.exceptions.ClientError:
                                continue
                        
                        _pi('SageMaker', f"Model: {modelName}")
                        resources['models'].append(modelDetails)
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] != 'AccessDenied':
                            print(f"Error describing model {modelName}: {e}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing models: {e}")
        
        # Get endpoint configurations with pagination
        try:
            paginator = self.sagemakerClient.get_paginator('list_endpoint_configs')
            for page in paginator.paginate():
                for config in page.get('EndpointConfigs', []):
                    configName = config['EndpointConfigName']
                    
                    # Get detailed endpoint configuration
                    try:
                        configDetails = self.sagemakerClient.describe_endpoint_config(
                            EndpointConfigName=configName
                        )
                        
                        # Handle tag filtering if configured
                        if self.tags:
                            try:
                                configArn = configDetails['EndpointConfigArn']
                                tagsResponse = self.sagemakerClient.list_tags(ResourceArn=configArn)
                                tags = tagsResponse.get('Tags', [])
                                if not self.resourceHasTags(tags):
                                    continue
                            except botocore.exceptions.ClientError:
                                continue
                        
                        _pi('SageMaker', f"Endpoint Config: {configName}")
                        resources['endpointConfigs'].append(configDetails)
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] != 'AccessDenied':
                            print(f"Error describing endpoint config {configName}: {e}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing endpoint configs: {e}")
        
        # Get endpoints with pagination
        try:
            paginator = self.sagemakerClient.get_paginator('list_endpoints')
            for page in paginator.paginate():
                for endpoint in page.get('Endpoints', []):
                    endpointName = endpoint['EndpointName']
                    
                    # Get detailed endpoint configuration
                    try:
                        endpointDetails = self.sagemakerClient.describe_endpoint(
                            EndpointName=endpointName
                        )
                        
                        # Handle tag filtering if configured
                        if self.tags:
                            try:
                                endpointArn = endpointDetails['EndpointArn']
                                tagsResponse = self.sagemakerClient.list_tags(ResourceArn=endpointArn)
                                tags = tagsResponse.get('Tags', [])
                                if not self.resourceHasTags(tags):
                                    continue
                            except botocore.exceptions.ClientError:
                                continue
                        
                        _pi('SageMaker', f"Endpoint: {endpointName}")
                        resources['endpoints'].append(endpointDetails)
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] != 'AccessDenied':
                            print(f"Error describing endpoint {endpointName}: {e}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing endpoints: {e}")
        
        # Get hyperparameter tuning jobs with pagination
        try:
            paginator = self.sagemakerClient.get_paginator('list_hyper_parameter_tuning_jobs')
            for page in paginator.paginate():
                for tuningJob in page.get('HyperParameterTuningJobSummaries', []):
                    tuningJobName = tuningJob['HyperParameterTuningJobName']
                    
                    # Get detailed tuning job configuration
                    try:
                        tuningJobDetails = self.sagemakerClient.describe_hyper_parameter_tuning_job(
                            HyperParameterTuningJobName=tuningJobName
                        )
                        
                        # Handle tag filtering if configured
                        if self.tags:
                            try:
                                tuningJobArn = tuningJobDetails['HyperParameterTuningJobArn']
                                tagsResponse = self.sagemakerClient.list_tags(ResourceArn=tuningJobArn)
                                tags = tagsResponse.get('Tags', [])
                                if not self.resourceHasTags(tags):
                                    continue
                            except botocore.exceptions.ClientError:
                                continue
                        
                        _pi('SageMaker', f"Tuning Job: {tuningJobName}")
                        resources['tuningJobs'].append(tuningJobDetails)
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] != 'AccessDenied':
                            print(f"Error describing tuning job {tuningJobName}: {e}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing tuning jobs: {e}")
        
        return resources
        
    
    def advise(self):
        objs = {}
        
        # Get all SageMaker resources
        resources = self.getResources()
        
        # NOTE: The following code requires driver classes from Task 8
        # Uncomment when NotebookDriver, TrainingJobDriver, ModelDriver, and EndpointConfigDriver are implemented
        
        # Check notebook instances
        for notebook in resources['notebooks']:
            try:
                notebookName = notebook['NotebookInstanceName']
                _pi('SageMaker', f"Analyzing Notebook: {notebookName}")
                obj = NotebookDriver(notebook, self.sagemakerClient)
                obj.run(self.__class__)
                objs[f"Notebook::{notebookName}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing notebook {notebookName}: {e}")
        
        # Check training jobs
        for job in resources['trainingJobs']:
            try:
                jobName = job['TrainingJobName']
                _pi('SageMaker', f"Analyzing Training Job: {jobName}")
                obj = TrainingJobDriver(job, self.sagemakerClient)
                obj.run(self.__class__)
                objs[f"TrainingJob::{jobName}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing training job {jobName}: {e}")
        
        # Check models
        for model in resources['models']:
            try:
                modelName = model['ModelName']
                _pi('SageMaker', f"Analyzing Model: {modelName}")
                obj = ModelDriver(model, self.sagemakerClient)
                obj.run(self.__class__)
                objs[f"Model::{modelName}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing model {modelName}: {e}")
        
        # Check endpoint configurations
        for config in resources['endpointConfigs']:
            try:
                configName = config['EndpointConfigName']
                _pi('SageMaker', f"Analyzing Endpoint Config: {configName}")
                obj = EndpointConfigDriver(config, self.sagemakerClient)
                obj.run(self.__class__)
                objs[f"EndpointConfig::{configName}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing endpoint config {configName}: {e}")
        
        # Check endpoints
        for endpoint in resources['endpoints']:
            try:
                endpointName = endpoint['EndpointName']
                _pi('SageMaker', f"Analyzing Endpoint: {endpointName}")
                obj = EndpointDriver(endpoint, self.sagemakerClient, self.autoscalingClient)
                obj.run(self.__class__)
                objs[f"Endpoint::{endpointName}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing endpoint {endpointName}: {e}")
        
        # Check hyperparameter tuning jobs
        for tuningJob in resources['tuningJobs']:
            try:
                tuningJobName = tuningJob['HyperParameterTuningJobName']
                _pi('SageMaker', f"Analyzing Tuning Job: {tuningJobName}")
                obj = TuningJobDriver(tuningJob, self.sagemakerClient)
                obj.run(self.__class__)
                objs[f"TuningJob::{tuningJobName}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing tuning job {tuningJobName}: {e}")
        
        return objs
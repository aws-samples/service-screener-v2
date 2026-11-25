import json
import concurrent.futures as cf

import boto3
import botocore

from utils.Config import Config
from utils.Tools import _pi, _warn
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
    
    ## Historical resource types (training/tuning jobs, models, endpoint configs)
    ## accumulate into the thousands. Only the most recent HISTORY_LIMIT of each
    ## are evaluated; models and endpoint configs used by live endpoints are
    ## always evaluated. Override with --others '{"sagemakerHistoryLimit": N}'.
    HISTORY_LIMIT = 100
    PAGE_SIZE = 100
    DESCRIBE_WORKERS = 8

    def _historyLimit(self):
        try:
            others = (Config.get('_SS_PARAMS', {}) or {}).get('others')
            if others:
                val = int(json.loads(others).get('sagemakerHistoryLimit', self.HISTORY_LIMIT))
                if val > 0:
                    return val
        except (ValueError, TypeError, AttributeError):
            pass
        return self.HISTORY_LIMIT

    def _listNewestFirst(self, listOp, listKey, limit=None):
        """List summaries newest first. Returns (summaries, truncated)."""
        summaries = []
        paginator = self.sagemakerClient.get_paginator(listOp)
        pages = paginator.paginate(SortBy='CreationTime', SortOrder='Descending',
                                   PaginationConfig={'PageSize': self.PAGE_SIZE})
        for page in pages:
            items = page.get(listKey, [])
            if limit is not None and len(summaries) + len(items) > limit:
                summaries.extend(items[:limit - len(summaries)])
                return summaries, True
            summaries.extend(items)
            if limit is not None and len(summaries) >= limit:
                return summaries, bool(page.get('NextToken'))
        return summaries, False

    def _hasRequiredTags(self, arn):
        if not self.tags:
            return True
        try:
            tags = self.sagemakerClient.list_tags(ResourceArn=arn).get('Tags', [])
        except botocore.exceptions.ClientError:
            return False
        return self.resourceHasTags(tags)

    def _collect(self, label, listOp, listKey, nameKey, arnKey, describe, driverName, idPrefix,
                 limit=None, mustInclude=()):
        """List (newest first, optionally capped), then describe the items that
        are not already checkpointed, in parallel. Items named in mustInclude
        are always described, even when older than the cap."""
        try:
            summaries, truncated = self._listNewestFirst(listOp, listKey, limit)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] not in ('AccessDenied', 'AccessDeniedException'):
                print(f"Error listing {label}: {e}")
            return []

        listed = {x[nameKey] for x in summaries}
        extraNames = [n for n in mustInclude if n and n not in listed]
        if truncated:
            _warn(f"SageMaker {label}: evaluating the {limit} most recent (older ones not scanned"
                  f"{'; plus ' + str(len(extraNames)) + ' in use by endpoints' if extraNames else ''}). "
                  f"Raise with --others '{{\"sagemakerHistoryLimit\": N}}'.")

        extras = [{nameKey: n} for n in extraNames]
        pending = {x[nameKey] for x in self.registerItems(
            driverName, summaries + extras,
            idFn=lambda x: f"{idPrefix}::{x[nameKey]}")}

        resources = []
        # Already checkpointed: keep the summary (or a name stub for in-use items
        # older than the cap) so advise() still builds the driver and
        # Evaluator.run() serves the cached result.
        resources.extend(x for x in summaries + extras if x[nameKey] not in pending)
        names = [n for n in [x[nameKey] for x in summaries] + extraNames if n in pending]

        def _one(name):
            try:
                detail = describe(name)
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                if code not in ('AccessDenied', 'AccessDeniedException', 'ValidationException'):
                    print(f"Error describing {label} {name}: {e}")
                return None
            if not self._hasRequiredTags(detail.get(arnKey)):
                return None
            return detail

        if names:
            workers = min(self.DESCRIBE_WORKERS, len(names))
            with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                for name, detail in zip(names, ex.map(_one, names)):
                    if detail is not None:
                        _pi('SageMaker', f"{label}: {name}")
                        resources.append(detail)
        return resources

    def _fieldValues(self, items, nameKey, field, describe):
        """Return {name: item[field]} for items, describing (in parallel) the ones that
        lack the field - e.g. checkpointed list summaries, which carry no
        EndpointConfigName / ProductionVariants. Undescribable items are skipped."""
        values, missing = {}, []
        for x in items:
            if field in x:
                values[x[nameKey]] = x.get(field)
            elif x.get(nameKey):
                missing.append(x[nameKey])

        def _one(name):
            try:
                return describe(name).get(field)
            except botocore.exceptions.ClientError:
                return None

        if missing:
            with cf.ThreadPoolExecutor(max_workers=min(self.DESCRIBE_WORKERS, len(missing))) as ex:
                for name, val in zip(missing, ex.map(_one, missing)):
                    if val is not None:
                        values[name] = val
        return values

    ## method to get resources for the services
    ## return the array of the resources
    def getResources(self):
        sm = self.sagemakerClient
        limit = self._historyLimit()

        # Live resources: always scanned in full.
        endpoints = self._collect(
            'Endpoint', 'list_endpoints', 'Endpoints', 'EndpointName', 'EndpointArn',
            lambda n: sm.describe_endpoint(EndpointName=n), 'EndpointDriver', 'Endpoint')
        notebooks = self._collect(
            'Notebook', 'list_notebook_instances', 'NotebookInstances', 'NotebookInstanceName', 'NotebookInstanceArn',
            lambda n: sm.describe_notebook_instance(NotebookInstanceName=n), 'NotebookDriver', 'Notebook')

        # Endpoint configs: those used by live endpoints, plus the most recent.
        inUseConfigs = sorted({c for c in self._fieldValues(
            endpoints, 'EndpointName', 'EndpointConfigName',
            lambda n: sm.describe_endpoint(EndpointName=n)).values() if c})
        endpointConfigs = self._collect(
            'Endpoint Config', 'list_endpoint_configs', 'EndpointConfigs', 'EndpointConfigName', 'EndpointConfigArn',
            lambda n: sm.describe_endpoint_config(EndpointConfigName=n), 'EndpointConfigDriver', 'EndpointConfig',
            limit=limit, mustInclude=inUseConfigs)

        # Models: those referenced by in-use endpoint configs, plus the most recent.
        inUseSet = set(inUseConfigs)
        variants = self._fieldValues(
            [c for c in endpointConfigs if c.get('EndpointConfigName') in inUseSet],
            'EndpointConfigName', 'ProductionVariants',
            lambda n: sm.describe_endpoint_config(EndpointConfigName=n))
        inUseModels = sorted({v.get('ModelName')
                              for vs in variants.values() for v in vs or [] if v.get('ModelName')})
        models = self._collect(
            'Model', 'list_models', 'Models', 'ModelName', 'ModelArn',
            lambda n: sm.describe_model(ModelName=n), 'ModelDriver', 'Model',
            limit=limit, mustInclude=inUseModels)

        # Immutable job history: the most recent only.
        trainingJobs = self._collect(
            'Training Job', 'list_training_jobs', 'TrainingJobSummaries', 'TrainingJobName', 'TrainingJobArn',
            lambda n: sm.describe_training_job(TrainingJobName=n), 'TrainingJobDriver', 'TrainingJob',
            limit=limit)
        tuningJobs = self._collect(
            'Tuning Job', 'list_hyper_parameter_tuning_jobs', 'HyperParameterTuningJobSummaries',
            'HyperParameterTuningJobName', 'HyperParameterTuningJobArn',
            lambda n: sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=n),
            'TuningJobDriver', 'TuningJob', limit=limit)

        return {
            'notebooks': notebooks,
            'trainingJobs': trainingJobs,
            'models': models,
            'endpointConfigs': endpointConfigs,
            'endpoints': endpoints,
            'tuningJobs': tuningJobs,
        }

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
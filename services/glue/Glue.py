import boto3
import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service
from services.glue.drivers.DataCatalogDriver import DataCatalogDriver
from services.glue.drivers.JobDriver import JobDriver
from services.glue.drivers.DevEndpointDriver import DevEndpointDriver
from services.glue.drivers.ConnectionDriver import ConnectionDriver
from services.glue.drivers.MLTransformDriver import MLTransformDriver
from services.glue.drivers.CrawlerDriver import CrawlerDriver


class Glue(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        
        # Initialize Glue client
        self.glueClient = ssBoto.client('glue', config=self.bConfig)
        
        # Cache account ID for ARN construction
        self._accountId = None
        
        return
    
    def getAccountId(self):
        """Get AWS account ID for ARN construction"""
        if self._accountId is None:
            stsClient = self.ssBoto.client('sts')
            self._accountId = stsClient.get_caller_identity()['Account']
        return self._accountId
    
    ## method to get resources for the services
    ## return the array of the resources
    def getResources(self):
        resources = {
            'dataCatalog': None,  # Account-level settings
            'jobs': [],
            'devEndpoints': [],
            'mlTransforms': [],
            'connections': [],
            'crawlers': []
        }
        
        # Get data catalog encryption settings (account-level)
        try:
            _pi('Glue', 'Data Catalog Encryption Settings')
            catalogSettings = self.glueClient.get_data_catalog_encryption_settings()
            resources['dataCatalog'] = catalogSettings.get('DataCatalogEncryptionSettings', {})
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error getting data catalog settings: {e}")
        
        # Get ETL jobs with pagination
        try:
            paginator = self.glueClient.get_paginator('get_jobs')
            for page in paginator.paginate():
                for job in page.get('Jobs', []):
                    # Handle tag filtering if configured
                    if self.tags:
                        try:
                            jobArn = f"arn:aws:glue:{self.region}:{self.getAccountId()}:job/{job['Name']}"
                            tagsResponse = self.glueClient.get_tags(ResourceArn=jobArn)
                            tags = self.convertKeyPairTagToTagFormat(tagsResponse.get('Tags', {}))
                            if not self.resourceHasTags(tags):
                                continue
                        except botocore.exceptions.ClientError:
                            continue
                    
                    _pi('Glue', f"Job: {job['Name']}")
                    resources['jobs'].append(job)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing jobs: {e}")
        
        # Get development endpoints with pagination
        try:
            paginator = self.glueClient.get_paginator('get_dev_endpoints')
            for page in paginator.paginate():
                for endpoint in page.get('DevEndpoints', []):
                    # Handle tag filtering if configured
                    if self.tags:
                        try:
                            endpointArn = f"arn:aws:glue:{self.region}:{self.getAccountId()}:devEndpoint/{endpoint['EndpointName']}"
                            tagsResponse = self.glueClient.get_tags(ResourceArn=endpointArn)
                            tags = self.convertKeyPairTagToTagFormat(tagsResponse.get('Tags', {}))
                            if not self.resourceHasTags(tags):
                                continue
                        except botocore.exceptions.ClientError:
                            continue
                    
                    _pi('Glue', f"Dev Endpoint: {endpoint['EndpointName']}")
                    resources['devEndpoints'].append(endpoint)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing dev endpoints: {e}")
        
        # Get ML transforms with pagination
        try:
            response = self.glueClient.get_ml_transforms(MaxResults=100)
            for transform in response.get('Transforms', []):
                # Handle tag filtering if configured
                if self.tags:
                    try:
                        transformArn = f"arn:aws:glue:{self.region}:{self.getAccountId()}:mlTransform/{transform['TransformId']}"
                        tagsResponse = self.glueClient.get_tags(ResourceArn=transformArn)
                        tags = self.convertKeyPairTagToTagFormat(tagsResponse.get('Tags', {}))
                        if not self.resourceHasTags(tags):
                            continue
                    except botocore.exceptions.ClientError:
                        continue
                
                _pi('Glue', f"ML Transform: {transform.get('Name', transform['TransformId'])}")
                resources['mlTransforms'].append(transform)
            
            # Manual pagination for ML transforms
            while 'NextToken' in response:
                response = self.glueClient.get_ml_transforms(
                    MaxResults=100,
                    NextToken=response['NextToken']
                )
                for transform in response.get('Transforms', []):
                    if self.tags:
                        try:
                            transformArn = f"arn:aws:glue:{self.region}:{self.getAccountId()}:mlTransform/{transform['TransformId']}"
                            tagsResponse = self.glueClient.get_tags(ResourceArn=transformArn)
                            tags = self.convertKeyPairTagToTagFormat(tagsResponse.get('Tags', {}))
                            if not self.resourceHasTags(tags):
                                continue
                        except botocore.exceptions.ClientError:
                            continue
                    
                    _pi('Glue', f"ML Transform: {transform.get('Name', transform['TransformId'])}")
                    resources['mlTransforms'].append(transform)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing ML transforms: {e}")
        
        # Get database connections with pagination
        try:
            response = self.glueClient.get_connections(MaxResults=100)
            for connection in response.get('ConnectionList', []):
                # Handle tag filtering if configured
                if self.tags:
                    try:
                        connectionArn = f"arn:aws:glue:{self.region}:{self.getAccountId()}:connection/{connection['Name']}"
                        tagsResponse = self.glueClient.get_tags(ResourceArn=connectionArn)
                        tags = self.convertKeyPairTagToTagFormat(tagsResponse.get('Tags', {}))
                        if not self.resourceHasTags(tags):
                            continue
                    except botocore.exceptions.ClientError:
                        continue
                
                _pi('Glue', f"Connection: {connection['Name']}")
                resources['connections'].append(connection)
            
            # Manual pagination for connections
            while 'NextToken' in response:
                response = self.glueClient.get_connections(
                    MaxResults=100,
                    NextToken=response['NextToken']
                )
                for connection in response.get('ConnectionList', []):
                    if self.tags:
                        try:
                            connectionArn = f"arn:aws:glue:{self.region}:{self.getAccountId()}:connection/{connection['Name']}"
                            tagsResponse = self.glueClient.get_tags(ResourceArn=connectionArn)
                            tags = self.convertKeyPairTagToTagFormat(tagsResponse.get('Tags', {}))
                            if not self.resourceHasTags(tags):
                                continue
                        except botocore.exceptions.ClientError:
                            continue
                    
                    _pi('Glue', f"Connection: {connection['Name']}")
                    resources['connections'].append(connection)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing connections: {e}")
        
        # Get crawlers with pagination
        try:
            paginator = self.glueClient.get_paginator('get_crawlers')
            for page in paginator.paginate():
                for crawler in page.get('Crawlers', []):
                    # Handle tag filtering if configured
                    if self.tags:
                        try:
                            crawlerArn = f"arn:aws:glue:{self.region}:{self.getAccountId()}:crawler/{crawler['Name']}"
                            tagsResponse = self.glueClient.get_tags(ResourceArn=crawlerArn)
                            tags = self.convertKeyPairTagToTagFormat(tagsResponse.get('Tags', {}))
                            if not self.resourceHasTags(tags):
                                continue
                        except botocore.exceptions.ClientError:
                            continue
                    
                    _pi('Glue', f"Crawler: {crawler['Name']}")
                    resources['crawlers'].append(crawler)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error listing crawlers: {e}")
        
        return resources
        
    
    def advise(self):
        objs = {}
        
        # Get all Glue resources
        resources = self.getResources()
        
        # Check data catalog encryption settings (account-level)
        if resources['dataCatalog'] is not None:
            try:
                _pi('Glue', 'Analyzing Data Catalog')
                obj = DataCatalogDriver(resources['dataCatalog'], self.glueClient)
                obj.run(self.__class__)
                objs['DataCatalog::Settings'] = obj.getInfo()
            except Exception as e:
                print(f"Error processing data catalog: {e}")
        
        # Check ETL jobs
        for job in resources['jobs']:
            try:
                obj = JobDriver(job, self.glueClient)
                obj.run(self.__class__)
                objs[f"Job::{job['Name']}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing job {job['Name']}: {e}")
        
        # Check development endpoints
        for endpoint in resources['devEndpoints']:
            try:
                obj = DevEndpointDriver(endpoint, self.glueClient)
                obj.run(self.__class__)
                objs[f"DevEndpoint::{endpoint['EndpointName']}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing dev endpoint {endpoint['EndpointName']}: {e}")
        
        # Check ML transforms
        for transform in resources['mlTransforms']:
            try:
                transformName = transform.get('Name', transform['TransformId'])
                obj = MLTransformDriver(transform, self.glueClient)
                obj.run(self.__class__)
                objs[f"MLTransform::{transformName}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing ML transform {transformName}: {e}")
        
        # Check database connections
        for connection in resources['connections']:
            try:
                obj = ConnectionDriver(connection, self.glueClient)
                obj.run(self.__class__)
                objs[f"Connection::{connection['Name']}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing connection {connection['Name']}: {e}")
        
        # Check crawlers
        for crawler in resources['crawlers']:
            try:
                obj = CrawlerDriver(crawler, self.glueClient)
                obj.run(self.__class__)
                objs[f"Crawler::{crawler['Name']}"] = obj.getInfo()
            except Exception as e:
                print(f"Error processing crawler {crawler['Name']}: {e}")
        
        return objs
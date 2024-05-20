import boto3
import botocore
import constants as _C
import json

from services.Service import Service
from services.Evaluator import Evaluator

class ApiGatewayRest(Evaluator):
    
    def __init__(self, api, apiClient):
        super().__init__()
        self.apiClient = apiClient
        self.api = api
        return

    def _checkStage(self):
        resp = self.apiClient.get_stages(
            restApiId = self.api['id'],
        )
        item = resp['item']
        if item == []:
            self.results['IdleAPIGateway'] = [-1, "No stages found"]
            return
        for stage in item:
            if stage['methodSettings'] == []:
                self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['stageName']]
                self.results['EncryptionAtRest'] = [-1, "Stage name: " + stage['stageName']]
            
            for k, json in stage['methodSettings'].items():
                for key, value in json.items():
                    if key == 'loggingLevel' and value != 'INFO' or 'ERROR':
                        self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['stageName']]    
                    if key == 'cachingEnabled' and value is True:
                        if key == 'cacheDataEncrypted' and value is False:
                            self.results['EncryptionAtRest'] = [-1, "Stage name: " + stage['stageName']]
            
            try:
                certid = stage['clientCertificateId']
            except KeyError:
                self.results['EncryptionInTransit'] = [-1, "Stage name: " + stage['stageName']]
            
            if not stage['tracingEnabled']:
                self.results['XRayTracing'] = [-1, "Stage name: " + stage['stageName']]
            
            try:
                wacl = stage['webAclArn']
            except KeyError:
                self.results['WAFWACL'] = [-1, "Stage name: " + stage['stageName']]
            
        return

import boto3
import botocore
import constants as _C

from services.Service import Service
from services.Evaluator import Evaluator

class ApiGatewayCommon(Evaluator):
    
    def __init__(self, api, apiClient):
        super().__init__()
        self.apiClient = apiClient
        self.api = api

        self._resourceName = api['Name']

        return
    
    def _checkStage(self):
        resp = self.apiClient.get_stages(
                ApiId = self.api['ApiId'],
            )
        items = resp['Items']
        for stage in items:

            if self.api['ProtocolType'] == 'WEBSOCKET':           
                if stage['DefaultRouteSettings']['LoggingLevel'] != 'INFO' or 'ERROR':
                    self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['StageName']]
            try:
                accesslogs = stage['AccessLogSettings']
            except KeyError:
                self.results['AccessLogging'] = [-1, "Stage name: " + stage['StageName']]
        return
            
    def _checkRoute(self):
        resp = self.apiClient.get_routes(
                ApiId = self.api['ApiId'],
            )
        items = resp['Items']
        for route in items:
            if route['AuthorizationType'] == 'NONE':
                self.results['AuthorizationType'] = [-1, "Route key: " + route['RouteKey']]
        return
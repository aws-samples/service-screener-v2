import boto3
import botocore
import requests

from utils.Config import Config
from services.Service import Service
from services.apigateway.drivers.ApiGatewayCommon import ApiGatewayCommon
from services.apigateway.drivers.ApiGatewayRest import ApiGatewayRest

class Apigateway(Service):
   
   
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto

        self.apis = []
        self.apisv2 = []
        
        self.apiClient = ssBoto.client('apigateway', config=self.bConfig)
        self.apiv2Client = ssBoto.client('apigatewayv2', config=self.bConfig)
        
        return
    
    def getRestApis(self):
        apis = []   

        try:
            apis = self.apiClient.get_rest_apis()
            self.apis = apis.get('items')
            while apis.get('position') is not None:
                apis = self.apiClient.get_rest_apis(position=apis.get('position'))
                self.apis = self.apis + apis.get('items')

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
    
    def getApis(self):
        apis = []

        try:
            apis = self.apiv2Client.get_apis()
            self.apisv2 = apis.get('Items')
            while apis.get('position') is not None:
                apis = self.apiv2Client.get_apis(position=apis.get('position'))
                self.apisv2 = self.apisv2 + apis.get('Items')

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            
    def advise(self):
        try:
            objs = {}
            self.getApis()
            for api in self.apisv2:
                objName = api['ProtocolType'] + '::' + api['Name']
                print('... (APIGateway) inspecting ' + objName)
                obj = ApiGatewayCommon(api, self.apiv2Client)
                obj.run(self.__class__)
                objs[objName] = obj.getInfo()
                del obj

            self.getRestApis()
            for api in self.apis:
                objName = 'REST' + '::' + api['name']
                print('... (APIGateway) inspecting ' + objName)
                obj = ApiGatewayRest(api, self.apiClient)
                obj.run(self.__class__)
                objs[objName] = obj.getInfo()
                del obj
        
            return objs
        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(ecode)
import uuid
import sys

import boto3
import botocore
from botocore.config import Config as bConfig

from utils.Config import Config
from utils.Tools import _warn, _info

## Class name decided by Sarika
class CfnTrail():
    def __init__(self):
        self.stackName = None
        self.cfnTemplate = "zNullResourcesCfn.yml"
        self.stackPrefix = "ssv2-"
        self.defaultRegion = "us-east-1"
        self.ymlBody='''
AWSTemplateFormatVersion: '2010-09-09'
Description: '[aws-gh-ss-v2] Service Screener V2'

Conditions:
  HasNot: !Equals [ 'true', 'false' ]
 
# dummy (null) resource, never created
Resources:
  NullResource:
    Type: 'Custom::NullResource'
    Condition: HasNot 
 
Outputs:
  ExportsStackName:
    Value: !Ref 'AWS::StackName'
    Export:
      Name: !Sub 'ExportsStackName-${AWS::StackName}'
'''

        # self.boto3init()
        
    def boto3init(self):
        self.bConfig = bConfig(
            region_name = self.getRegion()
        )
        
        ssBoto = Config.get('ssBoto', None)
        self.cfClient = ssBoto.client('cloudformation', config=self.bConfig)
        
    def createStack(self):
        try:
            self.cfClient.create_stack(
                StackName=self.getStackName(),
                TemplateBody=self.ymlBody
            )
            msg = "Empty CF stacked created successfully, name:" + self.getStackName()
            _info(msg)
        
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
            print("----")
            sys.exit("Please grant cloudformation:CreateStack permission to the user and retry")
    
    def deleteStack(self):
        try:
            self.cfClient.delete_stack(
                StackName=self.getStackName()    
            )
            
            msg = "Empty CF stacked deleted successfully, name:" + self.getStackName()
            _info(msg)
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
            print("Unable to delete CF stack. Although no cost will be incur, recommend to clean up the stack for hygiene purposes")
    
    def getStackName(self):
        if self.stackName == None:
            self.stackName = self.stackPrefix + uuid.uuid4().hex[0:12]
        
        return self.stackName
    
    def getRegion(self):
        allRegions = Config.get('PARAMS_REGION_ALL')
        if allRegions == True:
            r = self.defaultRegion
        else:
            params = Config.get("_SS_PARAMS")
            regions = params['regions'].split(',')
            r = regions[0]
        
        return r
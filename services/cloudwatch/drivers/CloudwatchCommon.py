import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

###### TO DO #####
## Import modules that needed for this driver
## Example
## from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

###### TO DO #####
## Replace ServiceDriver with

class CloudwatchCommon(Evaluator):
    
    ###### TO DO #####
    ## Replace resource variable to meaningful name
    ## Modify based on your need
    def __init__(self, log, logClient):
        super().__init__()
        self.init()
        
        self.log = log
        self.logClient = logClient

        self._resourceName = log['logGroupName']

        return
    
    ###### TO DO #####
    ## Change the method name to meaningful name
    ## Check methods name must follow _check[Description]
    def _checkRetention(self):
        if self.log['retentionInDays'] == -1:
            self.results['SetRetentionDays'] = [-1, "{} MB".format(self.log['storedBytes']/1024/1024)]
        elif self.log['retentionInDays'] <= 365:
            self.results['CISRetentionAtLeast1Yr'] = [-1, self.log['retentionInDays']]
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
        ssBoto = self.ssBoto

        self.log = log
        self.logClient = logClient
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        self.snsClient = ssBoto.client('sns', config=self.bConfig)

        return
    
    ###### TO DO #####
    ## Change the method name to meaningful name
    ## Check methods name must follow _check[Description]
    def _checkRetention(self):
        if self.log['retentionInDays'] == -1:
            self.results['SetRetentionDays'] = [-1, "{} MB".format(self.log['storedBytes']/1024/1024)]
        elif self.log['retentionInDays'] <= 365:
            self.results['CISRetentionAtLeast1Yr'] = [-1, self.log['retentionInDays']]

    
    ###### TO DO #####
    ## Done by YT. Check if this function make sense/ work
    def _check_alarm_subscriptions(self):
        paginator = self.cwClient.get_paginator('describe_alarms')
        has_subscription = False
        for page in paginator.paginate():
            for alarm in page['MetricAlarms']:
                # Check if alarm has SNS actions
                if alarm.get('AlarmActions'):
                    for action in alarm['AlarmActions']:
                        if action.startswith('arn:aws:sns'):
                            # Get SNS topic subscriptions
                            response = self.snsClient.list_subscriptions_by_topic(
                                TopicArn=action
                            )
                            if response['Subscriptions']:
                                has_subscription = True
                                break
        if not has_subscription:
            self.result['hasNotifications'] = [-1, '']
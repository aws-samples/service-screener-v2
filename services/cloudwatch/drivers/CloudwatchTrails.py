import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator
from utils.Config import Config
import re

###### TO DO #####
## Import modules that needed for this driver
## Example
## from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

###### TO DO #####
## Replace ServiceDriver with

class CloudwatchTrails(Evaluator):
    ## WOMA = without metrics & alarm
    ## "$.userIdentity.type", "=", "Root" 
    ## ==> \$.userIdentity.type\s*=\s*[\'\"]*Root[\'\"']*
    CISMetricsMap = [
        {'trailWOMAroot1': [ 
                ["$.userIdentity.type", "=", "Root"]
            ]
        },
        {'trailWOMAunauthAPI2': [
                ["$.errorCode", "=", r"\*UnauthorizedOperation"], 
                ["$.errorCode", "=", r"AccessDenied\*"]
            ]
        },
        {'trailWOMAnoMFA3': [
                ["$.eventName", "=", "ConsoleLogin"], 
                ["$.additionalEventData.MFAUsed", "!=", "Yes"], 
                ["$.userIdentity.type", "=", "IAMUser"], 
                ["$.responseElements.ConsoleLogin", "=", "Success"]
            ]
        },
        {'trailWOMAalarm4': [
                ["$.eventSource", "=", "iam.amazonaws.com"],
                ["$.eventName", "=", "DeleteGroupPolicy"],
                ["$.eventName", "=", "DeleteRolePolicy"],
                ["$.eventName", "=", "DeleteUserPolicy"],
                ["$.eventName", "=", "PutGroupPolicy"],
                ["$.eventName", "=", "PutRolePolicy"],
                ["$.eventName", "=", "PutUserPolicy"],
                ["$.eventName", "=", "CreatePolicy"],
                ["$.eventName", "=", "DeletePolicy"],
                ["$.eventName", "=", "CreatePolicyVersion"],
                ["$.eventName", "=", "DeletePolicyVersion"],
                ["$.eventName", "=", "AttachRolePolicy"],
                ["$.eventName", "=", "DetachRolePolicy"],
                ["$.eventName", "=", "AttachUserPolicy"],
                ["$.eventName", "=", "DetachUserPolicy"],
                ["$.eventName", "=", "AttachGroupPolicy"],
                ["$.eventName", "=", "DetachGroupPolicy"]
            ]
        },
        {'trailWOMATrail5': [
                ["$.eventName", "=", "CreateTrail"],
                ["$.eventName", "=", "UpdateTrail"],
                ["$.eventName", "=", "DeleteTrail"],
                ["$.eventName", "=", "StartLogging"],
                ["$.eventName", "=", "StopLogging"],
            ]
        },
        {'trailWOMAAuthFail6': [
                ["$.eventName", "=", "ConsoleLogin"],
                ["$.errorMessage", "=", "Failed authentication"]
            ]
        },
        {'trailWOMACMK7': [
                ["$.eventSource", "=", "kms.amazonaws.com"],
                ["$.eventName", "=", "DisableKey"],
                ["$.eventName", "=", "ScheduleKeyDeletion"]
            ]
        },
        {'trailWOMAS3Policy8': [
                ["$.eventSource", "=", "s3.amazonaws.com"],
                ["$.eventName", "=", "PutBucketAcl"],
                ["$.eventName", "=", "PutBucketPolicy"],
                ["$.eventName", "=", "PutBucketCors"],
                ["$.eventName", "=", "PutBucketLifecycle"],
                ["$.eventName", "=", "PutBucketReplication"],
                ["$.eventName", "=", "DeleteBucketPolicy"],
                ["$.eventName", "=", "DeleteBucketCors"],
                ["$.eventName", "=", "DeleteBucketLifecycle"],
                ["$.eventName", "=", "DeleteBucketReplication"]
            ]
        }, #9-14
        {'trailWOMAConfig9': [
                ["$.eventSource", "=", "config.amazonaws.com"],
                ["$.eventName", "=", "StopConfigurationRecorder"],
                ["$.eventName", "=", "DeleteDeliveryChannel"],
                ["$.eventName", "=", "PutDeliveryChannel"],
                ["$.eventName", "=", "PutConfigurationRecorder"]
            ]
        },
        {'trailWOMASecGroup10': [
                ["$.eventName", "=", "AuthorizeSecurityGroupIngress"],
                ["$.eventName", "=", "AuthorizeSecurityGroupEgress"],
                ["$.eventName", "=", "RevokeSecurityGroupIngress"],
                ["$.eventName", "=", "RevokeSecurityGroupEgress"],
                ["$.eventName", "=", "CreateSecurityGroup"],
                ["$.eventName", "=", "DeleteSecurityGroup"]
            ]
        },
        {'trailWOMANACL11': [
                ["$.eventName", "=", "CreateNetworkAcl"],
                ["$.eventName", "=", "CreateNetworkAclEntry"],
                ["$.eventName", "=", "DeleteNetworkAcl"],
                ["$.eventName", "=", "DeleteNetworkAclEntry"],
                ["$.eventName", "=", "ReplaceNetworkAclEntry"],
                ["$.eventName", "=", "ReplaceNetworkAclAssociation"]
            ]
        },
        {'trailWOMAGateway12': [
                ["$.eventName", "=", "CreateCustomerGateway"],
                ["$.eventName", "=", "DeleteCustomerGateway"],
                ["$.eventName", "=", "AttachInternetGateway"],
                ["$.eventName", "=", "CreateInternetGateway"],
                ["$.eventName", "=", "DeleteInternetGateway"],
                ["$.eventName", "=", "DetachInternetGateway"]
            ]
        },
        {'trailWOMARouteTable13': [
                ["$.eventSource", "=", "ec2.amazonaws.com"],
                ["$.eventName", "=", "CreateRoute"],
                ["$.eventName", "=", "CreateRouteTable"],
                ["$.eventName", "=", "ReplaceRoute"],
                ["$.eventName", "=", "ReplaceRouteTableAssociation"],
                ["$.eventName", "=", "DeleteRouteTable"],
                ["$.eventName", "=", "DeleteRoute"],
                ["$.eventName", "=", "DisassociateRouteTable"]
            ]
        },
        {'trailWOMAVPC14': [
                ["$.eventName", "=", "CreateVpc"],
                ["$.eventName", "=", "DeleteVpc"],
                ["$.eventName", "=", "ModifyVpcAttribute"],
                ["$.eventName", "=", "AcceptVpcPeeringConnection"],
                ["$.eventName", "=", "CreateVpcPeeringConnection"],
                ["$.eventName", "=", "DeleteVpcPeeringConnection"],
                ["$.eventName", "=", "RejectVpcPeeringConnection"],
                ["$.eventName", "=", "AttachClassicLinkVpc"],
                ["$.eventName", "=", "DetachClassicLinkVpc"],
                ["$.eventName", "=", "DisableVpcClassicLink"],
                ["$.eventName", "=", "EnableVpcClassicLink"]
            ]
        }
    ]
    
    CISMetricsMapRegex = {}
    logMetricsFilterPattern = []
    
    def __init__(self, log, logname, logClient):
        super().__init__()
        self.init()
        
        self.logClient = logClient
        self.log = log
        self.logname = logname
        
        self.metricsInfo = []
        
        self.CISMetricsMapRegex = Config.get('Logs::CISMetricsMapRegex', {})
        if len(self.CISMetricsMapRegex) == 0:
            for lists in self.CISMetricsMap:
                for check, rules in lists.items():
                    self.CISMetricsMapRegex[check] = self.regexBuilder(rules)
            
            Config.set('Logs::CISMetricsMapRegex', self.CISMetricsMapRegex)
    
        return
    
    def regexBuilder(self, rules):
        regexPatterns = []
        for rule in rules:
            regexPattern = r"\\" + rule[0] + r"\s*\\" + rule[1] + r"\s*[\'\"]*" + rule[2] + r"[\'\"]*"
            regexPatterns.append(regexPattern)
        
        return regexPatterns
    
    # Loop available cloudwatch log metrics in logGroup
    def getAllMetrics(self, nextToken=None):
        args = {"logGroupName": self.log[2]}
        if nextToken:
            args['nextToken'] = nextToken

        resp = self.logClient.describe_metric_filters(**args)
        metricFilters = resp.get('metricFilters')
        for filters in metricFilters:
            self.logMetricsFilterPattern.append(filters['filterPattern'])
        
        if resp.get('nextToken'):
            self.getAllMetrics(resp.get('nextToken'))
    
    # write a function to loop through all regex pattern in self.CISMetricsMapRegex, and regex checks again array of string in self.logMetricsFilterPattern
    def regexFindCISPatterns(self):
        for check, rules in self.CISMetricsMapRegex.items():
            self.results[check] = [-1, None]
            for pattern in self.logMetricsFilterPattern:
                # print("-=-=-=-=- " + check + "=-=-=-=-=-=-")
                cnt = 0
                for rule in rules:
                    # print('**REGEX**::', rule, pattern)
                    # print(re.search(rule, pattern))
                    if re.search(rule, pattern):
                        cnt = cnt + 1
                        # self.results[check] = [-1, None]
                        # break
                
                if len(rules) == cnt:
                    del self.results[check] 
                    break

        return
    
    ###### TO DO #####
    ## Change the method name to meaningful name
    ## Check methods name must follow _check[Description]
    def _checkHasLogMetrics(self):
        if self.log[1] == None:
            self.results['trailWithoutCWLogs'] = [-1, None]
            return
        
        args = {"logGroupNamePrefix": self.log[2]}
        
        resp = self.logClient.describe_log_groups(**args)
        logDetail = resp.get('logGroups')[0]
        
        if logDetail['metricFilterCount'] == 0:
            self.results['trailWithCWLogsWithoutMetrics'] = [-1, None]
            return
        
        self.getAllMetrics()
        self.regexFindCISPatterns()

        return
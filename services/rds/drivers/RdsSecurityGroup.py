import boto3

import time
import datetime

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import aws_parseInstanceFamily
from utils.Tools import _warn
from utils.Tools import checkIsPrivateIp
from services.Evaluator import Evaluator

class RdsSecurityGroup(Evaluator):
    def __init__(self, sg, ec2Client, rdsLists):
        self.ec2Client = ec2Client
        self.sg = sg
        self.rdsLists = rdsLists
        
        self._resourceName = sg
        
        resp = self.ec2Client.describe_security_groups(GroupIds=[self.sg])
        self.sgSettings = resp.get('SecurityGroups')
        
        super(RdsSecurityGroup, self).__init__()
        
    def _checkSGIsDefaultVPC(self):
        settings = self.sgSettings
        
        for sg in settings:
            if 'GroupName' in sg and sg['GroupName'] == 'default':
                self.results['SecurityGroupDefault'] = [-1, ', '.join(self.rdsLists)]
        
    def _checkSGHasPublicRules(self):
        settings = self.sgSettings
        
        infoMsg = []
        hasNonPrivateIp = False
    
        for sg in settings:
            if not 'IpPermissions' in sg:
                continue
            
            IpPermissions = sg['IpPermissions']
            for IpPermission in IpPermissions:
                if not 'IpRanges' in IpPermission:
                    continue
                
                for rule in IpPermission['IpRanges']:
                    if not 'CidrIp' in rule:
                        continue
                    
                    currRule = rule['CidrIp']
                    if checkIsPrivateIp(currRule) == False:
                        hasNonPrivateIp = True
                        
                        fport = IpPermission['FromPort']
                        tport = IpPermission['ToPort']
                        
                        info = "Port: {}".format(fport)
                        if fport != tport:
                            info = "Port: {} - {}".format(fport, tport)
                        
                        resources = ', '.join(self.rdsLists)
                        infoMsg.append('.. ' + currRule + "<br>" + info + "<br>RDS: " + resources)
        
        if hasNonPrivateIp == True:
            self.results['SecurityGroupIPRangeNotPrivateCidr'] = [-1, ('<br>--<br>').join(infoMsg)]
                        
import boto3
import botocore

import constants as _C

from services.Evaluator import Evaluator
from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

class Ec2ElbCommon(Evaluator):
    def __init__(self, elb, sgList, elbClient, wafv2Client):
        super().__init__()
        self.elb = elb
        self.sgList = sgList
        self.wafv2Client = wafv2Client
        self.elbClient = elbClient
        self.init()
    
    # checks    
    def _checkListenerPortEncrypt(self):
        arn = self.elb['LoadBalancerArn']
        result = self.elbClient.describe_listeners(
            LoadBalancerArn = arn
        )
        
        listeners = result['Listeners']
        for listener in listeners:
            if listener['Port'] in Ec2SecGroup.NONENCRYPT_PORT:
                self.results['ELBListenerInsecure'] = [-1, listener['Port']]
        
        return
    
    def _checkSecurityGroupNo(self):
        elb = self.elb
        
        if 'SecurityGroups' in elb and len(elb['SecurityGroups']) > 50:
            self.results['ELBListenerInsecure'] = [-1, len(elb['SecurityGroups'])]
            
        return
    
    def _checkCrossZoneLB(self):
        elb = self.elb
        arn = elb['LoadBalancerArn']
        
        results = self.elbClient.describe_load_balancer_attributes(
            LoadBalancerArn = arn
        )
        
        
        for attr in results['Attributes']:
            if attr['Key'] == 'load_balancing.cross_zone.enabled' and attr['Value'] == 'false':
                self.results['ELBCrossZone'] = [-1, 'Disabled']
        
        return
    
    def _checkWAFEnabled(self):
        if self.elb['Type'] != 'application':
            return
        
        wafv2Client = self.wafv2Client
        arn = self.elb['LoadBalancerArn']
        
        results = wafv2Client.get_web_acl_for_resource(
            ResourceArn = arn
        )
        
        if 'WebACL' not in results:
            self.results['ELBEnableWAF'] = [-1, 'Disabled']
        
        return
    
    def _checkALBSGPortMatch(self):
        ## NLB not supported
        if self.elb['Type'] != 'application':
            return
        
        arn = self.elb['LoadBalancerArn']
        results = self.elbClient.describe_listeners(
            LoadBalancerArn = arn
        )
        
        portList = []
        for listener in results.get('Listeners'):
            portList.append(listener.get('Port'))
            
        unmatchPortList = portList
        
        flaggedSGs = []
        for group in self.sgList:
            for perm in group.get('IpPermissions'):
                if perm.get('FromPort') != perm.get('ToPort') or perm.get('FromPort') not in portList:
                    flaggedSGs.append(group.get('GroupId'))
        
        if len(flaggedSGs) > 0:
            self.results['ELBSGRulesMatch'] = [-1, ', '.join(flaggedSGs)]
        
        return
import boto3
import botocore

import constants as _C

from services.Evaluator import Evaluator
from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

class Ec2ElbCommon(Evaluator):
    def __init__(self, elb, elbClient):
        super().__init__()
        self.elb = elb
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
        
        if len(elb['SecurityGroups']) > 50:
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
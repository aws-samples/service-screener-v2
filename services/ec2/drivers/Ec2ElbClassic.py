import boto3
import botocore

import constants as _C

from services.Evaluator import Evaluator

class Ec2ElbClassic(Evaluator):
    def __init__(self, elb, elbClient):
        super().__init__()
        self.elb = elb
        self.elbClient = elbClient
        self.init()
        
    def _checkClassicLoadBalancer(self):
        self.results['ELBClassicLB'] = ['-1', self.elb['LoadBalancerName']]
        return
        
    def _checkListenerPortEncrypt(self):
        listeners = self.elb['ListenerDescriptions']
        
        for listener in listeners:
            if listener['Listener']['Protocol'] in ['HTTP', 'TCP']:
                self.results['ELBListenerInsecure'] = ['-1', listener['Listener']['Protocol']]
        return
        
    def _checkSecurityGroupNo(self):
        if(len(self.elb['SecurityGroups']) > 50):
            self.results['ELBSGNumber'] = [-1, len(self.elb['SecurityGroups'])]
        
        return
    
    def _checkAttributes(self):
        results = self.elbClient.describe_load_balancer_attributes(
            LoadBalancerName = self.elb['LoadBalancerName']    
        )
        
        attributes = results['LoadBalancerAttributes']
        
        if 'CrossZoneLoadBalancing' in attributes and attributes['CrossZoneLoadBalancing']['Enabled'] != 1:
            self.results['ELBCrossZone'] = ['-1', attributes['CrossZoneLoadBalancing']['Enabled']]
            
        if 'ConnectionDraining' in attributes and attributes['ConnectionDraining']['Enabled'] != 1:
            self.results['ELBConnectionDraining'] = ['-1', attributes['ConnectionDraining']['Enabled']]
            
        return
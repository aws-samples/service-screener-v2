import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2Vpc(Evaluator):
    def __init__(self, vpc, flowLogs, ec2Client):
        super().__init__()
        self.vpc = vpc
        self.flowLogs = flowLogs
        self.ec2Client = ec2Client

        self._resourceName = vpc['VpcId']

        self.init()
        return
        
    def _checkVpcFlowLogEnabled(self):
        vpcId = self.vpc['VpcId']
        for flowLog in self.flowLogs:
            if flowLog['ResourceId'] == vpcId and flowLog['TrafficType'] != 'ACCEPT':
                return
                
        self.results['VPCFlowLogEnabled'] = [-1, self.vpc['VpcId']]
        return
    
    
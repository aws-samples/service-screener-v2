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
    
    

    def _checkVPCMultiAZ(self):
        """Check if VPC has subnets in multiple availability zones"""
        vpcId = self.vpc['VpcId']
        
        try:
            # Get all subnets for this VPC
            subnetResp = self.ec2Client.describe_subnets(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpcId]
                    }
                ]
            )
            
            subnets = subnetResp.get('Subnets', [])
            
            if not subnets:
                # No subnets, can't determine
                return
            
            # Get unique availability zones
            availabilityZones = set()
            for subnet in subnets:
                az = subnet.get('AvailabilityZone')
                if az:
                    availabilityZones.add(az)
            
            # Flag if only one AZ
            if len(availabilityZones) < 2:
                self.results['VPCMultiAZ'] = [-1, f"{len(availabilityZones)} AZ"]
        
        except Exception as e:
            # If we can't check, skip
            return

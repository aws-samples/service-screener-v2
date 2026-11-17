import re

import boto3
import botocore

from services.Evaluator import Evaluator

INACTIVE_ENDPOINT_STATES = ('deleting', 'deleted', 'rejected', 'failed', 'expired')
_S3_SERVICE = re.compile(r'\.s3$')
_DDB_SERVICE = re.compile(r'\.dynamodb$')


class Ec2Vpc(Evaluator):
    """routing   - getSubnetRouting() context (None when vpcNoGatewayEndpoints is not run)
       endpoints - all VPC endpoints of the region (unfiltered), or None when unreadable
                   (endpointsError holds the error code)"""
    def __init__(self, vpc, flowLogs, ec2Client, routing=None, endpoints=None,
                 endpointsError=None, selfAccount=None):
        super().__init__()
        self.vpc = vpc
        self.flowLogs = flowLogs
        self.ec2Client = ec2Client
        self.routing = routing
        self.endpoints = endpoints
        self.endpointsError = endpointsError
        self.selfAccount = selfAccount

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

    def _checkVpcNoGatewayEndpoints(self):
        """Private subnets (effective route table without a default route to an
        internet gateway) should reach S3 through a VPC endpoint instead of a NAT /
        the internet. An S3 Gateway endpoint covers a subnet when it is associated
        with the subnet's route table; an S3 Interface endpoint covers the whole VPC.
        A missing DynamoDB endpoint is reported in the message only (not every VPC
        uses DynamoDB)."""
        key = 'vpcNoGatewayEndpoints'
        if self.routing is None:
            return
        vpcId = self.vpc['VpcId']
        owner = self.vpc.get('OwnerId')
        if self.selfAccount and owner and owner != self.selfAccount:
            self.results[key] = [0, f"Not evaluable: VPC shared from account {owner} (route tables and endpoints belong to the VPC owner)"]
            return
        if self.routing.get('error'):
            self.results[key] = [0, f"Unable to evaluate ({self.routing['error']})"]
            return
        if self.endpoints is None:
            self.results[key] = [0, f"Unable to evaluate ({self.endpointsError or 'VPC endpoints not readable'})"]
            return

        subnetVpc = self.routing.get('subnetVpc') or {}
        subnets = self.routing.get('subnets') or {}
        private = {}
        for sid, v in subnetVpc.items():
            if v != vpcId:
                continue
            entry = subnets.get(sid)
            if entry is None:
                self.results[key] = [0, f"Unable to evaluate (no visible route table for {sid})"]
                return
            if not entry.get('igwRoutes'):
                private[sid] = entry.get('routeTableId')
        if not private:
            self.results[key] = [1, 'No private subnets']
            return

        def coveredSubnets(pattern):
            covered = set()
            for ep in self.endpoints:
                if ep.get('VpcId') != vpcId or str(ep.get('State', '')).lower() in INACTIVE_ENDPOINT_STATES:
                    continue
                if not pattern.search(ep.get('ServiceName') or ''):
                    continue
                epType = ep.get('VpcEndpointType')
                if epType == 'Interface':
                    return set(private)
                if epType == 'Gateway':
                    rts = set(ep.get('RouteTableIds') or [])
                    covered.update(sid for sid, rt in private.items() if rt in rts)
            return covered

        s3Missing = sorted(set(private) - coveredSubnets(_S3_SERVICE))
        ddbMissing = sorted(set(private) - coveredSubnets(_DDB_SERVICE))
        ddbNote = ''
        if ddbMissing:
            ddbNote = f"; no DynamoDB endpoint for {len(ddbMissing)} private subnet(s) (add one if the VPC uses DynamoDB)"
        if s3Missing:
            shown = ', '.join(s3Missing[:5]) + (f" (+{len(s3Missing) - 5} more)" if len(s3Missing) > 5 else '')
            self.results[key] = [-1, f"{len(s3Missing)}/{len(private)} private subnet(s) without an S3 gateway/interface endpoint: {shown}{ddbNote}"]
            return
        self.results[key] = [1, f"S3 endpoint covers all {len(private)} private subnet(s){ddbNote}"]

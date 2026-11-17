import botocore

from utils.Tools import _pi
from services.Service import Service

from services.networkfirewall.drivers.NetworkfirewallFirewall import NetworkfirewallFirewall
from services.networkfirewall.drivers.NetworkfirewallVpc import NetworkfirewallVpc


class Networkfirewall(Service):
    """
    AWS Network Firewall service scanner.

    Two check subjects:
      NetworkfirewallFirewall -- per firewall (logging, policy strength,
                                 subnet routes that bypass the firewall)
      NetworkfirewallVpc      -- per internet-connected VPC (no Network
                                 Firewall / Gateway Load Balancer inspection)

    Hydration calls (all read-only):
      network-firewall: list_firewalls (paginated), describe_firewall,
                        describe_logging_configuration, describe_firewall_policy
      ec2:              describe_vpcs, describe_subnets, describe_route_tables,
                        describe_nat_gateways, describe_vpc_endpoints,
                        describe_internet_gateways (all paginated),
                        describe_network_interfaces (MaxResults=5, only for VPCs
                        that would otherwise be flagged by the VPC check)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnauthorizedOperation', 'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.nfwClient = ssBoto.client('network-firewall', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self._policyCache = {}
        self._listError = None
        ## VPC placement of every described firewall, recorded before the
        ## --tags filter so VPC-level logic sees all firewalls.
        self._allFirewalls = []
        self._describeError = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        """Return a list of firewall detail dicts. A detail with '_error' set
        means describe_firewall could not be read."""
        firewalls = []
        try:
            paginator = self.nfwClient.get_paginator('list_firewalls')
            summaries = []
            for page in paginator.paginate():
                summaries += page.get('Firewalls', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_firewalls', e)
            self._listError = self._code(e)
            return None
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Network Firewall not available in region {self.region}: {e}")
            self._listError = 'EndpointConnectionError'
            return None

        for s in summaries:
            arn = s.get('FirewallArn')
            name = s.get('FirewallName') or (arn.split('/')[-1] if arn else None)
            if not arn:
                continue
            detail = {'FirewallArn': arn, 'FirewallName': name}
            try:
                resp = self.nfwClient.describe_firewall(FirewallArn=arn)
                detail['Firewall'] = resp.get('Firewall') or {}
                detail['FirewallStatus'] = resp.get('FirewallStatus') or {}
            except botocore.exceptions.ClientError as e:
                self._logClientError(f'describe_firewall({name})', e)
                detail['_error'] = self._code(e)
                self._describeError = self._describeError or detail['_error']
                firewalls.append(detail)
                continue

            self._allFirewalls.append(detail)

            if self.tags and not self.resourceHasTags(detail['Firewall'].get('Tags') or []):
                continue

            detail['_logging'], detail['_loggingError'] = self._getLogging(arn)
            policyArn = detail['Firewall'].get('FirewallPolicyArn')
            detail['_policy'], detail['_policyError'] = self._getPolicy(policyArn)
            _pi('NetworkFirewall', f"Firewall: {name}")
            firewalls.append(detail)
        return firewalls

    def _getLogging(self, arn):
        try:
            resp = self.nfwClient.describe_logging_configuration(FirewallArn=arn)
            return (resp.get('LoggingConfiguration') or {}), None
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_logging_configuration', e)
            return None, self._code(e)

    def _getPolicy(self, policyArn):
        if not policyArn:
            return None, 'NoFirewallPolicyArn'
        if policyArn in self._policyCache:
            return self._policyCache[policyArn]
        try:
            resp = self.nfwClient.describe_firewall_policy(FirewallPolicyArn=policyArn)
            out = (resp.get('FirewallPolicy') or {}), None
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_firewall_policy', e)
            out = None, self._code(e)
        self._policyCache[policyArn] = out
        return out

    def _paginate(self, op, key, **kwargs):
        items = []
        for page in self.ec2Client.get_paginator(op).paginate(**kwargs):
            items += page.get(key, []) or []
        return items

    def getNetwork(self):
        """Region-wide EC2 network inventory, grouped by VPC id.
        Returns (byVpc, vpcs, error)."""
        try:
            vpcs = self._paginate('describe_vpcs', 'Vpcs')
            subnets = self._paginate('describe_subnets', 'Subnets')
            routeTables = self._paginate('describe_route_tables', 'RouteTables')
            natGateways = self._paginate('describe_nat_gateways', 'NatGateways')
            endpoints = self._paginate('describe_vpc_endpoints', 'VpcEndpoints')
            igws = self._paginate('describe_internet_gateways', 'InternetGateways')
        except botocore.exceptions.ClientError as e:
            self._logClientError('ec2 network inventory', e)
            return {}, [], self._code(e)
        except botocore.exceptions.EndpointConnectionError as e:
            return {}, [], 'EndpointConnectionError'

        byVpc = {}

        def bucket(vpcId):
            return byVpc.setdefault(vpcId, {
                'subnets': [], 'routeTables': [], 'natGateways': [],
                'gwlbEndpoints': [], 'gwlbSubnets': [], 'igws': [],
            })

        for v in vpcs:
            bucket(v.get('VpcId'))
        for s in subnets:
            bucket(s.get('VpcId'))['subnets'].append(s)
        for rt in routeTables:
            bucket(rt.get('VpcId'))['routeTables'].append(rt)
        for n in natGateways:
            if n.get('State') in ('deleted', 'deleting', 'failed'):
                continue
            bucket(n.get('VpcId'))['natGateways'].append(n)
        for ep in endpoints:
            if ep.get('VpcEndpointType') == 'GatewayLoadBalancer' and \
                    ep.get('State') not in ('deleted', 'deleting', 'failed', 'rejected', 'expired'):
                b = bucket(ep.get('VpcId'))
                b['gwlbEndpoints'].append(ep.get('VpcEndpointId'))
                b['gwlbSubnets'] += ep.get('SubnetIds') or []
        for igw in igws:
            for att in igw.get('Attachments', []) or []:
                if att.get('VpcId') and att.get('State') in ('available', 'attached', None):
                    bucket(att['VpcId'])['igws'].append(igw.get('InternetGatewayId'))
        return byVpc, vpcs, None

    def _hasNetworkInterfaces(self, vpcId):
        """True / False, or the error code string if unreadable."""
        try:
            resp = self.ec2Client.describe_network_interfaces(
                Filters=[{'Name': 'vpc-id', 'Values': [vpcId]}], MaxResults=5)
            return len(resp.get('NetworkInterfaces', []) or []) > 0
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_network_interfaces', e)
            return self._code(e)

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        firewalls = self.getResources()
        byVpc, vpcs, netError = self.getNetwork()

        ## VPC membership, endpoints and subnets of every described firewall
        ## (including ones excluded by --tags); several firewalls may share
        ## a VPC.
        firewallVpcs = set()
        fwEndpointsByVpc = {}
        fwSubnetsByVpc = {}
        for fw in self._allFirewalls:
            f = fw.get('Firewall') or {}
            vpcId = f.get('VpcId')
            if not vpcId:
                continue
            firewallVpcs.add(vpcId)
            subnets = fwSubnetsByVpc.setdefault(vpcId, set())
            for m in f.get('SubnetMappings') or []:
                if m.get('SubnetId'):
                    subnets.add(m['SubnetId'])
            for sid, state in ((fw.get('FirewallStatus') or {}).get('SyncStates') or {}).items():
                att = state.get('Attachment') or {}
                if att.get('EndpointId'):
                    fwEndpointsByVpc.setdefault(vpcId, set()).add(att['EndpointId'])
                if att.get('SubnetId'):
                    subnets.add(att['SubnetId'])

        for fw in firewalls or []:
            try:
                vpcId = (fw.get('Firewall') or {}).get('VpcId')
                obj = NetworkfirewallFirewall(
                    fw, byVpc.get(vpcId) if vpcId else None, netError,
                    fwEndpointsByVpc.get(vpcId, set()),
                    fwSubnetsByVpc.get(vpcId, set()))
                obj.run(self.__class__)
                objs[f"Firewall::{fw.get('FirewallName')}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Network Firewall {fw.get('FirewallName')}: {e}")

        if netError is None:
            for vpc in vpcs:
                vpcId = vpc.get('VpcId')
                if not vpcId:
                    continue
                if self.tags and not self.resourceHasTags(vpc.get('Tags') or []):
                    continue
                net = byVpc.get(vpcId) or {}
                ## Only spend a describe_network_interfaces call on VPCs that
                ## are internet-connected and have no inspection endpoint.
                hasEni = None
                if vpcId not in firewallVpcs and not net.get('gwlbEndpoints') \
                        and NetworkfirewallVpc.internetRoutes(net):
                    hasEni = self._hasNetworkInterfaces(vpcId)
                try:
                    ## A firewall whose describe_firewall failed has an unknown
                    ## VPC: do not FAIL VPCs that could be hosting it.
                    obj = NetworkfirewallVpc(vpc, net, vpcId in firewallVpcs,
                                             self._listError or self._describeError,
                                             hasEni)
                    obj.run(self.__class__)
                    objs[f"VPC::{vpcId}"] = obj.getInfo()
                    del obj
                except Exception as e:
                    print(f"Error processing VPC {vpcId} for Network Firewall: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _code(error):
        return error.response.get('Error', {}).get('Code', 'Unknown')

    def _logClientError(self, where, error):
        code = self._code(error)
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Networkfirewall {where}: {code} - {msg}")

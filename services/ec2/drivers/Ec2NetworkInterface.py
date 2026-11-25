import re

import botocore

from utils.Config import Config
from services.ec2.acctCache import acctKey
from services.Evaluator import Evaluator, _isTransient

DEFAULT_ROUTES = ('0.0.0.0/0', '::/0')

_ECS_DESC = re.compile(r'^arn:aws[a-z-]*:ecs:')


def _errCode(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return e.response.get('Error', {}).get('Code', 'ClientError')
    return type(e).__name__


def _igwDefaultRoutes(routeTable):
    """'0.0.0.0/0 -> igw-..' strings for active default routes to an internet gateway."""
    out = []
    for r in routeTable.get('Routes', []) or []:
        gw = r.get('GatewayId') or ''
        dest = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock')
        if gw.startswith('igw-') and dest in DEFAULT_ROUTES and r.get('State') != 'blackhole':
            out.append(f"{dest} -> {gw}")
    return out


_ROUTE_TARGETS = ('GatewayId', 'NatGatewayId', 'TransitGatewayId', 'NetworkInterfaceId', 'InstanceId',
                  'VpcPeeringConnectionId', 'EgressOnlyInternetGatewayId', 'CarrierGatewayId',
                  'LocalGatewayId', 'CoreNetworkArn')


def _defaultRoutes(routeTable):
    """'0.0.0.0/0 -> <target>' strings for every active default route (any target:
    IGW, NAT, transit gateway, appliance ENI, peering, ...)."""
    out = []
    for r in routeTable.get('Routes', []) or []:
        dest = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock')
        if dest not in DEFAULT_ROUTES or r.get('State') == 'blackhole':
            continue
        target = next((r[k] for k in _ROUTE_TARGETS if r.get(k)), 'unknown')
        out.append(f"{dest} -> {target}")
    return out


def getSubnetRouting(ec2Client):
    """Effective route table per subnet (explicit association, else the VPC main
    route table), memoized per region:
      {'subnets': {subnetId: {'routeTableId': .., 'igwRoutes': [..], 'defaultRoutes': [..]}},
       'subnetVpc': {subnetId: vpcId}, 'error': None|code,
       '_routeTables': [raw RouteTables] (only when readable; reused by getPeerRouteContext)}
    A subnet missing from 'subnets' has no visible route table (e.g. a subnet shared
    from another account through AWS RAM - participants cannot read its route table)."""
    region = ec2Client.meta.region_name
    cacheKey = acctKey('ec2::subnetRouting::' + str(region))
    cached = Config.get(cacheKey, None)
    if cached is not None:
        return cached

    ctx = {'subnets': {}, 'subnetVpc': {}, 'error': None}
    try:
        routeTables = []
        for page in ec2Client.get_paginator('describe_route_tables').paginate():
            routeTables.extend(page.get('RouteTables', []))
        subnets = []
        for page in ec2Client.get_paginator('describe_subnets').paginate():
            subnets.extend(page.get('Subnets', []))
    except Exception as e:
        ctx['error'] = _errCode(e)
        if not _isTransient(e):   # throttling / 5xx: let the next caller retry
            Config.set(cacheKey, ctx)
        return ctx

    ctx['_routeTables'] = routeTables
    mainByVpc, explicit = {}, {}
    for rt in routeTables:
        entry = {'routeTableId': rt.get('RouteTableId'), 'igwRoutes': _igwDefaultRoutes(rt),
                 'defaultRoutes': _defaultRoutes(rt)}
        for assoc in rt.get('Associations', []) or []:
            state = (assoc.get('AssociationState') or {}).get('State', 'associated')
            if state not in ('associated', 'associating'):
                continue
            if assoc.get('Main'):
                mainByVpc[rt.get('VpcId')] = entry
            elif assoc.get('SubnetId'):
                explicit[assoc['SubnetId']] = entry

    for sn in subnets:
        sid = sn.get('SubnetId')
        ctx['subnetVpc'][sid] = sn.get('VpcId')
        entry = explicit.get(sid) or mainByVpc.get(sn.get('VpcId'))
        if entry is not None:
            ctx['subnets'][sid] = entry
    # explicit associations for subnets not returned by describe_subnets
    for sid, entry in explicit.items():
        ctx['subnets'].setdefault(sid, entry)

    Config.set(cacheKey, ctx)
    return ctx


def evaluatePlacement(subnetIds, routing):
    """[status, message] for resources whose network interfaces sit in subnetIds."""
    if routing.get('error'):
        return [0, f"Unable to evaluate ({routing['error']})"]
    subnetIds = sorted({s for s in subnetIds if s})
    if not subnetIds:
        return [0, 'Unable to evaluate (no subnet)']

    public, unknown = [], []
    for sid in subnetIds:
        entry = routing['subnets'].get(sid)
        if entry is None:
            unknown.append(sid)
        elif entry['igwRoutes']:
            public.append(f"{sid} ({entry['routeTableId']}: {', '.join(entry['igwRoutes'])})")

    if public:
        return [-1, 'Public subnet: ' + '; '.join(public)]
    if unknown:
        return [0, f"Unable to evaluate (route table not visible for {', '.join(unknown)}; shared VPC?)"]
    return [1, 'Private subnet(s): ' + ', '.join(subnetIds)]


def classifyEni(eni):
    """'RDS' | 'ElastiCache' | 'ECS' | None for network interfaces owned by those
    services. EC2 instance interfaces are evaluated on the instance itself."""
    requester = eni.get('RequesterId') or ''
    desc = eni.get('Description') or ''
    if requester == 'amazon-rds' or desc == 'RDSNetworkInterface':
        return 'RDS'
    if requester == 'amazon-elasticache' or desc.startswith('ElastiCache '):
        return 'ElastiCache'
    if _ECS_DESC.match(desc):
        return 'ECS'
    return None


class Ec2NetworkInterface(Evaluator):
    """Network interfaces of internal-tier managed services (RDS, ElastiCache,
    ECS awsvpc tasks) placed in a subnet whose route table sends 0.0.0.0/0 or ::/0
    to an internet gateway."""

    def __init__(self, eni, kind, routing):
        super().__init__()
        self.eni = eni
        self.kind = kind
        self.routing = routing

        self._resourceName = eni['NetworkInterfaceId']

        self.init()

    def _checkEc2InstanceInPublicSubnet(self):
        eni = self.eni
        status, msg = evaluatePlacement([eni.get('SubnetId')], self.routing)
        publicIp = (eni.get('Association') or {}).get('PublicIp')
        desc = eni.get('Description') or ''
        detail = f"{self.kind} interface ({desc[:80]})" if desc else f"{self.kind} interface"
        if status == -1:
            msg = f"{detail} - {msg}; public IP: {publicIp or 'none'}"
        else:
            msg = f"{detail} - {msg}"
        self.results['ec2InstanceInPublicSubnet'] = [status, msg]

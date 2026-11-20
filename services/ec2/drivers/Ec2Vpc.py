import ipaddress
import re

import boto3
import botocore

from services.Evaluator import Evaluator

INACTIVE_ENDPOINT_STATES = ('deleting', 'deleted', 'rejected', 'failed', 'expired')
_S3_SERVICE = re.compile(r'\.s3$')
_DDB_SERVICE = re.compile(r'\.dynamodb$')
# Session Manager / Run Command need ssm + ssmmessages; ec2messages is only used by
# older SSM Agent versions (< 3.3.40.0) and is reported in the message.
_SSM_REQUIRED = ('ssm', 'ssmmessages')
_SSM_OPTIONAL = ('ec2messages',)
_SSM_SERVICE = re.compile(r'\.(ssm|ssmmessages|ec2messages)$')
LIVE_INSTANCE_STATES = ('pending', 'running', 'stopping', 'stopped')


def _errCode(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return e.response.get('Error', {}).get('Code', 'ClientError')
    return type(e).__name__


def _vpcCidrs(info):
    """IPv4 + IPv6 CIDR strings of a VPC dict or a peering Requester/AccepterVpcInfo."""
    out = [c.get('CidrBlock') for c in (info.get('CidrBlockSet') or info.get('CidrBlockAssociationSet') or [])
           if c.get('CidrBlock') and (c.get('CidrBlockState') or {}).get('State', 'associated') == 'associated']
    if not out and info.get('CidrBlock'):
        out = [info['CidrBlock']]
    for c in (info.get('Ipv6CidrBlockSet') or info.get('Ipv6CidrBlockAssociationSet') or []):
        if c.get('Ipv6CidrBlock') and (c.get('Ipv6CidrBlockState') or {}).get('State', 'associated') == 'associated':
            out.append(c['Ipv6CidrBlock'])
    return out


def _covers(dest, peer):
    try:
        d, p = ipaddress.ip_network(dest, strict=False), ipaddress.ip_network(peer, strict=False)
    except ValueError:
        return False
    return d.version == p.version and d.supernet_of(p)


def getPeerRouteContext(ec2Client, vpcs, routeTables=None):
    """Read-only context for vpcPeeringFullRoute:
      {'error': code|None,
       'routeTables': {vpcId: [routeTable, ..]},
       'peerings': {pcxId: VpcPeeringConnection (active only)},
       'peeringError': code|None,
       'tgwPeers': {(tgwId, vpcId): {'peers': {peerVpcId: [cidr, ..]}, 'note': str|None, 'error': code|None}}}
    TGW peers of a VPC are the other VPC attachments that have an active route in the
    TGW route table associated with the VPC's attachment (search_transit_gateway_routes);
    when that association is not visible, every other VPC attachment of the same TGW.
    routeTables - every route table of the region when already read (e.g. by
    getSubnetRouting); None to read them here."""
    ctx = {'error': None, 'routeTables': {}, 'peerings': {}, 'peeringError': None, 'tgwPeers': {}}
    if routeTables is not None:
        for rt in routeTables:
            ctx['routeTables'].setdefault(rt.get('VpcId'), []).append(rt)
    else:
        try:
            for page in ec2Client.get_paginator('describe_route_tables').paginate():
                for rt in page.get('RouteTables', []):
                    ctx['routeTables'].setdefault(rt.get('VpcId'), []).append(rt)
        except Exception as e:
            ctx['error'] = _errCode(e)
            return ctx

    def activeRoutes(target):
        for rts in ctx['routeTables'].values():
            for rt in rts:
                for r in rt.get('Routes', []) or []:
                    if r.get(target) and r.get('State', 'active') == 'active':
                        yield rt.get('VpcId'), r

    if any(True for _ in activeRoutes('VpcPeeringConnectionId')):
        try:
            for page in ec2Client.get_paginator('describe_vpc_peering_connections').paginate():
                for pcx in page.get('VpcPeeringConnections', []):
                    if (pcx.get('Status') or {}).get('Code') == 'active':
                        ctx['peerings'][pcx['VpcPeeringConnectionId']] = pcx
        except Exception as e:
            ctx['peeringError'] = _errCode(e)

    tgwVpcPairs = sorted({(r['TransitGatewayId'], v) for v, r in activeRoutes('TransitGatewayId')})
    if not tgwVpcPairs:
        return ctx
    localCidrs = {v['VpcId']: _vpcCidrs(v) for v in vpcs or []}
    attachments, attachErr = {}, None
    try:
        for page in ec2Client.get_paginator('describe_transit_gateway_attachments').paginate(
                Filters=[{'Name': 'resource-type', 'Values': ['vpc']}]):
            for a in page.get('TransitGatewayAttachments', []):
                if a.get('State') in ('available', 'modifying', 'pendingAcceptance', 'pending'):
                    attachments.setdefault(a.get('TransitGatewayId'), []).append(a)
    except Exception as e:
        attachErr = _errCode(e)
    rtRoutes = {}

    def searchRoutes(tgwRtId):
        if tgwRtId not in rtRoutes:
            try:
                routes, more = [], False
                for page in ec2Client.get_paginator('search_transit_gateway_routes').paginate(
                        TransitGatewayRouteTableId=tgwRtId,
                        Filters=[{'Name': 'state', 'Values': ['active']},
                                 {'Name': 'attachment.resource-type', 'Values': ['vpc']}]):
                    routes.extend(page.get('Routes', []))
                    more = more or bool(page.get('AdditionalRoutesAvailable'))
                rtRoutes[tgwRtId] = (routes, more, None)
            except Exception as e:
                rtRoutes[tgwRtId] = ([], False, _errCode(e))
        return rtRoutes[tgwRtId]

    for tgwId, vpcId in tgwVpcPairs:
        entry = {'peers': {}, 'note': None, 'error': None}
        ctx['tgwPeers'][(tgwId, vpcId)] = entry
        if attachErr:
            entry['error'] = attachErr
            continue
        tgwAtts = attachments.get(tgwId, [])
        own = [a for a in tgwAtts if a.get('ResourceId') == vpcId]
        assocRt = next(((a.get('Association') or {}).get('TransitGatewayRouteTableId') for a in own
                        if (a.get('Association') or {}).get('State') == 'associated'), None)
        if assocRt:
            routes, more, err = searchRoutes(assocRt)
            if err:
                entry['error'] = err
                continue
            for r in routes:
                for att in r.get('TransitGatewayAttachments', []) or []:
                    peer = att.get('ResourceId')
                    if att.get('ResourceType') != 'vpc' or not peer or peer == vpcId:
                        continue
                    cidrs = entry['peers'].setdefault(peer, [])
                    # propagated routes advertise exactly the attached VPC's CIDRs
                    if r.get('Type') == 'propagated' and r.get('DestinationCidrBlock'):
                        cidrs.append(r['DestinationCidrBlock'])
                    cidrs.extend(c for c in localCidrs.get(peer, []) if c not in cidrs)
            if more:
                entry['note'] = f"{assocRt} returned a partial route list (AdditionalRoutesAvailable)"
        else:
            for a in tgwAtts:
                peer = a.get('ResourceId')
                if peer and peer != vpcId:
                    entry['peers'].setdefault(peer, list(localCidrs.get(peer, [])))
            entry['note'] = 'TGW route table association not visible; using all VPC attachments of the TGW'
            # A TGW shared from another account: attachments of other accounts are not
            # visible to this account, so absence of a covered peer is not a PASS.
            entry['partial'] = any(a.get('TransitGatewayOwnerId') and a.get('ResourceOwnerId')
                                   and a['TransitGatewayOwnerId'] != a['ResourceOwnerId'] for a in own)
        for peer in [p for p, c in entry['peers'].items() if not c]:
            entry['peers'].pop(peer)
            entry['note'] = ((entry['note'] + '; ') if entry['note'] else '') + f"CIDR of {peer} not visible"
    return ctx



class Ec2Vpc(Evaluator):
    """routing   - getSubnetRouting() context (None when vpcNoGatewayEndpoints is not run)
       endpoints - all VPC endpoints of the region (unfiltered), or None when unreadable
                   (endpointsError holds the error code)
       instances - EC2 instance dicts of the region (None when ssmVpcEndpointsMissing is not run)
       peerRouting - getPeerRouteContext() (None when vpcPeeringFullRoute is not run)
       ssmPingStatus - {instanceId: SSM PingStatus} of SSM-managed instances, or None
                   when ssm:DescribeInstanceInformation was not read / not readable"""
    def __init__(self, vpc, flowLogs, ec2Client, routing=None, endpoints=None,
                 endpointsError=None, selfAccount=None, instances=None, peerRouting=None,
                 ssmPingStatus=None):
        super().__init__()
        self.vpc = vpc
        self.flowLogs = flowLogs
        self.ec2Client = ec2Client
        self.routing = routing
        self.endpoints = endpoints
        self.endpointsError = endpointsError
        self.selfAccount = selfAccount
        self.instances = instances
        self.peerRouting = peerRouting
        self.ssmPingStatus = ssmPingStatus

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


    def _checkSsmVpcEndpointsMissing(self):
        """Instances in isolated subnets (effective route table with no active
        0.0.0.0/0 or ::/0 route to any target - no IGW, NAT, transit gateway,
        appliance, ...) can reach Systems Manager only through interface VPC
        endpoints. FAIL when such instances exist and the VPC has no active
        ssm / ssmmessages interface endpoint. Subnets with a default route are
        not flagged: NAT / proxy egress is a valid path (EC2SSMNotManaged
        observes the outcome per instance).
        Without in-VPC endpoints, isolated instances whose SSM Agent is Online
        reach Systems Manager another way (typically centralized interface
        endpoints in a shared-services VPC, resolved through a private hosted
        zone associated with this VPC). PingStatus proves only that the ssm
        endpoint is reachable, so it is used only when 'ssm' has no in-VPC
        endpoint: all Online and ssmmessages present in-VPC -> PASS; all Online
        but ssmmessages also missing -> INFO (not proven); some Online -> INFO.
        When only ssmmessages is missing, Online status proves nothing about it
        and the result stays FAIL."""
        key = 'ssmVpcEndpointsMissing'
        if self.routing is None or self.instances is None:
            return
        vpcId = self.vpc['VpcId']
        owner = self.vpc.get('OwnerId')
        if self.selfAccount and owner and owner != self.selfAccount:
            self.results[key] = [0, f"Not evaluable: VPC shared from account {owner} (route tables and endpoints belong to the VPC owner)"]
            return
        if self.routing.get('error'):
            self.results[key] = [0, f"Unable to evaluate ({self.routing['error']})"]
            return

        subnets = self.routing.get('subnets') or {}
        isolated, unknown = {}, set()
        for inst in self.instances:
            if inst.get('VpcId') != vpcId or (inst.get('State') or {}).get('Name') not in LIVE_INSTANCE_STATES:
                continue
            sid = inst.get('SubnetId')
            entry = subnets.get(sid)
            if entry is None:
                unknown.add(sid)
            elif not entry.get('defaultRoutes'):
                isolated.setdefault(sid, []).append(inst['InstanceId'])
        if not isolated:
            if unknown:
                self.results[key] = [0, f"Unable to evaluate (no visible route table for {', '.join(sorted(s or '?' for s in unknown))})"]
            else:
                self.results[key] = [1, 'No instances in isolated subnets (no default route)']
            return
        if self.endpoints is None:
            self.results[key] = [0, f"Unable to evaluate ({self.endpointsError or 'VPC endpoints not readable'})"]
            return

        found, noDns = set(), {}
        for ep in self.endpoints:
            if ep.get('VpcId') != vpcId or ep.get('VpcEndpointType') != 'Interface':
                continue
            if str(ep.get('State', '')).lower() in INACTIVE_ENDPOINT_STATES:
                continue
            m = _SSM_SERVICE.search(ep.get('ServiceName') or '')
            if not m:
                continue
            if ep.get('PrivateDnsEnabled') is False:
                noDns.setdefault(m.group(1), ep.get('VpcEndpointId'))
            else:
                found.add(m.group(1))

        instIds = sorted(i for ids in isolated.values() for i in ids)
        shown = ', '.join(instIds[:5]) + (f" (+{len(instIds) - 5} more)" if len(instIds) > 5 else '')
        where = f"{len(instIds)} instance(s) in {len(isolated)} isolated subnet(s): {shown}"
        optional = [s for s in _SSM_OPTIONAL if s not in found]
        optNote = f"; no {', '.join(optional)} endpoint (only needed by SSM Agent < 3.3.40.0)" if optional else ''
        missing = [s for s in _SSM_REQUIRED if s not in found]
        if not missing:
            self.results[key] = [1, f"ssm and ssmmessages interface endpoints present for {where}{optNote}"]
            return
        dnsOff = [f"{s} ({noDns[s]})" for s in missing if s in noDns]
        if len(dnsOff) == len(missing):
            self.results[key] = [0, f"{where}; interface endpoint(s) {', '.join(dnsOff)} have private DNS disabled - verify a private hosted zone resolves the SSM hostnames{optNote}"]
            return
        # PingStatus is driven by the agent's calls to the ssm endpoint
        # (UpdateInstanceInformation), so Online proves only that 'ssm' is
        # reachable. It is used only when 'ssm' itself has no in-VPC endpoint;
        # ssmmessages reachability (Session Manager) is never inferred from it.
        ping = self.ssmPingStatus or {}
        online = [i for i in instIds if ping.get(i) == 'Online'] if 'ssm' in missing else []
        if online and len(online) == len(instIds):
            if 'ssmmessages' in missing:
                self.results[key] = [0, f"No {', '.join(missing)} interface endpoint in this VPC; the SSM Agent is Online for all {where}, so ssm is reachable another way (likely centralized endpoints in a shared-services VPC), but ssmmessages (Session Manager) reachability is not proven - verify it{optNote}"]
            else:
                self.results[key] = [1, f"No ssm interface endpoint in this VPC, but the SSM Agent is Online for all {where} (ssm reachable, likely via centralized endpoints in a shared-services VPC); ssmmessages endpoint present{optNote}"]
            return
        if online:
            offline = [i for i in instIds if i not in online]
            shownOff = ', '.join(offline[:5]) + (f" (+{len(offline) - 5} more)" if len(offline) > 5 else '')
            self.results[key] = [0, f"No {', '.join(missing)} interface endpoint in this VPC; SSM Agent Online for {len(online)}/{len(instIds)} instance(s) in isolated subnets (likely centralized endpoints), not Online: {shownOff}{optNote}"]
            return
        self.results[key] = [-1, f"No {', '.join(missing)} interface endpoint for {where}{optNote}"]


    def _checkVpcPeeringFullRoute(self):
        """Review flag (SEC05-BP02): a route in this VPC to an active VPC peering
        connection or transit gateway whose destination equals or contains a whole
        CIDR block of a peer VPC makes every subnet of that peer reachable from the
        associated subnets. Least-privilege network design routes only the peer
        subnets that are needed.
          -1   VPC peering route covering a whole CIDR of a peer VPC owned by ANOTHER
               account (full network reachability across an account boundary)
           0   same-account peering or transit gateway route covering a whole peer
               CIDR (the documented default - review item only)
           1   only partial peer routes, or only default / summary routes to a TGW
        Default (0.0.0.0/0, ::/0) and summary routes to a transit gateway (prefix
        shorter than this VPC's own CIDR, e.g. 10.0.0.0/8) are the standard
        hub-and-spoke egress / inspection design and are not treated as full peer
        routes; segmentation there is done by the TGW route tables. Blackhole routes
        are ignored; prefix-list destinations are not expanded (not evaluated)."""
        key = 'vpcPeeringFullRoute'
        ctx = self.peerRouting
        if ctx is None:
            return
        vpcId = self.vpc['VpcId']
        owner = self.vpc.get('OwnerId')
        if self.selfAccount and owner and owner != self.selfAccount:
            self.results[key] = [0, f"Not evaluable: VPC shared from account {owner} (route tables belong to the VPC owner)"]
            return
        if ctx.get('error'):
            self.results[key] = [0, f"Unable to evaluate ({ctx['error']})"]
            return
        myAccount = self.selfAccount or owner
        ownPrefix = {}
        for c in _vpcCidrs(self.vpc):
            try:
                n = ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            ownPrefix[n.version] = min(ownPrefix.get(n.version, n.prefixlen), n.prefixlen)

        def isSummary(dest):
            try:
                n = ipaddress.ip_network(dest, strict=False)
            except ValueError:
                return False
            return n.prefixlen == 0 or (n.version in ownPrefix and n.prefixlen < ownPrefix[n.version])

        crossAcct, review, unknown, notes, summaries, checked = [], [], [], [], [], 0
        for rt in ctx.get('routeTables', {}).get(vpcId, []):
            rtId = rt.get('RouteTableId')
            for r in rt.get('Routes', []) or []:
                pcxId, tgwId = r.get('VpcPeeringConnectionId'), r.get('TransitGatewayId')
                if not (pcxId or tgwId) or r.get('State', 'active') != 'active':
                    continue
                dest = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock')
                target = pcxId or tgwId
                if not dest:
                    unknown.append(f"{rtId} {r.get('DestinationPrefixListId') or '?'} -> {target} (prefix list)")
                    continue
                peerOwner = None
                if pcxId:
                    if ctx.get('peeringError'):
                        unknown.append(f"{rtId} {dest} -> {pcxId} ({ctx['peeringError']})")
                        continue
                    pcx = ctx.get('peerings', {}).get(pcxId)
                    if pcx is None:
                        continue  # peering not active: route carries no traffic
                    req, acc = pcx.get('RequesterVpcInfo') or {}, pcx.get('AccepterVpcInfo') or {}
                    peerInfo = acc if req.get('VpcId') == vpcId else req
                    peerOwner = peerInfo.get('OwnerId')
                    peers = {peerInfo.get('VpcId') or '?': _vpcCidrs(peerInfo)}
                else:
                    if isSummary(dest):
                        summaries.append(f"{dest} -> {tgwId}")
                        checked += 1
                        continue
                    entry = ctx.get('tgwPeers', {}).get((tgwId, vpcId)) or {}
                    if entry.get('error'):
                        unknown.append(f"{rtId} {dest} -> {tgwId} ({entry['error']})")
                        continue
                    if entry.get('note') and entry['note'] not in notes:
                        notes.append(f"{tgwId}: {entry['note']}")
                    peers = entry.get('peers') or {}
                hit = False
                for peerVpc, cidrs in sorted(peers.items()):
                    full = [c for c in cidrs if _covers(dest, c)]
                    if full:
                        hit = True
                        if pcxId and peerOwner and myAccount and peerOwner != myAccount:
                            crossAcct.append(f"{rtId} {dest} -> {target} covers {peerVpc} (account {peerOwner}) {', '.join(full)}")
                        else:
                            review.append(f"{rtId} {dest} -> {target} covers {peerVpc} {', '.join(full)}")
                if not hit and tgwId and entry.get('partial'):
                    unknown.append(f"{rtId} {dest} -> {tgwId} (TGW shared from another account; peer VPCs not visible)")
                    continue
                checked += 1

        def _list(items):
            return '; '.join(items[:5]) + (f" (+{len(items) - 5} more)" if len(items) > 5 else '')

        if summaries:
            notes.append(f"default/summary TGW route(s) not treated as full peer routes: {_list(summaries)}")
        noteTxt = (' [' + '; '.join(notes) + ']') if notes else ''
        if crossAcct:
            extra = f"; also {len(review)} same-account/TGW full route(s)" if review else ''
            self.results[key] = [-1, f"{len(crossAcct)} peering route(s) open a whole VPC CIDR of another account: {_list(crossAcct)}{extra}{noteTxt}"]
            return
        if unknown:
            self.results[key] = [0, f"Unable to evaluate {len(unknown)} route(s): {_list(unknown)}{noteTxt}"]
            return
        if review:
            self.results[key] = [0, f"Review: {len(review)} route(s) cover a whole peer VPC CIDR (common default; route only the needed peer subnets where possible): {_list(review)}{noteTxt}"]
            return
        if not checked:
            self.results[key] = [1, 'No active VPC peering or transit gateway routes']
            return
        self.results[key] = [1, f"{checked} peering/TGW route(s) limited to parts of the peer CIDRs or default/summary routes{noteTxt}"]

"""botocore Stubber tests for Networkfirewall discovery (real API shapes).

Why Stubber and not the emulator: the emulator rejects AWS managed rule group
ARNs (':aws-managed:') in firewall policies and cannot simulate AccessDenied
on describe_logging_configuration. Both paths matter: an unreadable logging
configuration must surface as status 0 ('Unable to evaluate'), never as a
PASS, and a policy referencing an AWS managed group must not be flagged.
No network calls are made: every client is wrapped by Stubber and uses
dummy credentials."""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.networkfirewall.Networkfirewall import Networkfirewall  # noqa: E402
from services.networkfirewall.drivers.NetworkfirewallFirewall import NetworkfirewallFirewall  # noqa: E402

ACCT = '111122223333'
FW_ARN = f'arn:aws:network-firewall:us-east-1:{ACCT}:firewall/fw1'
POL_ARN = f'arn:aws:network-firewall:us-east-1:{ACCT}:firewall-policy/p1'
MANAGED = 'arn:aws:network-firewall:us-east-1:aws-managed:stateful-rulegroup/ThreatSignaturesBotnetActionOrder'


class _Svc(Networkfirewall):
    """Networkfirewall without the Service bootstrap (no Config, no fork dir)."""
    def __init__(self, client):
        self.region = 'us-east-1'
        self.tags = []
        self.nfwClient = client
        self._policyCache = {}
        self._listError = None
        self._allFirewalls = []
        self._describeError = None

    def __del__(self):
        pass


def _client():
    return boto3.client('network-firewall', region_name='us-east-1',
                        aws_access_key_id='testing', aws_secret_access_key='testing')


def _firewallResp():
    return {
        'UpdateToken': 't',
        'Firewall': {'FirewallName': 'fw1', 'FirewallArn': FW_ARN, 'FirewallPolicyArn': POL_ARN,
                     'VpcId': 'vpc-1', 'SubnetMappings': [{'SubnetId': 'subnet-fw'}],
                     'FirewallId': '11111111-2222-3333-4444-555555555555'},
        'FirewallStatus': {'Status': 'READY', 'ConfigurationSyncStateSummary': 'IN_SYNC'},
    }


def _policyResp(policy):
    return {'UpdateToken': 't',
            'FirewallPolicyResponse': {'FirewallPolicyName': 'p1', 'FirewallPolicyArn': POL_ARN,
                                       'FirewallPolicyId': '66666666-7777-8888-9999-000000000000'},
            'FirewallPolicy': policy}


def _discover(loggingResp, loggingError, policy):
    client = _client()
    stub = Stubber(client)
    stub.add_response('list_firewalls', {'Firewalls': [{'FirewallName': 'fw1', 'FirewallArn': FW_ARN}]})
    stub.add_response('describe_firewall', _firewallResp(), {'FirewallArn': FW_ARN})
    if loggingError:
        stub.add_client_error('describe_logging_configuration', service_error_code=loggingError,
                              http_status_code=400, expected_params={'FirewallArn': FW_ARN})
    else:
        stub.add_response('describe_logging_configuration', loggingResp, {'FirewallArn': FW_ARN})
    stub.add_response('describe_firewall_policy', _policyResp(policy), {'FirewallPolicyArn': POL_ARN})
    with stub:
        fws = _Svc(client).getResources()
        stub.assert_no_pending_responses()
    assert len(fws) == 1
    return fws[0]


def _status(detail, method, key):
    d = NetworkfirewallFirewall(detail, None, None, set())
    getattr(d, method)()
    return d.results[key][0]


WEAK = {'StatelessDefaultActions': ['aws:pass'], 'StatelessFragmentDefaultActions': ['aws:pass']}
STRONG = {'StatelessDefaultActions': ['aws:forward_to_sfe'],
          'StatelessFragmentDefaultActions': ['aws:forward_to_sfe'],
          'StatefulRuleGroupReferences': [{'ResourceArn': MANAGED}]}


def test_stub_policy_flag_fix_with_managed_group():
    noLogs = {'FirewallArn': FW_ARN, 'LoggingConfiguration': {'LogDestinationConfigs': []}}
    bad = _discover(noLogs, None, WEAK)
    assert _status(bad, '_checkNetworkFirewallPolicyWeak', 'networkFirewallPolicyWeak') == -1
    good = _discover(noLogs, None, STRONG)
    assert _status(good, '_checkNetworkFirewallPolicyWeak', 'networkFirewallPolicyWeak') == 1


def test_stub_logging_flag_fix_and_access_denied():
    noLogs = {'FirewallArn': FW_ARN, 'LoggingConfiguration': {'LogDestinationConfigs': []}}
    full = {'FirewallArn': FW_ARN, 'LoggingConfiguration': {'LogDestinationConfigs': [
        {'LogType': t, 'LogDestinationType': 'CloudWatchLogs', 'LogDestination': {'logGroup': 'g'}}
        for t in ('ALERT', 'FLOW')]}}
    m, k = '_checkNetworkFirewallLoggingDisabled', 'networkFirewallLoggingDisabled'
    assert _status(_discover(noLogs, None, STRONG), m, k) == -1
    assert _status(_discover(full, None, STRONG), m, k) == 1
    assert _status(_discover(None, 'AccessDeniedException', STRONG), m, k) == 0


def test_stub_list_firewalls_access_denied():
    client = _client()
    stub = Stubber(client)
    stub.add_client_error('list_firewalls', service_error_code='AccessDeniedException', http_status_code=400)
    with stub:
        svc = _Svc(client)
        assert svc.getResources() is None
    assert svc._listError == 'AccessDeniedException'


# ------------------------------------------------------------------ #
# Route shape: EC2 DescribeRouteTables reports a route to a firewall /
# GWLB endpoint as GatewayId='vpce-...'. The Route shape has no
# VpcEndpointId member, so the driver must read GatewayId.
# ------------------------------------------------------------------ #
def _ec2():
    return boto3.client('ec2', region_name='us-east-1',
                        aws_access_key_id='testing', aws_secret_access_key='testing')


def _routeTables(routesBySubnet):
    out = []
    for i, (sid, routes) in enumerate(routesBySubnet.items()):
        out.append({'RouteTableId': f'rtb-{i}', 'VpcId': 'vpc-1',
                    'Associations': [{'Main': False, 'SubnetId': sid}],
                    'Routes': [{'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local',
                                'State': 'active'}] + routes})
    return out


def _parsedRouteTables(routesBySubnet):
    """Round-trip the route tables through a Stubber-wrapped EC2 client so
    the driver sees exactly the shape boto3 returns."""
    client = _ec2()
    stub = Stubber(client)
    stub.add_response('describe_route_tables', {'RouteTables': _routeTables(routesBySubnet)})
    with stub:
        return client.describe_route_tables()['RouteTables']


def test_stub_route_shape_has_no_vpc_endpoint_id_member():
    shape = _ec2().meta.service_model.shape_for('Route')
    assert 'VpcEndpointId' not in shape.members
    assert 'GatewayId' in shape.members


def test_stub_firewall_before_nat_design_real_route_shape():
    """Protected subnet -> firewall vpce -> NAT -> IGW. The NAT subnet returns
    the protected CIDR through the firewall endpoint (GatewayId=vpce-...), so
    its 0.0.0.0/0 -> igw route is not a bypass. Removing that return route
    makes the NAT subnet an uninspected internet path (flag -> fix)."""
    ep = 'vpce-fw1'
    detail = {'FirewallName': 'fw1', 'FirewallArn': FW_ARN,
              'Firewall': dict(_firewallResp()['Firewall']),
              'FirewallStatus': {'SyncStates': {'us-east-1a': {'Attachment': {
                  'SubnetId': 'subnet-fw', 'EndpointId': ep}}}}}
    nat = {'NatGatewayId': 'nat-1', 'SubnetId': 'subnet-nat', 'VpcId': 'vpc-1'}

    def net(natReturn):
        natRoutes = [{'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1', 'State': 'active'}]
        if natReturn:
            natRoutes.append({'DestinationCidrBlock': '10.0.2.0/24', 'GatewayId': ep, 'State': 'active'})
        tables = _parsedRouteTables({
            'subnet-fw': [{'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': 'nat-1', 'State': 'active'}],
            'subnet-a': [{'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': ep, 'State': 'active'}],
            'subnet-nat': natRoutes,
        })
        return {'subnets': [{'SubnetId': s} for s in ('subnet-fw', 'subnet-a', 'subnet-nat')],
                'routeTables': tables, 'natGateways': [nat], 'gwlbEndpoints': [], 'igws': ['igw-1']}

    m, k = '_checkNetworkFirewallRouteBypass', 'networkFirewallRouteBypass'
    bad = NetworkfirewallFirewall(detail, net(False), None, {ep})
    getattr(bad, m)()
    assert bad.results[k][0] == -1
    good = NetworkfirewallFirewall(detail, net(True), None, {ep})
    getattr(good, m)()
    assert good.results[k][0] == 1, good.results[k]


# ------------------------------------------------------------------ #
# Firewall VPC membership must include firewalls excluded by --tags.
# ------------------------------------------------------------------ #
def test_stub_tag_filtered_firewall_still_marks_vpc():
    client = _client()
    stub = Stubber(client)
    stub.add_response('list_firewalls', {'Firewalls': [{'FirewallName': 'fw1', 'FirewallArn': FW_ARN}]})
    stub.add_response('describe_firewall', _firewallResp(), {'FirewallArn': FW_ARN})
    svc = _Svc(client)
    svc.tags = [{'Name': 'tag:env', 'Values': ['prod']}]
    svc._tags = {'env': ['prod']}
    with stub:
        fws = svc.getResources()
        stub.assert_no_pending_responses()
    assert fws == []                       # excluded from per-firewall checks
    assert [f['Firewall']['VpcId'] for f in svc._allFirewalls] == ['vpc-1']


def _adviseVpcStatus(svc, firewalls):
    """Run advise() with a fixed network inventory: vpc-1 routes 0.0.0.0/0 to
    an IGW and has no GWLB endpoint. Driver run() is replaced by a direct
    check call (Evaluator.run needs the global scan Config)."""
    import services.networkfirewall.Networkfirewall as mod
    from services.networkfirewall.drivers.NetworkfirewallVpc import NetworkfirewallVpc

    class _Vpc(NetworkfirewallVpc):
        def run(self, serviceName):
            self._checkNetworkFirewallNotDeployed()

        def __del__(self):
            pass

    net = {'subnets': [], 'natGateways': [], 'gwlbEndpoints': [], 'gwlbSubnets': [],
           'igws': ['igw-1'],
           'routeTables': [{'RouteTableId': 'rtb-main', 'VpcId': 'vpc-1', 'Associations': [{'Main': True}],
                            'Routes': [{'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1',
                                        'State': 'active'}]}]}
    svc.getResources = lambda: firewalls
    svc.getNetwork = lambda: ({'vpc-1': net}, [{'VpcId': 'vpc-1'}], None)
    svc._hasNetworkInterfaces = lambda vpcId: True
    orig = mod.NetworkfirewallVpc
    mod.NetworkfirewallVpc = _Vpc
    try:
        objs = svc.advise()
    finally:
        mod.NetworkfirewallVpc = orig
    return objs['VPC::vpc-1']['results']


def _vpcResult(info):
    return info['networkFirewallNotDeployed'][0] if 'networkFirewallNotDeployed' in info else None


def test_stub_not_deployed_uses_all_described_firewalls():
    svc = _Svc(_client())
    ## No firewall at all -> FAIL.
    info = _adviseVpcStatus(svc, [])
    assert _vpcResult(info) == -1
    ## Firewall in vpc-1 excluded by --tags (only in _allFirewalls) -> PASS.
    svc = _Svc(_client())
    svc._allFirewalls = [{'FirewallName': 'fw1', 'Firewall': {'VpcId': 'vpc-1'}}]
    assert _vpcResult(_adviseVpcStatus(svc, [])) == 1
    ## describe_firewall failed for some firewall (VPC unknown) -> not evaluable.
    svc = _Svc(_client())
    svc._describeError = 'AccessDeniedException'
    assert _vpcResult(_adviseVpcStatus(svc, [])) == 0

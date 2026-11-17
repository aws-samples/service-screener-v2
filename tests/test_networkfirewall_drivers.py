"""Driver-level tests for the Network Firewall checks, covering branches the
AWS Emulator cannot reproduce:
- AWS managed rule group ARNs (the emulator rejects ':aws-managed:' ARNs),
- strict-order stateful default drop with no rule groups,
- transit-gateway-attached firewalls (no VpcId),
- the "firewall before NAT" design (NAT subnet -> IGW with return routes via
  the firewall endpoint),
- unreadable data (AccessDenied) -> status 0, never a silent PASS.
Inputs mirror the real API response shapes of describe_firewall,
describe_logging_configuration, describe_firewall_policy and
describe_route_tables. Flag -> fix: each scenario asserts -1 for the
misconfigured input and not -1 for the fixed input."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.networkfirewall.drivers.NetworkfirewallFirewall import NetworkfirewallFirewall  # noqa: E402
from services.networkfirewall.drivers.NetworkfirewallVpc import NetworkfirewallVpc  # noqa: E402

VPC = 'vpc-1'
EP = 'vpce-fw1'
MANAGED = 'arn:aws:network-firewall:us-east-1:aws-managed:stateful-rulegroup/ThreatSignaturesBotnetStrictOrder'
CUSTOM = 'arn:aws:network-firewall:us-east-1:111122223333:stateful-rulegroup/custom'


def fwDetail(policy=None, logging=None, **extra):
    d = {
        'FirewallName': 'fw1',
        'FirewallArn': 'arn:aws:network-firewall:us-east-1:111122223333:firewall/fw1',
        'Firewall': {'FirewallName': 'fw1', 'VpcId': VPC,
                     'FirewallPolicyArn': 'arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/p',
                     'SubnetMappings': [{'SubnetId': 'subnet-fw'}]},
        'FirewallStatus': {'SyncStates': {'us-east-1a': {'Attachment': {'SubnetId': 'subnet-fw', 'EndpointId': EP}}}},
        '_policy': policy if policy is not None else {},
        '_policyError': None,
        '_logging': logging if logging is not None else {'LogDestinationConfigs': []},
        '_loggingError': None,
    }
    d.update(extra)
    return d


def rt(rtId, subnet=None, main=False, routes=()):
    assoc = [{'Main': True}] if main else [{'Main': False, 'SubnetId': subnet}]
    return {'RouteTableId': rtId, 'VpcId': VPC, 'Associations': assoc,
            'Routes': [{'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local', 'State': 'active'}] + list(routes)}


def route(dest='0.0.0.0/0', **t):
    r = {'DestinationCidrBlock': dest, 'State': 'active'}
    r.update(t)
    return r


def run(driver, method, key):
    getattr(driver, method)()
    return driver.results[key][0]


def firewallStatus(method, key, fw, net=None, netError=None):
    return run(NetworkfirewallFirewall(fw, net, netError, {EP}), method, key)


# ---------------------------------------------------------------- logging
def test_logging_flow_only_flagged_then_fixed():
    L = '_checkNetworkFirewallLoggingDisabled', 'networkFirewallLoggingDisabled'
    flow = {'LogDestinationConfigs': [{'LogType': 'FLOW', 'LogDestinationType': 'S3', 'LogDestination': {'bucketName': 'b'}}]}
    both = {'LogDestinationConfigs': flow['LogDestinationConfigs'] + [
        {'LogType': 'ALERT', 'LogDestinationType': 'S3', 'LogDestination': {'bucketName': 'b'}}]}
    assert firewallStatus(*L, fwDetail(logging=flow)) == -1
    assert firewallStatus(*L, fwDetail(logging=both)) == 1


def test_logging_access_denied_is_not_evaluable():
    L = '_checkNetworkFirewallLoggingDisabled', 'networkFirewallLoggingDisabled'
    assert firewallStatus(*L, fwDetail(logging={}, _loggingError='AccessDeniedException')) == 0
    assert firewallStatus(*L, fwDetail(_error='AccessDeniedException')) == 0


# ---------------------------------------------------------------- policy
P = '_checkNetworkFirewallPolicyWeak', 'networkFirewallPolicyWeak'


def test_policy_fragment_pass_flagged_then_fixed_with_managed_group():
    bad = {'StatelessDefaultActions': ['aws:forward_to_sfe'], 'StatelessFragmentDefaultActions': ['aws:pass'],
           'StatefulRuleGroupReferences': [{'ResourceArn': MANAGED}]}
    good = dict(bad, StatelessFragmentDefaultActions=['aws:drop'])
    assert firewallStatus(*P, fwDetail(policy=bad)) == -1
    d = NetworkfirewallFirewall(fwDetail(policy=good), None, None, {EP})
    d._checkNetworkFirewallPolicyWeak()
    assert d.results['networkFirewallPolicyWeak'][0] == 1
    assert '1 AWS managed' in d.results['networkFirewallPolicyWeak'][1]


def test_policy_custom_groups_only_is_pass_with_advice():
    pol = {'StatelessDefaultActions': ['aws:forward_to_sfe'], 'StatelessFragmentDefaultActions': ['aws:forward_to_sfe'],
           'StatefulRuleGroupReferences': [{'ResourceArn': CUSTOM}]}
    d = NetworkfirewallFirewall(fwDetail(policy=pol), None, None, {EP})
    d._checkNetworkFirewallPolicyWeak()
    status, msg = d.results['networkFirewallPolicyWeak']
    assert status == 1 and 'none are AWS managed' in msg


def test_policy_no_groups_but_strict_default_drop_not_flagged():
    bad = {'StatelessDefaultActions': ['aws:forward_to_sfe'], 'StatelessFragmentDefaultActions': ['aws:forward_to_sfe'],
           'StatefulEngineOptions': {'RuleOrder': 'STRICT_ORDER'}}
    good = dict(bad, StatefulDefaultActions=['aws:drop_established', 'aws:alert_established'])
    assert firewallStatus(*P, fwDetail(policy=bad)) == -1
    assert firewallStatus(*P, fwDetail(policy=good)) != -1


def test_policy_unreadable_is_not_evaluable():
    assert firewallStatus(*P, fwDetail(policy={}, _policyError='AccessDeniedException')) == 0


# ---------------------------------------------------------------- route bypass
R = '_checkNetworkFirewallRouteBypass', 'networkFirewallRouteBypass'


def net(routeTables, nats=(), subnets=('subnet-fw', 'subnet-a', 'subnet-nat')):
    return {'subnets': [{'SubnetId': s, 'VpcId': VPC} for s in subnets], 'routeTables': routeTables,
            'natGateways': list(nats), 'gwlbEndpoints': [EP], 'igws': ['igw-1']}


def test_route_bypass_main_route_table_flagged_then_fixed():
    fwRt = rt('rtb-fw', 'subnet-fw', routes=[route(GatewayId='igw-1')])
    bad = net([fwRt, rt('rtb-main', main=True, routes=[route(GatewayId='igw-1')])], subnets=('subnet-fw', 'subnet-a'))
    good = net([fwRt, rt('rtb-main', main=True, routes=[route(VpcEndpointId=EP)])], subnets=('subnet-fw', 'subnet-a'))
    assert firewallStatus(*R, fwDetail(), bad) == -1
    assert firewallStatus(*R, fwDetail(), good) == 1


def test_route_bypass_ipv6_egress_only_flagged():
    fwRt = rt('rtb-fw', 'subnet-fw', routes=[route(GatewayId='igw-1')])
    v6 = {'DestinationIpv6CidrBlock': '::/0', 'EgressOnlyInternetGatewayId': 'eigw-1', 'State': 'active'}
    bad = net([fwRt, rt('rtb-a', 'subnet-a', routes=[route(VpcEndpointId=EP), v6])], subnets=('subnet-fw', 'subnet-a'))
    good = net([fwRt, rt('rtb-a', 'subnet-a', routes=[route(VpcEndpointId=EP)])], subnets=('subnet-fw', 'subnet-a'))
    assert firewallStatus(*R, fwDetail(), bad) == -1
    assert firewallStatus(*R, fwDetail(), good) == 1


def test_route_firewall_before_nat_design_not_flagged():
    """subnet-a -> firewall -> NAT (subnet-nat) -> IGW, with the NAT subnet
    returning subnet-a traffic through the firewall endpoint."""
    nat = {'NatGatewayId': 'nat-1', 'SubnetId': 'subnet-nat', 'VpcId': VPC}
    tables = [
        rt('rtb-fw', 'subnet-fw', routes=[route(NatGatewayId='nat-1')]),
        rt('rtb-a', 'subnet-a', routes=[route(VpcEndpointId=EP)]),
        rt('rtb-nat', 'subnet-nat', routes=[route(GatewayId='igw-1'), route('10.0.2.0/24', VpcEndpointId=EP)]),
    ]
    assert firewallStatus(*R, fwDetail(), net(tables, [nat])) == 1
    ## Without the return route the NAT subnet is an uninspected internet path.
    tables[2] = rt('rtb-nat', 'subnet-nat', routes=[route(GatewayId='igw-1')])
    assert firewallStatus(*R, fwDetail(), net(tables, [nat])) == -1


def test_route_transit_gateway_target_not_judged():
    tables = [rt('rtb-fw', 'subnet-fw', routes=[route(GatewayId='igw-1')]),
              rt('rtb-a', 'subnet-a', routes=[route(TransitGatewayId='tgw-1')])]
    assert firewallStatus(*R, fwDetail(), net(tables, subnets=('subnet-fw', 'subnet-a'))) == 1


def test_route_tgw_attached_firewall_and_errors_not_evaluable():
    tgw = fwDetail()
    tgw['Firewall'] = dict(tgw['Firewall'], VpcId=None, TransitGatewayId='tgw-1')
    assert firewallStatus(*R, tgw, None) == 0
    assert firewallStatus(*R, fwDetail(), None, 'UnauthorizedOperation') == 0


# ---------------------------------------------------------------- not deployed
N = '_checkNetworkFirewallNotDeployed', 'networkFirewallNotDeployed'


def vpcStatus(netData, hasFirewall=False, listError=None, hasEni=True):
    return run(NetworkfirewallVpc({'VpcId': VPC}, netData, hasFirewall, listError, hasEni), *N)


def test_not_deployed_flagged_then_fixed_by_gwlb_endpoint():
    tables = [rt('rtb-main', main=True, routes=[route(GatewayId='igw-1')])]
    bad = {'routeTables': tables, 'igws': ['igw-1'], 'gwlbEndpoints': []}
    assert vpcStatus(bad) == -1
    assert vpcStatus(dict(bad, gwlbEndpoints=['vpce-gwlb'])) == 1
    assert vpcStatus(bad, hasFirewall=True) == 1


def test_not_deployed_edge_cases():
    tables = [rt('rtb-main', main=True, routes=[route(GatewayId='igw-1')])]
    data = {'routeTables': tables, 'igws': ['igw-1'], 'gwlbEndpoints': []}
    assert vpcStatus(data, hasEni=False) == 1                       # no workloads
    assert vpcStatus(data, listError='AccessDeniedException') == 0  # cannot list firewalls
    assert vpcStatus(data, hasEni='UnauthorizedOperation') == 0
    tgwOnly = {'routeTables': [rt('rtb-main', main=True, routes=[route(TransitGatewayId='tgw-1')])],
               'igws': [], 'gwlbEndpoints': []}
    assert vpcStatus(tgwOnly) == 1                                  # centralised egress

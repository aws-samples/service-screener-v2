"""networkFirewallNotDeployed: only route tables that subnets use (the main
table or a table with a subnet association) make a VPC internet-connected.
Inputs mirror describe_route_tables response shapes."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from services.networkfirewall.drivers.NetworkfirewallVpc import NetworkfirewallVpc  # noqa: E402

VPC = 'vpc-1'
LOCAL = {'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local', 'State': 'active'}
IGW_DEFAULT = {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1', 'State': 'active'}
TGW_DEFAULT = {'DestinationCidrBlock': '0.0.0.0/0', 'TransitGatewayId': 'tgw-1', 'State': 'active'}


def _assoc(**kw):
    a = {'Main': False, 'RouteTableAssociationId': 'rtbassoc-1', 'RouteTableId': 'x',
         'AssociationState': {'State': 'associated'}}
    a.update(kw)
    return a


def _status(tables):
    net = {'routeTables': tables, 'igws': ['igw-1'], 'gwlbEndpoints': [], 'subnets': [{'SubnetId': 'subnet-a'}]}
    d = NetworkfirewallVpc({'VpcId': VPC}, net, False, None, True)
    d._checkNetworkFirewallNotDeployed()
    return d.results['networkFirewallNotDeployed']


MAIN_TGW = {'RouteTableId': 'rtb-main', 'VpcId': VPC, 'Associations': [_assoc(Main=True)],
            'Routes': [LOCAL, TGW_DEFAULT]}


def test_orphan_igw_route_table_not_internet_connected():
    orphan = {'RouteTableId': 'rtb-orphan', 'VpcId': VPC, 'Associations': [], 'Routes': [LOCAL, IGW_DEFAULT]}
    r = _status([MAIN_TGW, orphan])
    assert r[0] == 1, r


def test_disassociated_and_edge_only_tables_not_internet_connected():
    gone = {'RouteTableId': 'rtb-gone', 'VpcId': VPC, 'Routes': [LOCAL, IGW_DEFAULT],
            'Associations': [_assoc(SubnetId='subnet-a', AssociationState={'State': 'disassociated'})]}
    edge = {'RouteTableId': 'rtb-edge', 'VpcId': VPC, 'Routes': [LOCAL, IGW_DEFAULT],
            'Associations': [_assoc(GatewayId='igw-1')]}
    assert _status([MAIN_TGW, gone, edge])[0] == 1


def test_subnet_associated_igw_table_flagged_then_orphaned_passes():
    used = {'RouteTableId': 'rtb-pub', 'VpcId': VPC, 'Routes': [LOCAL, IGW_DEFAULT],
            'Associations': [_assoc(SubnetId='subnet-a')]}
    r = _status([MAIN_TGW, used])
    assert r[0] == -1 and 'rtb-pub' in r[1], r
    assert _status([MAIN_TGW, dict(used, Associations=[])])[0] == 1


def test_main_table_with_igw_route_is_internet_connected():
    main = dict(MAIN_TGW, Routes=[LOCAL, IGW_DEFAULT])
    assert _status([main])[0] == -1

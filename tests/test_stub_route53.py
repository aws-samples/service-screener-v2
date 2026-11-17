"""Stubber tests for route53 dnsFirewallNoBlockRules edge cases the emulator cannot
produce: list_firewall_rules AccessDenied (e.g. a rule group shared via RAM / Firewall
Manager that this account cannot read) and AWS-managed list classification. Drives
Route53.getDnsFirewallVpcs with a real boto3 route53resolver client wrapped by Stubber,
then the Route53DnsFirewallVpc driver directly."""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.route53.Route53 import Route53  # noqa: E402
from services.route53.drivers.Route53DnsFirewallVpc import Route53DnsFirewallVpc  # noqa: E402

VPC = 'vpc-0123456789abcdef0'
ASSOC = {'Id': 'rslvr-frgassoc-1', 'FirewallRuleGroupId': 'rslvr-frg-1', 'VpcId': VPC,
         'Name': 'a1', 'Priority': 101, 'Status': 'COMPLETE'}


def _client():
    return boto3.client('route53resolver', region_name='us-east-1',
                        aws_access_key_id='x', aws_secret_access_key='x')


class _Route53NoInit(Route53):
    """Skip Service.__init__/__del__ (needs a full scan Config); only discovery is used."""
    def __init__(self):
        pass

    def __del__(self):
        pass


def _vpcs(client):
    svc = _Route53NoInit()
    svc.region = 'us-east-1'
    svc.resolverClient = client
    return svc.getDnsFirewallVpcs({'_firewallAssociations': [ASSOC]})


def _status(client):
    vpcs = _vpcs(client)
    assert len(vpcs) == 1
    d = Route53DnsFirewallVpc(vpcs[0], client)
    d._checkDnsFirewallNoBlockRules()
    return d.results['dnsFirewallNoBlockRules']


def _run(rulesResp=None, rulesError=None):
    c = _client()
    with Stubber(c) as st:
        st.add_response('list_firewall_domain_lists', {'FirewallDomainLists': [
            {'Id': 'rslvr-fdl-m', 'Name': 'AWSManagedDomainsMalwareDomainList',
             'ManagedOwnerName': 'Route 53 Resolver DNS Firewall'}]})
        if rulesError:
            st.add_client_error('list_firewall_rules', service_error_code=rulesError,
                                http_status_code=403)
        else:
            st.add_response('list_firewall_rules', rulesResp,
                            {'FirewallRuleGroupId': 'rslvr-frg-1'})
        return _status(c)


def test_alert_only_flags_then_block_passes():
    bad = _run({'FirewallRules': [{'FirewallRuleGroupId': 'rslvr-frg-1',
                                   'FirewallDomainListId': 'rslvr-fdl-m',
                                   'Priority': 1, 'Action': 'ALERT'}]})
    assert bad[0] == -1
    good = _run({'FirewallRules': [{'FirewallRuleGroupId': 'rslvr-frg-1',
                                    'FirewallDomainListId': 'rslvr-fdl-m',
                                    'Priority': 1, 'Action': 'BLOCK', 'BlockResponse': 'NODATA'}]})
    assert good[0] == 1 and 'AWS-managed' in good[1]


def test_empty_rule_group_flags():
    assert _run({'FirewallRules': []})[0] == -1


def test_access_denied_is_not_evaluable():
    res = _run(rulesError='AccessDeniedException')
    assert res[0] == 0 and 'Unable to evaluate (AccessDeniedException)' in res[1]

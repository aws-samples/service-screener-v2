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

"""
Stubber tests for the EventBridge routing checks.

The emulator cannot represent these states: securityhub.get_administrator_account
is NotImplemented, GuardDuty membership needs a second (administrator) account,
Security Hub finding aggregation needs multiple Regions, and AWS Health global
routing needs a us-east-1 bus distinct from the scanned Region. These tests use
real boto3 clients wrapped in botocore.stub.Stubber (real API shapes, no network)
and drive the Eventbridge service helpers and EventbridgeRegional driver directly.
"""
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.eventbridge.Eventbridge import Eventbridge  # noqa: E402
from services.eventbridge.drivers.EventbridgeRegional import EventbridgeRegional  # noqa: E402

FAKE = dict(aws_access_key_id='testing', aws_secret_access_key='testing')


def _client(svc, region):
    return boto3.client(svc, region_name=region, endpoint_url='https://127.0.0.1:1', **FAKE)


class _Sess:
    """Minimal stand-in for Config ssBoto returning pre-stubbed clients."""
    def __init__(self, clients):
        self.clients = clients

    def client(self, svc, region_name=None, config=None):
        key = (svc, region_name) if (svc, region_name) in self.clients else svc
        return self.clients[key]


def _service(region, clients):
    svc = Eventbridge.__new__(Eventbridge)
    svc.region = region
    svc.ssBoto = _Sess(clients)
    from botocore.config import Config as C
    svc.bConfig = C(region_name=region)
    svc.ebClient = clients['events']
    svc.chartData = {}
    import time; svc.overallTimeStart = time.time()
    return svc


def _stubRules(stub, rules, targetsByRule):
    stub.add_response('list_rules', {'Rules': rules}, {'EventBusName': 'default'})
    for name, targets in targetsByRule:
        stub.add_response('list_targets_by_rule', {'Targets': targets} if targets else {},
                          {'Rule': name, 'EventBusName': 'default'})


def _rule(name, pattern, state='ENABLED'):
    return {'Name': name, 'Arn': f'arn:aws:events:eu-west-1:111111111111:rule/{name}',
            'EventPattern': json.dumps(pattern), 'State': state, 'EventBusName': 'default'}


TARGET = [{'Id': 't', 'Arn': 'arn:aws:sns:eu-west-1:111111111111:sec'}]


def _evaluate(routing, key):
    obj = EventbridgeRegional({'_routing': routing}, None)
    getattr(obj, '_check' + key[0].upper() + key[1:])()
    return obj.results[key][0]


def _securityHubStubs(sh, admin=None, aggregator=None):
    sh.add_response('get_administrator_account', {'Administrator': admin} if admin else {})
    if aggregator:
        arn = f"arn:aws:securityhub:{aggregator['FindingAggregationRegion']}:111111111111:finding-aggregator/x"
        sh.add_response('list_finding_aggregators', {'FindingAggregators': [{'FindingAggregatorArn': arn}]})
        sh.add_response('get_finding_aggregator', dict(aggregator, FindingAggregatorArn=arn),
                        {'FindingAggregatorArn': arn})
    else:
        sh.add_response('list_finding_aggregators', {'FindingAggregators': []})


def _routingFor(region, rules, targets, gdAdmin=None, shAdmin=None, aggregator=None, globalRules=None):
    ev = _client('events', region)
    gd = _client('guardduty', region)
    sh = _client('securityhub', region)
    clients = {'events': ev, 'guardduty': gd, 'securityhub': sh}
    stubs = [Stubber(ev), Stubber(gd), Stubber(sh)]
    _stubRules(stubs[0], rules, targets)
    if region != 'us-east-1':
        evg = _client('events', 'us-east-1')
        clients[('events', 'us-east-1')] = evg
        sg = Stubber(evg)
        _stubRules(sg, *(globalRules or ([], [])))
        stubs.append(sg)
    if gdAdmin:
        stubs[1].add_response('list_detectors', {'DetectorIds': ['d1']})
        stubs[1].add_response('get_administrator_account', {'Administrator': gdAdmin}, {'DetectorId': 'd1'})
    else:
        stubs[1].add_response('list_detectors', {'DetectorIds': []})
    _securityHubStubs(stubs[2], shAdmin, aggregator)
    for s in stubs:
        s.activate()
    routing = _service(region, clients)._getRoutingDetail()
    for s in stubs:
        s.assert_no_pending_responses()
    return routing


def test_security_flag_then_fix():
    bad = _routingFor('eu-west-1', [_rule('r1', {'source': ['aws.ec2']})], [])
    assert _evaluate(bad, 'securityFindingsNotRouted') == -1
    good = _routingFor('eu-west-1', [_rule('r1', {'source': ['aws.securityhub']})], [('r1', TARGET)])
    assert _evaluate(good, 'securityFindingsNotRouted') == 1


def test_security_rule_without_target_or_disabled_is_flagged():
    noTarget = _routingFor('eu-west-1', [_rule('r1', {'source': ['aws.guardduty']})], [('r1', [])])
    assert _evaluate(noTarget, 'securityFindingsNotRouted') == -1
    disabled = _routingFor('eu-west-1', [_rule('r1', {'source': ['aws.guardduty']}, 'DISABLED')], [('r1', TARGET)])
    assert _evaluate(disabled, 'securityFindingsNotRouted') == -1


def test_security_member_account_is_info():
    gd = {'AccountId': '222222222222', 'InvitationId': 'i', 'RelationshipStatus': 'Enabled', 'InvitedAt': 'x'}
    r = _routingFor('eu-west-1', [], [], gdAdmin=gd)
    assert _evaluate(r, 'securityFindingsNotRouted') == 0
    sh = {'AccountId': '222222222222', 'MemberStatus': 'Enabled'}
    r = _routingFor('eu-west-1', [], [], shAdmin=sh)
    assert _evaluate(r, 'securityFindingsNotRouted') == 0
    removed = {'AccountId': '222222222222', 'InvitationId': 'i', 'RelationshipStatus': 'Removed', 'InvitedAt': 'x'}
    r = _routingFor('eu-west-1', [], [], gdAdmin=removed)
    assert _evaluate(r, 'securityFindingsNotRouted') == -1


def test_security_aggregated_elsewhere_is_info():
    agg = {'FindingAggregationRegion': 'us-east-1', 'RegionLinkingMode': 'ALL_REGIONS'}
    r = _routingFor('eu-west-1', [], [], aggregator=agg)
    assert _evaluate(r, 'securityFindingsNotRouted') == 0
    notLinked = {'FindingAggregationRegion': 'us-east-1', 'RegionLinkingMode': 'SPECIFIED_REGIONS',
                 'Regions': ['ap-southeast-1']}
    r = _routingFor('eu-west-1', [], [], aggregator=notLinked)
    assert _evaluate(r, 'securityFindingsNotRouted') == -1


def test_security_access_denied_is_unable_to_evaluate():
    ev = _client('events', 'us-east-1')
    st = Stubber(ev)
    st.add_client_error('list_rules', 'AccessDeniedException', expected_params={'EventBusName': 'default'})
    st.activate()
    rules, err = _service('us-east-1', {'events': ev})._listRoutingRules(ev, ['aws.guardduty'])
    assert err == 'AccessDeniedException'
    assert _evaluate({'regionError': err}, 'securityFindingsNotRouted') == 0
    assert _evaluate({'regionError': err}, 'healthEventsNotRouted') == 0


def test_health_flag_then_fix_and_global_partial():
    bad = _routingFor('eu-west-1', [], [], globalRules=([], []))
    assert _evaluate(bad, 'healthEventsNotRouted') == -1
    globalOnly = _routingFor('eu-west-1', [], [],
                             globalRules=([_rule('g', {'source': ['aws.health']})], [('g', TARGET)]))
    assert _evaluate(globalOnly, 'healthEventsNotRouted') == 0
    good = _routingFor('eu-west-1', [_rule('h', {'source': [{'prefix': 'aws.he'}]})], [('h', TARGET)],
                       globalRules=([], []))
    assert _evaluate(good, 'healthEventsNotRouted') == 1


@pytest.mark.parametrize('pattern,source,expected', [
    ({'source': ['aws.health']}, 'aws.health', True),
    ({'source': ['aws.ec2']}, 'aws.health', False),
    ({'source': [{'prefix': 'aws.'}]}, 'aws.guardduty', True),
    ({'source': [{'anything-but': ['aws.health']}]}, 'aws.health', False),
    ({'source': [{'anything-but': 'aws.ec2'}]}, 'aws.health', True),
    ({'source': [{'wildcard': 'aws.*'}]}, 'aws.inspector2', True),
    ({'source': [{'equals-ignore-case': 'AWS.Health'}]}, 'aws.health', True),
    ({'$or': [{'source': ['aws.ec2']}, {'source': ['aws.securityhub']}]}, 'aws.securityhub', True),
    ({'account': ['111111111111']}, 'aws.health', True),
    ({'detail-type': ['AWS API Call via CloudTrail']}, 'aws.health', False),
    ('not json', 'aws.health', False),
])
def test_pattern_matching(pattern, source, expected):
    assert EventbridgeRegional.patternMatchesSource(
        pattern if isinstance(pattern, str) else json.dumps(pattern), source) is expected

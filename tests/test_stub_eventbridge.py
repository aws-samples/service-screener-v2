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


# ---- detail-type / detail evaluation (rules that never receive findings) -- #
## A rule names a finding source but narrows to events that are not findings:
## CloudTrail API calls (GuardDuty tamper alarms from CIS / landing-zone
## baselines), Security Hub custom actions (fire only when a person acts) or
## Inspector scan/coverage events. These were counted as routing findings.

GD_TAMPER = {'source': ['aws.guardduty'], 'detail-type': ['AWS API Call via CloudTrail'],
             'detail': {'eventSource': ['guardduty.amazonaws.com'],
                        'eventName': ['DeleteDetector', 'DisassociateFromMasterAccount']}}


@pytest.mark.parametrize('pattern,source,expected', [
    (GD_TAMPER, 'aws.guardduty', False),
    ({'source': [{'prefix': 'aws.'}], 'detail-type': ['AWS API Call via CloudTrail']}, 'aws.health', False),
    ({'source': [{'prefix': 'aws.'}], 'detail-type': ['AWS API Call via CloudTrail']}, 'aws.guardduty', False),
    ({'source': ['aws.securityhub'], 'detail-type': ['Security Hub Findings - Custom Action']},
     'aws.securityhub', False),
    ({'source': ['aws.inspector2'], 'detail-type': ['Inspector2 Scan', 'Inspector2 Coverage']},
     'aws.inspector2', False),
    ## CloudTrail-only detail field without a detail-type filter still cannot match a finding
    ({'source': ['aws.guardduty'], 'detail': {'eventName': ['DeleteDetector']}}, 'aws.guardduty', False),
    ({'source': ['aws.guardduty'], 'detail': {'userIdentity': {'type': ['Root']}}}, 'aws.guardduty', False),
    ## ... but an exists:false alternative is satisfied by a finding
    ({'source': ['aws.guardduty'], 'detail': {'eventName': [{'exists': False}]}}, 'aws.guardduty', True),
    ## $or inside detail: one alternative can match a finding
    ({'source': ['aws.guardduty'], 'detail': {'$or': [{'eventName': ['X']}, {'severity': [{'numeric': ['>=', 7]}]}]}},
     'aws.guardduty', True),
    ## Genuine finding routes keep matching
    ({'source': ['aws.guardduty'], 'detail-type': ['GuardDuty Finding']}, 'aws.guardduty', True),
    ({'source': ['aws.guardduty'], 'detail-type': ['GuardDuty Finding'],
      'detail': {'severity': [{'numeric': ['>=', 7]}]}}, 'aws.guardduty', True),
    ({'source': ['aws.securityhub'], 'detail-type': ['Security Hub Findings - Imported']}, 'aws.securityhub', True),
    ({'source': ['aws.securityhub'], 'detail-type': ['Findings Imported V2']}, 'aws.securityhub', True),
    ({'source': ['aws.inspector2'], 'detail-type': ['Inspector2 Finding']}, 'aws.inspector2', True),
    ({'source': ['aws.access-analyzer'], 'detail-type': ['Access Analyzer Finding']}, 'aws.access-analyzer', True),
    ({'source': ['aws.access-analyzer'], 'detail-type': ['Unused Access Finding for IAM entities']},
     'aws.access-analyzer', True),
    ({'source': ['aws.health'], 'detail-type': ['AWS Health Event']}, 'aws.health', True),
    ({'source': ['aws.health'], 'detail-type': ['AWS Health Abuse Event']}, 'aws.health', True),
    ({'source': ['aws.health'], 'detail-type': [{'prefix': 'AWS Health'}]}, 'aws.health', True),
    ({'source': ['aws.guardduty'], 'detail-type': [{'anything-but': ['AWS API Call via CloudTrail']}]},
     'aws.guardduty', True),
    ## detail-type alone identifies the event (source is implied)
    ({'detail-type': ['GuardDuty Finding']}, 'aws.guardduty', True),
    ({'detail-type': ['GuardDuty Finding']}, 'aws.inspector2', False),
    ## $or across detail-types: one finding alternative suffices
    ({'source': ['aws.guardduty'], '$or': [{'detail-type': ['AWS API Call via CloudTrail']},
                                           {'detail-type': ['GuardDuty Finding']}]}, 'aws.guardduty', True),
])
def test_pattern_matching_detail_type(pattern, source, expected):
    assert EventbridgeRegional.patternMatchesSource(json.dumps(pattern), source) is expected


def test_guardduty_tamper_rule_does_not_count_as_routing_findings():
    """CIS/landing-zone GuardDuty tamper alarm with an SNS target was a false PASS."""
    r = _routingFor('eu-west-1', [_rule('gd-tamper', GD_TAMPER)], [])
    assert _evaluate(r, 'securityFindingsNotRouted') == -1
    fixed = _routingFor('eu-west-1', [_rule('gd-tamper', GD_TAMPER),
                                      _rule('gd-findings', {'source': ['aws.guardduty'],
                                                            'detail-type': ['GuardDuty Finding']})],
                        [('gd-findings', TARGET)])
    assert _evaluate(fixed, 'securityFindingsNotRouted') == 1


def test_custom_action_only_rule_does_not_count_as_routing_findings():
    r = _routingFor('eu-west-1', [_rule('sh-ca', {'source': ['aws.securityhub'],
                                                  'detail-type': ['Security Hub Findings - Custom Action']})], [])
    assert _evaluate(r, 'securityFindingsNotRouted') == -1


def test_cloudtrail_catch_all_does_not_count_as_health_routing():
    ct = {'source': [{'prefix': 'aws.'}], 'detail-type': ['AWS API Call via CloudTrail']}
    r = _routingFor('us-east-1', [_rule('ct-all', ct)], [])
    assert _evaluate(r, 'healthEventsNotRouted') == -1
    assert _evaluate(r, 'securityFindingsNotRouted') == -1
    fixed = _routingFor('us-east-1', [_rule('ct-all', ct),
                                      _rule('health', {'source': ['aws.health'], 'detail-type': ['AWS Health Event']})],
                        [('health', TARGET)])
    assert _evaluate(fixed, 'healthEventsNotRouted') == 1


# ---------------- partition-aware global Health Region ----------------
@pytest.mark.parametrize('region,expected', [
    ('eu-west-1', 'us-east-1'), ('us-east-1', 'us-east-1'), ('us-gov-east-1', 'us-gov-west-1'),
    ('us-gov-west-1', 'us-gov-west-1'), ('cn-northwest-1', 'cn-north-1'), ('cn-north-1', 'cn-north-1'),
    ('us-iso-east-1', None), ('us-isob-east-1', None),
])
def test_health_global_region_by_partition(region, expected):
    assert Eventbridge.healthGlobalRegion(region) == expected


def _routingPartition(region, globalRegion, localRules, globalRules):
    ev = _client('events', region)
    gd = _client('guardduty', region)
    sh = _client('securityhub', region)
    clients = {'events': ev, 'guardduty': gd, 'securityhub': sh}
    stubs = [Stubber(ev), Stubber(gd), Stubber(sh)]
    _stubRules(stubs[0], *localRules)
    if globalRegion != region:
        evg = _client('events', globalRegion)
        clients[('events', globalRegion)] = evg
        sg = Stubber(evg)
        _stubRules(sg, *globalRules)
        stubs.append(sg)
    stubs[1].add_response('list_detectors', {'DetectorIds': []})
    _securityHubStubs(stubs[2])
    for s in stubs:
        s.activate()
    routing = _service(region, clients)._getRoutingDetail()
    for s in stubs:
        s.assert_no_pending_responses()
    return routing


def test_health_govcloud_reads_us_gov_west_1():
    """us-gov-east-1 without a local aws.health rule: the global lookup goes to
    us-gov-west-1 (not us-east-1, where GovCloud credentials are rejected)."""
    bad = _routingPartition('us-gov-east-1', 'us-gov-west-1', ([], []), ([], []))
    obj = EventbridgeRegional({'_routing': bad}, None)
    obj._checkHealthEventsNotRouted()
    r = obj.results['healthEventsNotRouted']
    assert r[0] == -1 and 'us-gov-west-1' in r[1] and 'us-east-1' not in r[1]
    partial = _routingPartition('us-gov-east-1', 'us-gov-west-1', ([], []),
                                ([_rule('g', {'source': ['aws.health']})], [('g', TARGET)]))
    obj = EventbridgeRegional({'_routing': partial}, None)
    obj._checkHealthEventsNotRouted()
    r = obj.results['healthEventsNotRouted']
    assert r[0] == 0 and 'routed in us-gov-west-1' in r[1]


def test_health_china_global_region_itself_is_not_partial():
    """In cn-north-1 (the China global-event Region) no second lookup is made."""
    r = _routingPartition('cn-north-1', 'cn-north-1', ([], []), None)
    assert r['_globalRegion'] == 'cn-north-1'
    assert _evaluate(r, 'healthEventsNotRouted') == -1
    obj = EventbridgeRegional({'_routing': r}, None)
    obj._checkHealthEventsNotRouted()
    assert ' or ' not in obj.results['healthEventsNotRouted'][1]


def test_health_unknown_partition_is_not_fail():
    r = _routingPartition('us-iso-east-1', 'us-iso-east-1', ([], []), None)
    assert r['globalError'] == 'UnknownPartition'
    assert _evaluate(r, 'healthEventsNotRouted') == 0


# ---------------- enrichment failures must not become FAIL ----------------
def _routingEnrich(gdErr=None, shAdminErr=None, describeHubErr=None, aggErr=None):
    region = 'us-east-1'
    ev, gd, sh = _client('events', region), _client('guardduty', region), _client('securityhub', region)
    stubs = [Stubber(ev), Stubber(gd), Stubber(sh)]
    _stubRules(stubs[0], [], [])
    if gdErr:
        stubs[1].add_client_error('list_detectors', gdErr)
    else:
        stubs[1].add_response('list_detectors', {'DetectorIds': []})
    if shAdminErr:
        stubs[2].add_client_error('get_administrator_account', shAdminErr)
        if shAdminErr != 'InvalidAccessException':
            if describeHubErr:
                stubs[2].add_client_error('describe_hub', describeHubErr)
            else:
                stubs[2].add_response('describe_hub', {'HubArn': 'arn:aws:securityhub:us-east-1:111111111111:hub/default'})
    else:
        stubs[2].add_response('get_administrator_account', {})
    if aggErr:
        stubs[2].add_client_error('list_finding_aggregators', aggErr)
    else:
        stubs[2].add_response('list_finding_aggregators', {'FindingAggregators': []})
    for s in stubs:
        s.activate()
    routing = _service(region, {'events': ev, 'guardduty': gd, 'securityhub': sh})._getRoutingDetail()
    for s in stubs:
        s.assert_no_pending_responses()
    return routing


def test_security_enrichment_denied_is_info_not_fail():
    r = _routingEnrich(gdErr='AccessDeniedException')
    obj = EventbridgeRegional({'_routing': r}, None)
    obj._checkSecurityFindingsNotRouted()
    res = obj.results['securityFindingsNotRouted']
    assert res[0] == 0 and 'guardduty: AccessDeniedException' in res[1]
    # Security Hub enabled but GetAdministratorAccount denied
    r = _routingEnrich(shAdminErr='AccessDeniedException')
    assert _evaluate(r, 'securityFindingsNotRouted') == 0
    r = _routingEnrich(aggErr='AccessDeniedException')
    assert _evaluate(r, 'securityFindingsNotRouted') == 0


def test_security_hub_not_enabled_is_conclusive_fail():
    """Security Hub not subscribed (InvalidAccessException) means no membership and no
    aggregation, so a missing route is still FAIL."""
    r = _routingEnrich(shAdminErr='InvalidAccessException', aggErr='InvalidAccessException')
    assert r['enrichmentErrors'] == []
    assert _evaluate(r, 'securityFindingsNotRouted') == -1
    # get_administrator_account unavailable, describe_hub proves the hub is off
    r = _routingEnrich(shAdminErr='NotImplemented', describeHubErr='InvalidAccessException',
                       aggErr='InvalidAccessException')
    assert _evaluate(r, 'securityFindingsNotRouted') == -1

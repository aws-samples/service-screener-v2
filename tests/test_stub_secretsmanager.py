"""Stubber tests for secretsmanager.secretChangeNotMonitored.

The flag -> fix -> re-run cycle is covered against the emulator in
tests/emulator/test_emu_secretsmanager.py. These tests use botocore Stubber
(real API shapes, no network) for the paths the single-account, single-region
emulator cannot produce: AccessDenied on the read APIs, a multi-region trail
whose log group lives in another region, composite-alarm notification, and
the pattern-matching edge cases.
"""
import json
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.secretsmanager.drivers.SecretsmanagerAccount import SecretsmanagerAccount  # noqa: E402

KEY = 'secretChangeNotMonitored'
ACCT = '111122223333'


def _client(svc, region='us-east-1'):
    return boto3.client(svc, region_name=region, aws_access_key_id='x', aws_secret_access_key='x')


class Harness:
    def __init__(self):
        self.events = _client('events')
        self.ct = _client('cloudtrail')
        self.regional = {}
        self.stubs = [Stubber(self.events), Stubber(self.ct)]

    def regionalClient(self, svc, region):
        key = (svc, region)
        if key not in self.regional:
            c = _client(svc, region)
            self.regional[key] = (c, Stubber(c))
        return self.regional[key][0]

    def stub(self, svc, region):
        self.regionalClient(svc, region)
        return self.regional[(svc, region)][1]

    def run(self):
        for s in self.stubs + [v[1] for v in self.regional.values()]:
            s.activate()
        d = SecretsmanagerAccount({'region': 'us-east-1', 'account': ACCT},
                                  self.events, self.ct, self.regionalClient)
        d._checkSecretChangeNotMonitored()
        for s in self.stubs + [v[1] for v in self.regional.values()]:
            s.assert_no_pending_responses()
        return d.results[KEY]


def _rule(name, pattern, state='ENABLED'):
    return {'Name': name, 'Arn': f'arn:aws:events:us-east-1:{ACCT}:rule/{name}',
            'EventPattern': json.dumps(pattern), 'State': state, 'EventBusName': 'default'}


def test_no_monitoring_flags_and_rule_with_target_passes():
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': []})
    ct.add_response('describe_trails', {'trailList': []})
    assert h.run()[0] == -1

    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': [_rule('r', {'source': ['aws.secretsmanager']})]})
    ev.add_response('list_targets_by_rule', {'Targets': [{'Id': '1', 'Arn': f'arn:aws:sns:us-east-1:{ACCT}:t'}]},
                    {'Rule': 'r', 'EventBusName': 'default'})
    ct.add_response('describe_trails', {'trailList': []})
    assert h.run()[0] == 1


def test_access_denied_is_not_evaluable_not_pass():
    h = Harness()
    ev, ct = h.stubs
    ev.add_client_error('list_rules', 'AccessDeniedException')
    ct.add_response('describe_trails', {'trailList': []})
    res = h.run()
    assert res[0] == 0 and 'AccessDeniedException' in res[1]


def test_rule_scoped_to_one_secret_does_not_count():
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': [_rule('r', {
        'source': ['aws.secretsmanager'],
        'detail': {'eventName': ['DeleteSecret', 'PutResourcePolicy'],
                   'requestParameters': {'secretId': ['only-this-one']}}})]})
    ct.add_response('describe_trails', {'trailList': []})
    assert h.run()[0] == -1


def test_cross_region_trail_log_group_with_composite_alarm():
    """Multi-region trail homed in eu-west-1; the alarm itself has no actions
    but a composite alarm with actions wraps it."""
    lgArn = f'arn:aws:logs:eu-west-1:{ACCT}:log-group:org-trail:*'
    trailArn = f'arn:aws:cloudtrail:eu-west-1:{ACCT}:trail/main'

    def build(compositeActions):
        h = Harness()
        ev, ct = h.stubs
        ev.add_response('list_rules', {'Rules': []})
        ct.add_response('describe_trails', {'trailList': [{
            'Name': 'main', 'TrailARN': trailArn, 'HomeRegion': 'eu-west-1',
            'IsMultiRegionTrail': True, 'CloudWatchLogsLogGroupArn': lgArn}]})
        ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': trailArn})
        h.stub('logs', 'eu-west-1').add_response('describe_metric_filters', {'metricFilters': [{
            'filterName': 'sm', 'logGroupName': 'org-trail',
            'filterPattern': '{($.eventName = DeleteSecret) || ($.eventName = PutResourcePolicy)}',
            'metricTransformations': [{'metricName': 'SM', 'metricNamespace': 'CIS', 'metricValue': '1'}]}]},
            {'logGroupName': 'org-trail'})
        h.stub('cloudwatch', 'eu-west-1').add_response('describe_alarms', {
            'MetricAlarms': [{'AlarmName': 'sm-child', 'MetricName': 'SM', 'Namespace': 'CIS',
                              'ActionsEnabled': True, 'AlarmActions': []}],
            'CompositeAlarms': [{'AlarmName': 'parent', 'AlarmRule': 'ALARM("sm-child")',
                                 'ActionsEnabled': True,
                                 'AlarmActions': [f'arn:aws:sns:eu-west-1:{ACCT}:t'] if compositeActions else []}]},
            {'AlarmTypes': ['MetricAlarm', 'CompositeAlarm']})
        return h

    assert build(False).run()[0] == -1
    assert build(True).run()[0] == 1


def test_stopped_trail_does_not_count():
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': []})
    ct.add_response('describe_trails', {'trailList': [{
        'Name': 't', 'TrailARN': f'arn:aws:cloudtrail:us-east-1:{ACCT}:trail/t', 'HomeRegion': 'us-east-1',
        'IsMultiRegionTrail': False,
        'CloudWatchLogsLogGroupArn': f'arn:aws:logs:us-east-1:{ACCT}:log-group:lg:*'}]})
    ct.add_response('get_trail_status', {'IsLogging': False})
    assert h.run()[0] == -1


def test_event_pattern_matcher():
    m = SecretsmanagerAccount.eventPatternMatches
    d = SecretsmanagerAccount({'region': 'us-east-1', 'account': ACCT}, None, None, None)
    ev = d._sampleEvent('DeleteSecret')
    assert m({'source': ['aws.secretsmanager']}, ev)
    assert m({'source': [{'prefix': 'aws.'}]}, ev)
    assert m({'detail': {'eventName': [{'anything-but': 'GetSecretValue'}]}, 'source': ['aws.secretsmanager']}, ev)
    assert m({'$or': [{'source': ['aws.kms']}, {'detail': {'eventName': ['DeleteSecret']}}]}, ev)
    assert m({'detail': {'eventName': [{'wildcard': 'Delete*'}]}}, ev)
    assert not m({'source': ['aws.kms']}, ev)
    assert not m({'detail': {'eventName': [{'anything-but': ['DeleteSecret']}]}}, ev)
    assert not m({'detail': {'userIdentity': {'type': ['Root']}}}, ev)
    assert m({'detail': {'errorCode': [{'exists': False}]}, 'source': ['aws.secretsmanager']}, ev)


def test_filter_pattern_matcher():
    f = SecretsmanagerAccount.filterPatternMatches
    assert f('{ $.eventSource = secretsmanager.amazonaws.com }', 'DeleteSecret')
    assert f('{ ($.eventSource = "secretsmanager.amazonaws.com") && ($.eventName = Put*) }', 'PutResourcePolicy')
    assert f('?DeleteSecret ?PutResourcePolicy', 'PutResourcePolicy')
    assert not f('{ $.eventSource = kms.amazonaws.com }', 'DeleteSecret')
    assert not f('{ ($.eventName = DeleteSecret) && ($.userIdentity.type = Root) }', 'DeleteSecret')
    assert not f('{ $.eventName = DeleteSecretVersion }', 'DeleteSecret')
    assert not f('', 'DeleteSecret')

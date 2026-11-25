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


TRAIL = f'arn:aws:cloudtrail:us-east-1:{ACCT}:trail/t'
# A multi-region trail without CloudWatch Logs delivery: feeds EventBridge only.
NOLOG_TRAIL = {'Name': 't', 'TrailARN': TRAIL, 'HomeRegion': 'us-east-1', 'IsMultiRegionTrail': True}


def _rule(name, pattern, state='ENABLED'):
    return {'Name': name, 'Arn': f'arn:aws:events:us-east-1:{ACCT}:rule/{name}',
            'EventPattern': json.dumps(pattern), 'State': state, 'EventBusName': 'default'}


def test_no_monitoring_flags_and_rule_with_target_passes():
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': []})
    ct.add_response('describe_trails', {'trailList': []})
    assert h.run()[0] == -1

    # Fix: a rule with a target, fed by a logging trail that records write
    # management events (EventBridge only receives CloudTrail API-call events
    # when such a trail exists).
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': [_rule('r', {'source': ['aws.secretsmanager']})]})
    ev.add_response('list_targets_by_rule', {'Targets': [{'Id': '1', 'Arn': f'arn:aws:sns:us-east-1:{ACCT}:t'}]},
                    {'Rule': 'r', 'EventBusName': 'default'})
    ct.add_response('describe_trails', {'trailList': [NOLOG_TRAIL]})
    ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': TRAIL})
    ct.add_response('get_event_selectors', {'TrailARN': TRAIL, 'EventSelectors': [
        {'ReadWriteType': 'All', 'IncludeManagementEvents': True}]}, {'TrailName': TRAIL})
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
        # Trail status / selectors are read from the trail's home region.
        homeCt = h.stub('cloudtrail', 'eu-west-1')
        homeCt.add_response('get_trail_status', {'IsLogging': True}, {'Name': trailArn})
        homeCt.add_response('get_event_selectors', {'TrailARN': trailArn, 'EventSelectors': [
            {'ReadWriteType': 'All', 'IncludeManagementEvents': True}]}, {'TrailName': trailArn})
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
    # userIdentity is always present on a real CloudTrail event, so an
    # exists:false condition on it (or on its children) never matches.
    assert not m({'detail': {'userIdentity': [{'exists': False}], 'eventName': ['DeleteSecret']}}, ev)
    assert not m({'detail': {'userIdentity': {'type': [{'exists': False}]}, 'eventName': ['DeleteSecret']}}, ev)
    assert m({'detail': {'userIdentity': [{'exists': True}], 'eventName': ['DeleteSecret']}}, ev)
    # Unknown optional field: cannot assume it is absent.
    assert not m({'detail': {'additionalEventData': [{'exists': False}], 'eventName': ['DeleteSecret']}}, ev)
    assert not m({'detail': {'eventName': ['DeleteSecret'], 'eventType': ['AwsConsoleSignIn']}}, ev)


def test_filter_pattern_matcher():
    f = SecretsmanagerAccount.filterPatternMatches
    assert f('{ $.eventSource = secretsmanager.amazonaws.com }', 'DeleteSecret')
    assert f('{ ($.eventSource = "secretsmanager.amazonaws.com") && ($.eventName = Put*) }', 'PutResourcePolicy')
    assert f('?DeleteSecret ?PutResourcePolicy', 'PutResourcePolicy')
    assert not f('{ $.eventSource = kms.amazonaws.com }', 'DeleteSecret')
    assert not f('{ ($.eventName = DeleteSecret) && ($.userIdentity.type = Root) }', 'DeleteSecret')
    assert not f('{ $.eventName = DeleteSecretVersion }', 'DeleteSecret')
    assert not f('', 'DeleteSecret')


def test_filter_pattern_closing_brace_without_space():
    """Review fix: '}' directly after an unquoted value was captured into it."""
    f = SecretsmanagerAccount.filterPatternMatches
    assert f('{$.eventName=DeleteSecret}', 'DeleteSecret')
    assert f('{ $.eventName = DeleteSecret}', 'DeleteSecret')
    assert f('{($.eventName=DeleteSecret)||($.eventName=PutResourcePolicy)}', 'PutResourcePolicy')
    assert not f('{$.eventName=DeleteSecretVersion}', 'DeleteSecret')


def test_term_patterns_that_narrow_do_not_count():
    """Review fix: space-separated terms are ANDed by CloudWatch Logs."""
    f = SecretsmanagerAccount.filterPatternMatches
    assert f('DeleteSecret', 'DeleteSecret')
    assert f('"DeleteSecret"', 'DeleteSecret')
    assert f('?DeleteSecret ?PutResourcePolicy', 'DeleteSecret')
    assert f('?"DeleteSecret" ?"PutResourcePolicy"', 'PutResourcePolicy')
    assert not f('DeleteSecret prod', 'DeleteSecret')
    assert not f('"DeleteSecret" "AccessDenied"', 'DeleteSecret')
    assert not f('DeleteSecret -prod', 'DeleteSecret')
    assert not f('?DeleteSecret ?GetSecretValue', 'PutResourcePolicy')
    assert not f('[ver, acct, DeleteSecret]', 'DeleteSecret')


def test_json_filter_boolean_structure_and_field_values():
    """Review fix: JSON patterns are evaluated as boolean expressions."""
    f = SecretsmanagerAccount.filterPatternMatches
    assert not f('{ ($.eventSource = kms.amazonaws.com && $.eventName = DeleteSecret) || '
                 '($.eventSource = secretsmanager.amazonaws.com && $.eventName = GetSecretValue) }', 'DeleteSecret')
    assert not f('{ $.eventSource = secretsmanager.amazonaws.com && $.readOnly IS TRUE }', 'DeleteSecret')
    assert f('{ $.eventSource = secretsmanager.amazonaws.com && $.readOnly IS FALSE }', 'DeleteSecret')
    assert not f('{ $.eventSource = secretsmanager.amazonaws.com && $.eventType = AwsConsoleSignIn }', 'DeleteSecret')
    assert not f('{ $.eventSource = secretsmanager.amazonaws.com && $.eventCategory = Data }', 'DeleteSecret')
    # Failed calls only: a successful deletion would not fire.
    assert not f('{ $.eventName = DeleteSecret && $.errorCode = "AccessDenied*" }', 'DeleteSecret')
    assert f('{ $.eventName = DeleteSecret && $.errorCode NOT EXISTS }', 'DeleteSecret')
    # An OR with a narrowing branch still covers through the other branch.
    assert f('{ ($.eventName = DeleteSecret) || ($.userIdentity.type = Root) }', 'DeleteSecret')
    assert not f('{ $.eventSource = secretsmanager.amazonaws.com && $.eventName != DeleteSecret }', 'DeleteSecret')
    assert f('{ $.eventName = %Delete.*% }', 'DeleteSecret')
    assert not f('{ ($.eventName = DeleteSecret }', 'DeleteSecret')  # malformed


LG = f'arn:aws:logs:us-east-1:{ACCT}:log-group:lg:*'
SM_FILTER = {'filterName': 'sm', 'logGroupName': 'lg',
             'filterPattern': '{ $.eventSource = secretsmanager.amazonaws.com }',
             'metricTransformations': [{'metricName': 'SM', 'metricNamespace': 'CIS', 'metricValue': '1'}]}
SM_ALARMS = {'MetricAlarms': [{'AlarmName': 'a', 'MetricName': 'SM', 'Namespace': 'CIS', 'ActionsEnabled': True,
                               'AlarmActions': [f'arn:aws:sns:us-east-1:{ACCT}:t']}], 'CompositeAlarms': []}


def _localTrailHarness(selectors):
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': []})
    ct.add_response('describe_trails', {'trailList': [{
        'Name': 't', 'TrailARN': TRAIL, 'HomeRegion': 'us-east-1', 'IsMultiRegionTrail': True,
        'CloudWatchLogsLogGroupArn': LG}]})
    ct.add_response('get_trail_status', {'IsLogging': True})
    ct.add_response('get_event_selectors', dict({'TrailARN': TRAIL}, **selectors))
    return h


def _withAlarmedFilter(h):
    h.stub('logs', 'us-east-1').add_response('describe_metric_filters', {'metricFilters': [SM_FILTER]})
    h.stub('cloudwatch', 'us-east-1').add_response('describe_alarms', SM_ALARMS)
    return h


def test_trail_without_write_management_events_does_not_count():
    """Review fix: event selectors are read. Data-event-only or read-only
    trails do not deliver DeleteSecret / PutResourcePolicy to the log group."""
    dataOnly = {'AdvancedEventSelectors': [{'Name': 'data', 'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Data']}, {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']}]}]}
    assert _localTrailHarness(dataOnly).run()[0] == -1
    readOnly = {'EventSelectors': [{'ReadWriteType': 'ReadOnly', 'IncludeManagementEvents': True}]}
    assert _localTrailHarness(readOnly).run()[0] == -1
    excluded = {'AdvancedEventSelectors': [{'Name': 'mgmt', 'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Management']},
        {'Field': 'eventSource', 'NotEquals': ['secretsmanager.amazonaws.com']}]}]}
    assert _localTrailHarness(excluded).run()[0] == -1
    # Fix: management events (write) are recorded.
    mgmt = {'AdvancedEventSelectors': [{'Name': 'mgmt', 'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Management']}, {'Field': 'readOnly', 'Equals': ['false']}]}]}
    assert _withAlarmedFilter(_localTrailHarness(mgmt)).run()[0] == 1
    basic = {'EventSelectors': [{'ReadWriteType': 'WriteOnly', 'IncludeManagementEvents': True}]}
    assert _withAlarmedFilter(_localTrailHarness(basic)).run()[0] == 1


def test_trail_status_error_is_not_counted_as_logging():
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': []})
    ct.add_response('describe_trails', {'trailList': [{
        'Name': 't', 'TrailARN': TRAIL, 'HomeRegion': 'us-east-1', 'IsMultiRegionTrail': True,
        'CloudWatchLogsLogGroupArn': LG}]})
    ct.add_client_error('get_trail_status', 'AccessDeniedException')
    res = h.run()
    assert res[0] == 0 and 'AccessDeniedException' in res[1]


def test_trail_log_group_in_other_account_is_not_evaluable():
    """Review fix: an organization trail delivering to the management
    account's log group must not be evaluated against a local log group."""
    def build(withRule):
        h = Harness()
        ev, ct = h.stubs
        rules = [_rule('r', {'source': ['aws.secretsmanager']})] if withRule else []
        ev.add_response('list_rules', {'Rules': rules})
        if withRule:
            ev.add_response('list_targets_by_rule', {'Targets': [{'Id': '1', 'Arn': f'arn:aws:sns:us-east-1:{ACCT}:t'}]})
        orgTrail = 'arn:aws:cloudtrail:us-east-1:999988887777:trail/org'
        ct.add_response('describe_trails', {'trailList': [{
            'Name': 'org', 'TrailARN': orgTrail,
            'HomeRegion': 'us-east-1', 'IsMultiRegionTrail': True, 'IsOrganizationTrail': True,
            'CloudWatchLogsLogGroupArn': 'arn:aws:logs:us-east-1:999988887777:log-group:org-lg:*'}]})
        if withRule:
            # The organization trail logs this member account's calls, which
            # is what delivers them to the local EventBridge rule.
            ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': orgTrail})
            ct.add_response('get_event_selectors', {'TrailARN': orgTrail}, {'TrailName': orgTrail})
        return h

    res = build(False).run()
    assert res[0] == 0 and 'TrailLogGroupInOtherAccount' in res[1]
    assert build(True).run()[0] == 1


# --------------------------------------------------------------------------- #
# Review fix: an EventBridge rule only receives "AWS API Call via CloudTrail"
# events when a CloudTrail trail covering the region is logging and records
# write management events. Without one the rule never fires, so it must not
# count as coverage (old code returned PASS in every case below).
# --------------------------------------------------------------------------- #
def _ruleHarness(trails):
    h = Harness()
    ev, ct = h.stubs
    ev.add_response('list_rules', {'Rules': [_rule('r', {
        'source': ['aws.secretsmanager'], 'detail-type': ['AWS API Call via CloudTrail']})]})
    ev.add_response('list_targets_by_rule', {'Targets': [{'Id': '1', 'Arn': f'arn:aws:sns:us-east-1:{ACCT}:t'}]},
                    {'Rule': 'r', 'EventBusName': 'default'})
    ct.add_response('describe_trails', {'trailList': trails})
    return h, ct


def test_eventbridge_rule_without_any_trail_fails():
    h, ct = _ruleHarness([])
    res = h.run()
    assert res[0] == -1, res
    assert 'EventBridge rule r would match' in res[1] and 'CloudTrail' in res[1]


def test_eventbridge_rule_with_stopped_trail_fails():
    h, ct = _ruleHarness([NOLOG_TRAIL])
    ct.add_response('get_trail_status', {'IsLogging': False}, {'Name': TRAIL})
    assert h.run()[0] == -1


def test_eventbridge_rule_with_data_events_only_trail_fails():
    h, ct = _ruleHarness([NOLOG_TRAIL])
    ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': TRAIL})
    ct.add_response('get_event_selectors', {'TrailARN': TRAIL, 'EventSelectors': [
        {'ReadWriteType': 'All', 'IncludeManagementEvents': False,
         'DataResources': [{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}]}]}, {'TrailName': TRAIL})
    assert h.run()[0] == -1


def test_eventbridge_rule_with_single_region_trail_elsewhere_fails():
    other = {'Name': 'eu', 'TrailARN': f'arn:aws:cloudtrail:eu-west-1:{ACCT}:trail/eu',
             'HomeRegion': 'eu-west-1', 'IsMultiRegionTrail': False}
    h, ct = _ruleHarness([other])
    assert h.run()[0] == -1


def test_eventbridge_rule_trail_status_unreadable_is_not_evaluable():
    h, ct = _ruleHarness([NOLOG_TRAIL])
    ct.add_client_error('get_trail_status', 'AccessDeniedException', expected_params={'Name': TRAIL})
    res = h.run()
    assert res == [0, 'Unable to evaluate (AccessDeniedException)'], res


def test_eventbridge_rule_with_logging_management_trail_passes():
    h, ct = _ruleHarness([NOLOG_TRAIL])
    ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': TRAIL})
    ct.add_response('get_event_selectors', {'TrailARN': TRAIL, 'AdvancedEventSelectors': [
        {'Name': 'mgmt', 'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']}]}]},
        {'TrailName': TRAIL})
    res = h.run()
    assert res == [1, 'DeleteSecret: EventBridge rule r; PutResourcePolicy: EventBridge rule r'], res


def test_trail_reads_are_shared_between_eventbridge_and_metric_filter_paths():
    """One describe_trails / get_trail_status / get_event_selectors per trail,
    even though both paths need them (the Stubber fails on extra calls)."""
    h, ct = _ruleHarness([dict(NOLOG_TRAIL, CloudWatchLogsLogGroupArn=LG)])
    ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': TRAIL})
    ct.add_response('get_event_selectors', {'TrailARN': TRAIL}, {'TrailName': TRAIL})
    _withAlarmedFilter(h)
    res = h.run()
    assert res[0] == 1 and 'metric filter sm on lg' in res[1] and 'EventBridge rule r' in res[1], res

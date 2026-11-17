"""Stubber-based tests for WAFS2027 CloudWatch check branches the single-account,
single-region AWS Emulator cannot reproduce:

- member-account / standalone-account (Organizations) handling,
- AccessDenied -> 'Unable to evaluate' (never a silent PASS),
- alarms stuck in INSUFFICIENT_DATA for > 7 days (the emulator stamps 'now'),
- centralization rules created in another region or metrics-only rules,
- EventBridge pattern / metric-filter edge cases.

Real boto3 clients (dummy credentials, unroutable endpoint) are wrapped in
botocore.stub.Stubber so request/response shapes are validated against the real
API models; no request ever leaves the process.
"""
import datetime
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.cloudwatch.drivers.CloudwatchAccount import CloudwatchAccount, eventPatternMatches  # noqa: E402
from services.cloudwatch.drivers.CloudwatchAlarms import CloudwatchAlarms  # noqa: E402

ACCT = '111122223333'
MGMT = '999988887777'
REGION = 'us-east-1'


def _client(svc, region=REGION):
    return boto3.session.Session(aws_access_key_id='x', aws_secret_access_key='x', region_name=region) \
        .client(svc, endpoint_url='https://127.0.0.1:1')


class Clients:
    def __init__(self):
        self.stubs = {}

    def __call__(self, svc, region=None):
        key = (svc, region or REGION)
        if key not in self.stubs:
            c = _client(svc, region or REGION)
            st = Stubber(c)
            st.activate()
            self.stubs[key] = (c, st)
        return self.stubs[key][0]

    def stub(self, svc, region=REGION):
        self(svc, region)
        return self.stubs[(svc, region)][1]


@pytest.fixture
def clients():
    Config.init()
    Config.set('stsInfo', {'Account': ACCT})
    return Clients()


def _driver(clients, ctLogs=None, logGroups=None, alarms=None):
    return CloudwatchAccount(REGION, clients, ctLogs or [], logGroups or [], alarms or [])


def _org(clients, mgmt):
    clients.stub('organizations').add_response('describe_organization', {'Organization': {
        'Id': 'o-abc1234567', 'MasterAccountId': mgmt, 'FeatureSet': 'ALL'}})


def _denied(stub, op):
    stub.add_client_error(op, service_error_code='AccessDeniedException', service_message='denied',
                          http_status_code=400)


# --------------------------------------------------------------------------- #
# cwLogsCentralizationRuleMissing
# --------------------------------------------------------------------------- #
def test_centralization_member_account_not_evaluable(clients):
    _org(clients, MGMT)
    _denied(clients.stub('observabilityadmin'), 'list_centralization_rules_for_organization')
    d = _driver(clients)
    d._checkCentralizationRule()
    assert d.results['cwLogsCentralizationRuleMissing'] == [0, 'Not evaluable from member account']


def test_centralization_mgmt_access_denied_unable(clients):
    _org(clients, ACCT)
    _denied(clients.stub('observabilityadmin'), 'list_centralization_rules_for_organization')
    d = _driver(clients)
    d._checkCentralizationRule()
    r = d.results['cwLogsCentralizationRuleMissing']
    assert r[0] == 0 and 'Unable to evaluate (AccessDeniedException)' in r[1]


def test_centralization_standalone_not_evaluable(clients):
    clients.stub('organizations').add_client_error('describe_organization',
                                                   service_error_code='AWSOrganizationsNotInUseException')
    d = _driver(clients)
    d._checkCentralizationRule()
    assert d.results['cwLogsCentralizationRuleMissing'][0] == 0


def _rule(name, region):
    return {'RuleName': name, 'RuleArn': f'arn:aws:observabilityadmin:{region}:{MGMT}:organization-centralization-rule/{name}',
            'CreatedRegion': region}


def test_centralization_rule_other_region_covering_this_region_passes(clients):
    _org(clients, ACCT)
    clients.stub('observabilityadmin').add_response('list_centralization_rules_for_organization',
                                                    {'CentralizationRuleSummaries': [_rule('r1', 'eu-west-1')]},
                                                    {'AllRegions': True})
    clients.stub('observabilityadmin', 'eu-west-1').add_response('get_centralization_rule_for_organization', {
        'RuleName': 'r1', 'CentralizationRule': {
            'Source': {'Regions': ['us-east-1', 'eu-west-1'],
                       'SourceLogsConfiguration': {'EncryptedLogGroupStrategy': 'SKIP'}},
            'Destination': {'Region': 'eu-west-1'}}})
    d = _driver(clients)
    d._checkCentralizationRule()
    assert d.results['cwLogsCentralizationRuleMissing'][0] == 1


def test_centralization_metrics_only_or_uncovered_region_fails(clients):
    _org(clients, ACCT)
    clients.stub('observabilityadmin').add_response('list_centralization_rules_for_organization', {
        'CentralizationRuleSummaries': [_rule('metrics', 'us-east-1'), _rule('logs-eu', 'eu-west-1')]})
    clients.stub('observabilityadmin').add_response('get_centralization_rule_for_organization', {
        'RuleName': 'metrics', 'CentralizationRule': {
            'Source': {'Regions': ['us-east-1'], 'SourceMetricsConfiguration': {}},
            'Destination': {'Region': 'us-east-1'}}})
    clients.stub('observabilityadmin', 'eu-west-1').add_response('get_centralization_rule_for_organization', {
        'RuleName': 'logs-eu', 'CentralizationRule': {
            'Source': {'Regions': ['eu-west-1'], 'SourceLogsConfiguration': {'EncryptedLogGroupStrategy': 'SKIP'}},
            'Destination': {'Region': 'eu-west-1'}}})
    d = _driver(clients)
    d._checkCentralizationRule()
    r = d.results['cwLogsCentralizationRuleMissing']
    assert r[0] == -1 and 'us-east-1' in r[1]


# --------------------------------------------------------------------------- #
# cwCrossAccountObservabilityNotLinked
# --------------------------------------------------------------------------- #
def test_oam_standalone_not_applicable(clients):
    clients.stub('organizations').add_client_error('describe_organization',
                                                   service_error_code='AWSOrganizationsNotInUseException')
    d = _driver(clients)
    d._checkCrossAccountObservability()
    assert d.results['cwCrossAccountObservabilityNotLinked'][0] == 0


def test_oam_flag_then_link(clients):
    _org(clients, MGMT)
    oam = clients.stub('oam')
    oam.add_response('list_links', {'Items': []})
    oam.add_response('list_sinks', {'Items': []})
    d = _driver(clients)
    d._checkCrossAccountObservability()
    assert d.results['cwCrossAccountObservabilityNotLinked'][0] == -1

    oam.add_response('list_links', {'Items': [{'Arn': 'arn:aws:oam:us-east-1:111122223333:link/abc',
                                               'SinkArn': f'arn:aws:oam:us-east-1:{MGMT}:sink/s1'}]})
    oam.add_response('list_sinks', {'Items': []})
    d = _driver(clients)
    d._checkCrossAccountObservability()
    assert d.results['cwCrossAccountObservabilityNotLinked'][0] == 1


def test_oam_access_denied_unable(clients):
    _org(clients, MGMT)
    _denied(clients.stub('oam'), 'list_links')
    d = _driver(clients)
    d._checkCrossAccountObservability()
    assert d.results['cwCrossAccountObservabilityNotLinked'] == [0, 'Unable to evaluate (AccessDeniedException)']


# --------------------------------------------------------------------------- #
# cwAlarmActionsDisabled - INSUFFICIENT_DATA for > 7 days
# --------------------------------------------------------------------------- #
def _alarm(clients, state, since):
    cw = clients('cloudwatch')
    clients.stub('cloudwatch').add_response('describe_alarms', {'MetricAlarms': [{
        'AlarmName': 'a1', 'ActionsEnabled': True, 'AlarmActions': ['arn:aws:sns:us-east-1:111122223333:t'],
        'StateValue': state, 'StateUpdatedTimestamp': since, 'StateTransitionedTimestamp': since}]})
    return cw.describe_alarms()['MetricAlarms'][0]


def test_alarm_insufficient_data_over_7_days(clients):
    now = datetime.datetime.now(datetime.timezone.utc)
    stale = CloudwatchAlarms(_alarm(clients, 'INSUFFICIENT_DATA', now - datetime.timedelta(days=30)), None)
    stale._checkAlarmActionsDisabled()
    assert stale.results['cwAlarmActionsDisabled'][0] == -1

    fixed = CloudwatchAlarms(_alarm(clients, 'OK', now - datetime.timedelta(days=30)), None)
    fixed._checkAlarmActionsDisabled()
    assert fixed.results['cwAlarmActionsDisabled'][0] == 1

    recent = CloudwatchAlarms(_alarm(clients, 'INSUFFICIENT_DATA', now - datetime.timedelta(days=2)), None)
    recent._checkAlarmActionsDisabled()
    assert recent.results['cwAlarmActionsDisabled'][0] == 1


# --------------------------------------------------------------------------- #
# logsResourcePolicyPublic
# --------------------------------------------------------------------------- #
def _rp(clients, stmt):
    clients.stub('logs').add_response('describe_resource_policies', {'resourcePolicies': [{
        'policyName': 'p', 'policyDocument': json.dumps({'Version': '2012-10-17', 'Statement': [stmt]})}]})


def test_resource_policy_public_vs_service_principal(clients):
    _rp(clients, {'Effect': 'Allow', 'Principal': '*', 'Action': 'logs:PutLogEvents', 'Resource': '*'})
    d = _driver(clients)
    d._checkLogsResourcePolicy()
    assert d.results['logsResourcePolicyPublic'][0] == -1

    _rp(clients, {'Effect': 'Allow', 'Principal': {'Service': 'delivery.logs.amazonaws.com'},
                  'Action': 'logs:PutLogEvents', 'Resource': '*'})
    d = _driver(clients)
    d._checkLogsResourcePolicy()
    assert d.results['logsResourcePolicyPublic'][0] == 1

    _rp(clients, {'Effect': 'Allow', 'Principal': {'AWS': ['*']}, 'Action': 'logs:PutLogEvents', 'Resource': '*',
                  'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-abc1234567'}}})
    d = _driver(clients)
    d._checkLogsResourcePolicy()
    assert d.results['logsResourcePolicyPublic'][0] == 1


def test_resource_policy_access_denied_unable(clients):
    _denied(clients.stub('logs'), 'describe_resource_policies')
    d = _driver(clients)
    d._checkLogsResourcePolicy()
    assert d.results['logsResourcePolicyPublic'][0] == 0


# --------------------------------------------------------------------------- #
# cwLogsNoDataProtectionPolicy / cwLogGroupNotKmsEncrypted unreadable sources
# --------------------------------------------------------------------------- #
def test_data_protection_access_denied_unable(clients):
    _denied(clients.stub('logs'), 'describe_account_policies')
    d = _driver(clients, logGroups=[{'logGroupName': 'g', 'dataProtectionStatus': ''}])
    d._checkDataProtectionPolicy()
    assert d.results['cwLogsNoDataProtectionPolicy'][0] == 0


def test_kms_unreadable_sources_not_pass(clients):
    clients.stub('ec2').add_client_error('describe_flow_logs', service_error_code='UnauthorizedOperation')
    _denied(clients.stub('route53resolver'), 'list_resolver_query_log_configs')
    d = _driver(clients, logGroups=[{'logGroupName': 'g', 'kmsKeyId': None}])
    d._checkAuditLogGroupEncryption()
    r = d.results['cwLogGroupNotKmsEncrypted']
    assert r[0] == 0 and 'Unable to evaluate' in r[1]


def test_kms_resolver_query_log_group_flagged(clients):
    clients.stub('ec2').add_response('describe_flow_logs', {'FlowLogs': []})
    clients.stub('route53resolver').add_response('list_resolver_query_log_configs', {'ResolverQueryLogConfigs': [{
        'Id': 'rqlc-1', 'DestinationArn': f'arn:aws:logs:{REGION}:{ACCT}:log-group:/r53/q'}]})
    d = _driver(clients, logGroups=[{'logGroupName': '/r53/q', 'kmsKeyId': None},
                                    {'logGroupName': 'app', 'kmsKeyId': None}])
    d._checkAuditLogGroupEncryption()
    r = d.results['cwLogGroupNotKmsEncrypted']
    assert r[0] == -1 and '/r53/q (Route 53 Resolver query logs)' in r[1] and 'app (' not in r[1]


# --------------------------------------------------------------------------- #
# detectionDisableNoAlarm
# --------------------------------------------------------------------------- #
def test_detection_unknown_enablement_is_unable_not_pass(clients):
    _denied(clients.stub('guardduty'), 'list_detectors')
    clients.stub('securityhub').add_client_error('describe_hub', service_error_code='InvalidAccessException')
    clients.stub('accessanalyzer').add_response('list_analyzers', {'analyzers': []})
    clients.stub('events').add_response('list_rules', {'Rules': []})
    d = _driver(clients)
    d._checkDetectionDisableAlarm()
    r = d.results['detectionDisableNoAlarm']
    assert r[0] == 0 and 'Unable to evaluate' in r[1]


def test_event_pattern_matcher():
    ev = {'source': 'aws.guardduty', 'detail-type': 'AWS API Call via CloudTrail',
          'detail': {'eventSource': 'guardduty.amazonaws.com', 'eventName': 'DeleteDetector'}}
    assert eventPatternMatches({'source': ['aws.guardduty']}, ev)
    assert eventPatternMatches({'detail': {'eventName': [{'prefix': 'Delete'}]}}, ev)
    assert eventPatternMatches({'$or': [{'source': ['aws.s3']}, {'detail': {'eventName': ['DeleteDetector']}}]}, ev)
    assert not eventPatternMatches({'detail': {'eventName': [{'anything-but': 'DeleteDetector'}]}}, ev)
    assert not eventPatternMatches({'detail-type': ['GuardDuty Finding']}, ev)
    # Constraints on fields the synthetic event does not carry are not credited.
    assert not eventPatternMatches({'source': ['aws.guardduty'], 'detail': {'userIdentity': {'type': ['Root']}}}, ev)
    assert not eventPatternMatches({'detail': {'eventName': [{'numeric': ['>', 0]}]}}, ev)


def test_detection_events_unreadable_is_unable_not_fail(clients):
    clients.stub('guardduty').add_response('list_detectors', {'DetectorIds': ['d1']})
    clients.stub('securityhub').add_client_error('describe_hub', service_error_code='InvalidAccessException')
    clients.stub('accessanalyzer').add_response('list_analyzers', {'analyzers': []})
    _denied(clients.stub('events'), 'list_rules')
    d = _driver(clients)
    d._checkDetectionDisableAlarm()
    r = d.results['detectionDisableNoAlarm']
    assert r[0] == 0 and 'events: AccessDeniedException' in r[1]


def test_detection_rule_without_target_flagged_with_target_passes(clients):
    pattern = json.dumps({'source': ['aws.guardduty'], 'detail': {'eventName': ['DeleteDetector']}})
    for resp, expected in (({}, -1), ({'Targets': [{'Id': '1', 'Arn': 'arn:aws:sns:us-east-1:111122223333:t'}]}, 1)):
        clients.stub('guardduty').add_response('list_detectors', {'DetectorIds': ['d1']})
        clients.stub('securityhub').add_client_error('describe_hub', service_error_code='InvalidAccessException')
        clients.stub('accessanalyzer').add_response('list_analyzers', {'analyzers': []})
        clients.stub('events').add_response('list_rules', {'Rules': [
            {'Name': 'r', 'State': 'ENABLED', 'EventPattern': pattern}]})
        clients.stub('events').add_response('list_targets_by_rule', resp)
        d = _driver(clients)
        d._checkDetectionDisableAlarm()
        assert d.results['detectionDisableNoAlarm'][0] == expected


# --------------------------------------------------------------------------- #
# replicationLagNotAlarmed
# Stubber because the emulator rejects PutMetricData into reserved 'AWS/'
# namespaces and does not vend RDS/DynamoDB/S3 replication metrics, so the
# replication-lag metric streams the check keys on cannot be produced there.
# --------------------------------------------------------------------------- #
LAG_DIMS = [{'Name': 'DBInstanceIdentifier', 'Value': 'db-replica-1'}]
SNS = 'arn:aws:sns:us-east-1:111122223333:ops'


def _lagMetrics(clients, found=None, error=None):
    """Queue one list_metrics response per REPLICATION_LAG_METRICS entry."""
    st = clients.stub('cloudwatch')
    for ns, mn in CloudwatchAccount.REPLICATION_LAG_METRICS:
        if error:
            _denied(st, 'list_metrics')
            continue
        metrics = [{'Namespace': ns, 'MetricName': mn, 'Dimensions': d}
                   for (fns, fmn, d) in (found or []) if (fns, fmn) == (ns, mn)]
        st.add_response('list_metrics', {'Metrics': metrics},
                        {'Namespace': ns, 'MetricName': mn, 'RecentlyActive': 'PT3H'})


def _lagAlarm(dims=LAG_DIMS, actions=True, name='replica-lag'):
    return {'AlarmName': name, 'AlarmArn': f'arn:aws:cloudwatch:us-east-1:{ACCT}:alarm:{name}',
            'Namespace': 'AWS/RDS', 'MetricName': 'ReplicaLag', 'Dimensions': dims,
            'ActionsEnabled': True, 'AlarmActions': [SNS] if actions else []}


def _runLag(clients, alarms=None, composites=None, found=None, error=None):
    _lagMetrics(clients, found=found, error=error)
    d = CloudwatchAccount(REGION, clients, [], [], alarms or [], composites or [])
    d._checkReplicationLagAlarm()
    clients.stub('cloudwatch').assert_no_pending_responses()
    return d.results['replicationLagNotAlarmed']


def test_replication_lag_flag_fix(clients):
    found = [('AWS/RDS', 'ReplicaLag', LAG_DIMS)]
    flagged = _runLag(clients, alarms=[], found=found)
    assert flagged[0] == -1 and 'DBInstanceIdentifier=db-replica-1' in flagged[1]
    ## Alarm exists but has no alarm action -> still flagged.
    assert _runLag(clients, alarms=[_lagAlarm(actions=False)], found=found)[0] == -1
    ## Alarm on another instance does not cover this one.
    other = _lagAlarm(dims=[{'Name': 'DBInstanceIdentifier', 'Value': 'other'}])
    found2 = found + [('AWS/RDS', 'ReplicaLag', other['Dimensions'])]
    r = _runLag(clients, alarms=[other], found=found2)
    assert r[0] == -1 and '1 of 2' in r[1]
    ## Fix: alarm with an SNS action on the replica's metric.
    assert _runLag(clients, alarms=[_lagAlarm()], found=found)[0] == 1


def test_replication_lag_composite_and_math_coverage(clients):
    found = [('AWS/DynamoDB', 'ReplicationLatency',
              [{'Name': 'TableName', 'Value': 't'}, {'Name': 'ReceivingRegion', 'Value': 'eu-west-1'}])]
    child = {'AlarmName': 'ddb-lag', 'Namespace': 'AWS/DynamoDB', 'MetricName': 'ReplicationLatency',
             'Dimensions': found[0][2], 'ActionsEnabled': True, 'AlarmActions': []}
    composite = {'AlarmName': 'c', 'ActionsEnabled': True, 'AlarmActions': [SNS],
                 'AlarmRule': 'ALARM("ddb-lag") OR ALARM("x")'}
    assert _runLag(clients, alarms=[child], found=found)[0] == -1
    assert _runLag(clients, alarms=[child], composites=[composite], found=found)[0] == 1
    search = {'AlarmName': 's', 'ActionsEnabled': True, 'AlarmActions': [SNS], 'Metrics': [
        {'Id': 'e1', 'Expression': "MAX(SEARCH('{AWS/DynamoDB,TableName,ReceivingRegion} MetricName=\"ReplicationLatency\"', 'Maximum', 60))"}]}
    assert _runLag(clients, alarms=[search], found=found)[0] == 1
    ## A SEARCH on the same metric name in another namespace does not count.
    s3search = {'AlarmName': 's3', 'ActionsEnabled': True, 'AlarmActions': [SNS], 'Metrics': [
        {'Id': 'e1', 'Expression': "MAX(SEARCH('{AWS/S3,SourceBucket} MetricName=\"ReplicationLatency\"', 'Maximum', 60))"}]}
    assert _runLag(clients, alarms=[s3search], found=found)[0] == -1


def test_replication_lag_no_replicas_or_unreadable(clients):
    assert _runLag(clients, found=[])[0] == 0
    r = _runLag(clients, error=True)
    assert r[0] == 0 and 'Unable to evaluate (' in r[1]


# --------------------------------------------------------------------------- #
# telemetryRulesNotConfigured
# Stubber because the emulator does not implement
# ListTelemetryRulesForOrganization (organization-wide rules), and cannot act as
# a member or standalone account.
# --------------------------------------------------------------------------- #
def _tRule(name):
    return {'RuleName': name, 'RuleArn': f'arn:aws:observabilityadmin:us-east-1:{ACCT}:telemetry-rule/{name}',
            'ResourceType': 'AWS::EC2::VPC', 'TelemetryType': 'Logs'}


def _telemetry(clients, acctStatus='NOT_STARTED', acctRules=(), org=ACCT, orgStatus='NOT_STARTED',
               orgRules=(), orgDenied=False):
    st = clients.stub('observabilityadmin')
    st.add_response('get_telemetry_evaluation_status', {'Status': acctStatus})
    st.add_response('list_telemetry_rules', {'TelemetryRuleSummaries': list(acctRules)})
    if acctRules and acctStatus == 'RUNNING':
        return
    if org is None:
        clients.stub('organizations').add_client_error('describe_organization',
                                                       service_error_code='AWSOrganizationsNotInUseException')
        return
    _org(clients, org)
    if orgDenied:
        _denied(st, 'get_telemetry_evaluation_status_for_organization')
        return
    st.add_response('get_telemetry_evaluation_status_for_organization', {'Status': orgStatus})
    st.add_response('list_telemetry_rules_for_organization', {'TelemetryRuleSummaries': list(orgRules)})


def _runTelemetry(clients, **kw):
    _telemetry(clients, **kw)
    d = _driver(clients)
    d._checkTelemetryRules()
    clients.stub('observabilityadmin').assert_no_pending_responses()
    return d.results['telemetryRulesNotConfigured']


def test_telemetry_rules_mgmt_flag_fix(clients):
    assert _runTelemetry(clients)[0] == -1
    ## Rule exists but evaluation never started -> still flagged.
    assert _runTelemetry(clients, orgRules=[_tRule('org-vpc')])[0] == -1
    assert _runTelemetry(clients, orgStatus='RUNNING', orgRules=[_tRule('org-vpc')])[0] == 1


def test_telemetry_rules_account_rule_passes(clients):
    assert _runTelemetry(clients, acctStatus='RUNNING', acctRules=[_tRule('acct-vpc')])[0] == 1


def test_telemetry_rules_standalone_flag_fix(clients):
    r = _runTelemetry(clients, org=None)
    assert r[0] == -1 and 'organization' not in r[1]
    assert _runTelemetry(clients, org=None, acctStatus='RUNNING', acctRules=[_tRule('acct')])[0] == 1


def test_telemetry_rules_member_account_not_evaluable(clients):
    r = _runTelemetry(clients, org=MGMT, orgDenied=True)
    assert r == [0, 'Not evaluable from member account']


def test_telemetry_rules_mgmt_denied_or_account_unreadable(clients):
    r = _runTelemetry(clients, org=ACCT, orgDenied=True)
    assert r[0] == 0 and 'Unable to evaluate (AccessDeniedException)' in r[1]
    st = clients.stub('observabilityadmin')
    _denied(st, 'get_telemetry_evaluation_status')
    _org(clients, ACCT)
    st.add_response('get_telemetry_evaluation_status_for_organization', {'Status': 'NOT_STARTED'})
    st.add_response('list_telemetry_rules_for_organization', {'TelemetryRuleSummaries': []})
    d = _driver(clients)
    d._checkTelemetryRules()
    assert d.results['telemetryRulesNotConfigured'][0] == 0

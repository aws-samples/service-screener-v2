"""Driver-level tests for services/arc execution-state handling.

The emulator cannot put a Region switch execution into failed/canceled states
(CancelPlanExecution is NotImplemented) nor simulate a Region whose
list_plan_executions is denied, so those branches are exercised here with
botocore Stubber-backed clients (real API shapes) feeding the real driver.
"""
import os
import sys

import datetime

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.arc.drivers.ArcRegionSwitchPlan import ArcRegionSwitchPlan  # noqa: E402
from services.arc.drivers.ArcAccount import ArcAccount  # noqa: E402

ARN = 'arn:aws:arc-region-switch::111122223333:plan/app1:abc123'
PLAN = {'arn': ARN, 'name': 'app1', 'owner': '111122223333', 'regions': ['us-east-1', 'us-west-2'],
        'recoveryApproach': 'activePassive', 'version': '1'}


def _client():
    return boto3.session.Session(aws_access_key_id='x', aws_secret_access_key='x',
                                 region_name='us-east-1').client('arc-region-switch')


def _executions(items):
    c = _client()
    with Stubber(c) as st:
        st.add_response('list_plan_executions', {'items': items}, {'planArn': ARN})
        return c.list_plan_executions(planArn=ARN)['items']


def _run(executions, errors=None, plan=PLAN):
    d = ArcRegionSwitchPlan(plan, executions, errors or {})
    d._checkRegionSwitchPlanNeverExecuted()
    return d.results['regionSwitchPlanNeverExecuted'][0]


def _ex(state, eid='us-west-2/1'):
    return {'planArn': ARN, 'executionId': eid, 'version': '1', 'mode': 'graceful',
            'startTime': datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
            'executionState': state, 'executionAction': 'activate', 'executionRegion': 'us-west-2'}


def test_never_executed_flags_then_completed_passes():
    assert _run(_executions([])) == -1
    assert _run(_executions([_ex('completed')])) == 1


def test_only_failed_or_canceled_executions_flag():
    assert _run(_executions([_ex('failed'), _ex('canceled', 'us-west-2/2')])) == -1
    assert _run(_executions([_ex('failed'), _ex('completedWithExceptions', 'us-west-2/2')])) == 1


def test_in_progress_is_info():
    assert _run(_executions([_ex('pendingManualApproval')])) == 0


def test_unreadable_region_is_not_evaluable_not_fail():
    c = _client()
    with Stubber(c) as st:
        st.add_client_error('list_plan_executions', 'AccessDeniedException', expected_params={'planArn': ARN})
        try:
            c.list_plan_executions(planArn=ARN)
            raise AssertionError('expected error')
        except c.exceptions.AccessDeniedException:
            pass
    r = ArcRegionSwitchPlan(PLAN, [], {'us-west-2': 'AccessDeniedException'})
    r._checkRegionSwitchPlanNeverExecuted()
    assert r.results['regionSwitchPlanNeverExecuted'][0] == 0
    assert 'Unable to evaluate' in r.results['regionSwitchPlanNeverExecuted'][1]


def test_account_check_unable_when_one_source_unreadable():
    def run(detail):
        a = ArcAccount(detail)
        a._checkRegionSwitchPlanMissing()
        return a.results['regionSwitchPlanMissing'][0]
    ## Both lists empty: the verdict depends on multi-Region evidence (below).
    assert run({'_plans': [], '_clusters': [], '_multiRegion': {'evidence': ['x'], 'errors': [], 'incomplete': []}}) == -1
    assert run({'_plans': None, '_planError': 'AccessDeniedException', '_clusters': []}) == 0
    assert run({'_plans': None, '_planError': 'AccessDeniedException', '_clusters': [{'Name': 'c'}]}) == 1
    assert run({'_plans': [PLAN], '_clusters': None, '_clusterError': 'AccessDeniedException'}) == 1


# ---- regionSwitchPlanMissing: FAIL only with multi-Region evidence --------- #
## A single-Region account without ARC used to FAIL although the reporter
## calls this a signal for multi-Region workloads only.

from services.arc.Arc import Arc  # noqa: E402


def _account(mr, plans=(), clusters=()):
    a = ArcAccount({'_region': 'us-east-1', '_plans': list(plans), '_clusters': list(clusters),
                    '_multiRegion': mr})
    a._checkRegionSwitchPlanMissing()
    return a.results['regionSwitchPlanMissing']


def test_single_region_account_without_arc_is_info_not_fail():
    r = _account({'evidence': [], 'errors': [], 'incomplete': []})
    assert r[0] == 0 and 'no multi-Region workload evidence' in r[1], r


def test_multi_region_account_without_arc_fails_then_plan_passes():
    mr = {'evidence': ['Aurora global database g1 (us-east-1, us-west-2)'], 'errors': [], 'incomplete': []}
    r = _account(mr)
    assert r[0] == -1 and 'Aurora global database g1' in r[1], r
    assert _account(mr, plans=[PLAN])[0] == 1


def test_unreadable_evidence_is_unable_to_evaluate():
    r = _account({'evidence': [], 'errors': ['rds:DescribeGlobalClusters: AccessDenied'], 'incomplete': []})
    assert r[0] == 0 and r[1].startswith('Unable to evaluate (rds:DescribeGlobalClusters: AccessDenied)'), r
    assert _account(None)[0] == 0


def test_partial_evidence_read_is_disclosed():
    r = _account({'evidence': [], 'errors': [], 'incomplete': ['DynamoDB replicas checked on 100 of 250 tables']})
    assert r[0] == 0 and 'Partially checked' in r[1], r


class _Sess:
    def __init__(self, clients):
        self.clients = clients

    def client(self, svc, region_name=None, config=None):
        return self.clients[svc]


class _Arc(Arc):
    def __del__(self):  # a real Service writes report files on GC
        pass


def _probeWith(stubFns):
    """stubFns: {service: fn(stubber)}; returns Arc._multiRegionEvidence()."""
    sess = boto3.session.Session(aws_access_key_id='x', aws_secret_access_key='x', region_name='us-east-1')
    clients = {svc: sess.client(svc) for svc in ('events', 'rds', 'dynamodb', 'route53')}
    stubs = {svc: Stubber(c) for svc, c in clients.items()}
    for svc, fn in stubFns.items():
        fn(stubs[svc])
    for st in stubs.values():
        st.activate()
    a = _Arc.__new__(_Arc)
    a.region = 'us-east-1'
    a.ssBoto = _Sess(clients)
    a.bConfig = None
    out = a._multiRegionEvidence()
    for st in stubs.values():
        st.assert_no_pending_responses()
    return out


def _noEndpoints(st):
    st.add_response('list_endpoints', {'Endpoints': []}, {})


def _noAurora(st):
    st.add_response('describe_global_clusters', {'GlobalClusters': []}, {})


def _noDdb(st, tables=()):
    st.add_response('list_global_tables', {'GlobalTables': []}, {})
    st.add_response('list_tables', {'TableNames': list(tables)}, {})


def _zones(st, records):
    st.add_response('list_hosted_zones', {'HostedZones': [
        {'Id': '/hostedzone/Z1', 'Name': 'example.com.', 'CallerReference': 'c'}],
        'Marker': '', 'IsTruncated': False, 'MaxItems': '100'}, {})
    st.add_response('list_resource_record_sets', {'ResourceRecordSets': records, 'IsTruncated': False,
                                                  'MaxItems': '300'}, {'HostedZoneId': '/hostedzone/Z1'})


def test_probe_no_evidence_single_region():
    def ddb(st):
        _noDdb(st, ['orders'])
        st.add_response('describe_table', {'Table': {'TableName': 'orders'}}, {'TableName': 'orders'})
    out = _probeWith({'events': _noEndpoints, 'rds': _noAurora, 'dynamodb': ddb,
                      'route53': lambda st: _zones(st, [
                          {'Name': 'app.example.com.', 'Type': 'A', 'SetIdentifier': 'p', 'Failover': 'PRIMARY',
                           'AliasTarget': {'HostedZoneId': 'Z', 'DNSName': 'dualstack.a-1.us-east-1.elb.amazonaws.com.',
                                           'EvaluateTargetHealth': True}},
                          {'Name': 'app.example.com.', 'Type': 'A', 'SetIdentifier': 's', 'Failover': 'SECONDARY',
                           'AliasTarget': {'HostedZoneId': 'Z', 'DNSName': 'dualstack.b-2.us-east-1.elb.amazonaws.com.',
                                           'EvaluateTargetHealth': True}}])})
    assert out == {'evidence': [], 'errors': [], 'incomplete': []}, out


def test_probe_aurora_global_database_is_evidence():
    def rds(st):
        st.add_response('describe_global_clusters', {'GlobalClusters': [{
            'GlobalClusterIdentifier': 'g1', 'GlobalClusterMembers': [
                {'DBClusterArn': 'arn:aws:rds:us-east-1:111122223333:cluster:a', 'IsWriter': True},
                {'DBClusterArn': 'arn:aws:rds:eu-west-1:111122223333:cluster:b', 'IsWriter': False}]}]}, {})
    out = _probeWith({'events': _noEndpoints, 'rds': rds})
    assert out['evidence'] == ['Aurora global database g1 (eu-west-1, us-east-1)'], out


def test_probe_dynamodb_replica_is_evidence():
    def ddb(st):
        _noDdb(st, ['orders'])
        st.add_response('describe_table', {'Table': {'TableName': 'orders', 'Replicas': [
            {'RegionName': 'us-west-2', 'ReplicaStatus': 'ACTIVE'}]}}, {'TableName': 'orders'})
    out = _probeWith({'events': _noEndpoints, 'rds': _noAurora, 'dynamodb': ddb})
    assert out['evidence'] == ['DynamoDB global table orders (replicas in us-west-2)'], out


def test_probe_route53_cross_region_failover_and_latency_are_evidence():
    fo = [{'Name': 'app.example.com.', 'Type': 'A', 'SetIdentifier': 'p', 'Failover': 'PRIMARY',
           'AliasTarget': {'HostedZoneId': 'Z', 'DNSName': 'dualstack.a-1.us-east-1.elb.amazonaws.com.',
                           'EvaluateTargetHealth': True}},
          {'Name': 'app.example.com.', 'Type': 'A', 'SetIdentifier': 's', 'Failover': 'SECONDARY',
           'AliasTarget': {'HostedZoneId': 'Z', 'DNSName': 'dualstack.b-2.us-west-2.elb.amazonaws.com.',
                           'EvaluateTargetHealth': True}}]
    out = _probeWith({'events': _noEndpoints, 'rds': _noAurora, 'dynamodb': _noDdb,
                      'route53': lambda st: _zones(st, fo)})
    assert out['evidence'] == ['Route 53 failover records app.example.com. A (PRIMARY us-east-1, SECONDARY us-west-2)']
    lat = [{'Name': 'api.example.com.', 'Type': 'CNAME', 'SetIdentifier': r, 'Region': r, 'TTL': 60,
            'ResourceRecords': [{'Value': f'x.{r}.example.net'}]} for r in ('us-east-1', 'eu-west-1')]
    out = _probeWith({'events': _noEndpoints, 'rds': _noAurora, 'dynamodb': _noDdb,
                      'route53': lambda st: _zones(st, lat)})
    assert out['evidence'] == ['Route 53 latency records api.example.com. CNAME (eu-west-1, us-east-1)']


def test_probe_global_endpoint_short_circuits():
    def ev(st):
        st.add_response('list_endpoints', {'Endpoints': [{'Name': 'ge1'}]}, {})
    out = _probeWith({'events': ev})
    assert out['evidence'] == ['EventBridge global endpoint ge1'] and out['errors'] == []


def test_probe_errors_are_recorded_not_absence():
    def rds(st):
        st.add_client_error('describe_global_clusters', 'AccessDenied', http_status_code=403)
    out = _probeWith({'events': _noEndpoints, 'rds': rds, 'dynamodb': _noDdb,
                      'route53': lambda st: _zones(st, [])})
    assert out['evidence'] == [] and out['errors'] == ['rds:DescribeGlobalClusters: AccessDenied'], out
    assert _account(out)[0] == 0

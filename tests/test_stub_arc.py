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
    assert run({'_plans': [], '_clusters': []}) == -1
    assert run({'_plans': None, '_planError': 'AccessDeniedException', '_clusters': []}) == 0
    assert run({'_plans': None, '_planError': 'AccessDeniedException', '_clusters': [{'Name': 'c'}]}) == 1
    assert run({'_plans': [PLAN], '_clusters': None, '_clusterError': 'AccessDeniedException'}) == 1

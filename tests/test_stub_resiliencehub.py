"""
Flag -> fix -> re-run tests for resiliencehub checks, using botocore Stubber around
real boto3 clients (real API request/response shapes are validated).

Why Stubber and not (only) the AWS Emulator:
- resilienceHubDriftOrBreach: the emulator always reports complianceStatus PolicyMet
  and driftStatus NotChecked, so a PolicyBreached / drift-Detected app cannot be produced.
- resilienceHubAssessmentStale: the "last success older than 30 days" branch needs an
  old endTime, which the emulator cannot produce; never-assessed is also covered by
  tests/emulator/test_emu_resiliencehub.py.
- resilienceHubNoPolicy: list_resiliency_policies is NotImplemented in the emulator,
  and AccessDenied / describe_app failure paths cannot be produced there.

No network is used: clients carry fake credentials and every call is served by a
Stubber (an unexpected call fails the test).
"""
import datetime
import os
import sys

import boto3
from botocore.stub import Stubber, ANY

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.resiliencehub.Resiliencehub import Resiliencehub  # noqa: E402
from services.resiliencehub.drivers.ResiliencehubApp import ResiliencehubApp  # noqa: E402
from services.resiliencehub.drivers.ResiliencehubCommon import ResiliencehubCommon  # noqa: E402

ACCT = '111111111111'
APP_ARN = f'arn:aws:resiliencehub:us-east-1:{ACCT}:app/11111111-2222-3333-4444-555555555555'
APP2_ARN = f'arn:aws:resiliencehub:us-east-1:{ACCT}:app/66666666-2222-3333-4444-555555555555'
POLICY_ARN = f'arn:aws:resiliencehub:us-east-1:{ACCT}:resiliency-policy/aaaaaaaa-2222-3333-4444-555555555555'
NOW = datetime.datetime.now(datetime.timezone.utc)


def _client():
    return boto3.session.Session(aws_access_key_id='AKIDSTUBONLY', aws_secret_access_key='stub',
                                 region_name='us-east-1').client('resiliencehub')


class _Svc(Resiliencehub):
    """Service object without the scan bootstrap (no session / fork dir)."""
    def __init__(self, client):
        self.rhClient = client
        self.region = 'us-east-1'
        self.tags = []
        self._tags = {}

    def __del__(self):
        pass


def _app(arn=APP_ARN, name='orders', **kw):
    a = {'appArn': arn, 'name': name, 'creationTime': NOW - datetime.timedelta(days=200),
         'status': 'Active', 'assessmentSchedule': 'Disabled',
         'complianceStatus': 'NotAssessed', 'driftStatus': 'NotChecked'}
    a.update(kw)
    return a


def _summary(app):
    keys = ('appArn', 'name', 'creationTime', 'status', 'assessmentSchedule', 'complianceStatus', 'driftStatus')
    return {k: app[k] for k in keys if k in app}


def _assessment(status, days_ago, name='a1'):
    row = {'appArn': APP_ARN, 'assessmentArn': f'arn:aws:resiliencehub:us-east-1:{ACCT}:app-assessment/{name}',
           'assessmentName': name, 'assessmentStatus': status, 'invoker': 'System',
           'startTime': NOW - datetime.timedelta(days=days_ago, minutes=5)}
    if status in ('Success', 'Failed'):
        row['endTime'] = NOW - datetime.timedelta(days=days_ago)
    return row


def _discover(apps, policies=None, policiesError=None, describeError=None):
    """Run Resiliencehub.getResources/_listPolicies against a stubbed client."""
    c = _client()
    st = Stubber(c)
    st.add_response('list_apps', {'appSummaries': [_summary(a) for a in apps]}, {})
    for a in apps:
        if describeError:
            st.add_client_error('describe_app', describeError, expected_params={'appArn': a['appArn']})
        else:
            st.add_response('describe_app', {'app': a}, {'appArn': a['appArn']})
    if policiesError:
        st.add_client_error('list_resiliency_policies', policiesError)
    else:
        st.add_response('list_resiliency_policies', {'resiliencyPolicies': policies or []}, {})
    with st:
        svc = _Svc(c)
        found, appsErr = svc.getResources()
        pol, polErr = svc._listPolicies()
        st.assert_no_pending_responses()
    return {'_region': 'us-east-1', '_apps': found, '_appsError': appsErr,
            '_policies': pol, '_policiesError': polErr}


def _common(detail):
    obj = ResiliencehubCommon(detail)
    obj._checkResilienceHubNoPolicy()
    return obj.results['resilienceHubNoPolicy']


# --------------------------------------------------------------------------- #
# resilienceHubNoPolicy
# --------------------------------------------------------------------------- #
def test_no_policy_flag_fix():
    policy = {'policyArn': POLICY_ARN, 'policyName': 'gold', 'tier': 'Critical',
              'policy': {'Software': {'rpoInSecs': 60, 'rtoInSecs': 60}}}
    before = _common(_discover([_app(), _app(APP2_ARN, 'billing', policyArn=POLICY_ARN)], policies=[policy]))
    assert before[0] == -1 and 'orders' in before[1] and 'billing' not in before[1], before
    after = _common(_discover([_app(policyArn=POLICY_ARN), _app(APP2_ARN, 'billing', policyArn=POLICY_ARN)],
                              policies=[policy]))
    assert after[0] == 1, after


def test_no_policy_flags_even_when_policy_list_unreadable():
    before = _common(_discover([_app()], policiesError='AccessDeniedException'))
    assert before[0] == -1 and 'AccessDeniedException' in before[1]


def test_no_policy_unable_to_evaluate():
    c = _client()
    st = Stubber(c)
    st.add_client_error('list_apps', 'AccessDeniedException')
    with st:
        apps, err = _Svc(c).getResources()
    assert _common({'_apps': apps, '_appsError': err, '_policies': None})[0] == 0
    ## describe_app failing must not silently PASS
    assert _common(_discover([_app()], describeError='AccessDeniedException'))[0] == 0
    ## ...but a summary that already says MissingPolicy is still a finding
    assert _common(_discover([_app(complianceStatus='MissingPolicy')], describeError='AccessDeniedException'))[0] == -1
    ## no apps at all: informational
    assert _common(_discover([]))[0] == 0


# --------------------------------------------------------------------------- #
# resilienceHubDriftOrBreach
# --------------------------------------------------------------------------- #
def _drift(app):
    detail = _discover([app], policies=[])
    obj = ResiliencehubApp(detail['_apps'][0], _client())
    obj._checkResilienceHubDriftOrBreach()
    return obj.results['resilienceHubDriftOrBreach']


def test_drift_or_breach_flag_fix():
    breached = _drift(_app(policyArn=POLICY_ARN, complianceStatus='PolicyBreached', driftStatus='NotDetected'))
    assert breached[0] == -1 and 'breached' in breached[1]
    drifted = _drift(_app(policyArn=POLICY_ARN, complianceStatus='PolicyMet', driftStatus='Detected'))
    assert drifted[0] == -1 and 'drift' in drifted[1]
    fixed = _drift(_app(policyArn=POLICY_ARN, complianceStatus='PolicyMet', driftStatus='NotDetected'))
    assert fixed[0] == 1


def test_drift_or_breach_not_evaluable_states():
    for status in ('NotAssessed', 'MissingPolicy', 'ChangesDetected', 'NotApplicable'):
        assert _drift(_app(complianceStatus=status))[0] == 0, status


# --------------------------------------------------------------------------- #
# resilienceHubAssessmentStale
# --------------------------------------------------------------------------- #
def _stale(successRows, recentRows=None, error=None):
    c = _client()
    st = Stubber(c)
    if error:
        st.add_client_error('list_app_assessments', error)
    else:
        st.add_response('list_app_assessments', {'assessmentSummaries': successRows},
                        {'appArn': APP_ARN, 'reverseOrder': True, 'assessmentStatus': ['Success']})
        if not successRows:
            st.add_response('list_app_assessments', {'assessmentSummaries': recentRows or []},
                            {'appArn': APP_ARN, 'reverseOrder': True})
    with st:
        obj = ResiliencehubApp(_app(), c)
        obj._checkResilienceHubAssessmentStale()
        st.assert_no_pending_responses()
    return obj.results['resilienceHubAssessmentStale']


def test_assessment_stale_flag_fix():
    old = _stale([_assessment('Success', 60)])
    assert old[0] == -1 and '60 day' in old[1], old
    fresh = _stale([_assessment('Success', 2, 'a2'), _assessment('Success', 60)])
    assert fresh[0] == 1, fresh


def test_assessment_never_succeeded():
    assert _stale([], [_assessment('Failed', 1)])[0] == -1
    assert _stale([], [])[0] == -1
    assert _stale([], [_assessment('InProgress', 0)])[0] == 0
    assert _stale(None, error='AccessDeniedException')[0] == 0

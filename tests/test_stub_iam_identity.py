"""
Stubber-based flag -> fix tests for WAFS2027 IAM identity checks that the AWS
Emulator cannot drive:

- iamActiveKeyUnused / iamUserHumanAndMachineCreds read the IAM credential
  report. The emulator (like IAM) caches the report, so users and keys created
  during a test never appear in it, and key age / last-used dates cannot be
  set. The report is fed through a real boto3 IAM client wrapped by
  botocore Stubber (real GetCredentialReport shape) and parsed exactly like
  Iam.getUsers() does.
- controlTowerLandingZoneDrift: the emulator cannot create a drifted landing
  zone or FAILED/DRIFTED enabled controls.
- healthLifecycleEventsOpen: the emulator returns SubscriptionRequiredException
  for health.describe_events, so only the not-evaluable path is reachable there.

No network calls are made: every client is wrapped by an activated Stubber
with fake credentials, so an unexpected call fails the test.

Pure helper tests for the trust/identity policy evaluators are included too.
"""
import datetime
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.iam.drivers.IamUser import IamUser  # noqa: E402
from services.iam.drivers.IamAccount import IamAccount  # noqa: E402
from services.iam.drivers import IamPolicyHelpers as H  # noqa: E402

ACCOUNT = '111122223333'
FIELDS = ('user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,'
          'password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,'
          'access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,'
          'access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,'
          'access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,'
          'cert_1_last_rotated,cert_2_active,cert_2_last_rotated')


def _client(service, region='us-east-1'):
    c = boto3.session.Session().client(service, region_name=region, aws_access_key_id='testing',
                                       aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')
    stub = Stubber(c)
    stub.activate()
    return c, stub


def _iso(daysAgo):
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=daysAgo)
    return t.strftime('%Y-%m-%dT%H:%M:%S+00:00')


def _row(user='alice', password='false', k1=('false', 'N/A', 'N/A'), k2=('false', 'N/A', 'N/A')):
    vals = [user, f'arn:aws:iam::{ACCOUNT}:user/{user}', _iso(400), password, 'N/A', 'N/A', 'N/A', 'false',
            k1[0], k1[1], k1[2], 'N/A', 'N/A', k2[0], k2[1], k2[2], 'N/A', 'N/A', 'false', 'N/A', 'false', 'N/A']
    return ','.join(vals)


def _reportUser(rowCsv):
    """Fetch the credential report through a stubbed IAM client and parse it
    the same way Iam.getUsers() does; return (row dict, client)."""
    iam, stub = _client('iam')
    content = (FIELDS + '\n' + rowCsv).encode()
    stub.add_response('get_credential_report', {
        'Content': content, 'ReportFormat': 'text/csv',
        'GeneratedTime': datetime.datetime.now(datetime.timezone.utc)})
    rows = iam.get_credential_report()['Content'].decode('UTF-8').split('\n')
    fields = rows[0].split(',')
    users = [dict(zip(fields, r.split(','))) for r in rows[1:]]
    stub.assert_no_pending_responses()
    return users[0], iam


def _runUser(rowCsv, method):
    row, iam = _reportUser(rowCsv)
    u = IamUser(row, iam)
    getattr(u, method)()
    return u.results


# --------------------------------------------------------------------------- #
# iamActiveKeyUnused
# --------------------------------------------------------------------------- #
class TestActiveKeyUnused:
    M = '_checkIamActiveKeyUnused'
    K = 'iamActiveKeyUnused'

    def test_flag_fix_last_used_over_90_days(self):
        bad = _runUser(_row(k1=('true', _iso(200), _iso(120))), self.M)
        assert bad[self.K][0] == -1, bad
        good = _runUser(_row(k1=('true', _iso(200), _iso(3))), self.M)
        assert good[self.K][0] == 1, good

    def test_flag_fix_never_used_older_than_7_days(self):
        bad = _runUser(_row(k1=('true', _iso(30), 'N/A')), self.M)
        assert bad[self.K][0] == -1 and 'never used' in bad[self.K][1], bad
        # fix: deactivate the unused key -> nothing to evaluate
        fixed = _runUser(_row(k1=('false', _iso(30), 'N/A')), self.M)
        assert self.K not in fixed or fixed[self.K][0] != -1

    def test_new_unused_key_within_grace(self):
        res = _runUser(_row(k1=('true', _iso(2), 'N/A')), self.M)
        assert res[self.K][0] == 1

    def test_second_key_evaluated_even_if_first_inactive(self):
        res = _runUser(_row(k1=('false', _iso(500), 'N/A'), k2=('true', _iso(300), _iso(100))), self.M)
        assert res[self.K][0] == -1 and 'access key 2' in res[self.K][1]

    def test_independent_of_console_activity(self):
        # console used recently (password enabled) - key still stale
        res = _runUser(_row(password='true', k1=('true', _iso(200), _iso(91))), self.M)
        assert res[self.K][0] == -1

    def test_root_and_placeholder_rows_skipped(self):
        res = _runUser(_row(user='<root_account>', k1=('true', _iso(200), _iso(150))), self.M)
        assert self.K not in res
        u = IamUser({'user': 'BedrockAPIKey-x', 'password_enabled': 'false', 'access_key_1_active': 'false',
                     'access_key_2_active': 'false', 'mfa_active': 'false',
                     'password_last_used': 'no_information', 'password_last_changed': 'no_information'}, None)
        u._checkIamActiveKeyUnused()
        u._checkIamUserHumanAndMachineCreds()
        assert u.results == {}


# --------------------------------------------------------------------------- #
# iamUserHumanAndMachineCreds
# --------------------------------------------------------------------------- #
class TestHumanAndMachineCreds:
    M = '_checkIamUserHumanAndMachineCreds'
    K = 'iamUserHumanAndMachineCreds'

    def test_flag_fix(self):
        bad = _runUser(_row(password='true', k2=('true', _iso(10), _iso(1))), self.M)
        assert bad[self.K][0] == -1, bad
        fixed = _runUser(_row(password='false', k2=('true', _iso(10), _iso(1))), self.M)
        assert fixed[self.K][0] == 1, fixed

    def test_password_only(self):
        assert _runUser(_row(password='true'), self.M)[self.K][0] == 1

    def test_root_skipped(self):
        assert self.K not in _runUser(_row(user='<root_account>', password='not_supported',
                                           k1=('true', _iso(1), _iso(1))), self.M)


# --------------------------------------------------------------------------- #
# IamAccount helpers
# --------------------------------------------------------------------------- #
@pytest.fixture
def cfg():
    saved = {k: Config.get(k, None) for k in ('stsInfo', 'REGIONS_SELECTED')}
    Config.set('stsInfo', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/x'})
    Config.set('REGIONS_SELECTED', ['us-east-1'])
    yield
    for k, v in saved.items():
        Config.set(k, v)


def _account(orgMaster=ACCOUNT, health=None):
    clients = {}
    stubs = {}
    for k, svc in (('iamClient', 'iam'), ('orgClient', 'organizations'), ('accClient', 'account'),
                   ('sppClient', 'support'), ('budgetClient', 'budgets'), ('curClient', 'cur'),
                   ('ctClient', 'cloudtrail'), ('backupClient', 'backup')):
        clients[k], stubs[k] = _client(svc)
    if orgMaster is None:
        stubs['orgClient'].add_client_error('describe_organization', 'AWSOrganizationsNotInUseException')
    else:
        stubs['orgClient'].add_response('describe_organization', {'Organization': {
            'Id': 'o-abcdefghij', 'MasterAccountId': orgMaster,
            'Arn': f'arn:aws:organizations::{orgMaster}:organization/o-abcdefghij'}})
    if health is not None:
        clients['healthClient'] = health
    acc = IamAccount(None, clients, [], [], None, {'roles': [], 'users': [], 'groups': [], 'policies': []}, {})
    return acc


LZ_ARN = f'arn:aws:controltower:us-east-1:{ACCOUNT}:landingzone/1A2B3C4D5E6F7G8H'


def _ctStub(lzStatus='ACTIVE', lzDrift='IN_SYNC', failed=(), drifted=(), regionCalls=1):
    ct, stub = _client('controltower')
    stub.add_response('list_landing_zones', {'landingZones': [{'arn': LZ_ARN}]})
    stub.add_response('get_landing_zone', {'landingZone': {
        'version': '3.3', 'arn': LZ_ARN, 'status': lzStatus, 'driftStatus': {'status': lzDrift},
        'manifest': {}}}, {'landingZoneIdentifier': LZ_ARN})

    def ctl(cid, status, drift):
        return {'arn': f'arn:aws:controltower:us-east-1:{ACCOUNT}:enabledcontrol/{cid}',
                'controlIdentifier': f'arn:aws:controlcatalog:::control/{cid}',
                'targetIdentifier': 'arn:aws:organizations::111122223333:ou/o-abcdefghij/ou-ab12-cdefgh34',
                'statusSummary': {'status': status}, 'driftStatusSummary': {'driftStatus': drift}}

    stub.add_response('list_enabled_controls', {'enabledControls': [ctl(c, 'FAILED', 'IN_SYNC') for c in failed]},
                      {'filter': {'statuses': ['FAILED']}})
    stub.add_response('list_enabled_controls', {'enabledControls': [ctl(c, 'SUCCEEDED', 'DRIFTED') for c in drifted]},
                      {'filter': {'driftStatuses': ['DRIFTED']}})
    return ct, stub


class TestControlTowerDrift:
    K = 'controlTowerLandingZoneDrift'

    def _run(self, ct):
        acc = _account()
        acc._controlTowerClient = lambda region: ct
        acc._checkControlTowerLandingZoneDrift()
        return acc.results[self.K]

    def test_flag_fix_landing_zone_drift(self, cfg):
        ct, stub = _ctStub(lzDrift='DRIFTED')
        assert self._run(ct)[0] == -1
        stub.assert_no_pending_responses()
        ct, stub = _ctStub(lzDrift='IN_SYNC')
        assert self._run(ct)[0] == 1
        stub.assert_no_pending_responses()

    def test_flag_fix_control_failed_or_drifted(self, cfg):
        ct, _ = _ctStub(failed=['abc123'], drifted=['def456'])
        r = self._run(ct)
        assert r[0] == -1 and 'abc123' in r[1] and 'def456' in r[1]
        ct, _ = _ctStub()
        assert self._run(ct)[0] == 1

    def test_landing_zone_failed(self, cfg):
        ct, _ = _ctStub(lzStatus='FAILED')
        assert self._run(ct)[0] == -1

    def test_no_landing_zone_is_info(self, cfg):
        ct, stub = _client('controltower')
        stub.add_response('list_landing_zones', {'landingZones': []})
        assert self._run(ct)[0] == 0

    def test_access_denied_is_not_evaluable(self, cfg):
        ct, stub = _client('controltower')
        stub.add_client_error('list_landing_zones', 'AccessDeniedException')
        r = self._run(ct)
        assert r[0] == 0 and 'AccessDeniedException' in r[1]

    def test_member_account_not_evaluable(self, cfg):
        acc = _account(orgMaster='999988887777')
        acc._controlTowerClient = lambda region: pytest.fail('must not call Control Tower from a member account')
        acc._checkControlTowerLandingZoneDrift()
        assert acc.results[self.K] == [0, 'Not evaluable from member account']

    def test_no_organization(self, cfg):
        acc = _account(orgMaster=None)
        acc._checkControlTowerLandingZoneDrift()
        assert acc.results[self.K][0] == 0


# --------------------------------------------------------------------------- #
# healthLifecycleEventsOpen
# --------------------------------------------------------------------------- #
HEALTH_FILTER = {'filter': {'eventTypeCategories': ['scheduledChange'], 'eventStatusCodes': ['open', 'upcoming']}}


def _event(code, region='us-east-1'):
    return {'arn': f'arn:aws:health:{region}::event/X/{code}/{code}_1', 'service': code.split('_')[1],
            'eventTypeCode': code, 'eventTypeCategory': 'scheduledChange', 'region': region,
            'statusCode': 'upcoming'}


class TestHealthLifecycle:
    K = 'healthLifecycleEventsOpen'

    def _run(self, events=None, error=None):
        h, stub = _client('health')
        if error:
            stub.add_client_error('describe_events', error)
        else:
            stub.add_response('describe_events', {'events': events}, HEALTH_FILTER)
        acc = _account(health=h)
        acc._checkHealthLifecycleEventsOpen()
        stub.assert_no_pending_responses()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        bad = self._run([_event('AWS_RDS_PLANNED_LIFECYCLE_EVENT'), _event('AWS_EKS_PLANNED_LIFECYCLE_EVENT', 'eu-west-1')])
        assert bad[0] == -1 and 'AWS_RDS_PLANNED_LIFECYCLE_EVENT' in bad[1]
        # fix: engines upgraded -> event closed, only routine maintenance left
        good = self._run([_event('AWS_EC2_INSTANCE_RETIREMENT_SCHEDULED')])
        assert good[0] == 1

    def test_subscription_required_not_evaluable(self, cfg):
        r = self._run(error='SubscriptionRequiredException')
        assert r[0] == 0 and 'SubscriptionRequiredException' in r[1]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
def _oidc(host, cond=None, action='sts:AssumeRoleWithWebIdentity'):
    s = {'Effect': 'Allow', 'Principal': {'Federated': f'arn:aws:iam::{ACCOUNT}:oidc-provider/{host}'},
         'Action': action}
    if cond:
        s['Condition'] = cond
    return {'Version': '2012-10-17', 'Statement': [s]}


GH = 'token.actions.githubusercontent.com'
EKS = 'oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789'


@pytest.mark.parametrize('host,cond,expect', [
    (GH, None, 'fail'),
    (GH, {'StringEquals': {f'{GH}:aud': 'sts.amazonaws.com'}}, 'fail'),
    (GH, {'StringLike': {f'{GH}:sub': '*'}}, 'fail'),
    (GH, {'StringLike': {f'{GH}:sub': 'repo:*'}}, 'fail'),
    (GH, {'StringLike': {f'{GH}:sub': 'repo:*/*'}}, 'fail'),
    (GH, {'StringLike': {f'{GH}:sub': 'repo:my-org*'}}, 'fail'),
    (GH, {'StringLike': {f'{GH}:sub': 'repo:*:environment:prod'}}, 'fail'),
    (GH, {'StringNotEquals': {f'{GH}:sub': 'repo:evil/x:ref:refs/heads/main'}}, 'fail'),
    (GH, {'StringLike': {f'{GH}:sub': ['repo:my-org/a:*', 'repo:*']}}, 'fail'),
    (GH, {'StringLike': {f'{GH}:sub': 'repo:my-org/*'}}, 'pass'),
    (GH, {'StringEquals': {f'{GH}:sub': 'repo:my-org/app:ref:refs/heads/main'}}, 'pass'),
    (GH, {'StringLike': {f'{GH}:SUB': 'repo:my-org/app:*'}}, 'pass'),
    (GH, {'ForAnyValue:StringLike': {f'{GH}:sub': 'repository_owner_id:12345:*'}}, 'pass'),
    ('gitlab.com', {'StringLike': {'gitlab.com:sub': 'project_path:*'}}, 'fail'),
    ('gitlab.com', {'StringLike': {'gitlab.com:sub': 'project_path:grp/proj:ref_type:branch:ref:main'}}, 'pass'),
    ('app.terraform.io', {'StringEquals': {'app.terraform.io:aud': 'aws.workload.identity'}}, 'fail'),
    ('app.terraform.io', {'StringLike': {'app.terraform.io:sub': 'organization:my-org:project:*:workspace:*:run_phase:*'}}, 'pass'),
    (EKS, {'StringEquals': {f'{EKS}:aud': 'sts.amazonaws.com'}}, 'fail'),
    (EKS, {'StringLike': {f'{EKS}:sub': 'system:serviceaccount:*'}}, 'fail'),
    (EKS, {'StringEquals': {f'{EKS}:sub': 'system:serviceaccount:default:app'}}, 'pass'),
    ('auth.example.com', None, 'info'),
    ('auth.example.com', {'StringEquals': {'auth.example.com:sub': 'user-1'}}, 'pass'),
])
def test_oidc_trust_rules(host, cond, expect):
    findings, notes = H.evaluateOidcTrust(_oidc(host, cond))
    got = 'fail' if findings else ('info' if notes else 'pass')
    assert got == expect, (findings, notes)


def test_oidc_trust_not_applicable():
    assert H.evaluateOidcTrust({'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'},
                                               'Action': 'sts:AssumeRole'}]}) == (None, None)
    assert H.evaluateOidcTrust(_oidc(GH, action='sts:TagSession')) == (None, None)


@pytest.mark.parametrize('stmt,public', [
    ({'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'sts:AssumeRole'}, True),
    ({'Effect': 'Allow', 'Principal': '*', 'Action': 'sts:*'}, True),
    ({'Effect': 'Allow', 'Principal': {'AWS': ['arn:aws:iam::1:root', '*']}, 'Action': ['sts:AssumeRole', 'sts:TagSession']}, True),
    ({'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'sts:AssumeRole',
      'Condition': {'StringEquals': {'sts:ExternalId': 'x'}}}, True),
    ({'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'sts:AssumeRole',
      'Condition': {'StringEqualsIfExists': {'aws:PrincipalOrgID': 'o-1'}}}, True),
    ({'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'sts:AssumeRole',
      'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-1'}}}, False),
    ({'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'sts:AssumeRole',
      'Condition': {'StringEquals': {'aws:PrincipalAccount': '111122223333'}}}, False),
    ({'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::111122223333:root'}, 'Action': 'sts:AssumeRole'}, False),
    ({'Effect': 'Deny', 'Principal': {'AWS': '*'}, 'Action': 'sts:AssumeRole'}, False),
    ({'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'sts:TagSession'}, False),
])
def test_trust_any_principal(stmt, public):
    assert bool(H.trustAllowsAnyPrincipal({'Statement': [stmt]})) is public


@pytest.mark.parametrize('stmt,broad', [
    ({'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': '*'}, True),
    ({'Effect': 'Allow', 'Action': 'secretsmanager:*', 'Resource': '*'}, True),
    ({'Effect': 'Allow', 'Action': 'ssm:GetParameter*', 'Resource': 'arn:aws:ssm:us-east-1:1:parameter/*'}, True),
    ({'Effect': 'Allow', 'Action': 'ssm:GetParameters', 'Resource': 'arn:aws:ssm:*:*:*'}, True),
    ({'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': '*'}, True),
    ({'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'NotResource': 'arn:aws:secretsmanager:*:*:secret:prod/*'}, True),
    ({'Effect': 'Allow', 'Action': '*', 'Resource': '*'}, False),
    ({'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': 'arn:aws:secretsmanager:us-east-1:1:secret:app/*'}, False),
    ({'Effect': 'Allow', 'Action': 'ssm:GetParameter', 'Resource': 'arn:aws:ssm:us-east-1:1:parameter/app/*'}, False),
    ({'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': '*',
      'Condition': {'StringEquals': {'aws:ResourceTag/team': 'blue'}}}, False),
    ({'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': '*',
      'Condition': {'StringEqualsIfExists': {'aws:ResourceTag/team': 'blue'}}}, True),
    ({'Effect': 'Allow', 'Action': 'secretsmanager:ListSecrets', 'Resource': '*'}, False),
    ({'Effect': 'Allow', 'Action': 'secretsmanager:DescribeSecret', 'Resource': '*'}, False),
    ({'Effect': 'Deny', 'Action': 'secretsmanager:GetSecretValue', 'Resource': '*'}, False),
])
def test_broad_secret_read(stmt, broad):
    assert bool(H.broadSecretReadActions({'Statement': [stmt]})) is broad

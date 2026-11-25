"""
Stubber-based flag -> fix tests for WAFS2027 IAM identity checks (chunk 2)
that the AWS Emulator cannot drive:

- iamUserTwoActiveKeys: reads the IAM credential report, which the emulator
  (like IAM) caches - users/keys created during a test never appear in it.
- rootVirtualMfaOnly: a virtual MFA device cannot be assigned to the root
  user through the IAM API, so the emulator never reports AccountMFAEnabled=1
  with a root device.
- healthOrgViewDisabled: health.describe_health_service_status_for_organization
  is not implemented by the emulator.
- auditManagerNoActiveAssessment: auditmanager.get_account_status is not
  implemented by the emulator.
- rolesAnywhereTrustAnchorCertExpiring (AWS_ACM_PCA source): the emulator
  cannot issue/activate a private CA with a chosen validity period. (The
  CERTIFICATE_BUNDLE and CRL paths are tested against the emulator.)

Real boto3 clients are wrapped by an activated botocore Stubber (real API
shapes, fake credentials, unroutable endpoint), so no network call is made and
any unexpected call fails the test. Pure helper tests are included too.
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
from services.iam.drivers import IamX509  # noqa: E402

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


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(daysAgo):
    return (_now() - datetime.timedelta(days=daysAgo)).strftime('%Y-%m-%dT%H:%M:%S+00:00')


# --------------------------------------------------------------------------- #
# iamUserTwoActiveKeys
# --------------------------------------------------------------------------- #
def _reportRow(user, k1, k2):
    vals = [user, f'arn:aws:iam::{ACCOUNT}:user/{user}', _iso(400), 'false', 'N/A', 'N/A', 'N/A', 'false',
            k1, _iso(20), _iso(1), 'us-east-1', 'sts', k2, _iso(10), _iso(1), 'us-east-1', 'sts',
            'false', 'N/A', 'false', 'N/A']
    iam, stub = _client('iam')
    stub.add_response('get_credential_report', {
        'Content': (FIELDS + '\n' + ','.join(vals)).encode(), 'ReportFormat': 'text/csv', 'GeneratedTime': _now()})
    rows = iam.get_credential_report()['Content'].decode('UTF-8').split('\n')
    stub.assert_no_pending_responses()
    fields = rows[0].split(',')
    return dict(zip(fields, rows[1].split(','))), iam


def _twoKeys(user, k1, k2):
    row, iam = _reportRow(user, k1, k2)
    u = IamUser(row, iam)
    u._checkIamUserTwoActiveKeys()
    return u.results


class TestTwoActiveKeys:
    K = 'iamUserTwoActiveKeys'

    def test_flag_fix(self):
        assert _twoKeys('alice', 'true', 'true')[self.K][0] == -1
        # fix: deactivate the old key
        assert _twoKeys('alice', 'false', 'true')[self.K][0] == 1

    def test_no_keys_no_result(self):
        assert self.K not in _twoKeys('alice', 'false', 'false')

    def test_root_skipped(self):
        assert self.K not in _twoKeys('<root_account>', 'true', 'true')


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
    clients, stubs = {}, {}
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
    return acc, stubs


# --------------------------------------------------------------------------- #
# rootVirtualMfaOnly
# --------------------------------------------------------------------------- #
def _vmfa(serial, userArn, userName):
    # (IAM returns the account ID as UserId for root; the service model's
    # 16-char minimum makes Stubber reject that, so a padded ID is used.)
    return {'SerialNumber': serial, 'User': {'Path': '/', 'UserName': userName, 'UserId': 'AIDA' + ACCOUNT,
                                             'Arn': userArn, 'CreateDate': _now()}}


ROOT_DEV = _vmfa(f'arn:aws:iam::{ACCOUNT}:mfa/my-root-phone', f'arn:aws:iam::{ACCOUNT}:root', 'root')
LEGACY_ROOT_DEV = {'SerialNumber': f'arn:aws:iam::{ACCOUNT}:mfa/root-account-mfa-device'}
USER_DEV = _vmfa(f'arn:aws:iam::{ACCOUNT}:mfa/alice', f'arn:aws:iam::{ACCOUNT}:user/alice', 'alice')


class TestRootVirtualMfa:
    K = 'rootVirtualMfaOnly'

    def _run(self, mfaEnabled, devices=None, listError=None):
        acc, stubs = _account()
        st = stubs['iamClient']
        st.add_response('get_account_summary', {'SummaryMap': {'AccountMFAEnabled': mfaEnabled, 'Users': 3}})
        if listError:
            st.add_client_error('list_virtual_mfa_devices', listError)
        elif devices is not None:
            st.add_response('list_virtual_mfa_devices', {'VirtualMFADevices': devices, 'IsTruncated': False},
                            {'AssignmentStatus': 'Assigned'})
        acc._checkRootVirtualMfaOnly()
        st.assert_no_pending_responses()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        assert self._run(1, [ROOT_DEV, USER_DEV])[0] == -1
        # fix: root virtual device replaced by a FIDO2 key (not listed as virtual)
        assert self._run(1, [USER_DEV])[0] == 1

    def test_legacy_serial_flagged(self, cfg):
        assert self._run(1, [LEGACY_ROOT_DEV])[0] == -1

    def test_no_root_mfa_is_info(self, cfg):
        assert self._run(0)[0] == 0

    def test_access_denied(self, cfg):
        r = self._run(1, listError='AccessDenied')
        assert r[0] == 0 and 'AccessDenied' in r[1]


# --------------------------------------------------------------------------- #
# healthOrgViewDisabled
# --------------------------------------------------------------------------- #
class TestHealthOrgView:
    K = 'healthOrgViewDisabled'

    def _run(self, orgMaster=ACCOUNT, status=None, error=None, expectCall=True):
        h, stub = _client('health')
        if expectCall:
            if error:
                stub.add_client_error('describe_health_service_status_for_organization', error)
            else:
                stub.add_response('describe_health_service_status_for_organization',
                                  {'healthServiceAccessStatusForOrganization': status})
        acc, _ = _account(orgMaster=orgMaster, health=h)
        acc._checkHealthOrgViewDisabled()
        stub.assert_no_pending_responses()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        assert self._run(status='DISABLED')[0] == -1
        assert self._run(status='ENABLED')[0] == 1

    def test_subscription_required(self, cfg):
        r = self._run(error='SubscriptionRequiredException')
        assert r[0] == 0 and 'SubscriptionRequiredException' in r[1]

    def test_member_account(self, cfg):
        assert self._run(orgMaster='999988887777', error='AccessDeniedException') == \
            [0, 'Not evaluable from member account']
        # a member cannot be a Health delegated admin unless the view is enabled
        assert self._run(orgMaster='999988887777', status='DISABLED') == [0, 'Not evaluable from member account']
        assert self._run(orgMaster='999988887777', status='ENABLED')[0] == 1

    def test_no_organization(self, cfg):
        assert self._run(orgMaster=None, expectCall=False)[0] == 0


# --------------------------------------------------------------------------- #
# auditManagerNoActiveAssessment
# --------------------------------------------------------------------------- #
class TestAuditManager:
    K = 'auditManagerNoActiveAssessment'

    def _run(self, status=None, assessments=None, error=None):
        am, stub = _client('auditmanager')
        if error:
            stub.add_client_error('get_account_status', error)
        else:
            stub.add_response('get_account_status', {'status': status})
            if assessments is not None:
                stub.add_response('list_assessments', {'assessmentMetadata': assessments}, {'status': 'ACTIVE'})
        acc, _ = _account()
        acc._regionalClient = lambda svc, region: am if svc == 'auditmanager' else pytest.fail(svc)
        acc._checkAuditManagerNoActiveAssessment()
        stub.assert_no_pending_responses()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        assert self._run('ACTIVE', [])[0] == -1
        assert self._run('ACTIVE', [{'name': 'soc2', 'id': '11111111-1111-1111-1111-111111111111',
                                     'status': 'ACTIVE'}])[0] == 1

    def test_not_enabled_is_info(self, cfg):
        assert self._run('INACTIVE')[0] == 0

    def test_error_not_evaluable(self, cfg):
        r = self._run(error='AccessDeniedException')
        assert r[0] == 0 and 'AccessDeniedException' in r[1]


# --------------------------------------------------------------------------- #
# rolesAnywhereTrustAnchorCertExpiring (ACM PCA source)
# --------------------------------------------------------------------------- #
PCA_ARN = f'arn:aws:acm-pca:us-east-1:{ACCOUNT}:certificate-authority/11111111-2222-3333-4444-555555555555'


class TestRolesAnywherePca:
    K = 'rolesAnywhereTrustAnchorCertExpiring'

    def _run(self, ca=None, caError=None, enabled=True):
        ra, rstub = _client('rolesanywhere')
        pca, pstub = _client('acm-pca')
        rstub.add_response('list_trust_anchors', {'trustAnchors': [{
            'trustAnchorId': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'name': 'pca-anchor', 'enabled': enabled,
            'trustAnchorArn': f'arn:aws:rolesanywhere:us-east-1:{ACCOUNT}:trust-anchor/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'source': {'sourceType': 'AWS_ACM_PCA', 'sourceData': {'acmPcaArn': PCA_ARN}}}]})
        rstub.add_response('list_crls', {'crls': []})
        if enabled:
            if caError:
                pstub.add_client_error('describe_certificate_authority', caError)
            else:
                pstub.add_response('describe_certificate_authority', {'CertificateAuthority': ca},
                                   {'CertificateAuthorityArn': PCA_ARN})
        acc, _ = _account()
        acc._regionalClient = lambda svc, region: {'rolesanywhere': ra, 'acm-pca': pca}[svc]
        acc._checkRolesAnywhereTrustAnchorCertExpiring()
        rstub.assert_no_pending_responses()
        pstub.assert_no_pending_responses()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        bad = self._run({'Arn': PCA_ARN, 'Status': 'ACTIVE', 'NotAfter': _now() + datetime.timedelta(days=10)})
        assert bad[0] == -1 and 'expires in' in bad[1]
        good = self._run({'Arn': PCA_ARN, 'Status': 'ACTIVE', 'NotAfter': _now() + datetime.timedelta(days=400)})
        assert good[0] == 1

    def test_expired_ca(self, cfg):
        assert self._run({'Arn': PCA_ARN, 'Status': 'EXPIRED',
                          'NotAfter': _now() - datetime.timedelta(days=1)})[0] == -1

    def test_cross_account_pca_not_evaluable(self, cfg):
        assert self._run(caError='AccessDeniedException')[0] == 0

    def test_disabled_anchor_not_flagged(self, cfg):
        assert self._run(enabled=False)[0] == 1


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize('value,expect', [
    ('prod', 'prod'), ('Production', 'prod'), ('prd-eu', 'prod'), ('live', 'prod'),
    ('dev', 'nonprod'), ('staging', 'nonprod'), ('non-prod', 'nonprod'), ('preprod', 'nonprod'),
    ('pre prod', 'nonprod'), ('nonprod', 'nonprod'), ('prod-test', 'nonprod'),
    ('shared', None), ('product', None), ('reproduce', None), ('', None),
])
def test_classify_environment_value(value, expect):
    assert IamAccount.classifyEnvironmentValue(value) == expect


def _stmt(**kw):
    return {'Version': '2012-10-17', 'Statement': [dict({'Effect': 'Allow'}, **kw)]}


@pytest.mark.parametrize('doc,expect', [
    (_stmt(Action='iam:AttachRolePolicy', Resource='*'), ['iam:AttachRolePolicy']),
    (_stmt(Action='iam:PassRole', Resource='arn:aws:iam::111122223333:role/*'), ['iam:PassRole']),
    (_stmt(Action='iam:PassRole', Resource='arn:aws:iam::111122223333:role/app-*'), []),
    (_stmt(Action='iam:PassRole', Resource='*',
           Condition={'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}}), []),
    (_stmt(Action='iam:CreatePolicyVersion', Resource='arn:aws:iam::111122223333:role/*'), []),
    (_stmt(NotAction='s3:*', Resource='*'), sorted(H.ESCALATION_ACTIONS)),
    (_stmt(Action='iam:Get*', Resource='*'), []),
    ({'Statement': [{'Effect': 'Allow', 'Action': 'iam:*', 'Resource': '*'},
                    {'Effect': 'Deny', 'Action': 'iam:*', 'Resource': '*'}]}, []),
])
def test_escalation_actions(doc, expect):
    assert H.escalationActions([doc]) == expect


def test_workload_services_trusted():
    trust = {'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                            'Principal': {'Service': ['lambda.amazonaws.com', 'events.amazonaws.com']}}]}
    assert H.workloadServicesTrusted(trust) == ['lambda.amazonaws.com']
    assert H.workloadServicesTrusted({'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                                     'Principal': {'AWS': 'arn:aws:iam::1:root'}}]}) == []
    assert H.workloadServicesTrusted({'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                                     'Principal': {'Service': 'ec2.amazonaws.com.cn'}}]}) == \
        ['ec2.amazonaws.com.cn']


def test_x509_rejects_garbage():
    assert IamX509.pemCertificates('') == []
    res = IamX509.pemCertificates('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----')
    assert len(res) == 1 and res[0][2]

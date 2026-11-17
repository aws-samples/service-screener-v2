"""
Stubber-based flag -> fix tests for WAFS2027 IAM identity checks (chunk 4).

- sirMembershipMissing / sirTeamTooSmall: the AWS Emulator does not implement
  security-ir ListMemberships (NOT_IMPLEMENTED) and GetMembership only returns
  validation errors, so an (in)active membership or its incident response team
  cannot be produced there. Organizations delegated-administrator and
  management/member account contexts are also multi-account.
- thirdPartyRoleUnused is reported by the existing iam.unusedRole check (no
  new key). The emulator stamps CreateDate/RoleLastUsed with the current time,
  so an aged, unused cross-account (third-party) role cannot be produced
  there; the IamRole driver is fed role details directly instead.

Real boto3 clients are wrapped by an activated botocore Stubber (real API
shapes, fake credentials, unroutable endpoint), so no network call is made and
any unexpected call fails the test.
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
from services.iam.drivers.IamAccount import IamAccount  # noqa: E402
from services.iam.drivers.IamRole import IamRole  # noqa: E402

ACCOUNT = '111122223333'
OTHER = '444455556666'
MID = 'm-abcdefghij12'


def _client(service, region='us-east-1'):
    c = boto3.session.Session().client(service, region_name=region, aws_access_key_id='testing',
                                       aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')
    stub = Stubber(c)
    stub.activate()
    return c, stub


@pytest.fixture
def cfg():
    saved = {k: Config.get(k, None) for k in ('stsInfo', 'REGIONS_SELECTED')}
    Config.set('stsInfo', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/x'})
    Config.set('REGIONS_SELECTED', ['us-east-1'])
    yield
    for k, v in saved.items():
        Config.set(k, v)


class _Regional:
    def __init__(self):
        self.clients = {}

    def get(self, service, region='us-east-1'):
        if (service, region) not in self.clients:
            self.clients[(service, region)] = _client(service, region)
        return self.clients[(service, region)]

    def __call__(self, service, region):
        return self.get(service, region)[0]

    def stub(self, service, region='us-east-1'):
        return self.get(service, region)[1]

    def assertDone(self):
        for _, s in self.clients.values():
            s.assert_no_pending_responses()


def _account(orgMaster=ACCOUNT):
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
    acc = IamAccount(None, clients, [], [], None, {'roles': [], 'users': [], 'groups': [], 'policies': []}, {})
    reg = _Regional()
    acc._regionalClient = reg
    return acc, stubs, reg


def _membership(status='Active', mid=MID):
    return {'membershipId': mid, 'accountId': ACCOUNT, 'region': 'us-east-1',
            'membershipArn': f'arn:aws:security-ir:us-east-1:{ACCOUNT}:membership/{mid}',
            'membershipStatus': status}


def _delegated(stubs, ids=None, error=None):
    st = stubs['orgClient']
    if error:
        st.add_client_error('list_delegated_administrators', error)
    else:
        st.add_response('list_delegated_administrators', {'DelegatedAdministrators': [
            {'Id': i, 'Arn': f'arn:aws:organizations::{ACCOUNT}:account/o-abcdefghij/{i}'} for i in ids]},
            {'ServicePrincipal': 'security-ir.amazonaws.com'})


# --------------------------------------------------------------------------- #
# sirMembershipMissing
# --------------------------------------------------------------------------- #
class TestSirMembershipMissing:
    K = 'sirMembershipMissing'

    def _run(self, items=None, error=None, orgMaster=None, admins=None, adminError=None):
        acc, stubs, reg = _account(orgMaster=orgMaster)
        st = reg.stub('security-ir')
        if error:
            st.add_client_error('list_memberships', error)
        else:
            st.add_response('list_memberships', {'items': items or []}, {})
        if admins is not None or adminError:
            _delegated(stubs, admins, adminError)
        acc._checkSirMembershipMissing()
        reg.assertDone()
        stubs['orgClient'].assert_no_pending_responses()
        return acc.results[self.K]

    def test_standalone_flag_fix(self, cfg):
        assert self._run(items=[])[0] == -1
        assert self._run(items=[_membership()])[0] == 1

    def test_not_active_exception_is_no_membership(self, cfg):
        assert self._run(error='SecurityIncidentResponseNotActiveException')[0] == -1

    def test_cancelled_only_flags(self, cfg):
        r = self._run(items=[_membership('Cancelled')])
        assert r[0] == -1 and 'Cancelled' in r[1]

    def test_management_flag_fix(self, cfg):
        assert self._run(items=[], orgMaster=ACCOUNT, admins=[])[0] == -1
        assert self._run(items=[_membership()], orgMaster=ACCOUNT)[0] == 1

    def test_management_with_other_delegated_admin_info(self, cfg):
        r = self._run(items=[], orgMaster=ACCOUNT, admins=[OTHER])
        assert r[0] == 0 and OTHER in r[1]

    def test_member_account_not_evaluable(self, cfg):
        r = self._run(items=[], orgMaster=OTHER, adminError='AccessDeniedException')
        assert r == [0, 'Not evaluable from member account']

    def test_delegated_admin_member_flags(self, cfg):
        assert self._run(items=[], orgMaster=OTHER, admins=[ACCOUNT])[0] == -1

    def test_access_denied_unable(self, cfg):
        r = self._run(error='AccessDeniedException')
        assert r[0] == 0 and 'Unable to evaluate' in r[1]


# --------------------------------------------------------------------------- #
# sirTeamTooSmall
# --------------------------------------------------------------------------- #
class TestSirTeamTooSmall:
    K = 'sirTeamTooSmall'

    def _run(self, team=None, items=None, getError=None):
        acc, _, reg = _account(orgMaster=None)
        st = reg.stub('security-ir')
        st.add_response('list_memberships', {'items': [_membership()] if items is None else items}, {})
        if team is not None or getError:
            if getError:
                st.add_client_error('get_membership', getError)
            else:
                st.add_response('get_membership', {
                    'membershipId': MID, 'accountId': ACCOUNT, 'region': 'us-east-1',
                    'membershipName': 'ir-team', 'membershipStatus': 'Active',
                    'incidentResponseTeam': [{'name': n, 'jobTitle': 'SecOps', 'email': e} for n, e in team]},
                    {'membershipId': MID})
        acc._checkSirTeamTooSmall()
        reg.assertDone()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        # Two entries sharing one mailbox = one distinct contact.
        shared = [('Alice', 'secops@example.com'), ('Bob', 'SecOps@example.com ')]
        assert self._run(team=shared)[0] == -1
        distinct = [('Alice', 'alice@example.com'), ('Bob', 'bob@example.com')]
        assert self._run(team=distinct)[0] == 1

    def test_three_entries_two_mailboxes_passes(self, cfg):
        team = [('Ann', 'a@example.com'), ('Ben', 'a@example.com'), ('Cat', 'c@example.com')]
        assert self._run(team=team)[0] == 1

    def test_no_active_membership_info(self, cfg):
        r = self._run(items=[_membership('Terminated')])
        assert r[0] == 0

    def test_get_membership_denied_unable(self, cfg):
        r = self._run(getError='AccessDeniedException')
        assert r[0] == 0 and 'Unable to evaluate' in r[1]


# --------------------------------------------------------------------------- #
# thirdPartyRoleUnused -> covered by existing iam.unusedRole
# --------------------------------------------------------------------------- #
class TestThirdPartyRoleUnusedCoveredByUnusedRole:
    TRUST = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{OTHER}:root'},
        'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {'sts:ExternalId': 'vendor-123'}}}]}

    def _run(self, lastUsedDaysAgo):
        now = datetime.datetime.now(datetime.timezone.utc)
        role = {'RoleName': 'VendorMonitoringRole', 'Path': '/', 'Arn': f'arn:aws:iam::{ACCOUNT}:role/VendorMonitoringRole',
                'CreateDate': now - datetime.timedelta(days=400), 'AssumeRolePolicyDocument': self.TRUST,
                'RoleLastUsed': {'LastUsedDate': now - datetime.timedelta(days=lastUsedDaysAgo), 'Region': 'us-east-1'}
                if lastUsedDaysAgo is not None else {}}
        iam, stub = _client('iam')
        r = IamRole(role, iam)
        r._checkRoleOldAge()
        stub.assert_no_pending_responses()
        return r.results.get('unusedRole')

    def test_flag_fix(self):
        assert self._run(None)[0] == -1     # third-party role never assumed
        assert self._run(120)[0] == -1      # last assumed 120 days ago
        assert self._run(2) is None         # recently used -> not flagged

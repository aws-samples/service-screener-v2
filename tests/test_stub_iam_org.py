"""
Flag -> fix -> re-run tests for the IAM AWS Organizations checks, using
botocore Stubber around real boto3 clients (real API shapes are validated).

Why Stubber and not the AWS Emulator: the emulator implements a single
account and does not implement organizations.list_policies /
describe_policy / list_targets_for_policy / list_accounts /
list_accounts_for_parent / enable_policy_type, and IAM
list_organizations_features always returns OrganizationNotFoundException. It
also cannot model a consolidated-billing org, a member/delegated-admin caller,
or alternate contacts of other accounts. The parts the emulator can drive are
in tests/emulator/test_emu_iam_org.py.

No network is used: clients carry fake credentials and every call is served by
a Stubber (an unexpected call fails the test).
"""
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.iam.drivers.IamAccount import IamAccount  # noqa: E402
from services.iam.drivers.IamOrgData import scpGuardrails, denyCoversAction  # noqa: E402

MGMT = '111111111111'
MEMBER = '222222222222'
MEMBER2 = '333333333333'
ORG_ID = 'o-abcdefghij'
ROOT_ID = 'r-ab12'
OU_ID = 'ou-ab12-11111111'


def _session():
    return boto3.session.Session(aws_access_key_id='AKIDSTUBONLY', aws_secret_access_key='stub',
                                 region_name='us-east-1')


def _org(featureSet='ALL', mgmt=MGMT):
    return {'Organization': {
        'Id': ORG_ID, 'Arn': f'arn:aws:organizations::{mgmt}:organization/{ORG_ID}',
        'FeatureSet': featureSet, 'MasterAccountArn': f'arn:aws:organizations::{mgmt}:account/{ORG_ID}/{mgmt}',
        'MasterAccountId': mgmt, 'MasterAccountEmail': 'mgmt@example.com',
        'AvailablePolicyTypes': [{'Type': 'SERVICE_CONTROL_POLICY', 'Status': 'ENABLED'}]}}


def _roots(types=('SERVICE_CONTROL_POLICY',)):
    return {'Roots': [{'Id': ROOT_ID, 'Arn': f'arn:aws:organizations::{MGMT}:root/{ORG_ID}/{ROOT_ID}', 'Name': 'Root',
                       'PolicyTypes': [{'Type': t, 'Status': 'ENABLED'} for t in types]}]}


def _doc(*stmts):
    return json.dumps({'Version': '2012-10-17', 'Statement': list(stmts)})


class _FakeSession:
    """Stands in for ssBoto: returns pre-stubbed regional clients."""
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, config=None):
        return self.clients[name]


class Harness:
    def __init__(self, orgResp=None, orgErr=None, caller=MGMT, regionalClients=None):
        Config.init()
        Config.set('stsInfo', {'Account': caller})
        Config.set('REGIONS_SELECTED', ['us-east-1'])
        s = _session()
        self.clients = {
            'iamClient': s.client('iam'), 'orgClient': s.client('organizations'),
            'accClient': s.client('account'), 'sppClient': s.client('support'),
            'budgetClient': s.client('budgets'), 'curClient': s.client('cur'),
            'ctClient': s.client('cloudtrail'), 'backupClient': s.client('backup'),
        }
        self.org = Stubber(self.clients['orgClient'])
        self.iam = Stubber(self.clients['iamClient'])
        self.acc = Stubber(self.clients['accClient'])
        for st in (self.org, self.iam, self.acc):
            st.activate()
        if orgErr:
            self.org.add_client_error('describe_organization', service_error_code=orgErr, http_status_code=400)
        else:
            self.org.add_response('describe_organization', orgResp or _org())
        self.drv = IamAccount(None, self.clients, [], [], _FakeSession(regionalClients or {}))

    def policies(self, policyType, items):
        """items: [(id, name, awsManaged, contentJson|None, [targets])]"""
        self.org.add_response('list_policies', {'Policies': [
            {'Id': pid, 'Arn': f'arn:aws:organizations::{MGMT}:policy/{ORG_ID}/{policyType.lower()}/{pid}',
             'Name': name, 'Type': policyType, 'AwsManaged': managed} for pid, name, managed, _, _ in items]},
            {'Filter': policyType})
        for pid, name, managed, content, targets in items:
            self.org.add_response('list_targets_for_policy', {'Targets': [
                {'TargetId': tid, 'Arn': f'arn:aws:organizations::{MGMT}:x/{tid}', 'Name': tname, 'Type': ttype}
                for tid, tname, ttype in targets]}, {'PolicyId': pid})
            if not managed:
                self.org.add_response('describe_policy', {'Policy': {
                    'PolicySummary': {'Id': pid, 'Name': name, 'Type': policyType, 'AwsManaged': False},
                    'Content': content}}, {'PolicyId': pid})

    def run(self, method, key):
        getattr(self.drv, '_check' + method)()
        self.org.assert_no_pending_responses()
        self.iam.assert_no_pending_responses()
        self.acc.assert_no_pending_responses()
        return self.drv.results[key]


def stubTree(h, children):
    """Stub the depth-first walk of OrgData.tree().
    children: {parentId: ([(ouId, name)], [(accountId, name, state)])}."""
    stack = [ROOT_ID]
    while stack:
        parent = stack.pop()
        ous, accs = children.get(parent, ([], []))
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': [
            {'Id': oid, 'Arn': f'arn:aws:organizations::{MGMT}:ou/{ORG_ID}/{oid}', 'Name': name} for oid, name in ous]},
            {'ParentId': parent})
        h.org.add_response('list_accounts_for_parent', {'Accounts': [
            {'Id': aid, 'Name': name, 'State': state} for aid, name, state in accs]}, {'ParentId': parent})
        stack.extend(oid for oid, _ in ous)


# Root -> management account + OU Workloads -> member account "app".
DEFAULT_TREE = {ROOT_ID: ([(OU_ID, 'Workloads')], [(MGMT, 'mgmt', 'ACTIVE')]),
                OU_ID: ([], [(MEMBER, 'app', 'ACTIVE')])}


FULL = ('p-FullAWSAccess', 'FullAWSAccess', True, None, [(ROOT_ID, 'Root', 'ROOT')])
RCP_FULL = ('p-RCPFullAWSAccess', 'RCPFullAWSAccess', True, None, [(ROOT_ID, 'Root', 'ROOT')])
OU_T = (OU_ID, 'Workloads', 'ORGANIZATIONAL_UNIT')
ROOT_T = (ROOT_ID, 'Root', 'ROOT')

DENY_ROOT = {'Effect': 'Deny', 'Action': '*', 'Resource': '*',
             'Condition': {'ArnLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'}}}
DENY_REGION = {'Effect': 'Deny', 'NotAction': ['iam:*', 'sts:*'], 'Resource': '*',
               'Condition': {'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']}}}
DENY_PRIVESC = {'Effect': 'Deny', 'Action': ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion'], 'Resource': '*'}


# --------------------------------------------------------------------------- #
class TestOrgNotAllFeatures:
    def test_flag_fix(self):
        h = Harness(_org('CONSOLIDATED_BILLING'))
        assert h.run('OrgNotAllFeatures', 'orgNotAllFeatures')[0] == -1
        h = Harness(_org('ALL'))
        assert h.run('OrgNotAllFeatures', 'orgNotAllFeatures')[0] == 1

    def test_not_in_org(self):
        h = Harness(orgErr='AWSOrganizationsNotInUseException')
        assert h.run('OrgNotAllFeatures', 'orgNotAllFeatures')[0] == 0


class TestMgmtAccountHostsWorkloads:
    def _regional(self, instances=0, functions=()):
        s = _session()
        c = {n: s.client(n) for n in ('ec2', 'lambda', 'rds', 'eks')}
        st = {n: Stubber(cl) for n, cl in c.items()}
        st['ec2'].add_response('describe_instances', {'Reservations': [
            {'ReservationId': 'r-1', 'Instances': [{'InstanceId': f'i-{n:017x}'} for n in range(instances)]}] if instances else []})
        st['lambda'].add_response('list_functions', {'Functions': [{'FunctionName': f} for f in functions]})
        st['rds'].add_response('describe_db_instances', {'DBInstances': []})
        st['eks'].add_response('list_clusters', {'clusters': []})
        for x in st.values():
            x.activate()
        return c

    def test_flag_fix(self):
        h = Harness(regionalClients=self._regional(instances=2))
        r = h.run('OrgMgmtAccountHostsWorkloads', 'orgMgmtAccountHostsWorkloads')
        assert r[0] == -1 and 'EC2 instances: 2' in r[1]
        h = Harness(regionalClients=self._regional(functions=['aws-controltower-NotificationForwarder']))
        assert h.run('OrgMgmtAccountHostsWorkloads', 'orgMgmtAccountHostsWorkloads')[0] == 1

    def test_member_account_passes_without_calls(self):
        h = Harness(caller=MEMBER)
        assert h.run('OrgMgmtAccountHostsWorkloads', 'orgMgmtAccountHostsWorkloads')[0] == 1


class TestSCPEnabled:
    def test_flag_fix(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-unattach1', 'Unattached', False, _doc(DENY_ROOT), [])])
        assert h.run('SCPEnabled', 'SCPEnabled')[0] == -1

        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-guard0001', 'Guard', False, _doc(DENY_ROOT), [OU_T])])
        assert h.run('SCPEnabled', 'SCPEnabled')[0] == 1

    def test_policy_type_disabled(self):
        h = Harness()
        h.org.add_response('list_roots', _roots(types=()))
        assert h.run('SCPEnabled', 'SCPEnabled')[0] == -1

    def test_member_account_not_evaluable(self):
        h = Harness(caller=MEMBER)
        h.org.add_client_error('list_roots', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run('SCPEnabled', 'SCPEnabled') == [0, 'Not evaluable from member account']

    def test_consolidated_billing_defers(self):
        h = Harness(_org('CONSOLIDATED_BILLING'))
        assert h.run('SCPEnabled', 'SCPEnabled')[0] == 0


class TestScpBestPractices:
    def _tree(self, h):
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': [
            {'Id': OU_ID, 'Arn': f'arn:aws:organizations::{MGMT}:ou/{ORG_ID}/{OU_ID}', 'Name': 'Workloads'}]},
            {'ParentId': ROOT_ID})
        h.org.add_response('list_accounts_for_parent', {'Accounts': [
            {'Id': MGMT, 'Name': 'mgmt', 'State': 'ACTIVE'}]}, {'ParentId': ROOT_ID})
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': []}, {'ParentId': OU_ID})
        h.org.add_response('list_accounts_for_parent', {'Accounts': [
            {'Id': MEMBER, 'Name': 'app', 'State': 'ACTIVE'}]}, {'ParentId': OU_ID})

    def test_flag_fix_effective_set(self):
        # FLAG: root has root-denial only; OU/account inherit it but lack region + priv-esc.
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-denyroot1', 'DenyRoot', False, _doc(DENY_ROOT), [ROOT_T])])
        self._tree(h)
        r = h.run('ScpBestPractices', 'scpBestPractices')
        assert r[0] == -1 and 'Account app (222222222222)' in r[1] and MGMT not in r[1]

        # FIX: a second SCP on the OU adds region + priv-esc. Each SCP alone is
        # incomplete (the old per-document check flagged both); the effective
        # set of the OU and its account is complete.
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [
            FULL, ('p-denyroot1', 'DenyRoot', False, _doc(DENY_ROOT), [ROOT_T]),
            ('p-workload1', 'WorkloadGuards', False, _doc(DENY_REGION, DENY_PRIVESC), [OU_T])])
        self._tree(h)
        r = h.run('ScpBestPractices', 'scpBestPractices')
        assert r[0] == 1, r

    def test_no_customer_scp_defers_to_scpenabled(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL])
        assert h.run('ScpBestPractices', 'scpBestPractices')[0] == 0

    def test_member_account_not_evaluable(self):
        h = Harness(caller=MEMBER)
        h.org.add_client_error('list_roots', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run('ScpBestPractices', 'scpBestPractices') == [0, 'Not evaluable from member account']


class TestOuStructureFlat:
    def _ous(self, h, ous):
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': [
            {'Id': OU_ID, 'Arn': f'arn:aws:organizations::{MGMT}:ou/{ORG_ID}/{OU_ID}', 'Name': 'Workloads'}] if ous else []},
            {'ParentId': ROOT_ID})

    def test_flag_fix_direct_member(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        self._ous(h, True)
        h.org.add_response('list_accounts_for_parent', {'Accounts': [
            {'Id': MGMT, 'Name': 'mgmt'}, {'Id': MEMBER, 'Name': 'app'}]}, {'ParentId': ROOT_ID})
        assert h.run('OrgOuStructureFlat', 'orgOuStructureFlat')[0] == -1

        h = Harness()
        h.org.add_response('list_roots', _roots())
        self._ous(h, True)
        h.org.add_response('list_accounts_for_parent', {'Accounts': [{'Id': MGMT, 'Name': 'mgmt'}]}, {'ParentId': ROOT_ID})
        assert h.run('OrgOuStructureFlat', 'orgOuStructureFlat')[0] == 1

    def test_no_ous(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        self._ous(h, False)
        assert h.run('OrgOuStructureFlat', 'orgOuStructureFlat')[0] == -1


class TestMemberAlternateContacts:
    def _accounts(self, h):
        h.org.add_response('list_accounts', {'Accounts': [
            {'Id': MGMT, 'Name': 'mgmt', 'State': 'ACTIVE'},
            {'Id': MEMBER, 'Name': 'app', 'State': 'ACTIVE'},
            {'Id': MEMBER2, 'Name': 'closed', 'State': 'SUSPENDED'}]})

    def _contact(self, h, typ):
        h.acc.add_response('get_alternate_contact', {'AlternateContact': {
            'AlternateContactType': typ, 'EmailAddress': 'sec@example.com', 'Name': 'n', 'PhoneNumber': '+10000000000',
            'Title': 't'}}, {'AccountId': MEMBER, 'AlternateContactType': typ})

    def test_flag_fix(self):
        h = Harness()
        self._accounts(h)
        h.acc.add_client_error('get_alternate_contact', service_error_code='ResourceNotFoundException',
                               http_status_code=404, expected_params={'AccountId': MEMBER, 'AlternateContactType': 'SECURITY'})
        self._contact(h, 'BILLING')
        self._contact(h, 'OPERATIONS')
        r = h.run('OrgMemberAlternateContactsMissing', 'orgMemberAlternateContactsMissing')
        assert r[0] == -1 and 'missing SECURITY' in r[1]

        h = Harness()
        self._accounts(h)
        for t in ('SECURITY', 'BILLING', 'OPERATIONS'):
            self._contact(h, t)
        assert h.run('OrgMemberAlternateContactsMissing', 'orgMemberAlternateContactsMissing')[0] == 1

    def test_trusted_access_disabled_is_unable(self):
        h = Harness()
        self._accounts(h)
        for _ in range(3):
            h.acc.add_client_error('get_alternate_contact', service_error_code='AccessDeniedException', http_status_code=403)
        r = h.run('OrgMemberAlternateContactsMissing', 'orgMemberAlternateContactsMissing')
        assert r == [0, 'Unable to evaluate (AccessDeniedException)']

    def test_member_account_not_evaluable(self):
        h = Harness(caller=MEMBER)
        h.org.add_client_error('list_accounts', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run('OrgMemberAlternateContactsMissing', 'orgMemberAlternateContactsMissing') == \
            [0, 'Not evaluable from member account']


class TestResourceControlPolicies:
    PERIMETER = {'Effect': 'Deny', 'Principal': '*', 'Action': ['s3:*', 'kms:*'], 'Resource': '*',
                 'Condition': {'StringNotEqualsIfExists': {'aws:PrincipalOrgID': ORG_ID},
                               'BoolIfExists': {'aws:PrincipalIsAWSService': 'false'}}}

    def test_flag_fix(self):
        h = Harness()
        h.org.add_response('list_roots', _roots(('SERVICE_CONTROL_POLICY', 'RESOURCE_CONTROL_POLICY')))
        h.policies('RESOURCE_CONTROL_POLICY', [RCP_FULL])
        assert h.run('OrgNoResourceControlPolicies', 'orgNoResourceControlPolicies')[0] == -1

        h = Harness()
        h.org.add_response('list_roots', _roots(('SERVICE_CONTROL_POLICY', 'RESOURCE_CONTROL_POLICY')))
        h.policies('RESOURCE_CONTROL_POLICY', [RCP_FULL, ('p-perimeter', 'Perimeter', False, _doc(self.PERIMETER), [ROOT_T])])
        assert h.run('OrgNoResourceControlPolicies', 'orgNoResourceControlPolicies')[0] == 1

    def test_not_enabled(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        assert h.run('OrgNoResourceControlPolicies', 'orgNoResourceControlPolicies')[0] == -1

    def test_rcp_without_org_condition(self):
        h = Harness()
        h.org.add_response('list_roots', _roots(('RESOURCE_CONTROL_POLICY',)))
        tls = {'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*', 'Resource': '*',
               'Condition': {'Bool': {'aws:SecureTransport': 'false'}}}
        h.policies('RESOURCE_CONTROL_POLICY', [RCP_FULL, ('p-tlsonly01', 'TlsOnly', False, _doc(tls), [ROOT_T])])
        assert h.run('OrgNoResourceControlPolicies', 'orgNoResourceControlPolicies')[0] == -1


class TestTagPolicy:
    CONTENT = json.dumps({'tags': {'dataclassification': {'tag_key': {'@@assign': 'DataClassification'},
                                                          'tag_value': {'@@assign': ['public', 'confidential']}}}})

    def test_flag_fix(self):
        h = Harness()
        h.org.add_response('list_roots', _roots(('TAG_POLICY',)))
        h.policies('TAG_POLICY', [('p-tagunatt1', 'Unattached', False, self.CONTENT, [])])
        assert h.run('OrgNoTagPolicy', 'orgNoTagPolicy')[0] == -1

        h = Harness()
        h.org.add_response('list_roots', _roots(('TAG_POLICY',)))
        h.policies('TAG_POLICY', [('p-tagatt001', 'Classification', False, self.CONTENT, [ROOT_T])])
        r = h.run('OrgNoTagPolicy', 'orgNoTagPolicy')
        assert r[0] == 1 and 'DataClassification' in r[1]

    def test_not_enabled(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        assert h.run('OrgNoTagPolicy', 'orgNoTagPolicy')[0] == -1


class TestRootCentralizedAccess:
    def test_flag_fix(self):
        h = Harness()
        h.iam.add_client_error('list_organizations_features', service_error_code='ServiceAccessNotEnabledException',
                               http_status_code=400)
        assert h.run('RootCentralizedAccessNotEnabled', 'rootCentralizedAccessNotEnabled')[0] == -1

        h = Harness()
        h.iam.add_response('list_organizations_features', {'OrganizationId': ORG_ID,
                                                           'EnabledFeatures': ['RootCredentialsManagement']})
        r = h.run('RootCentralizedAccessNotEnabled', 'rootCentralizedAccessNotEnabled')
        assert r[0] == -1 and 'RootSessions' in r[1]

        h = Harness()
        h.iam.add_response('list_organizations_features', {'OrganizationId': ORG_ID,
                                                           'EnabledFeatures': ['RootCredentialsManagement', 'RootSessions']})
        assert h.run('RootCentralizedAccessNotEnabled', 'rootCentralizedAccessNotEnabled')[0] == 1

    def test_member_account_not_evaluable(self):
        h = Harness(caller=MEMBER)
        h.iam.add_client_error('list_organizations_features',
                               service_error_code='AccountNotManagementOrDelegatedAdministratorException',
                               http_status_code=400)
        assert h.run('RootCentralizedAccessNotEnabled', 'rootCentralizedAccessNotEnabled') == \
            [0, 'Not evaluable from member account']


class TestBackupTamperScp:
    PARTIAL = {'Effect': 'Deny', 'Action': 'backup:Delete*', 'Resource': '*'}
    FULLDENY = {'Effect': 'Deny', 'Action': ['backup:DeleteBackupVault*', 'backup:DeleteRecoveryPoint',
                                             'backup:PutBackupVaultAccessPolicy', 'backup:UpdateRecoveryPointLifecycle'],
                'Resource': '*', 'Condition': {'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/BackupAdmin'}}}

    def test_flag_fix(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-partial01', 'Partial', False, _doc(self.PARTIAL), [ROOT_T])])
        stubTree(h, DEFAULT_TREE)
        r = h.run('ScpNoBackupTamperProtection', 'scpNoBackupTamperProtection')
        assert r[0] == -1 and 'Not denied: backup:PutBackupVaultAccessPolicy' in r[1]
        assert 'Not denied: backup:DeleteRecoveryPoint' not in r[1] and 'Account app (222222222222)' in r[1]

        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-backup001', 'BackupGuard', False, _doc(self.FULLDENY), [OU_T])])
        stubTree(h, DEFAULT_TREE)
        assert h.run('ScpNoBackupTamperProtection', 'scpNoBackupTamperProtection')[0] == 1

    def test_unattached_policy_does_not_count(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-backup001', 'BackupGuard', False, _doc(self.FULLDENY), [])])
        assert h.run('ScpNoBackupTamperProtection', 'scpNoBackupTamperProtection')[0] == -1


# --------------------------------------------------------------------------- #
class TestPolicyHelpers:
    @pytest.mark.parametrize('op', ['StringLike', 'ArnLike', 'ArnEquals'])
    def test_root_denial_operators(self, op):
        doc = {'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*',
                              'Condition': {op: {'aws:PrincipalArn': ['arn:aws:iam::*:root']}}}]}
        assert 'denyRoot' in scpGuardrails(doc)

    def test_root_denial_string_equals_is_literal(self):
        # StringEquals has no wildcard support: "arn:aws:iam::*:root" matches
        # no real principal, so it denies nothing. A literal root ARN covers
        # only that account.
        wild = {'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*',
                               'Condition': {'StringEquals': {'aws:PrincipalArn': 'arn:aws:iam::*:root'}}}]}
        assert 'denyRoot' not in scpGuardrails(wild)
        lit = {'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*',
                              'Condition': {'StringEquals': {'aws:PrincipalArn': 'arn:aws:iam::111122223333:root'}}}]}
        assert 'denyRoot' in scpGuardrails(lit, ['111122223333'])
        assert 'denyRoot' not in scpGuardrails(lit, ['111122223333', '444455556666'])
        assert 'denyRoot' not in scpGuardrails(lit)

    def test_broad_deny_star_is_not_privesc_guardrail(self):
        doc = {'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*',
                              'Condition': {'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']}}}]}
        assert scpGuardrails(doc) == {'restrictRegions'}

    def test_allow_statement_ignored(self):
        assert scpGuardrails({'Statement': {'Effect': 'Allow', 'Action': 'iam:*', 'Resource': '*'}}) == set()

    def test_not_action_coverage(self):
        st = {'Effect': 'Deny', 'NotAction': ['s3:*'], 'Resource': '*'}
        assert denyCoversAction(st, 'backup:DeleteRecoveryPoint')
        assert not denyCoversAction(st, 's3:GetObject')

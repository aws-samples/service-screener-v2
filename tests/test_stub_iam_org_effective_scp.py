"""
Flag -> fix -> re-run regression tests (botocore Stubber, real API shapes) for
the review findings on the IAM organization checks (fix round 1):

- scpNoBackupTamperProtection / scpNoDataProtectionGuardrail /
  scpNoIamUserCreationDeny / scpNoSecurityServiceProtection used to take the
  union of every customer SCP attached anywhere in the org. A deny-all SCP on a
  Suspended OU, or a Deny attached only to one sandbox account or to the
  management account (where SCPs never apply), made the whole org PASS. They
  now evaluate the effective SCP set of every active member account.
- scpBestPractices flagged empty OUs and quarantine (Deny "*") OUs.
- orgMemberAlternateContactsMissing queried the management account from a
  delegated-admin caller.
- rootCentralizedAccessNotEnabled wording from member accounts.
- orgMgmtAccountHostsWorkloads aborted on BotoCoreError.
- ssoPermissionSetOverprivileged admin-equivalent INFO detection.

Why Stubber and not the AWS Emulator: organizations.list_policies /
describe_policy / list_targets_for_policy / list_accounts /
list_accounts_for_parent are NotImplemented in the emulator, it cannot model
a member or delegated-admin caller, and it only has an account instance of IAM
Identity Center (see tests/emulator/test_emu_iam_org.py for the parts it can
drive). No network is used: every call is served by a Stubber.
"""
import json
import os
import sys

import botocore
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from test_stub_iam_org import (Harness, _roots, _doc, _session, FULL, ROOT_T, OU_T, ROOT_ID, OU_ID,  # noqa: E402
                               MGMT, MEMBER, MEMBER2, ORG_ID, DENY_ROOT, DENY_REGION, DENY_PRIVESC, stubTree)
from test_stub_iam_org_guardrails import SsoHarness, PS1, PS2  # noqa: E402
from services.iam.drivers.IamOrgData import scpGuardrails, SCP_GUARDRAILS  # noqa: E402

SUSP_ID = 'ou-ab12-22222222'
SUSP_T = (SUSP_ID, 'Suspended', 'ORGANIZATIONAL_UNIT')
EMPTY_ID = 'ou-ab12-33333333'
MGMT_T = (MGMT, 'mgmt', 'ACCOUNT')
MEMBER_T = (MEMBER, 'app', 'ACCOUNT')
MEMBER2_T = (MEMBER2, 'quarantined', 'ACCOUNT')

# Root -> mgmt + OU Workloads (app) + OU Suspended (quarantined) + empty OU.
TREE = {ROOT_ID: ([(OU_ID, 'Workloads'), (SUSP_ID, 'Suspended'), (EMPTY_ID, 'Empty')], [(MGMT, 'mgmt', 'ACTIVE')]),
        OU_ID: ([], [(MEMBER, 'app', 'ACTIVE')]),
        SUSP_ID: ([], [(MEMBER2, 'quarantined', 'ACTIVE')])}

DENY_ALL = {'Effect': 'Deny', 'Action': '*', 'Resource': '*'}
GUARDS = {
    'scpNoBackupTamperProtection': {'Effect': 'Deny', 'Resource': '*', 'Action': [
        'backup:DeleteBackupVault', 'backup:DeleteBackupVaultAccessPolicy', 'backup:DeleteBackupVaultLockConfiguration',
        'backup:DeleteRecoveryPoint', 'backup:PutBackupVaultAccessPolicy', 'backup:UpdateRecoveryPointLifecycle']},
    'scpNoDataProtectionGuardrail': {'Effect': 'Deny', 'Resource': '*', 'Action': [
        's3:PutAccountPublicAccessBlock', 'ec2:DisableEbsEncryptionByDefault', 'kms:ScheduleKeyDeletion']},
    'scpNoIamUserCreationDeny': {'Effect': 'Deny', 'Resource': '*', 'Action': ['iam:CreateUser']},
    'scpNoSecurityServiceProtection': {'Effect': 'Deny', 'Resource': '*', 'Action': [
        'cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'guardduty:DeleteDetector', 'guardduty:Disassociate*',
        'config:StopConfigurationRecorder', 'config:DeleteConfigurationRecorder', 'organizations:LeaveOrganization']},
}
CHECKS = sorted(GUARDS)


def _method(key):
    return key[0].upper() + key[1:]


def _run(key, items, tree=TREE):
    h = Harness()
    h.org.add_response('list_roots', _roots())
    h.policies('SERVICE_CONTROL_POLICY', [FULL] + list(items))
    stubTree(h, tree)
    return h.run(_method(key), key)


# --------------------------------------------------------------------------- #
class TestActionGuardsEffectivePerAccount:
    @pytest.mark.parametrize('key', CHECKS)
    def test_quarantine_deny_all_is_not_org_coverage(self, key):
        """FLAG: the only Deny is a deny-all SCP on the Suspended OU; the
        workload account is unprotected. FIX: guard attached to the root."""
        quarantine = ('p-quaran001', 'Quarantine', False, _doc(DENY_ALL), [SUSP_T])
        r = _run(key, [quarantine])
        assert r[0] == -1, r
        assert 'Account app (222222222222)' in r[1] and '1 of 2 active member account(s)' in r[1]
        assert 'quarantined (333333333333)' not in r[1]

        r = _run(key, [quarantine, ('p-guard0001', 'Guard', False, _doc(GUARDS[key]), [ROOT_T])])
        assert r[0] == 1, r

    @pytest.mark.parametrize('key', CHECKS)
    def test_deny_on_management_account_only_protects_nothing(self, key):
        r = _run(key, [('p-guard0001', 'Guard', False, _doc(GUARDS[key]), [MGMT_T])])
        assert r[0] == -1 and '2 of 2 active member account(s)' in r[1], r
        assert 'Account mgmt' not in r[1]

    @pytest.mark.parametrize('key', CHECKS)
    def test_deny_on_one_account_only(self, key):
        """FLAG: guard attached to the quarantined account only. FIX: also
        attached to the Workloads OU (OU-level inheritance counts)."""
        r = _run(key, [('p-guard0001', 'Guard', False, _doc(GUARDS[key]), [MEMBER2_T])])
        assert r[0] == -1 and 'Account app (222222222222)' in r[1] and '333333333333' not in r[1], r
        r = _run(key, [('p-guard0001', 'Guard', False, _doc(GUARDS[key]), [MEMBER2_T, OU_T])])
        assert r[0] == 1, r

    def test_management_account_only_org_is_not_evaluable(self):
        tree = {ROOT_ID: ([], [(MGMT, 'mgmt', 'ACTIVE'), (MEMBER, 'closed', 'SUSPENDED')])}
        r = _run('scpNoIamUserCreationDeny', [('p-guard0001', 'Guard', False, _doc(GUARDS['scpNoIamUserCreationDeny']),
                                               [ROOT_T])], tree=tree)
        assert r[0] == 0 and 'No active member accounts' in r[1]

    def test_tree_access_denied_is_unable(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-guard0001', 'Guard', False,
                                                     _doc(GUARDS['scpNoIamUserCreationDeny']), [ROOT_T])])
        h.org.add_client_error('list_organizational_units_for_parent', service_error_code='TooManyRequestsException',
                               http_status_code=400)
        r = h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')
        assert r == [0, 'Unable to evaluate (TooManyRequestsException)']


# --------------------------------------------------------------------------- #
class TestScpBestPracticesQuarantineAndEmptyOus:
    def test_quarantine_and_empty_ous_not_flagged(self):
        """FLAG: Workloads has only root denial. The Suspended OU (deny-all)
        and the empty OU must not be listed. FIX: region + priv-esc on the
        Workloads OU."""
        quarantine = ('p-quaran001', 'Quarantine', False, _doc(DENY_ALL), [SUSP_T])
        denyRoot = ('p-denyroot1', 'DenyRoot', False, _doc(DENY_ROOT), [ROOT_T])
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, denyRoot, quarantine])
        stubTree(h, TREE)
        r = h.run('ScpBestPractices', 'scpBestPractices')
        assert r[0] == -1 and '2 of 4 OUs/member accounts' in r[1], r
        assert 'OU Workloads' in r[1] and 'Account app' in r[1]
        assert 'Suspended' not in r[1] and 'quarantined' not in r[1] and 'Empty' not in r[1]

        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, denyRoot, quarantine,
                                              ('p-workload1', 'WorkloadGuards', False,
                                               _doc(DENY_REGION, DENY_PRIVESC), [OU_T])])
        stubTree(h, TREE)
        r = h.run('ScpBestPractices', 'scpBestPractices')
        assert r[0] == 1 and 'All 4 OUs/member accounts' in r[1], r

    def test_scp_guardrails_deny_all(self):
        assert scpGuardrails({'Statement': [DENY_ALL]}) == set(SCP_GUARDRAILS)
        breakGlass = dict(DENY_ALL, Condition={'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/BreakGlass'}})
        assert scpGuardrails({'Statement': [breakGlass]}) == set(SCP_GUARDRAILS)
        # Region deny "*" is still only region restriction.
        regionOnly = dict(DENY_ALL, Condition={'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']}})
        assert scpGuardrails({'Statement': [regionOnly]}) == {'restrictRegions'}


# --------------------------------------------------------------------------- #
class TestAlternateContactsFromDelegatedAdmin:
    def _contact(self, h, acct, typ):
        h.acc.add_response('get_alternate_contact', {'AlternateContact': {
            'AlternateContactType': typ, 'EmailAddress': 'sec@example.com', 'Name': 'n', 'PhoneNumber': '+10000000000',
            'Title': 't'}}, {'AccountId': acct, 'AlternateContactType': typ})

    def _accounts(self, h):
        h.org.add_response('list_accounts', {'Accounts': [
            {'Id': MGMT, 'Name': 'mgmt', 'State': 'ACTIVE'},
            {'Id': MEMBER, 'Name': 'delegated-admin', 'State': 'ACTIVE'},
            {'Id': MEMBER2, 'Name': 'app', 'State': 'ACTIVE'}]})

    def test_flag_fix_skips_management_account(self):
        # Caller is the delegated admin (MEMBER): only MEMBER2 is queried; an
        # unexpected get_alternate_contact for MGMT would fail the Stubber.
        h = Harness(caller=MEMBER)
        self._accounts(h)
        h.acc.add_client_error('get_alternate_contact', service_error_code='ResourceNotFoundException',
                               http_status_code=404, expected_params={'AccountId': MEMBER2, 'AlternateContactType': 'SECURITY'})
        self._contact(h, MEMBER2, 'BILLING')
        self._contact(h, MEMBER2, 'OPERATIONS')
        r = h.run('OrgMemberAlternateContactsMissing', 'orgMemberAlternateContactsMissing')
        assert r[0] == -1 and 'app (333333333333): missing SECURITY' in r[1] and '1 of 1' in r[1]

        h = Harness(caller=MEMBER)
        self._accounts(h)
        for t in ('SECURITY', 'BILLING', 'OPERATIONS'):
            self._contact(h, MEMBER2, t)
        r = h.run('OrgMemberAlternateContactsMissing', 'orgMemberAlternateContactsMissing')
        assert r[0] == 1 and 'All 1 member account(s)' in r[1]


class TestRootCentralizedAccessMemberWording:
    def test_service_access_not_enabled_from_member(self):
        h = Harness(caller=MEMBER)
        h.iam.add_client_error('list_organizations_features', service_error_code='ServiceAccessNotEnabledException',
                               http_status_code=400)
        assert h.run('RootCentralizedAccessNotEnabled', 'rootCentralizedAccessNotEnabled') == \
            [0, 'Not evaluable from member account']


# --------------------------------------------------------------------------- #
class _RaisingClient:
    """Regional client whose paginator raises a BotoCoreError."""
    def __init__(self, exc):
        self.exc = exc

    def get_paginator(self, op):
        exc = self.exc

        class P:
            def paginate(self, **kw):
                raise exc
        return P()


class TestMgmtWorkloadsProbeErrors:
    def _clients(self, ec2=None, functions=()):
        s = _session()
        c = {n: s.client(n) for n in ('ec2', 'lambda', 'rds', 'eks')}
        st = {n: Stubber(cl) for n, cl in c.items()}
        if ec2 == 'optin':
            st['ec2'].add_client_error('describe_instances', service_error_code='OptInRequired', http_status_code=401)
        elif ec2 is None:
            st['ec2'].add_response('describe_instances', {'Reservations': []})
        st['lambda'].add_response('list_functions', {'Functions': [{'FunctionName': f} for f in functions]})
        st['rds'].add_response('describe_db_instances', {'DBInstances': []})
        st['eks'].add_response('list_clusters', {'clusters': []})
        for x in st.values():
            x.activate()
        return c

    def test_botocore_error_is_unable_not_abort(self):
        c = self._clients(ec2='raise', functions=['orders-api'])
        c['ec2'] = _RaisingClient(botocore.exceptions.EndpointConnectionError(endpoint_url='https://ec2.example'))
        h = Harness(regionalClients=c)
        r = h.run('OrgMgmtAccountHostsWorkloads', 'orgMgmtAccountHostsWorkloads')
        assert r[0] == -1 and 'Lambda functions: 1' in r[1]

        c = self._clients(ec2='raise')
        c['ec2'] = _RaisingClient(botocore.exceptions.EndpointConnectionError(endpoint_url='https://ec2.example'))
        h = Harness(regionalClients=c)
        r = h.run('OrgMgmtAccountHostsWorkloads', 'orgMgmtAccountHostsWorkloads')
        assert r[0] == 0 and 'EndpointConnectionError' in r[1]

        h = Harness(regionalClients=self._clients())
        assert h.run('OrgMgmtAccountHostsWorkloads', 'orgMgmtAccountHostsWorkloads')[0] == 1

    def test_opt_in_region_skipped(self):
        s = _session()
        c = {n: s.client(n) for n in ('ec2', 'lambda', 'rds', 'eks')}
        st = Stubber(c['ec2'])
        st.add_client_error('describe_instances', service_error_code='OptInRequired', http_status_code=401)
        st.activate()
        h = Harness(regionalClients=c)
        r = h.run('OrgMgmtAccountHostsWorkloads', 'orgMgmtAccountHostsWorkloads')
        assert r[0] == 1 and 'skipped (not enabled): us-east-1' in r[1]


# --------------------------------------------------------------------------- #
class TestSsoAdminEquivalentInfo:
    @pytest.mark.parametrize('stmt,reason', [
        ({'Effect': 'Allow', 'NotAction': ['organizations:*'], 'Resource': '*'}, 'inline Allow NotAction'),
        ({'Effect': 'Allow', 'Action': ['iam:*'], 'Resource': '*'}, 'inline Allow iam:*'),
    ])
    def test_admin_equivalent_inline_is_info_then_pass(self, stmt, reason):
        s = SsoHarness()
        s.ps(PS1, 'PowerUser', 'PT1H')
        s.managed(PS1, [])
        s.inline(PS1, json.dumps({'Version': '2012-10-17', 'Statement': [stmt]}))
        s.ps(PS2, 'ReadOnly', 'PT1H')
        s.managed(PS2, [])
        s.inline(PS2, '')
        r = s.run('SsoPermissionSetOverprivileged', 'ssoPermissionSetOverprivileged')
        assert r[0] == 0 and r[1].startswith('INFO') and 'PowerUser ({})'.format(reason) in r[1], r

        s = SsoHarness()
        s.ps(PS1, 'PowerUser', 'PT1H')
        s.managed(PS1, [])
        s.inline(PS1, json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': ['s3:Get*'], 'Resource': '*'}]}))
        s.ps(PS2, 'ReadOnly', 'PT1H')
        s.managed(PS2, [])
        s.inline(PS2, '')
        r = s.run('SsoPermissionSetOverprivileged', 'ssoPermissionSetOverprivileged')
        assert r[0] == 1 and 'customer-managed policy references are not inspected' in r[1]

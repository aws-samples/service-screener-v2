"""
Flag -> fix -> re-run tests (botocore Stubber, real API shapes) for the IAM
organization hygiene checks (WAFS2027 tier 3) and the scpBestPractices
per-control detail.

Why Stubber and not the AWS Emulator:
- organizations.list_accounts / list_create_account_status / list_policies /
  list_targets_for_policy / describe_policy are NotImplemented in the
  emulator, and list_tags_for_resource only validates input. So
  accountNotVended, orgAccountsMissingOwnershipTags, orgBackupPolicyMissing,
  orgNoDeclarativePolicy, scpBestPractices and the account-name fallback of
  orgNoForensicsOu cannot be driven there.
- A Control Tower landing zone with enrolled accounts, Cognito user pools in
  several Regions and an organization instance of Identity Center cannot be
  modelled by the single-account emulator.
The OU-name checks and the inventory are also exercised end to end against the
emulator in tests/emulator/test_emu_iam_org.py.

No network is used: clients carry fake credentials and every call is served
by a Stubber (an unexpected call fails the test).
"""
import json
import os
import sys
from datetime import datetime, timezone

import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from test_stub_iam_org import (Harness, _roots, _doc, _session, _org, FULL, ROOT_T, OU_T, DENY_ROOT,  # noqa: E402
                               DENY_REGION, MGMT, MEMBER, MEMBER2, ORG_ID, ROOT_ID, OU_ID)

JOINED = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _acct(aid, name, joined='CREATED', state='ACTIVE'):
    return {'Id': aid, 'Arn': f'arn:aws:organizations::{MGMT}:account/{ORG_ID}/{aid}', 'Email': f'{aid}@example.com',
            'Name': name, 'State': state, 'JoinedMethod': joined, 'JoinedTimestamp': JOINED}


def _accounts(h, *accts):
    h.org.add_response('list_accounts', {'Accounts': list(accts)})


def _ou(oid, name):
    return {'Id': oid, 'Arn': f'arn:aws:organizations::{MGMT}:ou/{ORG_ID}/{oid}', 'Name': name}


def _ouTree(h, names):
    """Root with one level of OUs (names); stubbed in the walk order (LIFO)."""
    ous = [_ou('ou-ab12-{:08d}'.format(i), n) for i, n in enumerate(names)]
    h.org.add_response('list_roots', _roots())
    h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': ous}, {'ParentId': ROOT_ID})
    for o in reversed(ous):
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': []}, {'ParentId': o['Id']})


def _regional(**responses):
    """{'controltower': [(op, resp|ClientErrorCode, params)]} -> (clients, stubbers)."""
    s = _session()
    clients, stubs = {}, {}
    for svc, calls in responses.items():
        c = s.client(svc)
        st = Stubber(c)
        for op, resp, params in calls:
            if isinstance(resp, str):
                st.add_client_error(op, service_error_code=resp, http_status_code=400)
            else:
                st.add_response(op, resp, params)
        st.activate()
        clients[svc], stubs[svc] = c, st
    return clients, stubs


# --------------------------------------------------------------------------- #
class TestAccountNotVended:
    KEY = 'accountNotVended'

    def test_flag_fix(self):
        # FLAG: an invited member account, no Control Tower landing zone.
        clients, stubs = _regional(controltower=[('list_landing_zones', {'landingZones': []}, {})])
        h = Harness(regionalClients=clients)
        _accounts(h, _acct(MGMT, 'mgmt', 'INVITED'), _acct(MEMBER, 'legacy-app', 'INVITED'), _acct(MEMBER2, 'vended'))
        # Control Tower is not enabled for the organization (no trusted access).
        h.org.add_response('list_aws_service_access_for_organization', {'EnabledServicePrincipals': []})
        r = h.run('AccountNotVended', self.KEY)
        stubs['controltower'].assert_no_pending_responses()
        assert r[0] == -1 and 'legacy-app (222222222222)' in r[1] and MGMT not in r[1] and MEMBER2 not in r[1], r

        # FIX: the account is re-provisioned / vended (JoinedMethod CREATED).
        h = Harness()
        _accounts(h, _acct(MGMT, 'mgmt', 'INVITED'), _acct(MEMBER, 'app', 'CREATED'), _acct(MEMBER2, 'vended'))
        r = h.run('AccountNotVended', self.KEY)
        assert r[0] == 1, r

    def test_invited_but_enrolled_in_control_tower_not_reported(self):
        lz = {'landingZones': [{'arn': f'arn:aws:controltower:us-east-1:{MGMT}:landingzone/1A2B3C4D5E6F7G8H'}]}
        eb = {'enabledBaselines': [
            {'arn': f'arn:aws:controltower:us-east-1:{MGMT}:enabledbaseline/XOU1', 'baselineIdentifier': 'arn:aws:controltower:us-east-1::baseline/17BSJV3IGJ2QSGA2',
             'targetIdentifier': f'arn:aws:organizations::{MGMT}:ou/{ORG_ID}/{OU_ID}', 'statusSummary': {'status': 'SUCCEEDED'}},
            {'arn': f'arn:aws:controltower:us-east-1:{MGMT}:enabledbaseline/XACC1', 'baselineIdentifier': 'arn:aws:controltower:us-east-1::baseline/17BSJV3IGJ2QSGA2',
             'targetIdentifier': f'arn:aws:organizations::{MGMT}:account/{ORG_ID}/{MEMBER}',
             'parentIdentifier': f'arn:aws:controltower:us-east-1:{MGMT}:enabledbaseline/XOU1', 'statusSummary': {'status': 'SUCCEEDED'}}]}
        clients, stubs = _regional(controltower=[('list_landing_zones', lz, {}),
                                                 ('list_enabled_baselines', eb, {'includeChildren': True})])
        h = Harness(regionalClients=clients)
        _accounts(h, _acct(MGMT, 'mgmt', 'INVITED'), _acct(MEMBER, 'enrolled', 'INVITED'))
        r = h.run('AccountNotVended', self.KEY)
        stubs['controltower'].assert_no_pending_responses()
        assert r[0] == 1 and 'enrolled in Control Tower not reported' in r[1], r

    def test_member_account_not_evaluable(self):
        h = Harness(caller=MEMBER)
        h.org.add_client_error('list_accounts', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run('AccountNotVended', self.KEY) == [0, 'Not evaluable from member account']


class TestOrgAccountsMissingOwnershipTags:
    KEY = 'orgAccountsMissingOwnershipTags'

    def _tags(self, h, aid, keys):
        h.org.add_response('list_tags_for_resource', {'Tags': [{'Key': k, 'Value': 'x'} for k in keys]},
                           {'ResourceId': aid})

    def test_flag_fix(self):
        h = Harness()
        _accounts(h, _acct(MGMT, 'mgmt'), _acct(MEMBER, 'app'), _acct(MEMBER2, 'old', state='SUSPENDED'))
        self._tags(h, MGMT, ['owner-email'])
        self._tags(h, MEMBER, ['Environment'])
        r = h.run('OrgAccountsMissingOwnershipTags', self.KEY)
        assert r[0] == -1 and 'app (222222222222)' in r[1] and 'Environment' in r[1] and MGMT not in r[1], r

        h = Harness()
        _accounts(h, _acct(MGMT, 'mgmt'), _acct(MEMBER, 'app'), _acct(MEMBER2, 'old', state='SUSPENDED'))
        self._tags(h, MGMT, ['owner-email'])
        self._tags(h, MEMBER, ['Environment', 'CostCenter'])
        assert h.run('OrgAccountsMissingOwnershipTags', self.KEY)[0] == 1

    def test_tags_unreadable_not_pass(self):
        h = Harness()
        _accounts(h, _acct(MGMT, 'mgmt'), _acct(MEMBER, 'app'))
        h.org.add_client_error('list_tags_for_resource', service_error_code='TooManyRequestsException', http_status_code=400)
        assert h.run('OrgAccountsMissingOwnershipTags', self.KEY) == [0, 'Unable to evaluate (TooManyRequestsException)']


@pytest.mark.parametrize('method,key,ptype', [
    ('OrgBackupPolicyMissing', 'orgBackupPolicyMissing', 'BACKUP_POLICY'),
    ('OrgNoDeclarativePolicy', 'orgNoDeclarativePolicy', 'DECLARATIVE_POLICY_EC2'),
])
class TestOrgPolicyPresence:
    def test_flag_fix(self, method, key, ptype):
        content = json.dumps({'plans': {}} if ptype == 'BACKUP_POLICY' else {'ec2_attributes': {}})
        # FLAG: policy exists but is not attached anywhere.
        h = Harness()
        h.org.add_response('list_roots', _roots(types=('SERVICE_CONTROL_POLICY', ptype)))
        h.policies(ptype, [('p-unattach1', 'Draft', False, content, [])])
        assert h.run(method, key)[0] == -1

        # FIX: attached to an OU.
        h = Harness()
        h.org.add_response('list_roots', _roots(types=('SERVICE_CONTROL_POLICY', ptype)))
        h.policies(ptype, [('p-attached1', 'Baseline', False, content, [OU_T])])
        r = h.run(method, key)
        assert r[0] == 1 and 'Baseline' in r[1] and OU_ID in r[1], r

    def test_type_disabled_flags(self, method, key, ptype):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        r = h.run(method, key)
        assert r[0] == -1 and 'not enabled' in r[1]

    def test_consolidated_billing_and_member(self, method, key, ptype):
        h = Harness(_org('CONSOLIDATED_BILLING'))
        assert h.run(method, key)[0] == 0
        h = Harness(caller=MEMBER)
        h.org.add_client_error('list_roots', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run(method, key) == [0, 'Not evaluable from member account']


class TestOrgNoForensicsOu:
    KEY = 'orgNoForensicsOu'

    def test_flag_fix_account_name(self):
        h = Harness()
        _ouTree(h, ['Security', 'Workloads'])
        _accounts(h, _acct(MGMT, 'mgmt'), _acct(MEMBER, 'log-archive'))
        assert h.run('OrgNoForensicsOu', self.KEY)[0] == -1

        h = Harness()
        _ouTree(h, ['Security', 'Workloads'])
        _accounts(h, _acct(MGMT, 'mgmt'), _acct(MEMBER, 'Security-Forensics'))
        r = h.run('OrgNoForensicsOu', self.KEY)
        assert r[0] == 1 and 'Security-Forensics' in r[1], r

    def test_ou_name_passes_without_account_listing(self):
        h = Harness()
        _ouTree(h, ['Security', 'Incident Response'])
        r = h.run('OrgNoForensicsOu', self.KEY)
        assert r[0] == 1 and 'Root/Incident Response' in r[1], r

    def test_accounts_unreadable_not_fail(self):
        h = Harness()
        _ouTree(h, ['Workloads'])
        h.org.add_client_error('list_accounts', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run('OrgNoForensicsOu', self.KEY)[0] == 0


class TestOrgNoSandboxOrStagingOu:
    KEY = 'orgNoSandboxOrStagingOu'

    def test_flag_fix(self):
        h = Harness()
        # SDLC "Staging" is a workload environment, not a Policy Staging OU.
        _ouTree(h, ['Security', 'Staging', 'Prod'])
        assert h.run('OrgNoSandboxOrStagingOu', self.KEY)[0] == -1

        h = Harness()
        _ouTree(h, ['Security', 'Policy-Staging'])
        r = h.run('OrgNoSandboxOrStagingOu', self.KEY)
        assert r[0] == 1 and 'Root/Policy-Staging' in r[1] and 'No Sandbox-like OU' in r[1], r

        h = Harness()
        _ouTree(h, ['Sandbox'])
        assert h.run('OrgNoSandboxOrStagingOu', self.KEY)[0] == 1

    def test_member_not_evaluable(self):
        h = Harness(caller=MEMBER)
        h.org.add_client_error('list_roots', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run('OrgNoSandboxOrStagingOu', self.KEY) == [0, 'Not evaluable from member account']


class TestScpBestPracticesPerControl:
    """scpNoRootActionDeny is covered by scpBestPractices (effective SCP set,
    root user denial). The FAIL message now carries a per-control summary."""

    def _tree(self, h):
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': [_ou(OU_ID, 'Workloads')]},
                           {'ParentId': ROOT_ID})
        h.org.add_response('list_accounts_for_parent', {'Accounts': [
            {'Id': MGMT, 'Name': 'mgmt', 'State': 'ACTIVE'}]}, {'ParentId': ROOT_ID})
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': []}, {'ParentId': OU_ID})
        h.org.add_response('list_accounts_for_parent', {'Accounts': [
            {'Id': MEMBER, 'Name': 'app', 'State': 'ACTIVE'}]}, {'ParentId': OU_ID})

    def test_flag_fix_root_denial(self):
        # FLAG: region restriction only -> root user denial missing on OU + account.
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-region001', 'Regions', False,
                                                     _doc(DENY_REGION, {'Effect': 'Deny', 'Action': 'iam:PassRole', 'Resource': '*'}), [ROOT_T])])
        self._tree(h)
        r = h.run('ScpBestPractices', 'scpBestPractices')
        assert r[0] == -1 and 'root user denial: missing on 2' in r[1], r
        assert 'region restriction: missing' not in r[1] and 'privilege escalation prevention: missing' not in r[1]

        # FIX: a root-denial SCP on the OU.
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [
            FULL, ('p-region001', 'Regions', False,
                   _doc(DENY_REGION, {'Effect': 'Deny', 'Action': 'iam:PassRole', 'Resource': '*'}), [ROOT_T]),
            ('p-denyroot1', 'DenyRoot', False, _doc(DENY_ROOT), [OU_T])])
        self._tree(h)
        assert h.run('ScpBestPractices', 'scpBestPractices')[0] == 1


class TestPrincipalInventorySummary:
    KEY = 'principalInventorySummary'

    def _run(self, users, samlCount, pools):
        inst = {'InstanceArn': 'arn:aws:sso:::instance/ssoins-1111222233334444', 'IdentityStoreId': 'd-1111111111',
                'Status': 'ACTIVE'}
        clients, stubs = _regional(**{
            'sso-admin': [('list_instances', {'Instances': [inst]}, {}),
                          ('list_permission_sets', {'PermissionSets': []}, {'InstanceArn': inst['InstanceArn']})],
            'cognito-idp': [('list_user_pools', {'UserPools': [{'Id': f'us-east-1_p{i}', 'Name': f'p{i}'} for i in range(pools)]},
                             {'MaxResults': 60})],
            'rolesanywhere': [('list_trust_anchors', {'trustAnchors': []}, {})],
        })
        h = Harness(regionalClients=clients)
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        h.iam.add_response('list_users', {'Users': [
            {'Path': '/', 'UserName': u, 'UserId': 'AIDA' + 'X' * 17, 'Arn': f'arn:aws:iam::{MGMT}:user/{u}', 'CreateDate': now}
            for u in users]})
        h.iam.add_response('list_roles', {'Roles': [
            {'Path': '/aws-service-role/sso.amazonaws.com/', 'RoleName': 'AWSServiceRoleForSSO', 'RoleId': 'AROA' + 'X' * 17,
             'Arn': f'arn:aws:iam::{MGMT}:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO', 'CreateDate': now},
            {'Path': '/', 'RoleName': 'AWSReservedSSO_Admin_abc', 'RoleId': 'AROA' + 'Y' * 17,
             'Arn': f'arn:aws:iam::{MGMT}:role/AWSReservedSSO_Admin_abc', 'CreateDate': now}]})
        h.iam.add_response('list_saml_providers', {'SAMLProviderList': [
            {'Arn': f'arn:aws:iam::{MGMT}:saml-provider/idp{i}'} for i in range(samlCount)]})
        h.iam.add_response('list_open_id_connect_providers', {'OpenIDConnectProviderList': []})
        r = h.run('PrincipalInventorySummary', self.KEY)
        for st in stubs.values():
            st.assert_no_pending_responses()
        return r

    def test_inventory_is_informational_and_tracks_changes(self):
        """No pass/fail condition: never -1. 'Fix' = add a SAML IdP and a
        user pool; the re-run reflects the change."""
        r = self._run(['alice'], 0, 0)
        assert r[0] == 0 and 'IAM users: 1' in r[1] and 'IAM SAML providers: 0' in r[1], r
        assert 'service-linked: 1, Identity Center: 1, other: 0' in r[1]
        assert 'ssoins-1111222233334444 (org, us-east-1)' in r[1] and 'Cognito user pools: none' in r[1]
        r = self._run(['alice', 'bob'], 1, 2)
        assert r[0] == 0 and 'IAM users: 2' in r[1] and 'IAM SAML providers: 1' in r[1] and 'us-east-1: 2' in r[1], r

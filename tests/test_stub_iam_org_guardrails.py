"""
Flag -> fix -> re-run tests (botocore Stubber, real API shapes) for the IAM
organization guardrail, Identity Center and third-party trust checks.

Why Stubber and not the AWS Emulator:
- organizations.list_policies / describe_policy / list_targets_for_policy /
  list_delegated_administrators / list_delegated_services_for_account /
  list_accounts are NotImplemented in the emulator.
- The emulator only provides an *account* instance of IAM Identity Center:
  list_permission_sets and every permission-set API return
  ValidationException, so permission sets and assignments cannot be created.
- Third-party trust classification needs the org account list
  (list_accounts), which the emulator cannot serve; without it the checks
  correctly return 0 (covered in tests/emulator/test_emu_iam_org.py).

No network is used: clients carry fake credentials and every call is served
by a Stubber (an unexpected call fails the test).
"""
import json
import os
import sys
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from test_stub_iam_org import (Harness, _roots, _doc, _session, _org, FULL, ROOT_T, OU_T, DENY_ROOT,  # noqa: E402
                               DENY_REGION, MGMT, MEMBER, ORG_ID, stubTree, DEFAULT_TREE)
from services.iam.drivers.IamRole import IamRole  # noqa: E402
from services.iam.drivers.IamOrgData import OrgData, denyIsUnconditionalGuardrail  # noqa: E402
from services.iam.drivers.IamTrust import buildTrustContext, externalIdWeakness  # noqa: E402
from services.iam.drivers.IamSsoData import parseIsoDuration  # noqa: E402

THIRD = '999988887777'


def _scp(h, *items, tree=DEFAULT_TREE):
    """Stub the SCP list and, when any customer SCP is attached, the org
    tree walked for the per-account effective SCP set."""
    h.org.add_response('list_roots', _roots())
    h.policies('SERVICE_CONTROL_POLICY', [FULL] + list(items))
    if any(not managed and targets for _, _, managed, _, targets in items):
        stubTree(h, tree)


# --------------------------------------------------------------------------- #
# SCP action guardrails
# --------------------------------------------------------------------------- #
DATA_PROT = {'Effect': 'Deny', 'Resource': '*',
             'Action': ['s3:PutAccountPublicAccessBlock', 'ec2:DisableEbsEncryptionByDefault', 'kms:ScheduleKeyDeletion'],
             'Condition': {'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/PlatformAdmin'}}}
SEC_SVC = {'Effect': 'Deny', 'Resource': '*',
           'Action': ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'guardduty:DeleteDetector',
                      'guardduty:Disassociate*', 'config:StopConfigurationRecorder',
                      'config:DeleteConfigurationRecorder', 'organizations:LeaveOrganization']}
IAM_USER = {'Effect': 'Deny', 'Action': ['iam:CreateUser', 'iam:CreateAccessKey'], 'Resource': '*',
            'Condition': {'StringNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/IdentityAutomation'}}}


class TestScpNoDataProtectionGuardrail:
    def test_flag_fix(self):
        h = Harness()
        partial = dict(DATA_PROT, Action=['s3:PutAccountPublicAccessBlock'])
        _scp(h, ('p-partial01', 'Partial', False, _doc(partial), [ROOT_T]))
        r = h.run('ScpNoDataProtectionGuardrail', 'scpNoDataProtectionGuardrail')
        assert r[0] == -1 and 'Not denied: EBS default encryption' in r[1] and 'Not denied: KMS key deletion' in r[1]
        assert 'Not denied: S3' not in r[1]

        h = Harness()
        _scp(h, ('p-dataprot1', 'DataProtection', False, _doc(DATA_PROT), [OU_T]))
        r = h.run('ScpNoDataProtectionGuardrail', 'scpNoDataProtectionGuardrail')
        assert r[0] == 1 and 'DataProtection' in r[1]

    def test_root_only_or_region_deny_is_not_coverage(self):
        """Deny '*' for the root user / outside approved regions leaves the
        actions allowed for every IAM principal: must not PASS."""
        h = Harness()
        _scp(h, ('p-baseline1', 'Baseline', False, _doc(DENY_ROOT, DENY_REGION), [ROOT_T]))
        r = h.run('ScpNoDataProtectionGuardrail', 'scpNoDataProtectionGuardrail')
        assert r[0] == -1 and 'narrowing condition' in r[1]

    def test_unattached_does_not_count(self):
        h = Harness()
        _scp(h, ('p-dataprot1', 'DataProtection', False, _doc(DATA_PROT), []))
        assert h.run('ScpNoDataProtectionGuardrail', 'scpNoDataProtectionGuardrail')[0] == -1

    def test_member_account_not_evaluable(self):
        h = Harness(caller=MEMBER)
        h.org.add_client_error('list_roots', service_error_code='AccessDeniedException', http_status_code=400)
        assert h.run('ScpNoDataProtectionGuardrail', 'scpNoDataProtectionGuardrail') == \
            [0, 'Not evaluable from member account']

    def test_unparseable_content_is_unable(self):
        h = Harness()
        _scp(h, ('p-broken001', 'Broken', False, '{not json', [ROOT_T]))
        r = h.run('ScpNoDataProtectionGuardrail', 'scpNoDataProtectionGuardrail')
        assert r[0] == 0 and 'Unable to evaluate' in r[1]


class TestScpNoIamUserCreationDeny:
    def test_flag_fix(self):
        h = Harness()
        _scp(h, ('p-other0001', 'Other', False, _doc(SEC_SVC), [ROOT_T]))
        assert h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')[0] == -1

        h = Harness()
        _scp(h, ('p-iamuser01', 'NoIamUsers', False, _doc(IAM_USER), [OU_T]))
        r = h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')
        assert r[0] == 1 and 'NoIamUsers' in r[1]

    def test_access_key_only_counts(self):
        h = Harness()
        _scp(h, ('p-iamkey001', 'NoKeys', False, _doc(dict(IAM_USER, Action='iam:CreateAccessKey')), [ROOT_T]))
        assert h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')[0] == 1

    def test_scps_disabled(self):
        h = Harness()
        h.org.add_response('list_roots', _roots(types=()))
        assert h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')[0] == 0


class TestScpNoSecurityServiceProtection:
    def test_flag_fix(self):
        h = Harness()
        ctOnly = {'Effect': 'Deny', 'Action': ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail'], 'Resource': '*'}
        _scp(h, ('p-ctonly001', 'TrailOnly', False, _doc(ctOnly), [ROOT_T]))
        r = h.run('ScpNoSecurityServiceProtection', 'scpNoSecurityServiceProtection')
        assert r[0] == -1 and 'Not denied: GuardDuty' in r[1] and 'Not denied: AWS Config' in r[1] \
            and 'Not denied: Organizations' in r[1] and 'Denied: CloudTrail' in r[1]

        h = Harness()
        _scp(h, ('p-ctonly001', 'TrailOnly', False, _doc(ctOnly), [ROOT_T]),
             ('p-secsvc001', 'SecurityServices', False, _doc(SEC_SVC), [OU_T]))
        assert h.run('ScpNoSecurityServiceProtection', 'scpNoSecurityServiceProtection')[0] == 1

    def test_partial_cloudtrail_is_flagged(self):
        """Denying DeleteTrail alone still lets StopLogging disable the trail."""
        h = Harness()
        st = dict(SEC_SVC, Action=[a for a in SEC_SVC['Action'] if a != 'cloudtrail:StopLogging'])
        _scp(h, ('p-secsvc001', 'SecurityServices', False, _doc(st), [ROOT_T]))
        r = h.run('ScpNoSecurityServiceProtection', 'scpNoSecurityServiceProtection')
        assert r[0] == -1 and 'Not denied: CloudTrail' in r[1]

    def test_consolidated_billing(self):
        h = Harness(_org('CONSOLIDATED_BILLING'))
        assert h.run('ScpNoSecurityServiceProtection', 'scpNoSecurityServiceProtection')[0] == 0


class TestBackupTamperRegionDenyRegression:
    def test_region_deny_not_backup_protection(self):
        """A region-restriction SCP (Deny NotAction ... outside regions) used
        to be counted as backup tamper protection: false PASS."""
        h = Harness()
        _scp(h, ('p-region001', 'Regions', False, _doc(DENY_REGION), [ROOT_T]))
        assert h.run('ScpNoBackupTamperProtection', 'scpNoBackupTamperProtection')[0] == -1


class TestGuardrailHelper:
    @pytest.mark.parametrize('cond,expected', [
        (None, True),
        ({'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/Admin'}}, True),
        ({'StringNotEqualsIfExists': {'aws:PrincipalTag/team': 'sec'}}, True),
        ({'BoolIfExists': {'aws:PrincipalIsAWSService': 'false'}}, True),
        ({'ArnLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'}}, False),
        ({'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']}}, False),
        ({'Bool': {'aws:MultiFactorAuthPresent': 'false'}}, False),
    ])
    def test_condition_scope(self, cond, expected):
        st = {'Effect': 'Deny', 'Action': '*', 'Resource': '*'}
        if cond:
            st['Condition'] = cond
        assert denyIsUnconditionalGuardrail(st) is expected


# --------------------------------------------------------------------------- #
# Delegated administration of security services
# --------------------------------------------------------------------------- #
SEC_ACCT = '444455556666'


class TestSecurityServicesNoDelegatedAdmin:
    def _admins(self, h, services, trusted):
        if services:
            h.org.add_response('list_delegated_administrators', {'DelegatedAdministrators': [
                {'Id': SEC_ACCT, 'Name': 'security-tooling', 'Status': 'ACTIVE', 'State': 'ACTIVE'}]})
            h.org.add_response('list_delegated_services_for_account', {'DelegatedServices': [
                {'ServicePrincipal': sp} for sp in services]}, {'AccountId': SEC_ACCT})
        else:
            h.org.add_response('list_delegated_administrators', {'DelegatedAdministrators': []})
        h.org.add_response('list_aws_service_access_for_organization', {'EnabledServicePrincipals': [
            {'ServicePrincipal': sp} for sp in trusted]})

    def test_flag_none_delegated_then_fix(self):
        h = Harness()
        self._admins(h, [], ['guardduty.amazonaws.com', 'securityhub.amazonaws.com'])
        r = h.run('SecurityServicesNoDelegatedAdmin', 'securityServicesNoDelegatedAdmin')
        assert r[0] == -1 and 'No delegated administrator' in r[1]

        h = Harness()
        self._admins(h, ['guardduty.amazonaws.com', 'securityhub.amazonaws.com', 'ssm.amazonaws.com'],
                     ['guardduty.amazonaws.com', 'securityhub.amazonaws.com', 'ssm.amazonaws.com'])
        r = h.run('SecurityServicesNoDelegatedAdmin', 'securityServicesNoDelegatedAdmin')
        assert r[0] == 1 and 'security-tooling' in r[1]

    def test_flag_trusted_but_not_delegated(self):
        h = Harness()
        self._admins(h, ['guardduty.amazonaws.com'], ['guardduty.amazonaws.com', 'inspector2.amazonaws.com'])
        r = h.run('SecurityServicesNoDelegatedAdmin', 'securityServicesNoDelegatedAdmin')
        assert r[0] == -1 and 'Amazon Inspector' in r[1]

    def test_non_security_delegation_does_not_count(self):
        h = Harness()
        self._admins(h, ['ssm.amazonaws.com'], [])
        assert h.run('SecurityServicesNoDelegatedAdmin', 'securityServicesNoDelegatedAdmin')[0] == -1

    def test_member_account_not_evaluable(self):
        h = Harness(caller=MEMBER)
        assert h.run('SecurityServicesNoDelegatedAdmin', 'securityServicesNoDelegatedAdmin') == \
            [0, 'Not evaluable from member account']

    def test_access_denied_is_unable(self):
        h = Harness()
        h.org.add_client_error('list_delegated_administrators', service_error_code='AccessDeniedException',
                               http_status_code=400)
        r = h.run('SecurityServicesNoDelegatedAdmin', 'securityServicesNoDelegatedAdmin')
        assert r == [0, 'Unable to evaluate (AccessDeniedException)']


# --------------------------------------------------------------------------- #
# IAM Identity Center
# --------------------------------------------------------------------------- #
INST = 'arn:aws:sso:::instance/ssoins-1111222233334444'
PS1 = 'arn:aws:sso:::permissionSet/ssoins-1111222233334444/ps-1111111111111111'
PS2 = 'arn:aws:sso:::permissionSet/ssoins-1111222233334444/ps-2222222222222222'
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class SsoHarness:
    def __init__(self, accountInstance=False, instances=True):
        self.client = _session().client('sso-admin')
        self.st = Stubber(self.client)
        self.st.activate()
        self.h = Harness(regionalClients={'sso-admin': self.client})
        if not instances:
            self.st.add_response('list_instances', {'Instances': []})
            return
        self.st.add_response('list_instances', {'Instances': [{
            'InstanceArn': INST, 'IdentityStoreId': 'd-1234567890', 'OwnerAccountId': MGMT, 'Name': 'org',
            'Status': 'ACTIVE'}]})
        if accountInstance:
            self.st.add_client_error('list_permission_sets', service_error_code='ValidationException',
                                     http_status_code=400)
        else:
            self.st.add_response('list_permission_sets', {'PermissionSets': [PS1, PS2]}, {'InstanceArn': INST})

    def ps(self, arn, name, duration):
        self.st.add_response('describe_permission_set', {'PermissionSet': {
            'Name': name, 'PermissionSetArn': arn, 'SessionDuration': duration, 'CreatedDate': NOW}},
            {'InstanceArn': INST, 'PermissionSetArn': arn})

    def managed(self, arn, policies):
        self.st.add_response('list_managed_policies_in_permission_set', {'AttachedManagedPolicies': [
            {'Name': n, 'Arn': f'arn:aws:iam::aws:policy/{n}'} for n in policies]},
            {'InstanceArn': INST, 'PermissionSetArn': arn})

    def inline(self, arn, doc):
        # The API omits InlinePolicy when the permission set has none.
        self.st.add_response('get_inline_policy_for_permission_set', {'InlinePolicy': doc} if doc else {},
                             {'InstanceArn': INST, 'PermissionSetArn': arn})

    def accounts(self, arn, accts):
        self.st.add_response('list_accounts_for_provisioned_permission_set', {'AccountIds': accts},
                             {'InstanceArn': INST, 'PermissionSetArn': arn})

    def assigns(self, arn, acct, principals):
        self.st.add_response('list_account_assignments', {'AccountAssignments': [
            {'AccountId': acct, 'PermissionSetArn': arn, 'PrincipalType': t, 'PrincipalId': f'id-{t}-{i}'}
            for i, t in enumerate(principals)]}, {'InstanceArn': INST, 'AccountId': acct, 'PermissionSetArn': arn})

    def run(self, method, key):
        r = self.h.run(method, key)
        self.st.assert_no_pending_responses()
        return r


class TestSsoAssignmentsToIndividualUsers:
    def test_flag_fix(self):
        s = SsoHarness()
        s.accounts(PS1, [MEMBER])
        s.assigns(PS1, MEMBER, ['GROUP', 'USER'])
        s.ps(PS1, 'AdminAccess', 'PT1H')
        s.accounts(PS2, [MEMBER])
        s.assigns(PS2, MEMBER, ['GROUP'])
        r = s.run('SsoAssignmentsToIndividualUsers', 'ssoAssignmentsToIndividualUsers')
        assert r[0] == -1 and 'AdminAccess -> account 222222222222: 1 user' in r[1]

        s = SsoHarness()
        s.accounts(PS1, [MEMBER])
        s.assigns(PS1, MEMBER, ['GROUP'])
        s.accounts(PS2, [MEMBER])
        s.assigns(PS2, MEMBER, ['GROUP'])
        assert s.run('SsoAssignmentsToIndividualUsers', 'ssoAssignmentsToIndividualUsers')[0] == 1

    def test_account_instance_not_applicable(self):
        s = SsoHarness(accountInstance=True)
        r = s.run('SsoAssignmentsToIndividualUsers', 'ssoAssignmentsToIndividualUsers')
        assert r[0] == 0 and 'account instance' in r[1]

    def test_member_without_instance_not_evaluable(self):
        client = _session().client('sso-admin')
        st = Stubber(client)
        st.add_response('list_instances', {'Instances': []})
        st.activate()
        h = Harness(caller=MEMBER, regionalClients={'sso-admin': client})
        assert h.run('SsoAssignmentsToIndividualUsers', 'ssoAssignmentsToIndividualUsers') == \
            [0, 'Not evaluable from member account']

    def test_access_denied_is_unable(self):
        s = SsoHarness()
        s.st.add_client_error('list_accounts_for_provisioned_permission_set', service_error_code='AccessDeniedException',
                              http_status_code=400)
        s.st.add_client_error('list_accounts_for_provisioned_permission_set', service_error_code='AccessDeniedException',
                              http_status_code=400)
        assert s.run('SsoAssignmentsToIndividualUsers', 'ssoAssignmentsToIndividualUsers') == \
            [0, 'Unable to evaluate (AccessDeniedException)']


ADMIN_INLINE = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]})
RO_INLINE = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:Get*', 'Resource': '*'}]})


class TestSsoPermissionSetOverprivileged:
    def test_flag_fix(self):
        s = SsoHarness()
        s.ps(PS1, 'Admin', 'PT12H')
        s.managed(PS1, ['AdministratorAccess'])
        s.ps(PS2, 'ReadOnly', 'PT4H')
        s.managed(PS2, [])
        s.inline(PS2, RO_INLINE)
        r = s.run('SsoPermissionSetOverprivileged', 'ssoPermissionSetOverprivileged')
        assert r[0] == -1 and 'Admin: SessionDuration PT12H' in r[1] and 'Admin (AdministratorAccess)' in r[1]

        s = SsoHarness()
        s.ps(PS1, 'Dev', 'PT8H')
        s.managed(PS1, ['ReadOnlyAccess'])
        s.inline(PS1, '')
        s.ps(PS2, 'ReadOnly', 'PT1H')
        s.managed(PS2, [])
        s.inline(PS2, RO_INLINE)
        assert s.run('SsoPermissionSetOverprivileged', 'ssoPermissionSetOverprivileged')[0] == 1

    def test_admin_only_is_info(self):
        s = SsoHarness()
        s.ps(PS1, 'Admin', 'PT1H')
        s.managed(PS1, [])
        s.inline(PS1, ADMIN_INLINE)
        s.ps(PS2, 'ReadOnly', 'PT1H')
        s.managed(PS2, [])
        s.inline(PS2, '')
        r = s.run('SsoPermissionSetOverprivileged', 'ssoPermissionSetOverprivileged')
        assert r[0] == 0 and r[1].startswith('INFO') and 'Admin (inline Allow *:*)' in r[1]

    def test_no_instance_not_applicable(self):
        s = SsoHarness(instances=False)
        r = s.run('SsoPermissionSetOverprivileged', 'ssoPermissionSetOverprivileged')
        assert r[0] == 0 and 'no IAM Identity Center instance' in r[1]

    @pytest.mark.parametrize('v,secs', [('PT8H', 28800), ('PT1H30M', 5400), ('PT12H', 43200), ('P1D', 86400),
                                        ('bogus', None), ('PT', None)])
    def test_parse_duration(self, v, secs):
        assert parseIsoDuration(v) == secs


# --------------------------------------------------------------------------- #
# Third-party trusted roles (IamRole driver)
# --------------------------------------------------------------------------- #
def _trust(principal, condition=None):
    st = {'Effect': 'Allow', 'Principal': {'AWS': principal}, 'Action': 'sts:AssumeRole'}
    if condition:
        st['Condition'] = condition
    return {'Version': '2012-10-17', 'Statement': [st]}


def _ctx(accounts=(MGMT, MEMBER), err=None, caller=MEMBER):
    """Trust context built through the real OrgData/buildTrustContext path."""
    org = _session().client('organizations')
    st = Stubber(org)
    st.add_response('describe_organization', _org())
    if err:
        st.add_client_error('list_accounts', service_error_code=err, http_status_code=400)
    else:
        st.add_response('list_accounts', {'Accounts': [{'Id': a, 'Name': a, 'State': 'ACTIVE'} for a in accounts]})
    st.activate()
    ctx = buildTrustContext(OrgData(org, caller), caller)
    st.assert_no_pending_responses()
    return ctx


def _role(trust, attached=(), inline=()):
    return {'RoleName': 'VendorRole', 'Path': '/', 'Arn': f'arn:aws:iam::{MEMBER}:role/VendorRole',
            'CreateDate': NOW, 'RoleLastUsed': {}, 'AssumeRolePolicyDocument': trust,
            'AttachedManagedPolicies': [{'PolicyName': n, 'PolicyArn': f'arn:aws:iam::aws:policy/{n}'} for n in attached],
            'RolePolicyList': [{'PolicyName': n, 'PolicyDocument': d} for n, d in inline]}


def _runRole(role, ctx, method, key, docs=None):
    iam = _session().client('iam')
    st = Stubber(iam)  # no IAM call expected: everything comes from prefetched data
    st.activate()
    obj = IamRole(role, iam, None, docs or {}, None, ctx)
    getattr(obj, '_check' + method)()
    st.assert_no_pending_responses()
    return obj.results.get(key)


STRONG = {'StringEquals': {'sts:ExternalId': 'a3f9c2e1-vendor-tenant-7781'}}


class TestThirdPartyRoleNoExternalId:
    def test_flag_fix(self):
        ctx = _ctx()
        r = _runRole(_role(_trust(f'arn:aws:iam::{THIRD}:root')), ctx, 'ThirdPartyRoleNoExternalId',
                     'thirdPartyRoleNoExternalId')
        assert r[0] == -1 and 'no sts:ExternalId condition' in r[1]
        r = _runRole(_role(_trust(f'arn:aws:iam::{THIRD}:root', STRONG)), ctx, 'ThirdPartyRoleNoExternalId',
                     'thirdPartyRoleNoExternalId')
        assert r[0] == 1

    @pytest.mark.parametrize('cond,reason', [
        ({'StringEquals': {'sts:ExternalId': '1234'}}, 'shorter'),
        ({'StringEquals': {'sts:ExternalId': '12345678901'}}, 'numeric'),
        ({'StringEquals': {'sts:ExternalId': THIRD}}, 'numeric'),
        ({'StringLike': {'sts:ExternalId': 'vendor-*'}}, 'wildcards'),
        ({'StringEqualsIfExists': {'sts:ExternalId': 'a3f9c2e1-vendor-tenant'}}, 'IfExists'),
    ])
    def test_weak_external_id(self, cond, reason):
        r = _runRole(_role(_trust(THIRD, cond)), _ctx(), 'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId')
        assert r[0] == -1 and reason.lower() in r[1].lower()

    def test_org_account_and_self_not_flagged(self):
        ctx = _ctx(accounts=(MGMT, MEMBER, THIRD))
        assert _runRole(_role(_trust([f'arn:aws:iam::{THIRD}:role/Deployer', MEMBER])), ctx,
                        'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId') is None

    def test_principal_org_id_passes(self):
        r = _runRole(_role(_trust(THIRD, {'StringEquals': {'aws:PrincipalOrgID': ORG_ID}})), _ctx(),
                     'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId')
        assert r[0] == 1

    def test_unknown_org_membership_is_not_a_fail(self):
        ctx = _ctx(err='AccessDeniedException')
        r = _runRole(_role(_trust(THIRD)), ctx, 'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId')
        assert r[0] == 0 and 'unable to classify' in r[1]
        # The management account is always in the org, even without list_accounts.
        assert _runRole(_role(_trust(MGMT)), ctx, 'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId') is None

    def test_not_in_org_every_other_account_is_external(self):
        org = _session().client('organizations')
        st = Stubber(org)
        st.add_client_error('describe_organization', service_error_code='AWSOrganizationsNotInUseException',
                            http_status_code=400)
        st.activate()
        ctx = buildTrustContext(OrgData(org, MEMBER), MEMBER)
        r = _runRole(_role(_trust(THIRD)), ctx, 'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId')
        assert r[0] == -1

    def test_service_principal_ignored(self):
        trust = {'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
        assert _runRole(_role(trust), _ctx(), 'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId') is None

    def test_external_id_helper_strong(self):
        assert externalIdWeakness({'Condition': STRONG}, {THIRD}) is None


class TestThirdPartyRoleOverprivileged:
    def test_flag_fix(self):
        ctx = _ctx()
        trust = _trust(THIRD, STRONG)
        r = _runRole(_role(trust, attached=['AdministratorAccess']), ctx, 'ThirdPartyRoleOverprivileged',
                     'thirdPartyRoleOverprivileged')
        assert r[0] == -1 and 'AdministratorAccess' in r[1]
        r = _runRole(_role(trust, attached=['ReadOnlyAccess']), ctx, 'ThirdPartyRoleOverprivileged',
                     'thirdPartyRoleOverprivileged',
                     docs={'arn:aws:iam::aws:policy/ReadOnlyAccess': {'Statement': [
                         {'Effect': 'Allow', 'Action': ['s3:Get*', 'ec2:Describe*'], 'Resource': '*'}]}})
        assert r[0] == 1

    @pytest.mark.parametrize('doc', [
        {'Statement': [{'Effect': 'Allow', 'Action': 'iam:*', 'Resource': '*'}]},
        {'Statement': [{'Effect': 'Allow', 'Action': '*:*', 'Resource': '*'}]},
        {'Statement': [{'Effect': 'Allow', 'NotAction': 's3:*', 'Resource': '*'}]},
    ])
    def test_inline_admin_levels(self, doc):
        r = _runRole(_role(_trust(THIRD, STRONG), inline=[('vendor', doc)]), _ctx(),
                     'ThirdPartyRoleOverprivileged', 'thirdPartyRoleOverprivileged')
        assert r[0] == -1 and 'vendor (inline)' in r[1]

    def test_customer_managed_doc_from_prefetch(self):
        role = _role(_trust(THIRD, STRONG))
        role['AttachedManagedPolicies'] = [{'PolicyName': 'VendorFull', 'PolicyArn': f'arn:aws:iam::{MEMBER}:policy/VendorFull'}]
        r = _runRole(role, _ctx(), 'ThirdPartyRoleOverprivileged', 'thirdPartyRoleOverprivileged',
                     docs={f'arn:aws:iam::{MEMBER}:policy/VendorFull': {'Statement': [
                         {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}})
        assert r[0] == -1

    def test_intra_org_admin_role_not_flagged(self):
        ctx = _ctx(accounts=(MGMT, MEMBER, THIRD))
        assert _runRole(_role(_trust(THIRD), attached=['AdministratorAccess']), ctx,
                        'ThirdPartyRoleOverprivileged', 'thirdPartyRoleOverprivileged') is None

    def test_unknown_org_membership_is_not_a_fail(self):
        r = _runRole(_role(_trust(THIRD), attached=['AdministratorAccess']), _ctx(err='AccessDeniedException'),
                     'ThirdPartyRoleOverprivileged', 'thirdPartyRoleOverprivileged')
        assert r[0] == 0

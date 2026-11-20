"""
Regression tests for the low-severity IAM review findings (feature/wafs2027,
unit "iam"): SCP guardrail breadth, allow-list SCPs, region-deny operator
prefixes, Roles Anywhere / Control Tower / Identity Center "unable to
evaluate" paths, transient-error caching, ExternalId operators, OIDC sub
conditions in separate (ANDed) operator blocks and non-ClientError failures
of the trust-context Organizations reads.

Why Stubber and not the AWS Emulator: organizations.list_policies /
describe_policy / list_targets_for_policy / list_accounts /
list_aws_service_access_for_organization are NotImplemented in the emulator,
it has no Control Tower landing zone, no organization instance of IAM
Identity Center and no IAM Roles Anywhere trust anchors with arbitrary
source data, and it cannot inject throttling or connection errors. Every
call below is served by a botocore Stubber with real API shapes (an
unexpected call fails the test); no network is used.
"""
import datetime
import json
import os
import sys

import botocore
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from test_stub_iam_org import (Harness, _roots, _doc, _session, _org, FULL, ROOT_T, OU_T,  # noqa: E402
                               MGMT, MEMBER, MEMBER2, ORG_ID, ROOT_ID, OU_ID, stubTree, DEFAULT_TREE)
from test_stub_iam_org_hygiene import _acct, _accounts, _regional  # noqa: E402
from test_stub_iam_org_guardrails import INST  # noqa: E402
from services.iam.drivers.IamOrgData import (OrgData, denyIsUnconditionalGuardrail, scpGuardrails,  # noqa: E402
                                             guardrailCoverage)
from services.iam.drivers.IamSsoData import SsoData  # noqa: E402
from services.iam.drivers.IamTrust import buildTrustContext, externalIdWeakness  # noqa: E402
from services.iam.drivers.IamPolicyHelpers import evaluateOidcTrust  # noqa: E402


def _scp(h, *items, tree=DEFAULT_TREE, full=FULL):
    h.org.add_response('list_roots', _roots())
    h.policies('SERVICE_CONTROL_POLICY', [full] + list(items))
    if any(not managed and targets for _, _, managed, _, targets in items):
        stubTree(h, tree)


# --------------------------------------------------------------------------- #
# 1. Broad StringNot*/ArnNot* exceptions and PrincipalOrgID negation
# --------------------------------------------------------------------------- #
def _deny(cond, action='cloudtrail:StopLogging'):
    return {'Effect': 'Deny', 'Action': action, 'Resource': '*', 'Condition': cond}


class TestBroadExceptionIsNotGuardrail:
    @pytest.mark.parametrize('cond', [
        {'StringNotLike': {'aws:PrincipalArn': ['arn:aws:iam::*:role/*']}},
        {'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:user/*'}},
        {'ArnNotLike': {'aws:PrincipalArn': ['arn:aws:iam::*:role/BreakGlass', 'arn:aws:iam::*:*']}},
        {'StringNotLike': {'aws:PrincipalArn': '*'}},
        {'StringNotEquals': {'aws:PrincipalOrgID': ORG_ID}},
        {'StringNotEqualsIfExists': {'aws:PrincipalOrgID': ORG_ID}},
        # ANDed with a narrow exception: still never fires for org principals.
        {'StringNotEquals': {'aws:PrincipalOrgID': ORG_ID},
         'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/BreakGlass'}},
    ])
    def test_broad_exception_rejected(self, cond):
        assert denyIsUnconditionalGuardrail(_deny(cond)) is False

    @pytest.mark.parametrize('cond', [
        {'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/BreakGlass'}},
        {'StringNotLike': {'aws:PrincipalArn': ['arn:aws:iam::*:role/aws-reserved/*/AWSReservedSSO_Admin_*',
                                                'arn:aws:iam::*:role/OrgAutomation']}},
        {'StringNotEquals': {'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Admin'}},
        {'StringNotEqualsIfExists': {'aws:PrincipalTag/team': 'security'}},
    ])
    def test_narrow_exception_still_counts(self, cond):
        assert denyIsUnconditionalGuardrail(_deny(cond)) is True

    def test_check_fails_with_role_wide_exception(self):
        """scpNoSecurityServiceProtection: a Deny that exempts every role is
        reported as not denied (conditional), not as 'Denied ... by'."""
        stmt = {'Effect': 'Deny', 'Resource': '*',
                'Action': ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'guardduty:DeleteDetector',
                           'guardduty:Disassociate*', 'config:StopConfigurationRecorder',
                           'config:DeleteConfigurationRecorder', 'organizations:LeaveOrganization'],
                'Condition': {'StringNotLike': {'aws:PrincipalArn': ['arn:aws:iam::*:role/*']}}}
        h = Harness()
        _scp(h, ('p-secsvc001', 'SecSvc', False, _doc(stmt), [OU_T]))
        r = h.run('ScpNoSecurityServiceProtection', 'scpNoSecurityServiceProtection')
        assert r[0] == -1 and 'only denied under a narrowing condition' in r[1] and 'SecSvc' in r[1], r

        # FIX: exempt only the break-glass role.
        stmt['Condition'] = {'StringNotLike': {'aws:PrincipalArn': ['arn:aws:iam::*:role/BreakGlass']}}
        h = Harness()
        _scp(h, ('p-secsvc001', 'SecSvc', False, _doc(stmt), [OU_T]))
        r = h.run('ScpNoSecurityServiceProtection', 'scpNoSecurityServiceProtection')
        assert r[0] == 1 and 'SecSvc' in r[1], r

    def test_region_deny_with_role_wide_exception_is_not_restriction(self):
        stmt = {'Effect': 'Deny', 'NotAction': ['iam:*', 'sts:*'], 'Resource': '*',
                'Condition': {'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']},
                              'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/*'}}}
        assert 'restrictRegions' not in scpGuardrails({'Statement': [stmt]})
        stmt['Condition']['ArnNotLike'] = {'aws:PrincipalArn': 'arn:aws:iam::*:role/NetworkAdmin'}
        assert 'restrictRegions' in scpGuardrails({'Statement': [stmt]})

    def test_root_denial_with_role_exception_still_counts(self):
        """Exempting roles does not weaken a root-user denial (root is not a
        role); exempting a pattern that matches root does."""
        stmt = {'Effect': 'Deny', 'Action': '*', 'Resource': '*',
                'Condition': {'ArnLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'},
                              'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/*'}}}
        assert 'denyRoot' in scpGuardrails({'Statement': [stmt]})
        stmt['Condition']['ArnNotLike'] = {'aws:PrincipalArn': 'arn:aws:iam::*:*'}
        assert 'denyRoot' not in scpGuardrails({'Statement': [stmt]})

    def test_resource_scoped_deny_counts(self):
        """Locked behaviour: a Deny scoped to the organization trail's ARN is
        how customers protect that trail; it counts as coverage for the
        action (resource scope is not a principal exception)."""
        stmt = {'Effect': 'Deny', 'Action': ['cloudtrail:StopLogging'],
                'Resource': 'arn:aws:cloudtrail:*:*:trail/org-trail'}
        cov = guardrailCoverage([{'Name': 'P', 'Content': {'Statement': [stmt]}}],
                                [('ct', [['cloudtrail:StopLogging']])])
        assert cov['met'] == {'ct': {'P'}}


# --------------------------------------------------------------------------- #
# 2. ForAnyValue:/ForAllValues: prefix on the region condition
# --------------------------------------------------------------------------- #
class TestRegionOperatorPrefix:
    @pytest.mark.parametrize('op', ['ForAnyValue:StringNotEquals', 'ForAllValues:StringNotEquals',
                                    'ForAnyValue:StringNotLike'])
    def test_prefixed_region_deny_is_restriction(self, op):
        stmt = {'Effect': 'Deny', 'NotAction': ['iam:*', 'sts:*'], 'Resource': '*',
                'Condition': {op: {'aws:RequestedRegion': ['eu-west-1', 'eu-central-1']}}}
        assert 'restrictRegions' in scpGuardrails({'Statement': [stmt]})

    def test_positive_operator_still_rejected(self):
        stmt = {'Effect': 'Deny', 'NotAction': ['iam:*'], 'Resource': '*',
                'Condition': {'ForAnyValue:StringEquals': {'aws:RequestedRegion': ['ap-east-1']}}}
        assert 'restrictRegions' not in scpGuardrails({'Statement': [stmt]})


# --------------------------------------------------------------------------- #
# 3. Allow-list SCP strategy (FullAWSAccess replaced on an OU)
# --------------------------------------------------------------------------- #
ACCT_T = (MEMBER, 'app', 'ACCOUNT')
MGMT_T = (MGMT, 'mgmt', 'ACCOUNT')
FULL_EVERYWHERE_BUT_OU = ('p-FullAWSAccess', 'FullAWSAccess', True, None, [ROOT_T, ACCT_T, MGMT_T])
ALLOW_LIST = {'Effect': 'Allow', 'Action': ['ec2:*', 's3:*', 'lambda:*', 'logs:*'], 'Resource': '*'}


class TestAllowListScp:
    def test_not_allowed_actions_are_implicitly_denied(self):
        # FLAG: FullAWSAccess everywhere, an unrelated customer SCP.
        h = Harness()
        _scp(h, ('p-other0001', 'Other', False, _doc({'Effect': 'Deny', 'Action': 'ec2:DeleteVpc', 'Resource': '*'}),
                 [OU_T]))
        assert h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')[0] == -1

        # FIX: the OU uses an allow-list SCP instead of FullAWSAccess; IAM
        # user creation is not allowed there, so it is implicitly denied.
        h = Harness()
        _scp(h, ('p-allowlst1', 'AllowList', False, _doc(ALLOW_LIST), [OU_T]), full=FULL_EVERYWHERE_BUT_OU)
        r = h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')
        assert r[0] == 1 and 'not allowed by the SCPs attached to OU Workloads' in r[1], r

        h = Harness()
        _scp(h, ('p-allowlst1', 'AllowList', False, _doc(ALLOW_LIST), [OU_T]), full=FULL_EVERYWHERE_BUT_OU)
        assert h.run('ScpNoSecurityServiceProtection', 'scpNoSecurityServiceProtection')[0] == 1

    def test_allowed_action_is_not_implicitly_denied(self):
        allowIam = dict(ALLOW_LIST, Action=ALLOW_LIST['Action'] + ['iam:*'])
        h = Harness()
        _scp(h, ('p-allowlst1', 'AllowList', False, _doc(allowIam), [OU_T]), full=FULL_EVERYWHERE_BUT_OU)
        assert h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')[0] == -1

    def test_conditional_allow_counts_as_allowed(self):
        """Fail closed: an Allow under a condition may allow the action, so
        it is never treated as an implicit deny."""
        allowIam = {'Effect': 'Allow', 'Action': 'iam:*', 'Resource': '*',
                    'Condition': {'StringEquals': {'aws:RequestedRegion': 'us-east-1'}}}
        h = Harness()
        _scp(h, ('p-allowlst1', 'AllowList', False, _doc(ALLOW_LIST, allowIam), [OU_T]), full=FULL_EVERYWHERE_BUT_OU)
        assert h.run('ScpNoIamUserCreationDeny', 'scpNoIamUserCreationDeny')[0] == -1

    def test_best_practices_priv_esc_via_allow_list(self):
        rootDeny = {'Effect': 'Deny', 'Action': '*', 'Resource': '*',
                    'Condition': {'ArnLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'}}}
        regionDeny = {'Effect': 'Deny', 'NotAction': ['iam:*', 'sts:*'], 'Resource': '*',
                      'Condition': {'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']}}}
        h = Harness()
        _scp(h, ('p-allowlst1', 'AllowList', False, _doc(ALLOW_LIST, rootDeny, regionDeny), [OU_T]),
             full=FULL_EVERYWHERE_BUT_OU)
        r = h.run('ScpBestPractices', 'scpBestPractices')
        assert r[0] == 1, r


# --------------------------------------------------------------------------- #
# 4. Roles Anywhere: no validity date read must not PASS
# --------------------------------------------------------------------------- #
ACCOUNT = MEMBER


def _raRun(source):
    from services.iam.drivers.IamAccount import IamAccount
    from utils.Config import Config
    Config.init()
    Config.set('stsInfo', {'Account': ACCOUNT})
    Config.set('REGIONS_SELECTED', ['us-east-1'])
    s = _session()
    ra = s.client('rolesanywhere')
    st = Stubber(ra)
    st.add_response('list_trust_anchors', {'trustAnchors': [{
        'trustAnchorId': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'name': 'anchor', 'enabled': True,
        'trustAnchorArn': f'arn:aws:rolesanywhere:us-east-1:{ACCOUNT}:trust-anchor/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        'source': source}]})
    st.add_response('list_crls', {'crls': []})
    pca = s.client('acm-pca')
    pst = Stubber(pca)
    if source.get('sourceType') == 'AWS_ACM_PCA':
        pst.add_response('describe_certificate_authority', {'CertificateAuthority': {
            'Arn': source['sourceData']['acmPcaArn'], 'Status': 'PENDING_CERTIFICATE'}},
            {'CertificateAuthorityArn': source['sourceData']['acmPcaArn']})
    st.activate()
    pst.activate()
    h = Harness(caller=ACCOUNT)
    acc = h.drv
    acc._regionalClient = lambda svc, region: {'rolesanywhere': ra, 'acm-pca': pca}[svc]
    acc._checkRolesAnywhereTrustAnchorCertExpiring()
    st.assert_no_pending_responses()
    pst.assert_no_pending_responses()
    return acc.results['rolesAnywhereTrustAnchorCertExpiring']


class TestRolesAnywhereUnevaluated:
    def test_bundle_without_certificate(self):
        r = _raRun({'sourceType': 'CERTIFICATE_BUNDLE', 'sourceData': {'x509CertificateData': 'not a pem'}})
        assert r[0] == 0 and 'no certificate found in bundle' in r[1], r

    def test_unknown_source_type(self):
        r = _raRun({'sourceType': 'SELF_SIGNED_REPOSITORY', 'sourceData': {'x509CertificateData': 'opaque'}})
        assert r[0] == 0 and 'SELF_SIGNED_REPOSITORY' in r[1], r

    def test_pca_without_validity_date(self):
        arn = f'arn:aws:acm-pca:us-east-1:{ACCOUNT}:certificate-authority/11111111-2222-3333-4444-555555555555'
        r = _raRun({'sourceType': 'AWS_ACM_PCA', 'sourceData': {'acmPcaArn': arn}})
        assert r[0] == 0 and 'no validity date' in r[1], r


# --------------------------------------------------------------------------- #
# 5. accountNotVended: Control Tower home Region not scanned / unreadable
# --------------------------------------------------------------------------- #
def _serviceAccess(h, principals=(), err=None):
    if err:
        h.org.add_client_error('list_aws_service_access_for_organization', service_error_code=err,
                               http_status_code=400)
    else:
        h.org.add_response('list_aws_service_access_for_organization', {'EnabledServicePrincipals': [
            {'ServicePrincipal': p, 'DateEnabled': datetime.datetime(2024, 1, 1)} for p in principals]})


class TestAccountNotVendedControlTower:
    KEY = 'accountNotVended'

    def _run(self, ct, principals=(), err=None, access=True):
        clients, stubs = _regional(controltower=ct)
        h = Harness(regionalClients=clients)
        _accounts(h, _acct(MGMT, 'mgmt'), _acct(MEMBER, 'legacy-app', 'INVITED'))
        if access:
            _serviceAccess(h, principals, err)
        r = h.run('AccountNotVended', self.KEY)
        stubs['controltower'].assert_no_pending_responses()
        return r

    def test_control_tower_home_region_not_scanned(self):
        r = self._run([('list_landing_zones', {'landingZones': []}, {})], ['controltower.amazonaws.com'])
        assert r[0] == 0 and r[1].startswith('Unable to evaluate') and 'home Region' in r[1], r

    def test_no_control_tower_is_fail(self):
        r = self._run([('list_landing_zones', {'landingZones': []}, {})], ['sso.amazonaws.com'])
        assert r[0] == -1 and 'legacy-app' in r[1], r

    def test_landing_zone_unreadable_with_control_tower(self):
        r = self._run([('list_landing_zones', 'AccessDeniedException', None)], ['controltower.amazonaws.com'])
        assert r[0] == 0 and 'AccessDeniedException' in r[1], r

    def test_landing_zone_unreadable_without_control_tower_is_fail(self):
        r = self._run([('list_landing_zones', 'AccessDeniedException', None)], [])
        assert r[0] == -1, r

    def test_landing_zone_and_service_access_unreadable(self):
        r = self._run([('list_landing_zones', 'AccessDeniedException', None)], err='AccessDeniedException')
        assert r[0] == 0 and r[1].startswith('Unable to evaluate'), r

    def test_enrollment_unreadable_is_unable(self):
        lz = {'landingZones': [{'arn': f'arn:aws:controltower:us-east-1:{MGMT}:landingzone/1A2B3C4D5E6F7G8H'}]}
        r = self._run([('list_landing_zones', lz, {}), ('list_enabled_baselines', 'AccessDeniedException', None)],
                      access=False)
        assert r[0] == 0 and 'enrollment unreadable' in r[1] and 'AccessDeniedException' in r[1], r


# --------------------------------------------------------------------------- #
# 6. Identity Center: member account sees the org instance
# --------------------------------------------------------------------------- #
class TestSsoMemberSeesOrgInstance:
    @pytest.mark.parametrize('method,key', [
        ('SsoAssignmentsToIndividualUsers', 'ssoAssignmentsToIndividualUsers'),
        ('SsoPermissionSetOverprivileged', 'ssoPermissionSetOverprivileged'),
    ])
    def test_member_access_denied_is_not_evaluable(self, method, key):
        client = _session().client('sso-admin')
        st = Stubber(client)
        st.add_response('list_instances', {'Instances': [{
            'InstanceArn': INST, 'IdentityStoreId': 'd-1234567890', 'OwnerAccountId': MGMT, 'Status': 'ACTIVE'}]})
        st.add_client_error('list_permission_sets', service_error_code='AccessDeniedException', http_status_code=400)
        st.activate()
        h = Harness(caller=MEMBER, regionalClients={'sso-admin': client})
        assert h.run(method, key) == [0, 'Not evaluable from member account']
        st.assert_no_pending_responses()

    def test_management_access_denied_stays_unable(self):
        client = _session().client('sso-admin')
        st = Stubber(client)
        st.add_response('list_instances', {'Instances': [{
            'InstanceArn': INST, 'IdentityStoreId': 'd-1234567890', 'OwnerAccountId': MGMT, 'Status': 'ACTIVE'}]})
        st.add_client_error('list_permission_sets', service_error_code='AccessDeniedException', http_status_code=400)
        st.activate()
        h = Harness(caller=MGMT, regionalClients={'sso-admin': client})
        assert h.run('SsoAssignmentsToIndividualUsers', 'ssoAssignmentsToIndividualUsers') == \
            [0, 'Unable to evaluate (AccessDeniedException)']


# --------------------------------------------------------------------------- #
# 7. Transient errors are not cached
# --------------------------------------------------------------------------- #
class TestTransientNotCached:
    def test_orgdata_policies_retry_after_throttle(self):
        org = _session().client('organizations')
        st = Stubber(org)
        st.add_client_error('list_policies', service_error_code='TooManyRequestsException', http_status_code=400)
        st.add_response('list_policies', {'Policies': []}, {'Filter': 'SERVICE_CONTROL_POLICY'})
        st.activate()
        od = OrgData(org, MGMT)
        assert od.policies('SERVICE_CONTROL_POLICY') == (None, 'TooManyRequestsException')
        assert od.policies('SERVICE_CONTROL_POLICY') == ([], None)
        st.assert_no_pending_responses()

    def test_orgdata_access_denied_is_cached(self):
        org = _session().client('organizations')
        st = Stubber(org)
        st.add_client_error('list_policies', service_error_code='AccessDeniedException', http_status_code=400)
        st.activate()
        od = OrgData(org, MGMT)
        assert od.policies('SERVICE_CONTROL_POLICY') == (None, 'AccessDeniedException')
        assert od.policies('SERVICE_CONTROL_POLICY') == (None, 'AccessDeniedException')
        st.assert_no_pending_responses()

    def test_orgdata_list_children_retry_after_throttle(self):
        org = _session().client('organizations')
        st = Stubber(org)
        st.add_client_error('list_accounts_for_parent', service_error_code='TooManyRequestsException',
                            http_status_code=400)
        st.add_response('list_accounts_for_parent', {'Accounts': []}, {'ParentId': ROOT_ID})
        st.activate()
        od = OrgData(org, MGMT)
        with pytest.raises(botocore.exceptions.ClientError):
            od.listChildren('list_accounts_for_parent', 'Accounts', ParentId=ROOT_ID)
        assert od.listChildren('list_accounts_for_parent', 'Accounts', ParentId=ROOT_ID) == []
        st.assert_no_pending_responses()

    def test_ssodata_retry_after_throttle(self):
        client = _session().client('sso-admin')
        st = Stubber(client)
        ps = 'arn:aws:sso:::permissionSet/ssoins-1111222233334444/ps-1111111111111111'
        st.add_client_error('describe_permission_set', service_error_code='ThrottlingException', http_status_code=400)
        st.add_response('describe_permission_set', {'PermissionSet': {'Name': 'Admin', 'PermissionSetArn': ps}},
                        {'InstanceArn': INST, 'PermissionSetArn': ps})
        st.activate()
        sd = SsoData(None, ['us-east-1'])
        inst = {'Client': client, 'Instance': {'InstanceArn': INST}}
        assert sd.permissionSet(inst, ps) == (None, 'ThrottlingException')
        assert sd.permissionSet(inst, ps)[0]['Name'] == 'Admin'
        st.assert_no_pending_responses()


# --------------------------------------------------------------------------- #
# 8. ExternalId operators
# --------------------------------------------------------------------------- #
class TestExternalIdOperators:
    @pytest.mark.parametrize('cond', [
        {'StringEqualsIgnoreCase': {'sts:ExternalId': 'Abcdefgh-123-xyz'}},
        {'ForAnyValue:StringEquals': {'sts:ExternalId': 'a3f9c2e1-vendor-tenant-7781'}},
        # ANDed: the strong StringEquals pins the value whatever the other says.
        {'StringLike': {'sts:ExternalId': '*'}, 'StringEquals': {'sts:ExternalId': 'a3f9c2e1-vendor-tenant-7781'}},
        # IfExists pins the value when present; the StringLike requires presence.
        {'StringLike': {'sts:ExternalId': 'vendor-*'},
         'StringEqualsIfExists': {'sts:ExternalId': 'a3f9c2e1-vendor-tenant-7781'}},
    ])
    def test_enforced(self, cond):
        assert externalIdWeakness({'Condition': cond}, {'999988887777'}) is None

    @pytest.mark.parametrize('cond,reason', [
        ({'ForAllValues:StringEquals': {'sts:ExternalId': 'a3f9c2e1-vendor-tenant-7781'}}, 'not enforced'),
        ({'StringNotEquals': {'sts:ExternalId': 'a3f9c2e1-vendor-tenant-7781'}}, 'unsupported operator'),
        ({'StringEqualsIgnoreCase': {'sts:ExternalId': 'short'}}, 'shorter'),
        ({'StringLike': {'sts:ExternalId': 'vendor-*'}, 'StringNotEquals': {'sts:ExternalId': 'a3f9c2e1-x-7781'}},
         'wildcards'),
    ])
    def test_weak(self, cond, reason):
        r = externalIdWeakness({'Condition': cond}, {'999988887777'})
        assert r is not None and reason.lower() in r.lower(), r


# --------------------------------------------------------------------------- #
# 9. Non-ClientError from Organizations must not abort the IAM scan
# --------------------------------------------------------------------------- #
class _RaisingOrg:
    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    def describe_organization(self):
        self.calls += 1
        raise self.exc


class TestTrustContextBotoCoreError:
    @pytest.mark.parametrize('exc,name', [
        (botocore.exceptions.EndpointConnectionError(endpoint_url='https://organizations.us-east-1.amazonaws.com'),
         'EndpointConnectionError'),
        (botocore.exceptions.NoCredentialsError(), 'NoCredentialsError'),
        (botocore.exceptions.ReadTimeoutError(endpoint_url='https://organizations.us-east-1.amazonaws.com'),
         'ReadTimeoutError'),
    ])
    def test_context_records_reason(self, exc, name):
        ctx = buildTrustContext(OrgData(_RaisingOrg(exc), MEMBER), MEMBER)
        assert ctx['inOrg'] is None and ctx['orgAccounts'] is None and name in ctx['reason'], ctx

    def test_connection_error_not_cached(self):
        org = _RaisingOrg(botocore.exceptions.EndpointConnectionError(endpoint_url='https://x'))
        od = OrgData(org, MEMBER)
        od.organization()
        od.organization()
        assert org.calls == 2


# --------------------------------------------------------------------------- #
# 10. OIDC sub values in separate (ANDed) operator blocks
# --------------------------------------------------------------------------- #
GH = 'token.actions.githubusercontent.com'


def _oidcTrust(cond):
    return {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
        'Principal': {'Federated': f'arn:aws:iam::{MEMBER}:oidc-provider/{GH}'}, 'Condition': cond}]}


class TestOidcAndedBlocks:
    def test_pinned_block_restricts(self):
        findings, _ = evaluateOidcTrust(_oidcTrust({
            'StringLike': {f'{GH}:sub': 'repo:*'},
            'StringEquals': {f'{GH}:sub': 'repo:my-org/app:ref:refs/heads/main', f'{GH}:aud': 'sts.amazonaws.com'}}))
        assert findings == []

    def test_loose_only_still_flagged(self):
        findings, _ = evaluateOidcTrust(_oidcTrust({
            'StringLike': {f'{GH}:sub': 'repo:*'}, 'StringEquals': {f'{GH}:aud': 'sts.amazonaws.com'}}))
        assert findings and 'repo:*' in findings[0]

    def test_one_loose_value_in_a_block_is_flagged(self):
        """Values inside one block are alternatives (OR): one loose value lets
        any identity in."""
        findings, _ = evaluateOidcTrust(_oidcTrust({
            'StringLike': {f'{GH}:sub': ['repo:my-org/app:*', 'repo:*']}}))
        assert findings and 'repo:*' in findings[0]

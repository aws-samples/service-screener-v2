"""
Regression tests for confirmed review findings in services/iam (fix/iam).

Each test class names the finding it locks. Every "flag" assertion below
failed on the code before the fix (it returned PASS, or FAIL where the state is
unknown); the "fix" assertions prove the genuinely good state still PASSes.

botocore Stubber around real boto3 clients (real API shapes, fake credentials,
no network). The emulator cannot model these cases: it has one account, a
fixed organization, no list_policies / list_accounts_for_parent, and caches
the IAM credential report.
"""
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from test_stub_iam_org import (Harness, _roots, _doc, _session, FULL, ROOT_T, OU_T, ROOT_ID, OU_ID,  # noqa: E402
                               MGMT, MEMBER, ORG_ID, DENY_ROOT, DENY_REGION, DENY_PRIVESC, DEFAULT_TREE, stubTree)
from test_stub_iam_org_guardrails import THIRD, _trust, _ctx, _role, _runRole, STRONG  # noqa: E402
from test_stub_iam_identity3 import _row, _detail, _user, ALLOW_S3, DENY_OUTSIDE, ACCOUNT  # noqa: E402
from services.iam.drivers.IamOrgData import scpGuardrails, SCP_GUARDRAILS  # noqa: E402
from services.iam.drivers.IamTrust import crossAccountTrusts, orgConditionScope  # noqa: E402
from services.iam.drivers import IamPolicyHelpers as H  # noqa: E402


# =========================================================================== #
# Finding: scpGuardrails ignored Action scope and narrowing conditions
# =========================================================================== #
# AWS example SCP "Prevent creating root user access keys".
ROOT_ACCESS_KEY_ONLY = {'Effect': 'Deny', 'Action': 'iam:CreateAccessKey', 'Resource': '*',
                        'Condition': {'StringLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'}}}
REGION_RUNINSTANCES_ONLY = {'Effect': 'Deny', 'Action': 'ec2:RunInstances', 'Resource': '*',
                            'Condition': {'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']}}}
PRIVESC_ROOT_ONLY = {'Effect': 'Deny', 'Action': ['iam:CreatePolicyVersion', 'iam:AttachRolePolicy'], 'Resource': '*',
                     'Condition': {'StringLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'}}}
# AWS example SCP "Deny access to AWS based on the requested AWS Region"
# (abridged NotAction of global services + break-glass role exception).
AWS_REGION_DENY = {'Effect': 'Deny', 'Resource': '*',
                   'NotAction': ['a4b:*', 'acm:*', 'budgets:*', 'ce:*', 'cloudfront:*', 'config:*', 'cur:*',
                                 'globalaccelerator:*', 'health:*', 'iam:*', 'kms:*', 'organizations:*',
                                 'route53:*', 's3:GetAccountPublic*', 's3:ListAllMyBuckets', 'shield:*', 'sts:*',
                                 'support:*', 'trustedadvisor:*', 'waf:*', 'wafv2:*'],
                   'Condition': {'StringNotEquals': {'aws:RequestedRegion': ['eu-central-1', 'eu-west-1']},
                                 'ArnNotLike': {'aws:PrincipalARN': 'arn:aws:iam::*:role/BreakGlass'}}}


class TestScpGuardrailsScope:
    def test_finding_scenario_is_not_full_guardrails(self):
        """Old code returned all three guardrails for these narrow Denies."""
        doc = {'Statement': [ROOT_ACCESS_KEY_ONLY, REGION_RUNINSTANCES_ONLY, PRIVESC_ROOT_ONLY]}
        assert scpGuardrails(doc) == set()

    def test_deny_root_requires_all_actions(self):
        assert 'denyRoot' not in scpGuardrails({'Statement': [ROOT_ACCESS_KEY_ONLY]})
        assert 'denyRoot' in scpGuardrails({'Statement': [DENY_ROOT]})

    def test_deny_root_not_on_one_resource_or_narrowed(self):
        oneBucket = dict(DENY_ROOT, Resource='arn:aws:s3:::logs/*')
        assert 'denyRoot' not in scpGuardrails({'Statement': [oneBucket]})
        regional = dict(DENY_ROOT, Condition={'ArnLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'},
                                              'StringEquals': {'aws:RequestedRegion': 'us-east-1'}})
        assert 'denyRoot' not in scpGuardrails({'Statement': [regional]})
        withException = dict(DENY_ROOT, Condition={'ArnLike': {'aws:PrincipalArn': 'arn:aws:iam::*:root'},
                                                   'Bool': {'aws:PrincipalIsAWSService': 'false'}})
        assert 'denyRoot' in scpGuardrails({'Statement': [withException]})

    def test_deny_root_specific_account_only_covers_that_account(self):
        one = dict(DENY_ROOT, Condition={'ArnEquals': {'aws:PrincipalArn': f'arn:aws:iam::{MEMBER}:root'}})
        assert 'denyRoot' in scpGuardrails({'Statement': [one]}, [MEMBER])
        assert 'denyRoot' not in scpGuardrails({'Statement': [one]}, [MEMBER, '444455556666'])

    def test_region_requires_all_regional_actions(self):
        assert 'restrictRegions' not in scpGuardrails({'Statement': [REGION_RUNINSTANCES_ONLY]})
        assert scpGuardrails({'Statement': [AWS_REGION_DENY]}) == {'restrictRegions'}
        assert scpGuardrails({'Statement': [DENY_REGION]}) == {'restrictRegions'}

    def test_region_not_like_star_denies_nothing(self):
        st = dict(DENY_REGION, Condition={'StringNotLike': {'aws:RequestedRegion': '*'}})
        assert 'restrictRegions' not in scpGuardrails({'Statement': [st]})

    def test_region_with_positive_narrowing_condition(self):
        st = dict(DENY_REGION, Condition={'StringNotEquals': {'aws:RequestedRegion': ['us-east-1']},
                                          'StringEquals': {'aws:PrincipalTag/team': 'sandbox'}})
        assert 'restrictRegions' not in scpGuardrails({'Statement': [st]})

    def test_privesc_requires_unconditional_deny(self):
        assert 'preventPrivEscalation' not in scpGuardrails({'Statement': [PRIVESC_ROOT_ONLY]})
        assert scpGuardrails({'Statement': [DENY_PRIVESC]}) == {'preventPrivEscalation'}
        exc = dict(DENY_PRIVESC, Condition={'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::*:role/IamAdmin'}})
        assert scpGuardrails({'Statement': [exc]}) == {'preventPrivEscalation'}

    def test_privesc_on_one_role_only_is_not_a_guardrail(self):
        one = dict(DENY_PRIVESC, Resource='arn:aws:iam::*:role/OrgAdmin')
        assert 'preventPrivEscalation' not in scpGuardrails({'Statement': [one]})
        allRoles = dict(DENY_PRIVESC, Resource='arn:aws:iam::*:role/*')
        assert 'preventPrivEscalation' in scpGuardrails({'Statement': [allRoles]})

    def test_quarantine_on_one_resource_is_not_every_guardrail(self):
        st = {'Effect': 'Deny', 'Action': '*', 'Resource': 'arn:aws:s3:::x'}
        assert scpGuardrails({'Statement': [st]}) != set(SCP_GUARDRAILS)

    def _run(self, *stmts):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.policies('SERVICE_CONTROL_POLICY', [FULL, ('p-guard0001', 'Guards', False, _doc(*stmts), [ROOT_T])])
        stubTree(h, DEFAULT_TREE)
        return h.run('ScpBestPractices', 'scpBestPractices')

    def test_check_flag_fix(self):
        """Old code: PASS 'All 2 OUs/member accounts have ...' for the narrow set."""
        r = self._run(ROOT_ACCESS_KEY_ONLY, REGION_RUNINSTANCES_ONLY, PRIVESC_ROOT_ONLY)
        assert r[0] == -1, r
        assert 'root user denial: missing on 2' in r[1] and 'region restriction: missing on 2' in r[1]
        assert 'privilege escalation prevention: missing on 2' in r[1]
        r = self._run(DENY_ROOT, AWS_REGION_DENY, DENY_PRIVESC)
        assert r[0] == 1 and 'All 2 OUs/member accounts' in r[1], r

    def test_check_specific_root_arn_of_member(self):
        """A literal root ARN of the only member account covers the OU and the account."""
        lit = dict(DENY_ROOT, Condition={'StringEquals': {'aws:PrincipalArn': f'arn:aws:iam::{MEMBER}:root'}})
        r = self._run(lit, AWS_REGION_DENY, DENY_PRIVESC)
        assert r[0] == 1, r
        other = dict(DENY_ROOT, Condition={'StringEquals': {'aws:PrincipalArn': 'arn:aws:iam::444455556666:root'}})
        r = self._run(other, AWS_REGION_DENY, DENY_PRIVESC)
        assert r[0] == -1 and 'root user denial: missing on 2' in r[1], r


# =========================================================================== #
# Finding: any describe_organization error was treated as "no organization"
# =========================================================================== #
def _sirClient(items=()):
    c = _session().client('security-ir')
    st = Stubber(c)
    st.add_response('list_memberships', {'items': list(items)}, {})
    st.activate()
    return c, st


class TestOrgStateUnknown:
    def test_sir_access_denied_is_unable_to_evaluate(self):
        """Old code: [-1, 'No active AWS Security Incident Response membership ...']."""
        c, st = _sirClient()
        h = Harness(orgErr='AccessDeniedException', caller=MEMBER, regionalClients={'security-ir': c})
        assert h.run('SirMembershipMissing', 'sirMembershipMissing') == [0, 'Unable to evaluate (AccessDeniedException)']
        st.assert_no_pending_responses()

    def test_sir_standalone_still_flags_and_passes(self):
        c, _ = _sirClient()
        h = Harness(orgErr='AWSOrganizationsNotInUseException', caller=MEMBER, regionalClients={'security-ir': c})
        assert h.run('SirMembershipMissing', 'sirMembershipMissing')[0] == -1
        member = {'membershipId': 'm-abcdefghij12', 'accountId': MEMBER, 'region': 'us-east-1',
                  'membershipArn': f'arn:aws:security-ir:us-east-1:{MEMBER}:membership/m-abcdefghij12',
                  'membershipStatus': 'Active'}
        c, _ = _sirClient([member])
        h = Harness(orgErr='AWSOrganizationsNotInUseException', caller=MEMBER, regionalClients={'security-ir': c})
        assert h.run('SirMembershipMissing', 'sirMembershipMissing')[0] == 1

    def test_cost_allocation_tags_access_denied(self):
        """Old code evaluated the member account as a payer (no ce stub -> would call CE)."""
        h = Harness(orgErr='AccessDeniedException', caller=MEMBER)
        assert h.run('CostAllocationTagsNotActivated', 'costAllocationTagsNotActivated') == \
            [0, 'Unable to evaluate (AccessDeniedException)']

    def test_cost_allocation_tags_standalone_evaluated(self):
        ce = _session().client('ce')
        st = Stubber(ce)
        st.add_response('list_cost_allocation_tags', {'CostAllocationTags': [
            {'TagKey': 'Owner', 'Type': 'UserDefined', 'Status': 'Active'}]}, {'Status': 'Active', 'Type': 'UserDefined'})
        st.activate()
        h = Harness(orgErr='AWSOrganizationsNotInUseException', caller=MEMBER, regionalClients={'ce': ce})
        assert h.run('CostAllocationTagsNotActivated', 'costAllocationTagsNotActivated')[0] == 1

    @pytest.mark.parametrize('method,key', [
        ('HasOrganization', 'hasOrganization'),
        ('ControlTowerLandingZoneDrift', 'controlTowerLandingZoneDrift'),
        ('HealthOrgViewDisabled', 'healthOrgViewDisabled'),
    ])
    def test_other_org_branching_checks(self, method, key):
        h = Harness(orgErr='AccessDeniedException', caller=MEMBER)
        assert h.run(method, key) == [0, 'Unable to evaluate (AccessDeniedException)']

    def test_has_organization_standalone_still_fails(self):
        h = Harness(orgErr='AWSOrganizationsNotInUseException', caller=MEMBER)
        assert h.run('HasOrganization', 'hasOrganization')[0] == -1


# =========================================================================== #
# Finding: any aws:PrincipalOrgID condition counted as "restricted to our org"
# =========================================================================== #
VENDOR_ORG = 'o-vendor9999'
ADMIN = ('AdministratorAccess',)


class TestOrgConditionMustNameOwnOrg:
    @pytest.mark.parametrize('cond', [
        {'StringEquals': {'aws:PrincipalOrgID': VENDOR_ORG}},
        {'StringLike': {'aws:PrincipalOrgID': '*'}},
        {'StringLike': {'aws:PrincipalOrgID': 'o-*'}},
        {'StringEqualsIfExists': {'aws:PrincipalOrgID': ORG_ID}},
        {'StringEquals': {'aws:PrincipalOrgID': [ORG_ID, VENDOR_ORG]}},
        {'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': 'o-*/*'}},
        {'ForAllValues:StringLike': {'aws:PrincipalOrgPaths': f'{ORG_ID}/*'}},
        {'StringNotEquals': {'aws:PrincipalOrgID': ORG_ID}},
    ])
    def test_not_own_org(self, cond):
        """Old code: PASS for both checks (admin role trusted by the vendor)."""
        ctx = _ctx()
        r = _runRole(_role(_trust(THIRD, cond)), ctx, 'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId')
        assert r[0] == -1, r
        r = _runRole(_role(_trust(THIRD, cond), attached=ADMIN), ctx, 'ThirdPartyRoleOverprivileged',
                     'thirdPartyRoleOverprivileged')
        assert r[0] == -1 and 'AdministratorAccess' in r[1], r

    @pytest.mark.parametrize('cond', [
        {'StringEquals': {'aws:PrincipalOrgID': ORG_ID}},
        {'StringLike': {'aws:PrincipalOrgID': ORG_ID}},
        {'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': f'{ORG_ID}/r-ab12/*'}},
        {'StringEquals': {'aws:PrincipalOrgPaths': f'{ORG_ID}/r-ab12/{OU_ID}/'}},
    ])
    def test_own_org_passes(self, cond):
        ctx = _ctx()
        r = _runRole(_role(_trust(THIRD, cond)), ctx, 'ThirdPartyRoleNoExternalId', 'thirdPartyRoleNoExternalId')
        assert r[0] == 1, r
        r = _runRole(_role(_trust(THIRD, cond), attached=ADMIN), ctx, 'ThirdPartyRoleOverprivileged',
                     'thirdPartyRoleOverprivileged')
        assert r == [1, 'Admin-level role is not trusted by accounts outside the organization'], r

    def test_context_stores_own_org_id(self):
        assert _ctx()['orgId'] == ORG_ID

    def test_unknown_own_org_id_is_info(self):
        ctx = dict(_ctx(), orgId=None)
        t = crossAccountTrusts(_trust(THIRD, {'StringEquals': {'aws:PrincipalOrgID': ORG_ID}}), ctx)
        assert t[0]['class'] == 'unknown' and t[0]['orgConditioned'] is False
        r = _runRole(_role(_trust(THIRD, {'StringEquals': {'aws:PrincipalOrgID': ORG_ID}}), attached=ADMIN), ctx,
                     'ThirdPartyRoleOverprivileged', 'thirdPartyRoleOverprivileged')
        assert r[0] == 0, r

    def test_standalone_account_org_condition_names_another_org(self):
        ctx = {'self': MEMBER, 'orgAccounts': None, 'inOrg': False, 'mgmt': None, 'orgId': None, 'reason': None}
        t = crossAccountTrusts(_trust(THIRD, {'StringEquals': {'aws:PrincipalOrgID': VENDOR_ORG}}), ctx)
        assert t[0]['class'] == 'external' and t[0]['orgConditioned'] is False

    def test_scope_helper(self):
        assert orgConditionScope({'Condition': {'StringEquals': {'aws:PrincipalOrgID': ORG_ID}}}, ORG_ID) == 'own'
        assert orgConditionScope({'Condition': {'StringEquals': {'aws:PrincipalOrgID': ORG_ID}}}, None) == 'unknown'
        assert orgConditionScope({'Condition': STRONG}, ORG_ID) is None


# =========================================================================== #
# Finding: any permissions boundary was a PASS for longTermKeyNotContained
# =========================================================================== #
BOUNDARY = f'arn:aws:iam::{ACCOUNT}:policy/boundary'
ADMIN_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
ADMIN_DOC = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}


class TestBoundaryMustBeNetworkContained:
    def _run(self, boundary, policyMap=None, inline=None, stubs=None):
        u, stub = _user(_row('ci-bot'), _detail('ci-bot', inline=inline or [{'PolicyName': 's3', 'PolicyDocument': ALLOW_S3}],
                                               boundary=boundary), policyMap=policyMap)
        for op, resp, params in (stubs or []):
            if isinstance(resp, str):
                stub.add_client_error(op, resp, expected_params=params)
            else:
                stub.add_response(op, resp, params)
        u._checkLongTermKeyNotContained()
        stub.assert_no_pending_responses()
        return u.results['longTermKeyNotContained']

    def test_admin_boundary_fails(self):
        """Old code: [1, 'Permissions boundary AdministratorAccess']."""
        stubs = [('get_policy', {'Policy': {'PolicyName': 'AdministratorAccess', 'Arn': ADMIN_ARN,
                                            'DefaultVersionId': 'v1'}}, {'PolicyArn': ADMIN_ARN}),
                 ('get_policy_version', {'PolicyVersion': {'Document': '%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D',
                                                           'VersionId': 'v1', 'IsDefaultVersion': True}},
                  {'PolicyArn': ADMIN_ARN, 'VersionId': 'v1'})]
        r = self._run(ADMIN_ARN, stubs=stubs)
        assert r[0] == -1 and 'permissions boundary AdministratorAccess has no network restriction' in r[1], r

    def test_contained_boundary_passes(self):
        doc = {'Version': '2012-10-17', 'Statement': ADMIN_DOC['Statement'] + DENY_OUTSIDE['Statement']}
        r = self._run(BOUNDARY, {BOUNDARY: doc})
        assert r[0] == 1 and r[1].startswith('Permissions boundary boundary:'), r

    def test_uncontained_boundary_but_contained_identity_passes(self):
        inline = [{'PolicyName': 's3', 'PolicyDocument': ALLOW_S3}, {'PolicyName': 'net', 'PolicyDocument': DENY_OUTSIDE}]
        r = self._run(BOUNDARY, {BOUNDARY: ADMIN_DOC}, inline=inline)
        assert r[0] == 1 and r[1].startswith('Identity policies:'), r

    def test_unreadable_boundary_is_unable_to_evaluate(self):
        r = self._run(BOUNDARY, stubs=[('get_policy', 'AccessDenied', {'PolicyArn': BOUNDARY})])
        assert r == [0, 'Unable to evaluate (permissions boundary boundary not readable: AccessDenied)'], r

    def test_boundary_granting_nothing(self):
        r = self._run(BOUNDARY, {BOUNDARY: {'Version': '2012-10-17', 'Statement': []}})
        assert r[0] == 1 and 'grants no permissions' in r[1], r


# =========================================================================== #
# Finding: networkContainment treated any Deny mentioning a network key as a guard
# =========================================================================== #
def _pol(*stmts):
    return {'Version': '2012-10-17', 'Statement': list(stmts)}


ALLOW_ALL = {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}


class TestNetworkDenyGuard:
    @pytest.mark.parametrize('deny', [
        # Finding scenario: denylist of one IP for one action.
        {'Effect': 'Deny', 'Action': 's3:DeleteBucket', 'Resource': '*',
         'Condition': {'IpAddress': {'aws:SourceIp': '6.6.6.6/32'}}},
        # Right operator, but only one action.
        {'Effect': 'Deny', 'Action': 's3:DeleteBucket', 'Resource': '*',
         'Condition': {'NotIpAddress': {'aws:SourceIp': '203.0.113.0/24'}}},
        # All actions, but a denylist.
        {'Effect': 'Deny', 'Action': '*', 'Resource': '*', 'Condition': {'IpAddress': {'aws:SourceIp': '6.6.6.6/32'}}},
        # All actions, one resource.
        {'Effect': 'Deny', 'Action': '*', 'Resource': 'arn:aws:s3:::b/*',
         'Condition': {'NotIpAddress': {'aws:SourceIp': '203.0.113.0/24'}}},
        # Every IPv4 address allowed.
        {'Effect': 'Deny', 'Action': '*', 'Resource': '*', 'Condition': {'NotIpAddress': {'aws:SourceIp': '0.0.0.0/0'}}},
        # Narrowed by an unrelated condition.
        {'Effect': 'Deny', 'Action': '*', 'Resource': '*',
         'Condition': {'NotIpAddress': {'aws:SourceIp': '203.0.113.0/24'},
                       'StringEquals': {'aws:RequestedRegion': 'us-east-1'}}},
        # NotAction exempting almost everything.
        {'Effect': 'Deny', 'NotAction': ['s3:*', 'ec2:*'], 'Resource': '*',
         'Condition': {'NotIpAddress': {'aws:SourceIp': '203.0.113.0/24'}}},
    ])
    def test_not_a_guard(self, deny):
        """Old code: (True, 'Deny statement conditioned on aws:SourceIp')."""
        assert H.networkContainment([_pol(ALLOW_ALL, deny)])[0] is False

    @pytest.mark.parametrize('deny', [
        DENY_OUTSIDE['Statement'][0],
        # AWS docs example: deny outside IP, except calls made by AWS services.
        {'Effect': 'Deny', 'Action': '*', 'Resource': '*',
         'Condition': {'NotIpAddress': {'aws:SourceIp': ['192.0.2.0/24', '203.0.113.0/24']},
                       'Bool': {'aws:ViaAWSService': 'false'}}},
        {'Effect': 'Deny', 'Action': '*', 'Resource': '*',
         'Condition': {'StringNotEquals': {'aws:SourceVpce': 'vpce-1a2b3c4d'}}},
        {'Effect': 'Deny', 'Action': '*', 'Resource': '*',
         'Condition': {'StringNotEqualsIfExists': {'aws:SourceVpc': 'vpc-111'},
                       'NotIpAddressIfExists': {'aws:SourceIp': '203.0.113.0/24'}}},
        {'Effect': 'Deny', 'NotAction': ['iam:ChangePassword', 'iam:GetAccountPasswordPolicy'], 'Resource': '*',
         'Condition': {'NotIpAddress': {'aws:SourceIp': '203.0.113.0/24'}}},
    ])
    def test_guard(self, deny):
        assert H.networkContainment([_pol(ALLOW_ALL, deny)])[0] is True

    @pytest.mark.parametrize('cond,expected', [
        ({'IpAddress': {'aws:SourceIp': '203.0.113.0/24'}}, True),
        ({'StringEquals': {'aws:SourceVpce': 'vpce-1'}}, True),
        ({'NotIpAddress': {'aws:SourceIp': '203.0.113.0/24'}}, False),
        ({'StringEqualsIfExists': {'aws:SourceVpc': 'vpc-111'}}, False),
        ({'IpAddress': {'aws:SourceIp': '0.0.0.0/0'}}, False),
    ])
    def test_allow_restriction(self, cond, expected):
        assert H.networkContainment([_pol(dict(ALLOW_ALL, Condition=cond))])[0] is expected

    def test_check_level_flag_fix(self):
        bad = _pol({'Effect': 'Deny', 'Action': 's3:DeleteBucket', 'Resource': '*',
                    'Condition': {'IpAddress': {'aws:SourceIp': '6.6.6.6/32'}}})
        inline = [{'PolicyName': 'all', 'PolicyDocument': _pol(ALLOW_ALL)}, {'PolicyName': 'deny', 'PolicyDocument': bad}]
        u, _ = _user(_row('ci-bot'), _detail('ci-bot', inline=inline))
        u._checkLongTermKeyNotContained()
        assert u.results['longTermKeyNotContained'][0] == -1
        inline[1] = {'PolicyName': 'deny', 'PolicyDocument': DENY_OUTSIDE}
        u, _ = _user(_row('ci-bot'), _detail('ci-bot', inline=inline))
        u._checkLongTermKeyNotContained()
        assert u.results['longTermKeyNotContained'][0] == 1

    def test_unreadable_policy_blocks_allow_route_not_deny_route(self):
        hidden = f'arn:aws:iam::{ACCOUNT}:policy/hidden'
        cond = [{'PolicyName': 'c', 'PolicyDocument': _pol(dict(ALLOW_ALL, Condition={'IpAddress': {'aws:SourceIp': '203.0.113.0/24'}}))}]
        u, stub = _user(_row('ci-bot'), _detail('ci-bot', inline=cond, attached=[{'PolicyName': 'hidden', 'PolicyArn': hidden}]))
        stub.add_client_error('get_policy', 'AccessDenied')
        u._checkLongTermKeyNotContained()
        assert u.results['longTermKeyNotContained'][0] == 0
        u, stub = _user(_row('ci-bot'), _detail('ci-bot', inline=cond + [{'PolicyName': 'n', 'PolicyDocument': DENY_OUTSIDE}],
                                               attached=[{'PolicyName': 'hidden', 'PolicyArn': hidden}]))
        stub.add_client_error('get_policy', 'AccessDenied')
        u._checkLongTermKeyNotContained()
        assert u.results['longTermKeyNotContained'][0] == 1


# =========================================================================== #
# Harness items: PASS states the emulator cannot (or only asynchronously) produce
# =========================================================================== #
class TestOrgOuStructureFlatPass:
    """Emulator: list_accounts_for_parent is NotImplemented, so the PASS state
    is proven here with real API shapes (flat -> OU + only mgmt at root)."""

    def test_flag_fix(self):
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': []}, {'ParentId': ROOT_ID})
        assert h.run('OrgOuStructureFlat', 'orgOuStructureFlat')[0] == -1
        h = Harness()
        h.org.add_response('list_roots', _roots())
        h.org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': [
            {'Id': OU_ID, 'Arn': f'arn:aws:organizations::{MGMT}:ou/{ORG_ID}/{OU_ID}', 'Name': 'Workloads'}]},
            {'ParentId': ROOT_ID})
        h.org.add_response('list_accounts_for_parent', {'Accounts': [{'Id': MGMT, 'Name': 'mgmt'}]}, {'ParentId': ROOT_ID})
        assert h.run('OrgOuStructureFlat', 'orgOuStructureFlat') == \
            [1, '1 top-level OU(s); no member accounts attached directly to the root']


class TestResourceExplorerAggregatorStates:
    """Promotion to AGGREGATOR is asynchronous: UPDATING is INFO, ACTIVE PASS."""

    def _run(self, state):
        c = _session().client('resource-explorer-2')
        st = Stubber(c)
        arn = f'arn:aws:resource-explorer-2:us-east-1:{MGMT}:index/0123abcd-0000-0000-0000-000000000000'
        st.add_response('list_indexes', {'Indexes': [{'Arn': arn, 'Region': 'us-east-1', 'Type': 'AGGREGATOR'}]}, {})
        st.add_response('get_index', {'Arn': arn, 'Type': 'AGGREGATOR', 'State': state}, {})
        st.activate()
        h = Harness(regionalClients={'resource-explorer-2': c})
        r = h.run('ResourceExplorerNoAggregatorIndex', 'resourceExplorerNoAggregatorIndex')
        st.assert_no_pending_responses()
        return r

    def test_states(self):
        assert self._run('UPDATING') == [0, 'Aggregator index in us-east-1 is UPDATING']
        assert self._run('ACTIVE')[0] == 1
        assert self._run('DELETING')[0] == -1

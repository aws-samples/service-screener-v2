"""Stubber tests for the shared Bedrock role-scope helper
(_inspectRoleForBroadPolicies / _statementsAreBroad, used by
bedrockAgentIamRoleOverprivileged, bedrockKBRoleOverprivileged,
bedrockACRuntimeWildcardRole and sfnRoleOverprivileged) and for
bedrockACRuntimeWildcardRole's aggregation over several runtimes.

Why Stubber: Bedrock Agents / AgentCore are not served by the local AWS
Emulator. Real boto3 IAM clients wrapped in botocore Stubber (real API
shapes); no network calls.
"""
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.bedrock.drivers.BedrockAgent import _inspectRoleForBroadPolicies, _statementsAreBroad  # noqa: E402
from services.bedrock.drivers.BedrockAgentCore import BedrockAgentCore  # noqa: E402

ACCT = '111122223333'
BROAD = BedrockAgentCore.BROAD_RUNTIME_ACTIONS


def _iam():
    return boto3.client('iam', region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')


def _doc(*stmts):
    return {'Version': '2012-10-17', 'Statement': list(stmts)}


def _stubRole(st, role, inline=None, attached=None, denied=False):
    """inline: {name: doc}; attached: [(arn, doc or None-for-no-default-version)]"""
    if denied:
        st.add_client_error('list_role_policies', service_error_code='AccessDenied',
                            expected_params={'RoleName': role})
        return
    inline = inline or {}
    st.add_response('list_role_policies', {'PolicyNames': list(inline), 'IsTruncated': False}, {'RoleName': role})
    for name, doc in inline.items():
        st.add_response('get_role_policy', {'RoleName': role, 'PolicyName': name,
                                            'PolicyDocument': json.dumps(doc)},
                        {'RoleName': role, 'PolicyName': name})
    attached = attached or []
    st.add_response('list_attached_role_policies',
                    {'AttachedPolicies': [{'PolicyName': a.split('/')[-1], 'PolicyArn': a} for a, _ in attached],
                     'IsTruncated': False}, {'RoleName': role})
    for arn, doc in attached:
        pol = {'PolicyName': arn.split('/')[-1], 'Arn': arn}
        if doc is not None:
            pol['DefaultVersionId'] = 'v1'
        st.add_response('get_policy', {'Policy': pol}, {'PolicyArn': arn})
        if doc is not None:
            st.add_response('get_policy_version', {'PolicyVersion': {'Document': json.dumps(doc), 'VersionId': 'v1',
                                                                     'IsDefaultVersion': True}},
                            {'PolicyArn': arn, 'VersionId': 'v1'})


def _inspect(**kw):
    iam = _iam()
    with Stubber(iam) as st:
        _stubRole(st, 'r', **kw)
        out = _inspectRoleForBroadPolicies(iam, 'r', BROAD)
        st.assert_no_pending_responses()
    return out


SCOPED = _doc({'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::b/*'})


@pytest.mark.parametrize('stmt', [
    {'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': '*'},
    {'Effect': 'Allow', 'NotAction': ['iam:*', 'organizations:*'], 'Resource': ['*']},
    {'Effect': 'Allow', 'Action': 'S3:*', 'Resource': '*'},
    {'Effect': 'Allow', 'Action': ['KMS:*'], 'Resource': '*'},
    {'Effect': 'Allow', 'Action': '*:*', 'Resource': 'arn:aws:s3:::b'},
    {'Effect': 'Allow', 'Action': 's3:*', 'NotResource': 'arn:aws:s3:::other'},
])
def test_broad_grants_in_other_forms_are_flagged(stmt):
    """Old code: NotAction / upper-case / '*:*' / NotResource grants were 'scoped' (false PASS)."""
    assert _inspect(inline={'p': _doc(stmt)}) == ['inline:p']


def test_broad_flag_then_fix():
    assert _inspect(inline={'p': _doc({'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': '*'})}) == ['inline:p']
    assert _inspect(inline={'p': SCOPED}) == []


@pytest.mark.parametrize('stmt', [
    {'Effect': 'Allow', 'Action': 's3:Get*', 'Resource': '*'},          # not service-wide
    {'Effect': 'Allow', 'Action': 's3:*', 'Resource': 'arn:aws:s3:::b/*'},  # scoped resource
    {'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': 'arn:aws:s3:::b/*'},
    {'Effect': 'Deny', 'NotAction': 's3:GetObject', 'Resource': '*'},
])
def test_narrow_or_deny_statements_are_not_flagged(stmt):
    assert _inspect(inline={'p': _doc(stmt)}) == []


def test_managed_policy_without_default_version_is_unknown_not_scoped():
    arn = f'arn:aws:iam::{ACCT}:policy/NoDefault'
    assert _inspect(inline={'p': SCOPED}, attached=[(arn, None)]) is None


def test_managed_policy_notaction_is_flagged():
    arn = f'arn:aws:iam::{ACCT}:policy/PowerUser'
    doc = _doc({'Effect': 'Allow', 'NotAction': ['iam:*', 'organizations:*'], 'Resource': '*'})
    assert _inspect(attached=[(arn, doc)]) == ['managed:PowerUser']


def test_unparseable_document_is_unknown():
    assert _statementsAreBroad('{not json', BROAD) is None
    assert _statementsAreBroad({'Statement': []}, BROAD) is False


# ---------------- bedrockACRuntimeWildcardRole aggregation ----------------

def _runtimes(n):
    return [{'agentRuntimeName': f'rt{i}', 'agentRuntimeId': f'rt{i}', 'status': 'READY',
             'roleArn': f'arn:aws:iam::{ACCT}:role/rt-role-{i}'} for i in range(n)]


def _runtimeCheck(n, perRole):
    """perRole: list of kwargs for _stubRole, one per runtime."""
    iam = _iam()
    with Stubber(iam) as st:
        for i, kw in enumerate(perRole):
            _stubRole(st, f'rt-role-{i}', **kw)
        obj = BedrockAgentCore({'runtimes': _runtimes(n)}, None, iam)
        obj._checkBedrockACRuntimeWildcardRole()
        st.assert_no_pending_responses()
    return obj.results['bedrockACRuntimeWildcardRole']


def test_runtime_roles_partially_unreadable_is_unable_not_pass():
    r = _runtimeCheck(4, [{'inline': {'p': SCOPED}}, {'denied': True}, {'denied': True}, {'denied': True}])
    assert r[0] == 0, r
    assert r[1].startswith('Unable to evaluate (3 of 4'), r


def test_runtime_roles_flag_then_fix():
    bad = _doc({'Effect': 'Allow', 'Action': 'bedrock-agentcore:*', 'Resource': '*'})
    r = _runtimeCheck(2, [{'inline': {'p': SCOPED}}, {'inline': {'p': bad}}])
    assert r[0] == -1 and 'rt1' in r[1], r
    r = _runtimeCheck(2, [{'inline': {'p': SCOPED}}, {'inline': {'p': SCOPED}}])
    assert r[0] == 1, r


def test_runtime_offender_wins_over_unreadable():
    bad = _doc({'Effect': 'Allow', 'Action': '*', 'Resource': '*'})
    r = _runtimeCheck(2, [{'denied': True}, {'inline': {'p': bad}}])
    assert r[0] == -1, r

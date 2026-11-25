"""_inspectRoleForBroadPolicies must not report "scoped" when the role's
policies could not be read (shared by Bedrock agents/KBs/AgentCore and the
Step Functions role check)."""
import os
import sys
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from services.bedrock.drivers.BedrockAgent import _inspectRoleForBroadPolicies  # noqa: E402

BROAD = {'*', 's3:*'}


def _err(code):
    return botocore.exceptions.ClientError({'Error': {'Code': code, 'Message': 'x'}}, 'Op')


def _iam(inline=None, attached=None, inlineErr=None, listErr=None):
    c = MagicMock()
    if listErr:
        c.list_role_policies.side_effect = _err(listErr)
    c.list_role_policies.return_value = {'PolicyNames': list(inline or {})}
    def getRolePolicy(RoleName, PolicyName):
        if inlineErr:
            raise _err(inlineErr)
        return {'PolicyDocument': inline[PolicyName]}
    c.get_role_policy.side_effect = getRolePolicy
    c.list_attached_role_policies.return_value = {'AttachedPolicies': attached or []}
    return c


SCOPED = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::b/*'}]}
BROADDOC = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}


@pytest.mark.parametrize('code', ['AccessDenied', 'NoSuchEntity', 'Throttling'])
def test_listing_denied_is_unknown(code):
    assert _inspectRoleForBroadPolicies(_iam(listErr=code), 'r', BROAD) is None


def test_unreadable_inline_policy_is_unknown():
    assert _inspectRoleForBroadPolicies(_iam(inline={'p': SCOPED}, inlineErr='AccessDenied'), 'r', BROAD) is None


def test_scoped_role_is_empty_list():
    assert _inspectRoleForBroadPolicies(_iam(inline={'p': SCOPED}), 'r', BROAD) == []


def test_broad_policy_is_reported():
    assert _inspectRoleForBroadPolicies(_iam(inline={'p': BROADDOC}), 'r', BROAD) == ['inline:p']


def test_admin_managed_policy_reported_even_if_inline_unreadable():
    c = _iam(inline={'p': SCOPED}, inlineErr='AccessDenied',
             attached=[{'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess', 'PolicyName': 'AdministratorAccess'}])
    assert _inspectRoleForBroadPolicies(c, 'r', BROAD) == ['managed:AdministratorAccess']

"""
Regression tests for wildcard-principal detection in resource policies.

Covers the shared helper (utils/PolicyPrincipal.py) and every driver that
uses it: Glue Data Catalog, S3 bucket policy, SQS access policy and Lambda
function policy (via utils/Policy.inspectPrinciple).

Background: several checks compared Principal / Principal.AWS against the
literal string "*", so the equivalent list form {"AWS": ["*"]} (emitted by
Terraform's aws_iam_policy_document, among others) was reported as not
public.
"""
import json
import os
import sys
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import PolicyPrincipal as pp  # noqa: E402
from utils.Policy import Policy  # noqa: E402

# Evaluator.__del__ writes to __fork/error.txt, which only exists in a full scan run.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")


def _stmt(principal=None, effect='Allow', action='*', condition=None, not_principal=None):
    s = {'Effect': effect, 'Action': action, 'Resource': '*'}
    if principal is not None:
        s['Principal'] = principal
    if not_principal is not None:
        s['NotPrincipal'] = not_principal
    if condition is not None:
        s['Condition'] = condition
    return s


def _policy(*stmts):
    return {'Version': '2012-10-17', 'Statement': list(stmts)}


ORG_CONDITION = {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123'}}

PUBLIC_PRINCIPALS = [
    '*',
    {'AWS': '*'},
    {'AWS': ['*']},
    {'AWS': ['arn:aws:iam::222222222222:root', '*']},
]

NON_PUBLIC_PRINCIPALS = [
    {'AWS': 'arn:aws:iam::222222222222:root'},
    {'AWS': ['arn:aws:iam::222222222222:root', 'arn:aws:iam::333333333333:root']},
    {'Service': 's3.amazonaws.com'},
]


# --------------------------------------------------------------------------- #
# Helper unit tests
# --------------------------------------------------------------------------- #
class TestPrincipalIsWildcard:
    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS + [{'Service': ['*']}, {'CanonicalUser': '*'}])
    def test_wildcard_forms(self, principal):
        assert pp.principalIsWildcard(principal) is True

    @pytest.mark.parametrize('principal', NON_PUBLIC_PRINCIPALS + [None, '', {}, []])
    def test_non_wildcard_forms(self, principal):
        assert pp.principalIsWildcard(principal) is False


class TestConditionScopes:
    @pytest.mark.parametrize('condition', [
        ORG_CONDITION,
        {'StringEquals': {'aws:SourceAccount': '111111111111'}},
        {'ArnLike': {'aws:SourceArn': 'arn:aws:s3:::my-bucket'}},
        {'StringEquals': {'aws:SourceVpce': 'vpce-1234'}},
        {'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': 'o-abc/r-ab12/ou-ab12-*'}},
        {'stringequals': {'AWS:PrincipalOrgID': 'o-abc123'}},  # case-insensitive keys/operators
    ])
    def test_scoping(self, condition):
        assert pp.conditionScopes(condition) is True

    @pytest.mark.parametrize('condition', [
        None,
        {},
        {'Bool': {'aws:SecureTransport': 'true'}},
        {'IpAddress': {'aws:SourceIp': '0.0.0.0/0'}},
        # IfExists: an anonymous caller has no PrincipalOrgID, so the condition passes
        {'StringEqualsIfExists': {'aws:PrincipalOrgID': 'o-abc123'}},
        # Negated operator does not restrict to a known set
        {'StringNotEquals': {'aws:PrincipalOrgID': 'o-abc123'}},
        # ForAllValues passes vacuously when the key is absent
        {'ForAllValues:StringEquals': {'aws:PrincipalOrgID': 'o-abc123'}},
        # Wildcard value matches anything
        {'StringLike': {'aws:PrincipalOrgID': '*'}},
        {'StringLike': {'aws:SourceAccount': ['*']}},
        {'StringEquals': {'lambda:FunctionUrlAuthType': 'NONE'}},
    ])
    def test_non_scoping(self, condition):
        assert pp.conditionScopes(condition) is False


class TestStatementIsPublic:
    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_public(self, principal):
        assert pp.statementIsPublic(_stmt(principal)) is True

    @pytest.mark.parametrize('principal', NON_PUBLIC_PRINCIPALS)
    def test_named_principals(self, principal):
        assert pp.statementIsPublic(_stmt(principal)) is False

    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_deny_never_public(self, principal):
        assert pp.statementIsPublic(_stmt(principal, effect='Deny')) is False

    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_scoped_by_condition(self, principal):
        assert pp.statementIsPublic(_stmt(principal, condition=ORG_CONDITION)) is False

    def test_allow_not_principal_is_public(self):
        stmt = _stmt(not_principal={'AWS': 'arn:aws:iam::222222222222:root'})
        assert pp.statementIsPublic(stmt) is True

    def test_non_dict_statement(self):
        assert pp.statementIsPublic('garbage') is False


class TestIterStatements:
    def test_single_statement_object(self):
        doc = {'Statement': _stmt('*')}
        assert len(pp.iterStatements(doc)) == 1

    def test_json_string(self):
        assert len(pp.iterStatements(json.dumps(_policy(_stmt('*'), _stmt('*'))))) == 2

    @pytest.mark.parametrize('doc', [None, '', 'not-json', {}, {'Statement': 'x'}, [1, 2]])
    def test_bad_input(self, doc):
        assert pp.iterStatements(doc) == []


class TestStatementAllowsAction:
    @pytest.mark.parametrize('action', ['s3:GetObject', ['s3:GetObject'], 's3:*', '*', 's3:Get*', 'S3:getobject'])
    def test_matches(self, action):
        assert pp.statementAllowsAction(_stmt('*', action=action), ['s3:GetObject']) is True

    def test_no_match(self):
        assert pp.statementAllowsAction(_stmt('*', action='s3:PutObject'), ['s3:GetObject']) is False

    def test_not_action_excluding_target(self):
        stmt = {'Effect': 'Allow', 'Principal': '*', 'NotAction': 's3:Get*'}
        assert pp.statementAllowsAction(stmt, ['s3:GetObject']) is False

    def test_not_action_other(self):
        stmt = {'Effect': 'Allow', 'Principal': '*', 'NotAction': 's3:DeleteBucket'}
        assert pp.statementAllowsAction(stmt, ['s3:GetObject']) is True


# --------------------------------------------------------------------------- #
# Glue Data Catalog
# --------------------------------------------------------------------------- #
from services.glue.drivers.DataCatalogDriver import DataCatalogDriver  # noqa: E402


def _glue(policy=None, error_code=None):
    client = MagicMock()
    if error_code:
        client.get_resource_policy.side_effect = botocore.exceptions.ClientError(
            {'Error': {'Code': error_code, 'Message': 'x'}}, 'GetResourcePolicy')
    else:
        client.get_resource_policy.return_value = {'PolicyInJson': json.dumps(policy) if policy else None}
    d = DataCatalogDriver({}, client)
    d._checkPublicAccessibility()
    return d.results['PublicAccessibility']


class TestGlue:
    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_public(self, principal):
        assert _glue(_policy(_stmt(principal)))[0] == -1

    def test_reported_poc(self):
        # List-form wildcard principal granting glue:GetTable
        policy = _policy({
            'Effect': 'Allow',
            'Principal': {'AWS': ['*']},
            'Action': 'glue:GetTable',
            'Resource': 'arn:aws:glue:us-east-1:111111111111:*',
        })
        assert _glue(policy) == [-1, 'Publicly Accessible']

    @pytest.mark.parametrize('principal', NON_PUBLIC_PRINCIPALS)
    def test_not_public(self, principal):
        assert _glue(_policy(_stmt(principal)))[0] == 1

    def test_org_scoped_not_public(self):
        assert _glue(_policy(_stmt({'AWS': '*'}, condition=ORG_CONDITION)))[0] == 1

    def test_no_policy(self):
        assert _glue(None)[0] == 1

    def test_entity_not_found(self):
        assert _glue(error_code='EntityNotFoundException')[0] == 1

    def test_access_denied_records_not_evaluated(self):
        assert _glue(error_code='AccessDeniedException')[0] == 0
        assert _glue(error_code='AccessDenied')[0] == 0


# --------------------------------------------------------------------------- #
# S3
# --------------------------------------------------------------------------- #
from services.s3.drivers.S3Bucket import S3Bucket  # noqa: E402


@pytest.fixture
def s3():
    return S3Bucket('test-bucket', MagicMock())


class TestS3:
    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_public_read(self, s3, principal):
        assert s3.policyAllowsPublicRead(json.dumps(_policy(_stmt(principal, action='s3:GetObject')))) is True

    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_public_write(self, s3, principal):
        assert s3.policyAllowsPublicWrite(json.dumps(_policy(_stmt(principal, action='s3:PutObject')))) is True

    @pytest.mark.parametrize('action', ['s3:*', '*', 's3:Get*'])
    def test_wildcard_actions_read(self, s3, action):
        assert s3.policyAllowsPublicRead(json.dumps(_policy(_stmt({'AWS': ['*']}, action=action)))) is True

    @pytest.mark.parametrize('action', ['s3:*', '*', 's3:Put*'])
    def test_wildcard_actions_write(self, s3, action):
        assert s3.policyAllowsPublicWrite(json.dumps(_policy(_stmt({'AWS': ['*']}, action=action)))) is True

    @pytest.mark.parametrize('principal', NON_PUBLIC_PRINCIPALS)
    def test_not_public(self, s3, principal):
        doc = json.dumps(_policy(_stmt(principal, action='s3:*')))
        assert s3.policyAllowsPublicRead(doc) is False
        assert s3.policyAllowsPublicWrite(doc) is False

    def test_org_scoped(self, s3):
        doc = json.dumps(_policy(_stmt({'AWS': '*'}, action='s3:GetObject', condition=ORG_CONDITION)))
        assert s3.policyAllowsPublicRead(doc) is False

    def test_read_only_not_write(self, s3):
        doc = json.dumps(_policy(_stmt('*', action='s3:GetObject')))
        assert s3.policyAllowsPublicWrite(doc) is False

    def test_single_statement_object(self, s3):
        doc = json.dumps({'Statement': _stmt({'AWS': ['*']}, action='s3:GetObject')})
        assert s3.policyAllowsPublicRead(doc) is True

    @pytest.mark.parametrize('doc', [None, '', 'not-json'])
    def test_bad_docs(self, s3, doc):
        assert s3.policyAllowsPublicRead(doc) is False


# --------------------------------------------------------------------------- #
# SQS
# --------------------------------------------------------------------------- #
from services.sqs.drivers.SqsQueueDriver import SqsQueueDriver  # noqa: E402


def _sqs(policy):
    queue = {'QueueUrl': 'https://sqs/q', 'QueueName': 'q',
             'Attributes': {'Policy': json.dumps(policy)} if policy else {}}
    d = SqsQueueDriver(queue, MagicMock(), MagicMock())
    d._checkAccessPolicy()
    return d.results['AccessPolicy']


class TestSqs:
    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_wildcard_principal_flagged(self, principal):
        res = _sqs(_policy(_stmt(principal, action='sqs:SendMessage')))
        assert res[0] == -1 and 'Wildcard principal' in res[1]

    @pytest.mark.parametrize('principal', NON_PUBLIC_PRINCIPALS)
    def test_named_principal_ok(self, principal):
        assert _sqs(_policy(_stmt(principal, action='sqs:SendMessage')))[0] == 1

    def test_scoped_wildcard_ok(self):
        stmt = _stmt('*', action='sqs:SendMessage',
                     condition={'ArnEquals': {'aws:SourceArn': 'arn:aws:sns:us-east-1:111111111111:t'}})
        assert _sqs(_policy(stmt))[0] == 1

    def test_deny_wildcard_ok(self):
        stmt = _stmt('*', effect='Deny', action='sqs:SendMessage',
                     condition={'Bool': {'aws:SecureTransport': 'false'}})
        assert _sqs(_policy(stmt))[0] == 1


# --------------------------------------------------------------------------- #
# Lambda (utils/Policy.inspectPrinciple)
# --------------------------------------------------------------------------- #
class TestLambdaPolicy:
    @pytest.mark.parametrize('principal', PUBLIC_PRINCIPALS)
    def test_public(self, principal):
        p = Policy(_policy(_stmt(principal, action='lambda:InvokeFunction')))
        p.inspectPrinciple()
        assert p.hasPublicAccess() is True

    @pytest.mark.parametrize('principal', NON_PUBLIC_PRINCIPALS)
    def test_not_public(self, principal):
        p = Policy(_policy(_stmt(principal, action='lambda:InvokeFunction')))
        p.inspectPrinciple()
        assert p.hasPublicAccess() is False

    def test_service_principal_scoped(self):
        stmt = _stmt({'Service': 's3.amazonaws.com'}, action='lambda:InvokeFunction',
                     condition={'ArnLike': {'AWS:SourceArn': 'arn:aws:s3:::b'}})
        p = Policy(_policy(stmt))
        p.inspectPrinciple()
        assert p.hasPublicAccess() is False

    def test_function_url_auth_none_is_public(self):
        stmt = _stmt('*', action='lambda:InvokeFunctionUrl',
                     condition={'StringEquals': {'lambda:FunctionUrlAuthType': 'NONE'}})
        p = Policy(_policy(stmt))
        p.inspectPrinciple()
        assert p.hasPublicAccess() is True

    def test_statement_without_principal_key(self):
        p = Policy(_policy({'Effect': 'Allow', 'Action': '*', 'Resource': '*'}))
        p.inspectPrinciple()
        assert p.hasPublicAccess() is False

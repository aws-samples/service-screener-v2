"""
Regression tests for resource-policy evaluation robustness:

- utils/Policy.extractPolicyInfo tolerates NotPrincipal / NotAction / a
  single-object Statement and carries each statement's Condition.
- KMS key-policy checks use each statement's own Condition (including
  statements without a Sid) and do not flag a wildcard principal that is
  restricted by a scoping Condition.
- S3 and ECR record "Unable to evaluate" when the resource policy cannot be
  read (e.g. AccessDenied) instead of treating it as "no policy".
"""
import json
import os
import sys
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Policy import Policy  # noqa: E402
from utils import PolicyPrincipal as pp  # noqa: E402
from services.kms.drivers.KmsCommon import KmsCommon  # noqa: E402
from services.s3.drivers.S3Bucket import S3Bucket  # noqa: E402
from services.ecr.Ecr import Ecr  # noqa: E402
from services.ecr.drivers.EcrCommon import EcrCommon  # noqa: E402

# Evaluator.__del__ writes to __fork/error.txt, which only exists in a full scan run.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

ACCOUNT = '111111111111'
KEY_ARN = f'arn:aws:kms:us-east-1:{ACCOUNT}:key/abcd'
ROOT_STMT = {
    'Sid': 'Root', 'Effect': 'Allow',
    'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'},
    'Action': 'kms:*', 'Resource': '*',
}


def _client_error(code, op='Op'):
    return botocore.exceptions.ClientError({'Error': {'Code': code, 'Message': 'x'}}, op)


# --------------------------------------------------------------------------- #
# utils/Policy.extractPolicyInfo
# --------------------------------------------------------------------------- #
class TestExtractPolicyInfo:
    def _extract(self, doc):
        p = Policy(doc)
        return p.extractPolicyInfo()

    def test_not_principal_treated_as_wildcard(self):
        info = self._extract({'Statement': [{'Sid': 'A', 'Effect': 'Allow',
                                             'NotPrincipal': {'AWS': 'arn:aws:iam::2:root'},
                                             'Action': 'kms:Decrypt'}]})
        assert info['allow']['A']['Principal'] == '*'

    def test_not_action_treated_as_wildcard(self):
        info = self._extract({'Statement': [{'Sid': 'A', 'Effect': 'Allow', 'Principal': '*',
                                             'NotAction': 'kms:ScheduleKeyDeletion'}]})
        assert info['allow']['A']['Action'] == '*'

    def test_single_statement_object(self):
        info = self._extract({'Statement': {'Sid': 'A', 'Effect': 'Deny', 'Principal': '*', 'Action': '*'}})
        assert 'A' in info['deny']

    def test_condition_carried_for_statement_without_sid(self):
        cond = {'StringEquals': {'kms:CallerAccount': ACCOUNT}}
        info = self._extract({'Statement': [
            {'Effect': 'Allow', 'Principal': '*', 'Action': 'kms:Decrypt', 'Condition': cond},
            {'Effect': 'Allow', 'Principal': '*', 'Action': 'kms:Encrypt'},
        ]})
        assert info['allow']['noSid:1']['Condition'] == cond
        assert info['allow']['noSid:2']['Condition'] == {}

    def test_missing_effect_skipped(self):
        assert self._extract({'Statement': [{'Principal': '*', 'Action': '*'}]}) == {'allow': {}, 'deny': {}}


# --------------------------------------------------------------------------- #
# PolicyPrincipal.conditionScopes extraKeys
# --------------------------------------------------------------------------- #
def test_condition_scopes_extra_keys():
    cond = {'StringEquals': {'kms:CallerAccount': ACCOUNT}}
    assert pp.conditionScopes(cond) is False
    assert pp.conditionScopes(cond, extraKeys=['kms:CallerAccount']) is True
    assert pp.conditionScopes({'StringEquals': {'KMS:calleraccount': ACCOUNT}}, extraKeys=['kms:CallerAccount']) is True


# --------------------------------------------------------------------------- #
# KMS key policy
# --------------------------------------------------------------------------- #
def _kms(*stmts):
    client = MagicMock()
    client.get_key_policy.return_value = {'Policy': json.dumps({'Statement': [ROOT_STMT, *stmts]})}
    d = KmsCommon({'Arn': KEY_ARN, 'KeyId': 'abcd'}, client)
    d._checkPolicyAdminUser()
    return d.results


class TestKmsKeyPolicy:
    def test_not_principal_policy_evaluated(self):
        # Previously raised KeyError('Principal') and recorded no result.
        res = _kms({'Sid': 'Open', 'Effect': 'Allow',
                    'NotPrincipal': {'AWS': 'arn:aws:iam::222222222222:root'},
                    'Action': 'kms:Decrypt', 'Resource': '*'})
        assert res['KeyPolicyWildcardPrincipal'][0] == -1

    def test_not_action_policy_evaluated(self):
        res = _kms({'Sid': 'Broad', 'Effect': 'Allow',
                    'Principal': {'AWS': 'arn:aws:iam::222222222222:root'},
                    'NotAction': 'kms:ScheduleKeyDeletion', 'Resource': '*'})
        assert 'KeyPolicyWildcardAction' in res

    @pytest.mark.parametrize('principal', ['*', {'AWS': '*'}, {'AWS': ['*']}])
    def test_unscoped_wildcard_flagged(self, principal):
        res = _kms({'Sid': 'Open', 'Effect': 'Allow', 'Principal': principal,
                    'Action': 'kms:Decrypt', 'Resource': '*'})
        assert res['KeyPolicyWildcardPrincipal'][0] == -1

    @pytest.mark.parametrize('condition', [
        {'StringEquals': {'kms:CallerAccount': ACCOUNT, 'kms:ViaService': 'ec2.us-east-1.amazonaws.com'}},
        {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}},
    ])
    def test_scoped_wildcard_not_flagged(self, condition):
        res = _kms({'Sid': 'Scoped', 'Effect': 'Allow', 'Principal': {'AWS': '*'},
                    'Action': 'kms:Decrypt', 'Resource': '*', 'Condition': condition})
        assert 'KeyPolicyWildcardPrincipal' not in res

    def test_condition_on_sidless_statement_recognised(self):
        # Previously the Condition lookup used 'noSid' while extractPolicyInfo
        # used 'noSid:N', so conditioned Sid-less statements were reported as
        # having no conditions.
        res = _kms({'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::222222222222:role/r'},
                    'Action': 'kms:*', 'Resource': '*',
                    'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}}})
        assert 'noSid:1' not in res.get('KeyPolicyWildcardAction', [0, ''])[1]
        assert 'noSid:1' not in res.get('KeyPolicyNoConditions', [0, ''])[1]

    def test_sidless_statement_without_condition_still_flagged(self):
        res = _kms({'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::222222222222:role/r'},
                    'Action': 'kms:*', 'Resource': '*'})
        assert 'Statement noSid:1: Action kms:* without conditions' in res['KeyPolicyWildcardAction'][1]


# --------------------------------------------------------------------------- #
# S3: unreadable bucket policy
# --------------------------------------------------------------------------- #
def _s3(policy_error=None, policy=None, restrict_public_buckets=False, acl_public=False):
    client = MagicMock()
    pab = {k: True for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy')}
    pab['RestrictPublicBuckets'] = restrict_public_buckets
    client.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': pab}
    grants = []
    if acl_public:
        grants.append({'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                       'Permission': 'READ'})
    client.get_bucket_acl.return_value = {'Grants': grants}
    if policy_error:
        client.get_bucket_policy.side_effect = _client_error(policy_error, 'GetBucketPolicy')
    elif policy is None:
        client.get_bucket_policy.side_effect = _client_error('NoSuchBucketPolicy', 'GetBucketPolicy')
    else:
        client.get_bucket_policy.return_value = {'Policy': json.dumps(policy)}
    b = S3Bucket('test-bucket', client)
    b._checkAccess()
    b._checkWildcardPrincipalsActions()
    return b.results


class TestS3UnreadablePolicy:
    def test_access_denied_not_reported_as_prohibited(self):
        res = _s3(policy_error='AccessDenied')
        assert res['PublicReadAccessBlock'][0] == 0
        assert res['PublicWriteAccessBlock'][0] == 0
        assert 'AccessDenied' in res['PublicReadAccessBlock'][1]
        assert res['WildcardPrincipalsActions'][0] == 0

    def test_restrict_public_buckets_still_prohibited(self):
        # RestrictPublicBuckets neutralises any public policy, so the result stands.
        res = _s3(policy_error='AccessDenied', restrict_public_buckets=True)
        assert res['PublicReadAccessBlock'] == [1, 'Prohibited']

    def test_public_acl_still_fails(self):
        res = _s3(policy_error='AccessDenied', acl_public=True)
        assert res['PublicReadAccessBlock'] == [-1, 'NotProhibited']

    def test_no_policy_prohibited(self):
        res = _s3()
        assert res['PublicReadAccessBlock'] == [1, 'Prohibited']
        assert res['WildcardPrincipalsActions'] == [1, 'No risky wildcards']

    def test_public_policy_not_prohibited(self):
        policy = {'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': ['*']},
                                 'Action': 's3:GetObject', 'Resource': '*'}]}
        res = _s3(policy=policy)
        assert res['PublicReadAccessBlock'] == [-1, 'NotProhibited']


# --------------------------------------------------------------------------- #
# ECR: unreadable repository policy
# --------------------------------------------------------------------------- #
def _ecr_fetch(error_code=None, policy=None):
    svc = Ecr.__new__(Ecr)  # skip boto3 session setup
    svc.ecrClient = MagicMock()
    if error_code:
        svc.ecrClient.get_repository_policy.side_effect = _client_error(error_code, 'GetRepositoryPolicy')
    else:
        svc.ecrClient.get_repository_policy.return_value = {'policyText': json.dumps(policy)}
    return svc._getRepositoryPolicy('repo')


def _ecr_checks(repo_policy):
    repo = {'repositoryName': 'repo',
            'repositoryArn': f'arn:aws:ecr:us-east-1:{ACCOUNT}:repository/repo',
            '_repositoryPolicy': repo_policy}
    d = EcrCommon(repo, MagicMock())
    d._checkEcrRepoPublicAccess()
    d._checkEcrRepoCrossAccount()
    return d.results


class TestEcrUnreadablePolicy:
    def test_not_found_is_none(self):
        assert _ecr_fetch('RepositoryPolicyNotFoundException') is None

    @pytest.mark.parametrize('code', ['AccessDeniedException', 'AccessDenied'])
    def test_access_denied_is_marked_unreadable(self, code):
        assert _ecr_fetch(code) == {'_unreadable': code}

    def test_unreadable_reports_unable_to_evaluate(self):
        res = _ecr_checks({'_unreadable': 'AccessDeniedException'})
        assert res['ecrRepoPublicAccess'][0] == 0
        assert res['ecrRepoCrossAccount'][0] == 0
        assert 'AccessDeniedException' in res['ecrRepoPublicAccess'][1]

    def test_no_policy_passes(self):
        res = _ecr_checks(None)
        assert res['ecrRepoPublicAccess'][0] == 1

    def test_public_policy_fails(self):
        policy = {'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': ['*']}, 'Action': 'ecr:BatchGetImage'}]}
        res = _ecr_checks(policy)
        assert res['ecrRepoPublicAccess'][0] == -1

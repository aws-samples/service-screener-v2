"""KeyPolicyCrossAccount must not PASS a wildcard principal that a condition
scopes to ANOTHER account (kms:CallerAccount / aws:PrincipalAccount /
aws:SourceAccount / aws:PrincipalArn). Proven with a botocore Stubber using
real GetKeyPolicy response shapes."""
import datetime
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.kms.drivers.KmsCommon import KmsCommon  # noqa: E402

ACCOUNT = '111111111111'
EXTERNAL = '999999999999'
KEY_ID = '1234abcd-12ab-34cd-56ef-1234567890ab'
KEY_ARN = f'arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY_ID}'
ROOT_STMT = {'Sid': 'Root', 'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'},
             'Action': 'kms:*', 'Resource': '*'}
ORG = {'StringEquals': {'aws:PrincipalOrgID': 'o-abcdefghij'}}


def _run(stmt, check='_checkPolicyAdminUser'):
    kms = boto3.client('kms', region_name='us-east-1', aws_access_key_id='testing',
                       aws_secret_access_key='testing')  # nosec - dummy, Stubber only
    policy = json.dumps({'Version': '2012-10-17', 'Statement': [ROOT_STMT, stmt]})
    stub = Stubber(kms)
    stub.add_response('get_key_policy', {'Policy': policy, 'PolicyName': 'default'},
                      {'KeyId': KEY_ID, 'PolicyName': 'default'})
    md = {'KeyId': KEY_ID, 'Arn': KEY_ARN, 'KeyState': 'Enabled', 'KeyManager': 'CUSTOMER',
          'Origin': 'AWS_KMS', 'KeyRotationEnabled': True,
          'CreationDate': datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)}
    with stub:
        drv = KmsCommon(md, kms)
        getattr(drv, check)()
    return drv.results


def _wild(condition, principal=None):
    return {'Sid': 'Wild', 'Effect': 'Allow', 'Principal': principal or {'AWS': '*'},
            'Action': 'kms:Decrypt', 'Resource': '*', 'Condition': condition}


## Fails on the old code: each of these returned [1, 'No cross-account principals in key policy'].
@pytest.mark.parametrize('condition', [
    {'StringEquals': {'kms:CallerAccount': EXTERNAL}},
    {'StringEquals': {'kms:CallerAccount': [ACCOUNT, EXTERNAL]}},
    {'StringEquals': {'aws:PrincipalAccount': EXTERNAL}},
    {'StringEquals': {'aws:SourceAccount': EXTERNAL}},
    {'ArnLike': {'aws:PrincipalArn': f'arn:aws:iam::{EXTERNAL}:role/app'}},
])
@pytest.mark.parametrize('principal', [{'AWS': '*'}, '*'])
def test_wildcard_scoped_to_external_account_fails(condition, principal):
    r = _run(_wild(condition, principal))
    assert r['KeyPolicyCrossAccount'] == [-1, f'Statement Wild: * (condition-scoped to account {EXTERNAL})']
    assert 'KeyPolicyWildcardPrincipal' not in r


def test_wildcard_scoped_to_external_account_reported_as_centralized_management():
    ## Fails on the old code: wildcard principals were ignored entirely.
    r = _run(_wild({'StringEquals': {'kms:CallerAccount': EXTERNAL}}), '_checkKeyManagementPattern')
    assert r['KeyCentralizedManagement'][0] == -1
    assert EXTERNAL in r['KeyCentralizedManagement'][1]


def test_wildcard_scoped_to_external_account_inside_org_is_org_scoped():
    cond = {'StringEquals': {'kms:CallerAccount': EXTERNAL, 'aws:PrincipalOrgID': 'o-abcdefghij'}}
    r = _run(_wild(cond))
    assert r['KeyPolicyCrossAccount'] == [
        1, 'Cross-account access restricted by aws:PrincipalOrgID/aws:PrincipalOrgPaths: '
           f'Statement Wild: * (condition-scoped to account {EXTERNAL})']


def test_wildcard_org_only_is_reported_as_org_scoped():
    ## Fails on the old code: an org-wide wildcard was reported as having no cross-account principals.
    r = _run(_wild(ORG))
    assert r['KeyPolicyCrossAccount'] == [
        1, 'Cross-account access restricted by aws:PrincipalOrgID/aws:PrincipalOrgPaths: '
           'Statement Wild: * (organization-scoped)']


def test_wildcard_scoped_only_by_network_is_unable_to_evaluate():
    ## Fails on the old code (was PASS): the caller's account is not bounded by the policy.
    r = _run(_wild({'StringEquals': {'aws:SourceVpce': 'vpce-0123456789abcdef0'}}))
    assert r['KeyPolicyCrossAccount'][0] == 0
    assert r['KeyPolicyCrossAccount'][1].startswith('Unable to evaluate (')


## Locks the correct PASS: the AWS default "all principals in this account" pattern.
@pytest.mark.parametrize('condition', [
    {'StringEquals': {'kms:CallerAccount': ACCOUNT, 'kms:ViaService': 'ec2.us-east-1.amazonaws.com'}},
    {'StringEquals': {'aws:PrincipalAccount': ACCOUNT}},
    ## Caller confined to own account even though a source key names another (AND-ed).
    {'StringEquals': {'kms:CallerAccount': ACCOUNT, 'aws:SourceAccount': EXTERNAL}},
    {'StringEquals': {'aws:SourceAccount': ACCOUNT}},
])
def test_wildcard_scoped_to_own_account_passes(condition):
    r = _run(_wild(condition))
    assert r['KeyPolicyCrossAccount'] == [1, 'No cross-account principals in key policy']
    assert 'KeyPolicyWildcardPrincipal' not in r
    assert 'KeyCentralizedManagement' not in _run(_wild(condition), '_checkKeyManagementPattern')


def test_unscoped_wildcard_still_flagged_as_wildcard_principal():
    r = _run(_wild({'StringEqualsIfExists': {'kms:CallerAccount': EXTERNAL}}))
    assert r['KeyPolicyWildcardPrincipal'] == [-1, 'Statement Wild: AWS Principal is *']


def test_caller_account_keys_are_intersected():
    ## kms:CallerAccount and aws:PrincipalAccount are AND-ed: only EXTERNAL satisfies both.
    other = '222222222222'
    cond = {'StringEquals': {'kms:CallerAccount': [other, EXTERNAL],
                             'aws:PrincipalAccount': [ACCOUNT, EXTERNAL]}}
    r = _run(_wild(cond))
    assert r['KeyPolicyCrossAccount'] == [-1, f'Statement Wild: * (condition-scoped to account {EXTERNAL})']


def test_contradictory_caller_accounts_match_no_caller():
    cond = {'StringEquals': {'kms:CallerAccount': EXTERNAL, 'aws:PrincipalAccount': ACCOUNT}}
    r = _run(_wild(cond))
    assert r['KeyPolicyCrossAccount'] == [1, 'No cross-account principals in key policy']

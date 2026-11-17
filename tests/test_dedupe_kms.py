"""Read-once tests for the KMS drivers.

Each test queues exactly the number of responses the drivers may now consume
on a botocore Stubber (an extra AWS call fails with an unexpected-request
error) and asserts the checks still produce their expected results.
"""
import datetime
import json
import os
import sys
import threading
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.kms.Kms import Kms  # noqa: E402
from services.kms.drivers.KmsAccount import KmsAccount  # noqa: E402
from services.kms.drivers.KmsCommon import KmsCommon  # noqa: E402

ACCOUNT = '123456789012'
EXTERNAL = '111122223333'
KEY_ID = '1234abcd-12ab-34cd-56ef-1234567890ab'
KEY_ARN = f'arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY_ID}'
OLD = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)


def _client():
    return boto3.client('kms', region_name='us-east-1', aws_access_key_id='testing',
                        aws_secret_access_key='testing')  # nosec - dummy, Stubber only


def _key(**extra):
    md = {'KeyId': KEY_ID, 'Arn': KEY_ARN, 'KeyState': 'Enabled', 'KeyManager': 'CUSTOMER',
          'Origin': 'AWS_KMS', 'CreationDate': OLD, 'KeyRotationEnabled': True}
    md.update(extra)
    return md


POLICY = json.dumps({'Version': '2012-10-17', 'Statement': [
    {'Sid': 'Root', 'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'},
     'Action': 'kms:*', 'Resource': '*'},
    {'Sid': 'Ext', 'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{EXTERNAL}:role/app'},
     'Action': ['kms:Encrypt', 'kms:Decrypt'], 'Resource': '*'},
]})

GRANTS = {'Grants': [
    {'KeyId': KEY_ARN, 'GrantId': 'g1', 'Name': 'n', 'CreationDate': OLD,
     'GranteePrincipal': f'arn:aws:iam::{EXTERNAL}:role/other',
     'IssuingAccount': f'arn:aws:iam::{ACCOUNT}:root',
     'Operations': ['Decrypt', 'Encrypt', 'GenerateDataKey']},
], 'Truncated': False}

GRANT_CHECKS = ('_checkGrantPermissions', '_checkKeyManagementPattern', '_checkKeyUsage')
POLICY_CHECKS = ('_checkPolicyAdminUser', '_checkKeyManagementPattern')


def _runConcurrently(drv, methods):
    errors = {}

    def go(m):
        try:
            getattr(drv, m)()
        except Exception as e:  # recorded: some checks let errors propagate
            errors[m] = e

    threads = [threading.Thread(target=go, args=(m,)) for m in methods]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def _assertPolicyGrantResults(r):
    assert r['GrantOverlyPermissive'] == [-1, 'Grant g1: Full crypto operations']
    assert r['GrantMissingEncryptionContext'] == [-1, 'Grant g1: No encryption context constraint']
    assert r['GrantOldAge'][0] == -1 and r['GrantOldAge'][1].startswith('Grant g1: ')
    assert r['KeyPolicyCrossAccount'] == [-1, f'Statement Ext: arn:aws:iam::{EXTERNAL}:role/app']
    assert r['KeyCentralizedManagement'] == [-1, f'Cross-account access from 1 account(s): {EXTERNAL}'
                                                 '<br>This may indicate centralized key management']
    ## Key has a grant -> not "unused" (KeyUnused needs >= 2 indicators).
    assert 'KeyUnused' not in r


def test_key_policy_and_grants_read_once_per_key():
    kms = _client()
    stub = Stubber(kms)
    ## Exactly one of each: a second call would hit an empty Stubber queue.
    stub.add_response('get_key_policy', {'Policy': POLICY, 'PolicyName': 'default'},
                      {'KeyId': KEY_ID, 'PolicyName': 'default'})
    stub.add_response('list_grants', GRANTS, {'KeyId': KEY_ID, 'Limit': 100})
    with stub:
        drv = KmsCommon(_key(), kms)
        for m in ('_checkPolicyAdminUser', '_checkGrantPermissions', '_checkKeyManagementPattern', '_checkKeyUsage'):
            getattr(drv, m)()
        stub.assert_no_pending_responses()
    _assertPolicyGrantResults(drv.results)


def test_key_policy_and_grants_read_once_when_checks_run_concurrently():
    kms = MagicMock()
    kms.get_key_policy.return_value = {'Policy': POLICY, 'PolicyName': 'default'}
    kms.list_grants.return_value = GRANTS
    drv = KmsCommon(_key(), kms)
    assert _runConcurrently(drv, sorted(set(GRANT_CHECKS + POLICY_CHECKS))) == {}
    kms.get_key_policy.assert_called_once_with(KeyId=KEY_ID, PolicyName='default')
    kms.list_grants.assert_called_once_with(KeyId=KEY_ID, Limit=100)
    _assertPolicyGrantResults(drv.results)


def test_key_usage_without_grants_uses_shared_page():
    kms = _client()
    stub = Stubber(kms)
    stub.add_response('list_grants', {'Grants': [], 'Truncated': False}, {'KeyId': KEY_ID, 'Limit': 100})
    with stub:
        drv = KmsCommon(_key(KeyState='Disabled'), kms)
        assert _runConcurrently(drv, ('_checkGrantPermissions', '_checkKeyUsage')) == {}
        stub.assert_no_pending_responses()
    assert drv.results['KeyUnused'][0] == -1
    assert drv.results['KeyUnused'][1].startswith('Key is disabled<br>No grants<br>Key is ')
    assert 'GrantOverlyPermissive' not in drv.results


def test_grant_pagination_still_reads_remaining_pages_once():
    kms = _client()
    stub = Stubber(kms)
    page1 = dict(GRANTS, Truncated=True, NextMarker='m1')
    page2 = {'Grants': [dict(GRANTS['Grants'][0], GrantId='g2')], 'Truncated': False}
    stub.add_response('list_grants', page1, {'KeyId': KEY_ID, 'Limit': 100})
    stub.add_response('list_grants', page2, {'KeyId': KEY_ID, 'Limit': 100, 'Marker': 'm1'})
    with stub:
        drv = KmsCommon(_key(), kms)
        drv._checkGrantPermissions()
        drv._checkKeyUsage()
        stub.assert_no_pending_responses()
    assert drv.results['GrantDuplicate'] == [-1, 'Grant g2 duplicates g1']


def test_key_policy_error_reaches_same_handlers_once():
    kms = _client()
    stub = Stubber(kms)
    stub.add_client_error('get_key_policy', service_error_code='AccessDeniedException', http_status_code=400)
    with stub:
        drv = KmsCommon(_key(), kms)
        ## _checkKeyManagementPattern swallows the error; _checkPolicyAdminUser
        ## lets it propagate (Evaluator.run handles it), both from one call.
        drv._checkKeyManagementPattern()
        with pytest.raises(ClientError):
            drv._checkPolicyAdminUser()
        stub.assert_no_pending_responses()
    assert drv.results == {}


def test_grant_error_reaches_same_handlers_once():
    kms = _client()
    stub = Stubber(kms)
    stub.add_client_error('list_grants', service_error_code='AccessDeniedException', http_status_code=400)
    with stub:
        drv = KmsCommon(_key(KeyState='Disabled'), kms)
        assert _runConcurrently(drv, GRANT_CHECKS) == {}
        stub.assert_no_pending_responses()
    assert 'KeyUnused' not in drv.results


def test_tags_from_service_class_are_not_reread():
    kms = _client()
    stub = Stubber(kms)  # no responses: any list_resource_tags call fails
    with stub:
        drv = KmsCommon(_key(_resourceTags=[{'TagKey': 'Owner', 'TagValue': 'a'},
                                            {'TagKey': 'DataClassification', 'TagValue': 'b'}]), kms)
        drv._checkKeyMissingOwnershipTags()
        missing = KmsCommon(_key(_resourceTags=[]), kms)
        missing._checkKeyMissingOwnershipTags()
    assert drv.results['KeyMissingOwnershipTags'] == [1, 'Ownership and classification tags present']
    assert missing.results['KeyMissingOwnershipTags'][0] == -1


def test_tags_without_service_data_still_paginated():
    kms = _client()
    stub = Stubber(kms)
    stub.add_response('list_resource_tags', {'Tags': [{'TagKey': 'team', 'TagValue': 'x'}], 'Truncated': False},
                      {'KeyId': KEY_ID})
    with stub:
        drv = KmsCommon(_key(), kms)
        drv._checkKeyMissingOwnershipTags()
        stub.assert_no_pending_responses()
    assert drv.results['KeyMissingOwnershipTags'] == [-1, 'Missing tag: data classification (e.g. DataClassification)']


class _Kms(Kms):
    def __init__(self, client, tagFilter):
        self.kmsClient = client
        self.kmsCustomerManagedKeys = []
        self.kmsKeyMetadata = {}
        self.tags = tagFilter
        self._tags = tagFilter

    def __del__(self):
        pass

    def registerItems(self, objType, items, idFn=None):
        return list(items)


@pytest.mark.parametrize('truncated', [False, True])
def test_service_passes_complete_tag_page_and_key_metadata(truncated):
    kms = _client()
    stub = Stubber(kms)
    md = _key()
    md.pop('KeyRotationEnabled')
    stub.add_response('describe_key', {'KeyMetadata': md}, {'KeyId': KEY_ID})
    stub.add_response('get_key_rotation_status', {'KeyRotationEnabled': True}, {'KeyId': KEY_ID})
    tags = [{'TagKey': 'env', 'TagValue': 'prod'}]
    resp = {'Tags': tags, 'Truncated': truncated}
    if truncated:
        resp['NextMarker'] = 'm'
    stub.add_response('list_resource_tags', resp, {'KeyId': KEY_ID})
    svc = _Kms(kms, {'env': ['prod']})
    with stub:
        svc.checkKmsKey({'Keys': [{'KeyId': KEY_ID, 'KeyArn': KEY_ARN}]})
        stub.assert_no_pending_responses()
    [key] = svc.kmsCustomerManagedKeys
    if truncated:
        assert '_resourceTags' not in key   # driver re-reads every page
    else:
        assert key['_resourceTags'] == tags
    assert svc.kmsKeyMetadata[KEY_ID]['KeyState'] == 'Enabled'
    assert '_resourceTags' not in svc.kmsKeyMetadata[KEY_ID]


def _store(state):
    return {'CustomKeyStoreId': 'cks-1234567890abcdef0', 'CustomKeyStoreName': 'hsm-store',
            'CloudHsmClusterId': 'cluster-abcdefghijk', 'TrustAnchorCertificate': 'cert',
            'ConnectionState': state, 'CreationDate': OLD, 'CustomKeyStoreType': 'AWS_CLOUDHSM'}


def test_account_reuses_service_key_metadata():
    sid = 'cks-1234567890abcdef0'
    kms = _client()
    stub = Stubber(kms)
    stub.add_response('describe_custom_key_stores', {'CustomKeyStores': [_store('DISCONNECTED')], 'Truncated': False}, {})
    ## k2 was not described by the service (checkpointed): one describe_key only.
    stub.add_response('describe_key', {'KeyMetadata': {'KeyId': 'k2', 'KeyState': 'Unavailable',
                                                       'CustomKeyStoreId': sid}}, {'KeyId': 'k2'})
    known = {'k1': {'KeyId': 'k1', 'KeyState': 'Unavailable', 'CustomKeyStoreId': sid}, 'k2': None,
             'k3': {'KeyId': 'k3', 'KeyState': 'PendingDeletion', 'CustomKeyStoreId': sid}}
    with stub:
        drv = KmsAccount(kms, lambda name: None, keyMetadata=known)
        drv._checkCustomKeyStoreUnhealthy()
        assert drv._describeKey('k2')['KeyId'] == 'k2'   # memoized, no second call
        stub.assert_no_pending_responses()
    assert drv.results['CustomKeyStoreUnhealthy'] == [-1, f'hsm-store ({sid}, AWS_CLOUDHSM): DISCONNECTED with 2 key(s) unavailable']


def test_account_describe_key_error_cached_and_reraised():
    kms = _client()
    stub = Stubber(kms)
    stub.add_client_error('describe_key', service_error_code='AccessDeniedException', http_status_code=400)
    with stub:
        drv = KmsAccount(kms, lambda name: None)
        for _ in range(2):
            with pytest.raises(ClientError):
                drv._describeKey('k9')
        stub.assert_no_pending_responses()

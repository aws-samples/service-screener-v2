"""Stubber-based flag -> fix tests for KMS checks the emulator cannot drive.

CustomKeyStoreUnhealthy: creating a custom key store needs a reachable AWS
CloudHSM cluster or external key store (XKS) proxy. The emulator rejects
CreateCustomKeyStore with XksProxyUriUnreachableException and has no CloudHSM
cluster to bind to, so no FAILED / DISCONNECTED store can be produced there.
These tests drive services.kms.drivers.KmsAccount directly with real boto3 KMS
clients wrapped by botocore.stub.Stubber (real API shapes are validated; no
request ever leaves the process).
"""
import datetime
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.kms.drivers.KmsAccount import KmsAccount  # noqa: E402
from services.kms.drivers.KmsCommon import orgConditionScopes, principalAccountId  # noqa: E402

ACCOUNT = '123456789012'
NOW = datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc)


def _client(name='kms'):
    return boto3.client(name, region_name='us-east-1', aws_access_key_id='testing',
                        aws_secret_access_key='testing')  # nosec - dummy, Stubber only


def _store(state, **extra):
    s = {'CustomKeyStoreId': 'cks-1234567890abcdef0', 'CustomKeyStoreName': 'hsm-store',
         'CloudHsmClusterId': 'cluster-abcdefghijk', 'TrustAnchorCertificate': 'cert',
         'ConnectionState': state, 'CreationDate': NOW, 'CustomKeyStoreType': 'AWS_CLOUDHSM'}
    s.update(extra)
    return s


def _run(stubResponses):
    kms = _client()
    stub = Stubber(kms)
    for op, resp, params in stubResponses:
        if isinstance(resp, Exception):
            stub.add_client_error(op, service_error_code=resp.args[0], http_status_code=400)
        else:
            stub.add_response(op, resp, params)
    with stub:
        drv = KmsAccount(kms, lambda name: _client(name))
        drv._checkCustomKeyStoreUnhealthy()
        stub.assert_no_pending_responses()
    return drv.results.get('CustomKeyStoreUnhealthy')


def _keyMd(keyId, state, storeId=None):
    md = {'KeyId': keyId, 'Arn': f'arn:aws:kms:us-east-1:{ACCOUNT}:key/{keyId}', 'KeyState': state,
          'KeyManager': 'CUSTOMER', 'Origin': 'AWS_CLOUDHSM' if storeId else 'AWS_KMS'}
    if storeId:
        md['CustomKeyStoreId'] = storeId
    return {'KeyMetadata': md}


def test_custom_key_store_failed_flags_then_connected_passes():
    failed = _run([('describe_custom_key_stores',
                    {'CustomKeyStores': [_store('FAILED', ConnectionErrorCode='NETWORK_ERRORS')], 'Truncated': False}, {})])
    assert failed[0] == -1 and 'NETWORK_ERRORS' in failed[1]

    fixed = _run([('describe_custom_key_stores', {'CustomKeyStores': [_store('CONNECTED')], 'Truncated': False}, {})])
    assert fixed[0] == 1


def test_custom_key_store_disconnected_with_keys_flags_then_reconnected_passes():
    sid = 'cks-1234567890abcdef0'
    flagged = _run([
        ('describe_custom_key_stores', {'CustomKeyStores': [_store('DISCONNECTED')], 'Truncated': False}, {}),
        ('list_keys', {'Keys': [{'KeyId': 'k1', 'KeyArn': 'arn:aws:kms:us-east-1:123456789012:key/k1'},
                                {'KeyId': 'k2', 'KeyArn': 'arn:aws:kms:us-east-1:123456789012:key/k2'}],
                       'Truncated': False}, {}),
        ('describe_key', _keyMd('k1', 'Unavailable', sid), {'KeyId': 'k1'}),
        ('describe_key', _keyMd('k2', 'Enabled'), {'KeyId': 'k2'}),
    ])
    assert flagged[0] == -1 and '1 key(s)' in flagged[1]

    fixed = _run([('describe_custom_key_stores', {'CustomKeyStores': [_store('CONNECTED')], 'Truncated': False}, {})])
    assert fixed[0] == 1


def test_custom_key_store_disconnected_without_active_keys_is_info():
    sid = 'cks-1234567890abcdef0'
    res = _run([
        ('describe_custom_key_stores', {'CustomKeyStores': [_store('DISCONNECTED')], 'Truncated': False}, {}),
        ('list_keys', {'Keys': [{'KeyId': 'k1', 'KeyArn': 'arn:aws:kms:us-east-1:123456789012:key/k1'}],
                       'Truncated': False}, {}),
        ('describe_key', _keyMd('k1', 'PendingDeletion', sid), {'KeyId': 'k1'}),
    ])
    assert res[0] == 0


def test_custom_key_store_access_denied_is_not_evaluable():
    res = _run([('describe_custom_key_stores', Exception('AccessDeniedException'), None)])
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']


def test_no_custom_key_stores_records_nothing():
    assert _run([('describe_custom_key_stores', {'CustomKeyStores': [], 'Truncated': False}, {})]) is None


def test_org_condition_helper():
    assert orgConditionScopes({'StringEquals': {'aws:PrincipalOrgID': 'o-abc123'}})
    assert orgConditionScopes({'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': ['o-abc/r-1/ou-1/*']}})
    assert not orgConditionScopes({'StringNotEquals': {'aws:PrincipalOrgID': 'o-abc123'}})
    assert not orgConditionScopes({'StringEqualsIfExists': {'aws:PrincipalOrgID': 'o-abc123'}})
    assert not orgConditionScopes({'StringLike': {'aws:PrincipalOrgID': '*'}})
    assert not orgConditionScopes({'StringEquals': {'aws:PrincipalAccount': '111122223333'}})
    assert principalAccountId('111122223333') == '111122223333'
    assert principalAccountId('arn:aws:sts::111122223333:assumed-role/r/s') == '111122223333'
    assert principalAccountId('arn:aws-cn:iam::111122223333:role/r') == '111122223333'
    assert principalAccountId('arn:aws:iam::aws:policy/x') is None


def test_imported_key_noncurrent_material_expiring_flags():
    """Older (NON_CURRENT) imported key material can expire independently of the
    current material; the emulator cannot rotate imported key material on demand,
    so this branch is driven with Stubber."""
    from services.kms.drivers.KmsCommon import KmsCommon
    soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3)
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=400)
    md = {'KeyId': 'k1', 'Arn': f'arn:aws:kms:us-east-1:{ACCOUNT}:key/k1', 'KeyState': 'Enabled',
          'Origin': 'EXTERNAL', 'ExpirationModel': 'KEY_MATERIAL_EXPIRES', 'ValidTo': later,
          'CurrentKeyMaterialId': 'm2'}

    def run(rotations):
        kms = _client()
        stub = Stubber(kms)
        stub.add_response('list_key_rotations', {'Rotations': rotations, 'Truncated': False},
                          {'KeyId': 'k1', 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        with stub:
            drv = KmsCommon(dict(md), kms)
            drv._checkImportedKeyMaterialExpiring()
        return drv.results['ImportedKeyMaterialExpiring']

    def rot(mid, state, validTo):
        return {'KeyId': 'k1', 'KeyMaterialId': mid, 'ImportState': 'IMPORTED', 'KeyMaterialState': state,
                'ExpirationModel': 'KEY_MATERIAL_EXPIRES', 'ValidTo': validTo}

    m1, m2 = 'a' * 64, 'b' * 64
    md['CurrentKeyMaterialId'] = m2
    flagged = run([rot(m1, 'NON_CURRENT', soon), rot(m2, 'CURRENT', later)])
    assert flagged[0] == -1 and m1 in flagged[1] and m2 not in flagged[1]
    fixed = run([rot(m1, 'NON_CURRENT', later), rot(m2, 'CURRENT', later)])
    assert fixed[0] == 1

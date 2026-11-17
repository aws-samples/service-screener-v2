"""Flag -> fix -> re-run tests for KMS checks against the local AWS Emulator.

Covers: ImportedKeyMaterialExpiring, KeyPolicyCrossAccount (org-condition
refinement), RotationPeriodTooLong, KeyMissingOwnershipTags, SingleKeyBroadUse.
CustomKeyStoreUnhealthy needs a reachable CloudHSM cluster / XKS proxy, which
the emulator cannot provide: see tests/test_stub_kms.py.
"""
import datetime
import hashlib
import json
import os

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ACCOUNT = '000000000000'
EXTERNAL_ACCOUNT = '111122223333'


# --------------------------------------------------------------------------- #
# Minimal RSAES-OAEP-SHA-256 wrapping (the test venv has no `cryptography`).
# Used only to wrap random test key material for ImportKeyMaterial.
# --------------------------------------------------------------------------- #
def _der(b, i):
    i += 1
    length = b[i]
    i += 1
    if length & 0x80:
        n = length & 0x7f
        length = int.from_bytes(b[i:i + n], 'big')
        i += n
    return b[i:i + length], i + length


def _rsaPublicKey(spki):
    body, _ = _der(spki, 0)
    _, j = _der(body, 0)                  # AlgorithmIdentifier
    bits, _ = _der(body, j)               # BIT STRING
    seq, _ = _der(bits[1:], 0)
    n, j = _der(seq, 0)
    e, _ = _der(seq, j)
    return int.from_bytes(n, 'big'), int.from_bytes(e, 'big')


def _mgf1(seed, length):
    out, c = b'', 0
    while len(out) < length:
        out += hashlib.sha256(seed + c.to_bytes(4, 'big')).digest()
        c += 1
    return out[:length]


def _oaepWrap(spki, msg):
    n, e = _rsaPublicKey(spki)
    k = (n.bit_length() + 7) // 8
    hl = 32
    db = hashlib.sha256(b'').digest() + b'\x00' * (k - len(msg) - 2 * hl - 2) + b'\x01' + msg
    seed = os.urandom(hl)
    maskedDb = bytes(a ^ b for a, b in zip(db, _mgf1(seed, k - hl - 1)))
    maskedSeed = bytes(a ^ b for a, b in zip(seed, _mgf1(maskedDb, hl)))
    return pow(int.from_bytes(b'\x00' + maskedSeed + maskedDb, 'big'), e, n).to_bytes(k, 'big')


def _importMaterial(kms, keyId, material, **kw):
    p = kms.get_parameters_for_import(KeyId=keyId, WrappingAlgorithm='RSAES_OAEP_SHA_256',
                                      WrappingKeySpec='RSA_2048')
    kms.import_key_material(KeyId=keyId, ImportToken=p['ImportToken'],
                            EncryptedKeyMaterial=_oaepWrap(p['PublicKey'], material), **kw)


def _deleteKey(kms, keyId):
    try:
        kms.schedule_key_deletion(KeyId=keyId, PendingWindowInDays=7)
    except Exception:
        pass


def _policy(statements):
    return json.dumps({'Version': '2012-10-17', 'Statement': statements})


ROOT_STMT = {'Sid': 'Root', 'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'},
             'Action': 'kms:*', 'Resource': '*'}


# --------------------------------------------------------------------------- #
def test_kms_imported_key_material_expiring(emu, uid):
    kms = emu.client('kms')
    keyId = kms.create_key(Origin='EXTERNAL', Description=f'ss-test-{uid}')['KeyMetadata']['KeyId']
    material = os.urandom(32)
    try:
        def misconfigure():
            validTo = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5)
            _importMaterial(kms, keyId, material, ExpirationModel='KEY_MATERIAL_EXPIRES', ValidTo=validTo)

        def fix():
            kms.delete_imported_key_material(KeyId=keyId)
            _importMaterial(kms, keyId, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')

        before, after = assertFlagFixCycle(emu, 'kms', 'ImportedKeyMaterialExpiring', keyId, misconfigure, fix)
        assert set(after.values()) == {1}
    finally:
        _deleteKey(kms, keyId)


def test_kms_imported_key_pending_import_flags_then_far_expiry_passes(emu, uid):
    kms = emu.client('kms')
    keyId = kms.create_key(Origin='EXTERNAL', Description=f'ss-test-{uid}')['KeyMetadata']['KeyId']
    try:
        def misconfigure():
            pass  # freshly created EXTERNAL key: PendingImport, unusable

        def fix():
            validTo = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=200)
            _importMaterial(kms, keyId, os.urandom(32), ExpirationModel='KEY_MATERIAL_EXPIRES', ValidTo=validTo)

        assertFlagFixCycle(emu, 'kms', 'ImportedKeyMaterialExpiring', keyId, misconfigure, fix)
    finally:
        _deleteKey(kms, keyId)


def test_kms_imported_check_ignores_aws_kms_origin(emu, uid):
    kms = emu.client('kms')
    keyId = kms.create_key(Description=f'ss-test-{uid}')['KeyMetadata']['KeyId']
    try:
        assert runCheck(emu, 'kms', 'ImportedKeyMaterialExpiring', keyId).statuses() == {}
    finally:
        _deleteKey(kms, keyId)


def test_kms_key_policy_cross_account_org_condition(emu, uid):
    kms = emu.client('kms')
    keyId = kms.create_key(Description=f'ss-test-{uid}')['KeyMetadata']['KeyId']
    ext = {'Sid': 'External', 'Effect': 'Allow',
           'Principal': {'AWS': f'arn:aws:iam::{EXTERNAL_ACCOUNT}:root'},
           'Action': ['kms:Decrypt', 'kms:DescribeKey'], 'Resource': '*'}
    try:
        def misconfigure():
            kms.put_key_policy(KeyId=keyId, PolicyName='default', Policy=_policy([ROOT_STMT, ext]))

        def fix():
            scoped = dict(ext, Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-exampleorgid'}})
            kms.put_key_policy(KeyId=keyId, PolicyName='default', Policy=_policy([ROOT_STMT, scoped]))

        assertFlagFixCycle(emu, 'kms', 'KeyPolicyCrossAccount', keyId, misconfigure, fix)
    finally:
        _deleteKey(kms, keyId)


def test_kms_key_policy_cross_account_negated_org_condition_still_flags(emu, uid):
    """StringNotEquals aws:PrincipalOrgID and a bare account-ID principal must not pass."""
    kms = emu.client('kms')
    keyId = kms.create_key(Description=f'ss-test-{uid}')['KeyMetadata']['KeyId']
    ext = {'Sid': 'External', 'Effect': 'Allow', 'Principal': {'AWS': EXTERNAL_ACCOUNT},
           'Action': 'kms:Decrypt', 'Resource': '*',
           'Condition': {'StringNotEquals': {'aws:PrincipalOrgID': 'o-exampleorgid'}}}
    try:
        def misconfigure():
            kms.put_key_policy(KeyId=keyId, PolicyName='default', Policy=_policy([ROOT_STMT, ext]))

        def fix():
            kms.put_key_policy(KeyId=keyId, PolicyName='default', Policy=_policy([ROOT_STMT]))

        assertFlagFixCycle(emu, 'kms', 'KeyPolicyCrossAccount', keyId, misconfigure, fix)
    finally:
        _deleteKey(kms, keyId)


def test_kms_rotation_period_too_long(emu, uid):
    kms = emu.client('kms')
    keyId = kms.create_key(Description=f'ss-test-{uid}')['KeyMetadata']['KeyId']
    try:
        def misconfigure():
            kms.enable_key_rotation(KeyId=keyId, RotationPeriodInDays=2000)

        def fix():
            kms.enable_key_rotation(KeyId=keyId, RotationPeriodInDays=365)

        assertFlagFixCycle(emu, 'kms', 'RotationPeriodTooLong', keyId, misconfigure, fix)
    finally:
        _deleteKey(kms, keyId)


def test_kms_key_missing_ownership_tags(emu, uid):
    kms = emu.client('kms')
    keyId = kms.create_key(Description=f'ss-test-{uid}')['KeyMetadata']['KeyId']
    try:
        def misconfigure():
            kms.tag_resource(KeyId=keyId, Tags=[{'TagKey': 'Project', 'TagValue': 'demo'},
                                                {'TagKey': 'Owner', 'TagValue': 'team-a'}])

        def fix():
            kms.tag_resource(KeyId=keyId, Tags=[{'TagKey': 'data-classification', 'TagValue': 'internal'}])

        assertFlagFixCycle(emu, 'kms', 'KeyMissingOwnershipTags', keyId, misconfigure, fix)
    finally:
        _deleteKey(kms, keyId)


def test_kms_single_key_broad_use(emu, uid):
    kms = emu.client('kms')
    ec2, sm, ssm = emu.client('ec2'), emu.client('secretsmanager'), emu.client('ssm')
    keyArn = kms.create_key(Description=f'ss-test-{uid}')['KeyMetadata']['Arn']
    alias = f'alias/ss-test-{uid}'
    kms.create_alias(AliasName=alias, TargetKeyId=keyArn)
    state = {}
    try:
        def misconfigure():
            state['vol'] = ec2.create_volume(AvailabilityZone='us-east-1a', Size=1, Encrypted=True,
                                             KmsKeyId=keyArn)['VolumeId']
            ## Secrets Manager referenced through the alias, to exercise alias resolution.
            state['secret'] = sm.create_secret(Name=f'ss-test-{uid}', SecretString='x', KmsKeyId=alias)['ARN']
            state['param'] = f'/ss-test/{uid}'
            ssm.put_parameter(Name=state['param'], Value='x', Type='SecureString', KeyId=keyArn)

        def fix():
            ## Keep the volume on the shared key; move the other stores to their own keys.
            sm.delete_secret(SecretId=state.pop('secret'), ForceDeleteWithoutRecovery=True)
            ssm.delete_parameter(Name=state.pop('param'))

        assertFlagFixCycle(emu, 'kms', 'SingleKeyBroadUse', 'KMS::Account', misconfigure, fix)
    finally:
        if 'secret' in state:
            sm.delete_secret(SecretId=state['secret'], ForceDeleteWithoutRecovery=True)
        if 'param' in state:
            ssm.delete_parameter(Name=state['param'])
        if 'vol' in state:
            ec2.delete_volume(VolumeId=state['vol'])
        try:
            kms.delete_alias(AliasName=alias)
        except Exception:
            pass
        _deleteKey(kms, keyArn)

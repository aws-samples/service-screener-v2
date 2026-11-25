"""Flag -> fix -> re-run tests for the WAFS2027 IAM identity checks that the
AWS Emulator can drive end to end (role trust policies, IAM server
certificates, identity policies).

Credential-report based checks (iamActiveKeyUnused, iamUserHumanAndMachineCreds)
are tested with botocore Stubber in tests/test_stub_iam_identity.py: the
emulator, like IAM, caches the credential report, so a user created after the
first report never appears in it during a test run.
"""
import json
import os
import shutil
import subprocess
import tempfile

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ACCOUNT = '000000000000'


def _trust(statement):
    return json.dumps({'Version': '2012-10-17', 'Statement': [statement]})


def _deleteRole(iam, name):
    try:
        for p in iam.list_role_policies(RoleName=name).get('PolicyNames', []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# iamRoleTrustPublicPrincipal
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize('principal', [{'AWS': '*'}, '*', {'AWS': ['*']}])
def test_role_trust_public_principal(emu, uid, principal):
    iam = emu.client('iam')
    role = f'ss-test-trust-{uid}'
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=_trust(
        {'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'}, 'Action': 'sts:AssumeRole'}))
    try:
        def misconfigure():
            iam.update_assume_role_policy(RoleName=role, PolicyDocument=_trust(
                {'Effect': 'Allow', 'Principal': principal, 'Action': 'sts:AssumeRole'}))

        def fix():
            iam.update_assume_role_policy(RoleName=role, PolicyDocument=_trust(
                {'Effect': 'Allow', 'Principal': principal, 'Action': 'sts:AssumeRole',
                 'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-abcdef1234'}}}))

        assertFlagFixCycle(emu, 'iam', 'iamRoleTrustPublicPrincipal', role, misconfigure, fix)
    finally:
        _deleteRole(iam, role)


def test_role_trust_external_id_only_is_still_public(emu, uid):
    """sts:ExternalId is not a secret, so it does not restrict a "*" principal."""
    iam = emu.client('iam')
    role = f'ss-test-trustx-{uid}'
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=_trust(
        {'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'sts:AssumeRole',
         'Condition': {'StringEquals': {'sts:ExternalId': 'abc123'}}}))
    try:
        res = runCheck(emu, 'iam', 'iamRoleTrustPublicPrincipal', role).statuses()
        assert res and all(v == -1 for v in res.values()), res
    finally:
        _deleteRole(iam, role)


# --------------------------------------------------------------------------- #
# oidcRoleTrustNoSubjectCondition
# --------------------------------------------------------------------------- #
GITHUB = 'token.actions.githubusercontent.com'


def _oidcTrust(host, condition):
    stmt = {'Effect': 'Allow',
            'Principal': {'Federated': f'arn:aws:iam::{ACCOUNT}:oidc-provider/{host}'},
            'Action': 'sts:AssumeRoleWithWebIdentity',
            'Condition': condition}
    return _trust(stmt)


@pytest.mark.parametrize('badCondition', [
    {'StringEquals': {f'{GITHUB}:aud': 'sts.amazonaws.com'}},
    {'StringEquals': {f'{GITHUB}:aud': 'sts.amazonaws.com'}, 'StringLike': {f'{GITHUB}:sub': 'repo:*'}},
    {'StringEquals': {f'{GITHUB}:aud': 'sts.amazonaws.com'}, 'StringLike': {f'{GITHUB}:sub': 'repo:my-org*'}},
])
def test_oidc_role_trust_no_subject_condition(emu, uid, badCondition):
    iam = emu.client('iam')
    role = f'ss-test-oidc-{uid}'
    providerArn = None
    try:
        try:
            providerArn = iam.create_open_id_connect_provider(
                Url=f'https://{GITHUB}', ClientIDList=['sts.amazonaws.com'],
                ThumbprintList=['6938fd4d98bab03faadb97b34396831e3780aea1'])['OpenIDConnectProviderArn']
        except iam.exceptions.EntityAlreadyExistsException:
            pass
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=_oidcTrust(
            GITHUB, {'StringEquals': {f'{GITHUB}:sub': 'repo:my-org/my-repo:ref:refs/heads/main'}}))

        def misconfigure():
            iam.update_assume_role_policy(RoleName=role, PolicyDocument=_oidcTrust(GITHUB, badCondition))

        def fix():
            iam.update_assume_role_policy(RoleName=role, PolicyDocument=_oidcTrust(GITHUB, {
                'StringEquals': {f'{GITHUB}:aud': 'sts.amazonaws.com'},
                'StringLike': {f'{GITHUB}:sub': 'repo:my-org/my-repo:*'}}))

        assertFlagFixCycle(emu, 'iam', 'oidcRoleTrustNoSubjectCondition', role, misconfigure, fix)
    finally:
        _deleteRole(iam, role)
        if providerArn:
            try:
                iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=providerArn)
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# broadSecretReadAccess
# --------------------------------------------------------------------------- #
def _policy(action, resource):
    return json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': action, 'Resource': resource}]})


@pytest.mark.parametrize('action,resource', [
    ('secretsmanager:GetSecretValue', '*'),
    (['ssm:GetParameters', 'ssm:GetParametersByPath'], 'arn:aws:ssm:*:*:parameter/*'),
    ('secretsmanager:Get*', f'arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:*'),
])
def test_broad_secret_read_access_inline(emu, uid, action, resource):
    iam = emu.client('iam')
    role = f'ss-test-secret-{uid}'
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=_trust(
        {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}))
    try:
        def misconfigure():
            iam.put_role_policy(RoleName=role, PolicyName='read', PolicyDocument=_policy(action, resource))

        def fix():
            iam.put_role_policy(RoleName=role, PolicyName='read', PolicyDocument=_policy(
                action, [f'arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-*',
                         f'arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/*']))

        before, _ = assertFlagFixCycle(emu, 'iam', 'broadSecretReadAccess', 'Account', misconfigure, fix)
    finally:
        _deleteRole(iam, role)


def test_broad_secret_read_access_managed(emu, uid):
    iam = emu.client('iam')
    user = f'ss-test-secretu-{uid}'
    iam.create_user(UserName=user)
    arn = iam.create_policy(PolicyName=f'ss-test-secretp-{uid}',
                            PolicyDocument=_policy('secretsmanager:GetSecretValue', '*'))['Policy']['Arn']
    try:
        def misconfigure():
            iam.attach_user_policy(UserName=user, PolicyArn=arn)

        def fix():
            iam.detach_user_policy(UserName=user, PolicyArn=arn)

        assertFlagFixCycle(emu, 'iam', 'broadSecretReadAccess', 'Account', misconfigure, fix)
    finally:
        try:
            iam.detach_user_policy(UserName=user, PolicyArn=arn)
        except Exception:
            pass
        iam.delete_policy(PolicyArn=arn)
        iam.delete_user(UserName=user)


# --------------------------------------------------------------------------- #
# iamServerCertificates
# --------------------------------------------------------------------------- #
def _openssl():
    for cand in (shutil.which('openssl'), '/opt/homebrew/bin/openssl', '/usr/local/bin/openssl'):
        if not cand or not os.path.exists(cand):
            continue
        ver = subprocess.run([cand, 'version'], capture_output=True, text=True).stdout
        # -not_before/-not_after on `req` need OpenSSL >= 3.4
        if ver.startswith('OpenSSL') and tuple(int(x) for x in ver.split()[1].split('.')[:2]) >= (3, 4):
            return cand
    return None


def _selfSigned(notBefore, notAfter):
    exe = _openssl()
    if not exe:
        pytest.skip('OpenSSL >= 3.4 not available to create a test certificate')
    d = tempfile.mkdtemp(prefix='ss-cert-')
    try:
        subprocess.run([exe, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', d + '/k.pem',
                        '-out', d + '/c.pem', '-subj', '/CN=ss-test.example.com',
                        '-not_before', notBefore, '-not_after', notAfter],
                       check=True, capture_output=True)
        return open(d + '/c.pem').read(), open(d + '/k.pem').read()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_iam_server_certificates_expired(emu, uid):
    iam = emu.client('iam')
    name = f'ss-test-cert-{uid}'
    body, key = _selfSigned('20200101000000Z', '20200201000000Z')
    try:
        def misconfigure():
            iam.upload_server_certificate(ServerCertificateName=name, CertificateBody=body, PrivateKey=key)

        def fix():
            iam.delete_server_certificate(ServerCertificateName=name)

        assertFlagFixCycle(emu, 'iam', 'iamServerCertificates', 'Account', misconfigure, fix)
    finally:
        try:
            iam.delete_server_certificate(ServerCertificateName=name)
        except Exception:
            pass


def test_iam_server_certificates_valid_is_info(emu, uid):
    iam = emu.client('iam')
    name = f'ss-test-certok-{uid}'
    body, key = _selfSigned('20260101000000Z', '20991231000000Z')
    iam.upload_server_certificate(ServerCertificateName=name, CertificateBody=body, PrivateKey=key)
    try:
        res = runCheck(emu, 'iam', 'iamServerCertificates', 'Account').statuses()
        assert list(res.values()) == [0], res
    finally:
        iam.delete_server_certificate(ServerCertificateName=name)

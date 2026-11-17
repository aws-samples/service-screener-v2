"""Flag -> fix -> re-run tests for WAFS2027 Lambda checks against the local AWS Emulator.

lambdaDeprecatedRuntime, lambdaEnvVarSecrets, lambdaCodeSigningWarnOnly, signerProfileInvalid.
"""
import datetime
import io
import json
import zipfile

from tests.emulator.conftest import assertFlagFixCycle, runCheck

TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('index.py', 'def handler(event, context):\n    return 1\n')
    return buf.getvalue()


class _Fn:
    """Creates an IAM role + Lambda function; deletes both on exit."""

    def __init__(self, emu, uid, runtime='python3.12', env=None):
        self.iam = emu.client('iam')
        self.lam = emu.client('lambda')
        self.name = f'ss-test-fn-{uid}'
        self.role = f'ss-test-role-{uid}'
        self.runtime = runtime
        self.env = env

    def __enter__(self):
        arn = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
        kw = {'Environment': {'Variables': self.env}} if self.env else {}
        self.lam.create_function(FunctionName=self.name, Runtime=self.runtime, Role=arn,
                                 Handler='index.handler', Code={'ZipFile': _zip()}, **kw)
        self.lam.get_waiter('function_active_v2').wait(FunctionName=self.name)
        return self

    def update(self, **kw):
        self.lam.update_function_configuration(FunctionName=self.name, **kw)
        self.lam.get_waiter('function_updated_v2').wait(FunctionName=self.name)

    def __exit__(self, *a):
        for fn in (lambda: self.lam.delete_function_code_signing_config(FunctionName=self.name),
                   lambda: self.lam.delete_function(FunctionName=self.name),
                   lambda: self.iam.delete_role(RoleName=self.role)):
            try:
                fn()
            except Exception:
                pass


def test_lambda_deprecated_runtime(emu, uid):
    with _Fn(emu, uid, runtime='python3.12') as f:
        assertFlagFixCycle(emu, 'lambda', 'lambdaDeprecatedRuntime', f.name,
                           lambda: f.update(Runtime='python3.8'),
                           lambda: f.update(Runtime='python3.13'))


def test_lambda_deprecated_runtime_provided_al2(emu, uid):
    """provided.al2 passed its AWS deprecation date on 2026-07-31."""
    with _Fn(emu, uid, runtime='python3.12') as f:
        assertFlagFixCycle(emu, 'lambda', 'lambdaDeprecatedRuntime', f.name,
                           lambda: f.update(Runtime='provided.al2', Handler='bootstrap'),
                           lambda: f.update(Runtime='provided.al2023', Handler='bootstrap'))


def test_lambda_env_var_secrets(emu, uid):
    with _Fn(emu, uid, env={'LOG_LEVEL': 'INFO'}) as f:
        def misconfigure():
            f.update(Environment={'Variables': {'LOG_LEVEL': 'INFO', 'DB_PASSWORD': 'hunter2-plaintext'}})

        def fix():
            f.update(Environment={'Variables': {
                'LOG_LEVEL': 'INFO',
                'DB_PASSWORD': 'arn:aws:secretsmanager:us-east-1:000000000000:secret:db-AbCdEf',
                'DB_PASSWORD_SECRET_NAME': 'prod/db',
                'TOKEN_TTL': '3600'}})

        assertFlagFixCycle(emu, 'lambda', 'lambdaEnvVarSecrets', f.name, misconfigure, fix)
        # never echo secret values into the report
        assert 'hunter2' not in json.dumps(runCheck(emu, 'lambda', 'lambdaEnvVarSecrets', f.name).results)


def test_lambda_env_var_secrets_value_patterns(emu, uid):
    with _Fn(emu, uid, env={'LOG_LEVEL': 'INFO'}) as f:
        assertFlagFixCycle(emu, 'lambda', 'lambdaEnvVarSecrets', f.name,
                           lambda: f.update(Environment={'Variables': {'UPSTREAM': 'postgres://app:pw123@db:5432/x'}}),
                           lambda: f.update(Environment={'Variables': {'UPSTREAM': 'postgres://db:5432/x'}}))
        assertFlagFixCycle(emu, 'lambda', 'lambdaEnvVarSecrets', f.name,
                           lambda: f.update(Environment={'Variables': {'K': 'AKIAIOSFODNN7EXAMPLE'}}),
                           lambda: f.update(Environment={'Variables': {'K': 'value'}}))
        # empty-user Redis URL; fixed form references an SSM parameter path
        assertFlagFixCycle(emu, 'lambda', 'lambdaEnvVarSecrets', f.name,
                           lambda: f.update(Environment={'Variables': {'REDIS_URL': 'redis://:s3cretpw@cache:6379'}}),
                           lambda: f.update(Environment={'Variables': {'REDIS_URL': 'redis://cache:6379',
                                                                        'REDIS_PASSWORD': '/prod/redis/password'}}))


def _signingProfile(emu, uid, suffix='p'):
    sig = emu.client('signer')
    name = f'ssTest{uid}{suffix}'
    p = sig.put_signing_profile(profileName=name, platformId='AWSLambda-SHA384-ECDSA')
    return sig, name, p


def test_lambda_code_signing_warn_only(emu, uid):
    lam = emu.client('lambda')
    sig, pname, prof = _signingProfile(emu, uid)
    csc = lam.create_code_signing_config(
        AllowedPublishers={'SigningProfileVersionArns': [prof['profileVersionArn']]},
        CodeSigningPolicies={'UntrustedArtifactOnDeployment': 'Enforce'})['CodeSigningConfig']
    cscArn = csc['CodeSigningConfigArn']
    try:
        with _Fn(emu, uid) as f:
            def misconfigure():
                lam.update_code_signing_config(CodeSigningConfigArn=cscArn,
                                               CodeSigningPolicies={'UntrustedArtifactOnDeployment': 'Warn'})
                lam.put_function_code_signing_config(FunctionName=f.name, CodeSigningConfigArn=cscArn)

            def fix():
                lam.update_code_signing_config(CodeSigningConfigArn=cscArn,
                                               CodeSigningPolicies={'UntrustedArtifactOnDeployment': 'Enforce'})

            _, after = assertFlagFixCycle(emu, 'lambda', 'lambdaCodeSigningWarnOnly', f.name, misconfigure, fix)
            assert all(s == 1 for s in after.values()), after
    finally:
        try:
            lam.delete_code_signing_config(CodeSigningConfigArn=cscArn)
        except Exception:
            pass
        try:
            sig.cancel_signing_profile(profileName=pname)
        except Exception:
            pass


def test_signer_profile_invalid(emu, uid):
    lam = emu.client('lambda')
    sig, goodName, good = _signingProfile(emu, uid, 'good')
    _, badName, bad = _signingProfile(emu, uid, 'bad')
    csc = lam.create_code_signing_config(
        AllowedPublishers={'SigningProfileVersionArns': [good['profileVersionArn']]},
        CodeSigningPolicies={'UntrustedArtifactOnDeployment': 'Enforce'})['CodeSigningConfig']
    cscArn, cscId = csc['CodeSigningConfigArn'], csc['CodeSigningConfigId']
    try:
        def misconfigure():
            sig.revoke_signing_profile(profileName=badName, profileVersion=bad['profileVersion'],
                                       reason='compromised', effectiveTime=datetime.datetime.now(datetime.timezone.utc))
            lam.update_code_signing_config(CodeSigningConfigArn=cscArn, AllowedPublishers={
                'SigningProfileVersionArns': [good['profileVersionArn'], bad['profileVersionArn']]})

        def fix():
            lam.update_code_signing_config(CodeSigningConfigArn=cscArn, AllowedPublishers={
                'SigningProfileVersionArns': [good['profileVersionArn']]})

        _, after = assertFlagFixCycle(emu, 'lambda', 'signerProfileInvalid', cscId, misconfigure, fix)
        assert all(s == 1 for s in after.values()), after
    finally:
        try:
            lam.delete_code_signing_config(CodeSigningConfigArn=cscArn)
        except Exception:
            pass
        for n in (goodName, badName):
            try:
                sig.cancel_signing_profile(profileName=n)
            except Exception:
                pass

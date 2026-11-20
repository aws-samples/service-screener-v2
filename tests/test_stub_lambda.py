"""Stubber-based edge-case tests for WAFS2027 Lambda checks.

The emulator flag->fix->re-run tests live in tests/emulator/test_emu_lambda.py.
These cover states the emulator cannot produce on demand: AccessDenied, cross-account
signing profiles, older (non-current) profile versions, cross-account not-found, undecryptable environment variables
(Environment.Error), container-image functions and default (absent) CSC policy.
Real boto3 clients wrapped by botocore Stubber validate the API shapes; no network.
"""
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.lambda_.drivers.LambdaCommon import LambdaCommon  # noqa: E402
from services.lambda_.drivers.LambdaCodeSigningConfig import LambdaCodeSigningConfig  # noqa: E402

ACCT = '111122223333'
REGION = 'us-east-1'


def _client(svc):
    return boto3.client(svc, region_name=REGION, aws_access_key_id='x', aws_secret_access_key='x')


def _fn(**kw):
    f = {'FunctionName': 'fn1', 'FunctionArn': f'arn:aws:lambda:{REGION}:{ACCT}:function:fn1',
         'Role': f'arn:aws:iam::{ACCT}:role/r', 'PackageType': 'Zip', 'Runtime': 'python3.12'}
    f.update(kw)
    return f


def _driver(fn, lam=None):
    Config.init()
    return LambdaCommon(fn, lam or _client('lambda'), None, {fn['Role']: 1})


# ---------------- lambdaDeprecatedRuntime ----------------
import services.lambda_.drivers.LambdaCommon as _lcMod  # noqa: E402
from datetime import datetime as _realDatetime, date as _date  # noqa: E402

PINNED_TODAY = _date(2026, 11, 20)


def _pinToday(monkeypatch, day):
    """Pin the driver's notion of 'today' so these tests never depend on the wall clock."""
    class _Fixed(_realDatetime):
        @classmethod
        def now(cls, tz=None):
            return _realDatetime(day.year, day.month, day.day, 12, 0, tzinfo=tz)
    monkeypatch.setattr(_lcMod, 'datetime', _Fixed)


@pytest.fixture
def pinnedToday(monkeypatch):
    _pinToday(monkeypatch, PINNED_TODAY)


@pytest.mark.usefixtures('pinnedToday')
@pytest.mark.parametrize('runtime,expected', [
    ('python3.8', -1), ('nodejs16.x', -1), ('go1.x', -1), ('provided', -1), ('java8', -1),
    ('provided.al2', -1), ('python3.10', -1),
    ('python3.13', 1), ('nodejs22.x', 1), ('java21', 1), ('provided.al2023', 1),
])
def test_deprecated_runtime(runtime, expected):
    d = _driver(_fn(Runtime=runtime))
    d._checkLambdaDeprecatedRuntime()
    assert d.results['lambdaDeprecatedRuntime'][0] == expected


def test_deprecated_runtime_image_not_evaluable():
    fn = _fn(PackageType='Image')
    fn.pop('Runtime')
    d = _driver(fn)
    d._checkLambdaDeprecatedRuntime()
    assert d.results['lambdaDeprecatedRuntime'][0] == 0


# ---------------- lambdaEnvVarSecrets ----------------
@pytest.mark.parametrize('variables,expected', [
    ({'DB_PASSWORD': 'p@ss'}, -1),
    ({'API_KEY': 'abcd1234efgh'}, -1),
    ({'GITHUB_TOKEN': 'ghp_xxx'}, -1),
    ({'ANYTHING': 'ASIAIOSFODNN7EXAMPLE'}, -1),
    ({'CERT': '-----BEGIN RSA PRIVATE KEY-----\nMIIB'}, -1),
    ({'DATABASE_URL': 'mysql://u:secretpw@h/db'}, -1),
    ({'DB_PASSWORD': 'arn:aws:secretsmanager:us-east-1:111122223333:secret:x'}, 1),
    ({'API_KEY': 'arn:aws:ssm:us-east-1:111122223333:parameter/k'}, 1),
    ({'DB_PASSWORD_SECRET_ARN': 'whatever', 'TOKEN_TTL': '3600', 'SECRET_NAME': 'prod/db'}, 1),
    ({'ENABLE_TOKEN': 'true', 'LOG_LEVEL': 'DEBUG', 'DATABASE_URL': 'postgres://h:5432/db'}, 1),
])
def test_env_var_secrets(variables, expected):
    d = _driver(_fn(Environment={'Variables': variables}))
    d._checkLambdaEnvVarSecrets()
    res = d.results['lambdaEnvVarSecrets']
    assert res[0] == expected, res
    for v in variables.values():
        if len(v) > 4:
            assert v not in res[1]  # values are never echoed


def test_env_var_secrets_undecryptable():
    d = _driver(_fn(Environment={'Error': {'ErrorCode': 'AccessDeniedException', 'Message': 'kms'}}))
    d._checkLambdaEnvVarSecrets()
    assert d.results['lambdaEnvVarSecrets'] == [0, 'Unable to evaluate (AccessDeniedException)']


def test_env_var_secrets_none():
    d = _driver(_fn())
    d._checkLambdaEnvVarSecrets()
    assert d.results['lambdaEnvVarSecrets'][0] == 1


# ---------------- lambdaCodeSigningWarnOnly ----------------
CSC_ARN = f'arn:aws:lambda:{REGION}:{ACCT}:code-signing-config:csc-0123456789abcdef0'
PV_ARN = f'arn:aws:signer:{REGION}:{ACCT}:/signing-profiles/prof/0000000001'


def _csc(policy):
    c = {'CodeSigningConfigId': 'csc-0123456789abcdef0', 'CodeSigningConfigArn': CSC_ARN,
         'AllowedPublishers': {'SigningProfileVersionArns': [PV_ARN]}, 'LastModified': '2026-01-01'}
    c['CodeSigningPolicies'] = {} if policy is None else {'UntrustedArtifactOnDeployment': policy}
    return c


@pytest.mark.parametrize('policy,expected', [('Warn', -1), ('Enforce', 1), (None, -1)])
def test_code_signing_warn_only(policy, expected):
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_response('get_function_code_signing_config',
                        {'CodeSigningConfigArn': CSC_ARN, 'FunctionName': 'fn1'}, {'FunctionName': 'fn1'})
        st.add_response('get_code_signing_config', {'CodeSigningConfig': _csc(policy)},
                        {'CodeSigningConfigArn': CSC_ARN})
        d = _driver(_fn(), lam)
        d._checkLambdaCodeSigningWarnOnly()
    assert d.results['lambdaCodeSigningWarnOnly'][0] == expected


def test_code_signing_warn_only_access_denied():
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_client_error('get_function_code_signing_config', 'AccessDeniedException')
        d = _driver(_fn(), lam)
        d._checkLambdaCodeSigningWarnOnly()
    assert d.results['lambdaCodeSigningWarnOnly'] == [0, 'Unable to evaluate (AccessDeniedException)']


def test_code_signing_warn_only_not_attached():
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_response('get_function_code_signing_config', {'CodeSigningConfigArn': '', 'FunctionName': 'fn1'},
                        {'FunctionName': 'fn1'})
        d = _driver(_fn(), lam)
        d._checkLambdaCodeSigningWarnOnly()
    assert d.results['lambdaCodeSigningWarnOnly'][0] == 0


# ---------------- signerProfileInvalid ----------------
def _profile(status='Active', version='0000000001'):
    return {'profileName': 'prof', 'profileVersion': version,
            'profileVersionArn': f'arn:aws:signer:{REGION}:{ACCT}:/signing-profiles/prof/{version}',
            'platformId': 'AWSLambda-SHA384-ECDSA', 'status': status}


def _runSigner(add, arns=None):
    Config.init()  # each test is a fresh scan (signing profiles are cached per scan)
    sig = _client('signer')
    csc = _csc('Enforce')
    if arns:
        csc['AllowedPublishers']['SigningProfileVersionArns'] = arns
    with Stubber(sig) as st:
        add(st)
        d = LambdaCodeSigningConfig(csc, sig)
        d._checkSignerProfileInvalid()
    return d.results['signerProfileInvalid']


@pytest.mark.parametrize('status,version,expected', [
    ('Active', '0000000001', 1), ('Revoked', '0000000001', -1), ('Canceled', '0000000001', -1), ('Active', '0000000002', 0),
    ('Revoked', '0000000002', 0), ('Canceled', '0000000002', -1),
])
def test_signer_profile_status(status, version, expected):
    res = _runSigner(lambda st: st.add_response('get_signing_profile', _profile(status, version),
                                                 {'profileName': 'prof'}))
    assert res[0] == expected, res


def test_signer_profile_not_found():
    res = _runSigner(lambda st: st.add_client_error('get_signing_profile', 'ResourceNotFoundException'))
    assert res[0] == -1


def test_signer_profile_access_denied_cross_account():
    other = f'arn:aws:signer:{REGION}:444455556666:/signing-profiles/prof/0000000001'
    res = _runSigner(lambda st: st.add_client_error('get_signing_profile', 'AccessDeniedException',
                                                     expected_params={'profileName': 'prof',
                                                                      'profileOwner': '444455556666'}),
                     arns=[other])
    assert res == [0, 'Unable to evaluate (prof (AccessDeniedException))']


def test_signer_profile_not_found_cross_account_not_evaluable():
    """A cross-account profile never shared with this account also returns not-found."""
    other = f'arn:aws:signer:{REGION}:444455556666:/signing-profiles/prof/0000000001'
    res = _runSigner(lambda st: st.add_client_error('get_signing_profile', 'ResourceNotFoundException',
                                                     expected_params={'profileName': 'prof',
                                                                      'profileOwner': '444455556666'}),
                     arns=[other])
    assert res[0] == 0, res


def test_deprecated_runtime_future_date_passes(monkeypatch):
    """Published future dates pass until reached, then flag automatically."""
    _pinToday(monkeypatch, PINNED_TODAY)
    d = _driver(_fn(Runtime='python3.11'))
    d._checkLambdaDeprecatedRuntime()
    assert d.results['lambdaDeprecatedRuntime'] == [1, 'python3.11 is scheduled for deprecation on 2027-06-30']
    monkeypatch.setitem(LambdaCommon.DEPRECATED_RUNTIMES, 'python3.11', '2026-01-01')
    d = _driver(_fn(Runtime='python3.11'))
    d._checkLambdaDeprecatedRuntime()
    assert d.results['lambdaDeprecatedRuntime'][0] == -1


@pytest.mark.parametrize('env,expected', [
    ({'REDIS_URL': 'redis://:s3cretpw@cache:6379'}, -1),
    ({'REDIS_URL': 'redis://cache:6379'}, 1),
    ({'API': 'https://api.example.com:443/v1'}, 1),
    ({'DB_PASSWORD': '/prod/db/password'}, 1),
    ({'DB_PASSWORD': 'hunter2 plaintext'}, -1),
])
def test_env_var_secrets_patterns(env, expected):
    d = _driver(_fn(Environment={'Variables': env}))
    d._checkLambdaEnvVarSecrets()
    assert d.results['lambdaEnvVarSecrets'][0] == expected


@pytest.mark.parametrize('runtime,deadline', [('nodejs22.x', '2027-05-30'), ('python3.11', '2027-06-30'),
                                              ('python3.10', '2026-10-31')])
def test_deprecated_runtime_boundary_dates(monkeypatch, runtime, deadline):
    """Day before the published date -> PASS (scheduled); on the date and after -> FAIL."""
    from datetime import timedelta
    day = _date.fromisoformat(deadline)
    assert LambdaCommon.DEPRECATED_RUNTIMES[runtime] == deadline
    for today, expected in ((day - timedelta(days=1), 1), (day, -1), (day + timedelta(days=1), -1)):
        _pinToday(monkeypatch, today)
        d = _driver(_fn(Runtime=runtime))
        d._checkLambdaDeprecatedRuntime()
        r = d.results['lambdaDeprecatedRuntime']
        assert r[0] == expected, (today, r)
        assert r[1] == (f'{runtime} is scheduled for deprecation on {deadline}' if expected == 1
                        else f'{runtime} deprecated since {deadline}')


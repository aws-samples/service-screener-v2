"""Unit tests for utils/CheckRunner.py (no AWS, no emulator)."""
import os
import sys

import boto3
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.CheckRunner import CheckResult, assertEmulatorOnly, emulatorSession  # noqa: E402


def test_refuses_non_emulator_endpoint(monkeypatch, tmp_path):
    for v in ('AWS_ENDPOINT_URL', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE'):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv('HOME', str(tmp_path))
    sess = boto3.session.Session(region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='y')
    with pytest.raises(RuntimeError, match='not the local emulator'):
        assertEmulatorOnly(sess)


def test_emulator_session_requires_files(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    with pytest.raises(RuntimeError, match='AWS Emulator files not found'):
        emulatorSession(port=59999)


def test_emulator_session_strips_real_credentials(monkeypatch, tmp_path):
    base = tmp_path / '.aws' / 'emulator' / '59998'
    base.mkdir(parents=True)
    (base / 'emulator_credentials').write_text('[default]\naws_access_key_id=emu\naws_secret_access_key=emu\n')
    (base / 'config').write_text('[default]\nregion=us-east-1\n')
    (base / 'ca.pem').write_text('')
    monkeypatch.setenv('HOME', str(tmp_path))
    for v in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_PROFILE'):
        monkeypatch.setenv(v, 'real')
    for v in ('AWS_ENDPOINT_URL', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE', 'AWS_CA_BUNDLE',
              'AWS_REGION', 'AWS_DEFAULT_REGION', 'AWS_EC2_METADATA_DISABLED', 'AWS_DISABLE_HOST_PREFIX_INJECTION'):
        monkeypatch.delenv(v, raising=False)
    sess = emulatorSession(port=59998)
    for v in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_PROFILE'):
        assert v not in os.environ
    assertEmulatorOnly(sess)
    assert sess.get_credentials().access_key == 'emu'


def test_check_result_statuses():
    r = CheckResult('s3', 'us-east-1', 'PublicReadAccessBlock', {
        'Bucket::a': {'PublicReadAccessBlock': [-1, 'NotProhibited'], 'Other': [1, '']},
        'Bucket::b': {'publicreadaccessblock': [1, 'Prohibited']},
        'Bucket::c': {'Other': [-1, '']},
    }, [])
    assert r.statuses() == {'Bucket::a': -1, 'Bucket::b': 1}
    assert r.flagged() == ['Bucket::a']
    assert r.statuses('Other') == {'Bucket::a': 1, 'Bucket::c': -1}


def _runCheckMain(monkeypatch, result, argv):
    import run_check
    monkeypatch.setattr(run_check.CheckRunner, 'run', staticmethod(lambda *a, **k: result))
    monkeypatch.setattr(run_check.boto3.session, 'Session', lambda **k: None)
    return run_check.main(argv)


def test_run_check_expect_with_method_name(monkeypatch):
    """--check Access runs _checkAccess, whose result keys differ from 'access'.
    The expectation must judge those keys, not report 'no result'."""
    r = CheckResult('s3', 'us-east-1', 'Access', {
        'Bucket::b1': {'PublicReadAccessBlock': [-1, 'x'], 'PublicAccessBlock': [1, '']}}, [])
    assert _runCheckMain(monkeypatch, r, ['-s', 's3', '-c', 'Access', '--expect-not', '-1']) == 1
    assert _runCheckMain(monkeypatch, r, ['-s', 's3', '-c', 'Access', '--expect', '-1']) == 1
    ok = CheckResult('s3', 'us-east-1', 'Access', {
        'Bucket::b1': {'PublicReadAccessBlock': [-1, 'x'], 'PublicAccessBlock': [-1, '']}}, [])
    assert _runCheckMain(monkeypatch, ok, ['-s', 's3', '-c', 'Access', '--expect', '-1']) == 0


def test_run_check_expect_with_result_key(monkeypatch):
    r = CheckResult('s3', 'us-east-1', 'PublicReadAccessBlock', {
        'Bucket::b1': {'PublicReadAccessBlock': [-1, 'x']}, 'Bucket::b2': {}}, [])
    assert _runCheckMain(monkeypatch, r, ['-s', 's3', '-c', 'PublicReadAccessBlock', '--expect', '-1']) == 0
    empty = CheckResult('s3', 'us-east-1', 'PublicReadAccessBlock', {'Bucket::b2': {}}, [])
    assert _runCheckMain(monkeypatch, empty, ['-s', 's3', '-c', 'PublicReadAccessBlock', '--expect', '-1']) == 1


def test_run_check_resource_is_exact(monkeypatch):
    """'bucket-1' must not also cover 'bucket-10' (CheckRunner filters by substring)."""
    r = CheckResult('s3', 'us-east-1', 'PublicReadAccessBlock', {
        'Bucket::bucket-1': {'PublicReadAccessBlock': [-1, 'x']},
        'Bucket::bucket-10': {'PublicReadAccessBlock': [1, '']}}, [])
    argv = ['-s', 's3', '-c', 'PublicReadAccessBlock', '--resource', 'bucket-1', '--expect', '-1']
    assert _runCheckMain(monkeypatch, r, argv) == 0
    assert list(r.results) == ['Bucket::bucket-1']


def test_resource_id_matches():
    from utils.CheckRunner import resourceIdMatches
    assert resourceIdMatches('Bucket::bucket-1', 'bucket-1')
    assert resourceIdMatches('Bucket::bucket-1', 'Bucket::bucket-1')
    assert not resourceIdMatches('Bucket::bucket-10', 'bucket-1')
    assert resourceIdMatches('Role::arn:aws:iam::1:role/app', 'app')
    assert resourceIdMatches('Fn::arn:aws:lambda:us-east-1:1:function:f1', 'f1')
    assert not resourceIdMatches('Fn::arn:aws:lambda:us-east-1:1:function:f10', 'f1')

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

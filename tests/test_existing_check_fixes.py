"""Regression tests for existing-check bugs found by the end-to-end emulator scan."""
import os
import pathlib
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_cloudtrail_lookup_attribute_key_is_valid_enum():
    """LookupEvents AttributeKey is case-sensitive: 'Eventname' is rejected."""
    for f in ('services/iam/drivers/IamAccount.py', 'services/rds/drivers/RdsSecretsManager.py'):
        src = (ROOT / f).read_text()
        assert "'Eventname'" not in src, f
        assert "'EventName'" in src, f


def test_credential_report_trailing_newline_creates_no_blank_user():
    from services.iam.Iam import Iam
    svc = Iam.__new__(Iam)
    svc.tags = []
    svc.iamClient = MagicMock()
    svc.iamClient.get_credential_report.return_value = {
        'Content': b'user,arn,mfa_active\n<root_account>,arn:aws:iam::1:root,true\nalice,arn:aws:iam::1:user/alice,false\n'}
    users = svc.getUsers()
    assert [u['user'] for u in users] == ['<root_account>', 'alice']

"""Driver-level tests for transfer.transferFamilyInsecure edge cases that the
emulator cannot produce (describe_server AccessDenied). The flag -> fix cycle
itself is covered against the emulator in tests/emulator/test_emu_transfer.py.
"""
import os
import sys

import boto3
import botocore
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.transfer.drivers.TransferServer import TransferServer  # noqa: E402


def _run(server):
    d = TransferServer(server, None)
    d._checkTransferFamilyInsecure()
    return d.results['transferFamilyInsecure']


def _client():
    return boto3.client('transfer', region_name='us-east-1', aws_access_key_id='x',
                        aws_secret_access_key='x', endpoint_url='https://127.0.0.1:1')


def _describe(stubbedResponse=None, errorCode=None):
    c = _client()
    with Stubber(c) as st:
        if errorCode:
            st.add_client_error('describe_server', service_error_code=errorCode,
                                expected_params={'ServerId': 's-0123456789abcdef0'})
        else:
            st.add_response('describe_server', stubbedResponse, {'ServerId': 's-0123456789abcdef0'})
        try:
            return dict(c.describe_server(ServerId='s-0123456789abcdef0')['Server'], _error=None)
        except botocore.exceptions.ClientError as e:
            return {'ServerId': 's-0123456789abcdef0', '_error': e.response['Error']['Code']}


def _server(**kw):
    s = {'Arn': 'arn:aws:transfer:us-east-1:111122223333:server/s-0123456789abcdef0', 'ServerId': 's-0123456789abcdef0'}
    s.update(kw)
    return {'Server': s}


def test_flag_then_fix_policy():
    assert _run(_describe(_server(Protocols=['SFTP'], SecurityPolicyName='TransferSecurityPolicy-FIPS-2020-06')))[0] == -1
    assert _run(_describe(_server(Protocols=['SFTP'], SecurityPolicyName='TransferSecurityPolicy-FIPS-2024-01')))[0] == 1


def test_flag_then_fix_ftp():
    assert _run(_describe(_server(Protocols=['FTP', 'FTPS'], SecurityPolicyName='TransferSecurityPolicy-2024-01')))[0] == -1
    assert _run(_describe(_server(Protocols=['FTPS'], SecurityPolicyName='TransferSecurityPolicy-2024-01')))[0] == 1


def test_access_denied_is_not_evaluable():
    r = _run(_describe(errorCode='AccessDeniedException'))
    assert r == [0, 'Unable to evaluate (AccessDeniedException)']


def test_missing_policy_is_not_pass():
    assert _run(_describe(_server(Protocols=['SFTP'])))[0] == 0

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


def test_restricted_variants_of_outdated_policies_flag():
    """Restricted-2018-11 / Restricted-2020-06 equal their base policy minus chacha20, so
    Restricted-2018-11 still offers diffie-hellman-group14-sha1 and hmac-sha1 (AWS docs)."""
    for pol in ('TransferSecurityPolicy-Restricted-2018-11', 'TransferSecurityPolicy-Restricted-2020-06',
                'TransferSecurityPolicy-PQ-SSH-Experimental-2023-04',
                'TransferSecurityPolicy-PQ-SSH-FIPS-Experimental-2023-04'):
        r = _run(_describe(_server(Protocols=['SFTP'], SecurityPolicyName=pol)))
        assert r[0] == -1 and pol in r[1], (pol, r)


def test_every_current_policy_passes():
    for pol in TransferServer.CURRENT_POLICIES:
        assert _run(_describe(_server(Protocols=['SFTP'], SecurityPolicyName=pol)))[0] == 1, pol


def test_unrecognised_policy_is_info_not_pass():
    r = _run(_describe(_server(Protocols=['SFTP'], SecurityPolicyName='TransferSecurityPolicy-Future-2099-01')))
    assert r == [0, 'Unable to evaluate (unrecognised security policy TransferSecurityPolicy-Future-2099-01)']
    ## FTP is still a FAIL whatever the policy name
    assert _run(_describe(_server(Protocols=['FTP'], SecurityPolicyName='TransferSecurityPolicy-Future-2099-01')))[0] == -1

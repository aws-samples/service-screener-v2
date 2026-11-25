"""Stubber tests for the Verified Permissions service/driver.

The emulator test (tests/emulator/test_emu_verifiedpermissions.py) covers the
flag -> fix cycle. These Stubber tests cover paths the emulator cannot
produce: AccessDenied on get_policy_store (must be 0 "Unable to evaluate",
never PASS) and the real-AWS "no schema" signal (get_schema raises
ResourceNotFoundException, whereas the emulator returns '{}').
They drive the Service.getResources() hydration and the driver directly with
a real boto3 client wrapped by botocore.stub.Stubber (real API shapes); no
network call is made.
"""
import datetime
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.verifiedpermissions.Verifiedpermissions import Verifiedpermissions  # noqa: E402
from services.verifiedpermissions.drivers.VerifiedpermissionsPolicyStore import VerifiedpermissionsPolicyStore  # noqa: E402

KEY = 'avpPolicyStoreValidationOff'
PSID = 'PSabcdefghijklmnopqrstuv'
ARN = f'arn:aws:verifiedpermissions::123456789012:policy-store/{PSID}'
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def _client():
    return boto3.client('verifiedpermissions', region_name='us-east-1',
                        aws_access_key_id='x', aws_secret_access_key='x')


class _Svc(Verifiedpermissions):
    """Skip Service.__init__/__del__ (session bootstrap and fork-dir output)."""
    def __del__(self):
        pass


def _hydrate(stubFn):
    client = _client()
    svc = _Svc.__new__(_Svc)
    svc.avpClient = client
    svc.region = 'us-east-1'
    svc.tags = []
    svc._tags = {}
    with Stubber(client) as st:
        st.add_response('list_policy_stores', {'policyStores': [
            {'policyStoreId': PSID, 'arn': ARN, 'createdDate': NOW}]}, {})
        stubFn(st)
        stores = svc.getResources()
        st.assert_no_pending_responses()
    assert len(stores) == 1
    drv = VerifiedpermissionsPolicyStore(stores[0], client)
    drv._checkAvpPolicyStoreValidationOff()
    return drv.results[KEY]


def _store(mode):
    return {'policyStoreId': PSID, 'arn': ARN, 'validationSettings': {'mode': mode},
            'createdDate': NOW, 'lastUpdatedDate': NOW}


def _noSchema(st):
    st.add_client_error('get_schema', 'ResourceNotFoundException', 'no schema',
                        expected_params={'policyStoreId': PSID})


def test_off_flagged_then_strict_passes():
    def off(st):
        st.add_response('get_policy_store', _store('OFF'), {'policyStoreId': PSID})
        _noSchema(st)
    res = _hydrate(off)
    assert res[0] == -1 and 'no schema' in res[1]

    def strict(st):
        st.add_response('get_policy_store', _store('STRICT'), {'policyStoreId': PSID})
        _noSchema(st)
    assert _hydrate(strict)[0] == 1


def test_off_with_schema_flagged():
    def off(st):
        st.add_response('get_policy_store', _store('OFF'), {'policyStoreId': PSID})
        st.add_response('get_schema', {'policyStoreId': PSID, 'schema': '{"App":{}}',
                                       'createdDate': NOW, 'lastUpdatedDate': NOW,
                                       'namespaces': ['App']}, {'policyStoreId': PSID})
    res = _hydrate(off)
    assert res[0] == -1 and 'not enforced' in res[1]


def test_access_denied_is_not_evaluable():
    def denied(st):
        st.add_client_error('get_policy_store', 'AccessDeniedException', 'denied',
                            expected_params={'policyStoreId': PSID})
        st.add_client_error('get_schema', 'AccessDeniedException', 'denied',
                            expected_params={'policyStoreId': PSID})
    res = _hydrate(denied)
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']

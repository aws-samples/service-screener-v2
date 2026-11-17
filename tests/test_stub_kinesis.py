"""
Stubber tests for kinesisResourcePolicyPublic error handling.

The emulator cannot return AccessDenied for get_resource_policy (IAM is not
evaluated), so the "unable to evaluate" path is driven here with a real boto3
kinesis client wrapped by botocore.stub.Stubber (real API shapes). The
flag/fix cycle itself is covered by tests/emulator/test_emu_kinesis.py.
"""
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.kinesis.Kinesis import Kinesis  # noqa: E402
from services.kinesis.drivers.KinesisCommon import KinesisCommon  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

STREAM_ARN = 'arn:aws:kinesis:us-east-1:111122223333:stream/s1'
CONSUMER_ARN = STREAM_ARN + '/consumer/c1:1700000000'
CONSUMERS = [{'ConsumerName': 'c1', 'ConsumerARN': CONSUMER_ARN}]


def _client():
    return boto3.client('kinesis', region_name='us-east-1',
                        aws_access_key_id='testing', aws_secret_access_key='testing')


def _svc(client):
    svc = object.__new__(Kinesis)
    svc.kinesisClient = client
    return svc


def _policy(principal, condition=None):
    st = {'Effect': 'Allow', 'Principal': principal, 'Action': 'kinesis:*', 'Resource': STREAM_ARN}
    if condition:
        st['Condition'] = condition
    return json.dumps({'Version': '2012-10-17', 'Statement': [st]})


def _evaluate(policies):
    drv = KinesisCommon({'_name': 's1', '_arn': STREAM_ARN, '_summary': {},
                         '_resourcePolicies': policies}, None)
    drv._checkKinesisResourcePolicyPublic()
    return drv.results['kinesisResourcePolicyPublic']


def _fetch(responses):
    client = _client()
    with Stubber(client) as st:
        for arn, resp in responses:
            if isinstance(resp, str) and resp.endswith('Exception'):
                st.add_client_error('get_resource_policy', service_error_code=resp,
                                    expected_params={'ResourceARN': arn})
            else:
                st.add_response('get_resource_policy', {'Policy': resp},
                                expected_params={'ResourceARN': arn})
        out = _svc(client)._fetchResourcePolicies(STREAM_ARN, CONSUMERS)
        st.assert_no_pending_responses()
    return out


def test_flag_then_fix_via_stubbed_api():
    flagged = _fetch([(STREAM_ARN, '{}'), (CONSUMER_ARN, _policy({'AWS': ['*']}))])
    assert _evaluate(flagged)[0] == -1
    fixed = _fetch([(STREAM_ARN, '{}'),
                    (CONSUMER_ARN, _policy({'AWS': 'arn:aws:iam::444455556666:root'}))])
    assert _evaluate(fixed)[0] == 1


def test_access_denied_is_not_a_pass():
    out = _fetch([(STREAM_ARN, 'AccessDeniedException'), (CONSUMER_ARN, '{}')])
    res = _evaluate(out)
    assert res[0] == 0 and 'AccessDeniedException' in res[1]


def test_public_finding_wins_over_partial_error():
    out = _fetch([(STREAM_ARN, _policy('*')), (CONSUMER_ARN, 'AccessDeniedException')])
    assert _evaluate(out)[0] == -1


def test_consumer_not_found_is_skipped():
    out = _fetch([(STREAM_ARN, '{}'), (CONSUMER_ARN, 'ResourceNotFoundException')])
    assert _evaluate(out)[0] == 1


def test_scoped_conditions_and_notprincipal():
    scoped = {'policies': [('stream', _policy('*', {'StringEquals': {'aws:PrincipalAccount': '111122223333'}}))],
              'errors': []}
    assert _evaluate(scoped)[0] == 1
    ifexists = {'policies': [('stream', _policy('*', {'StringEqualsIfExists': {'aws:PrincipalAccount': '111122223333'}}))],
                'errors': []}
    assert _evaluate(ifexists)[0] == -1
    notp = json.dumps({'Statement': [{'Effect': 'Allow', 'NotPrincipal': {'AWS': 'arn:aws:iam::1:root'},
                                      'Action': 'kinesis:PutRecord', 'Resource': STREAM_ARN}]})
    assert _evaluate({'policies': [('stream', notp)], 'errors': []})[0] == -1
    deny = json.dumps({'Statement': [{'Effect': 'Deny', 'Principal': '*', 'Action': '*', 'Resource': STREAM_ARN}]})
    assert _evaluate({'policies': [('stream', deny)], 'errors': []})[0] == 1


def test_not_retrieved_and_unparseable():
    assert _evaluate(None)[0] == 0
    assert _evaluate({'policies': [('stream', 'not-json')], 'errors': []})[0] == 0


def test_consumer_listing_denied_is_not_a_pass():
    """list_stream_consumers AccessDenied: consumer policies were never read,
    so an empty stream policy must not produce a PASS."""
    client = _client()
    svc = _svc(client)
    svc._logClientError = lambda *a, **k: None
    with Stubber(client) as st:
        st.add_client_error('list_stream_consumers', service_error_code='AccessDeniedException',
                            expected_params={'StreamARN': STREAM_ARN, 'MaxResults': 100})
        st.add_response('get_resource_policy', {'Policy': '{}'},
                        expected_params={'ResourceARN': STREAM_ARN})
        errs = []
        consumers = svc._listConsumers(STREAM_ARN, errs)
        out = svc._fetchResourcePolicies(STREAM_ARN, consumers, errs)
        st.assert_no_pending_responses()
    assert consumers == [] and errs == ['AccessDeniedException']
    res = _evaluate(out)
    assert res[0] == 0 and 'AccessDeniedException' in res[1]

    # Fixed: listing succeeds with no consumers -> PASS
    with Stubber(client) as st:
        st.add_response('list_stream_consumers', {'Consumers': []},
                        expected_params={'StreamARN': STREAM_ARN, 'MaxResults': 100})
        st.add_response('get_resource_policy', {'Policy': '{}'},
                        expected_params={'ResourceARN': STREAM_ARN})
        errs = []
        out = svc._fetchResourcePolicies(STREAM_ARN, svc._listConsumers(STREAM_ARN, errs), errs)
    assert _evaluate(out)[0] == 1

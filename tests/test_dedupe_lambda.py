"""Lambda drivers fetch each piece of AWS data once.

botocore Stubber with exactly one queued response per de-duplicated call: a
second call for the same data would raise (no response queued) and the check
would record a different result, so both the call count and the unchanged
check results are asserted. No network.
"""
import os
import sys
from unittest.mock import MagicMock

import boto3
import botocore.exceptions
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.lambda_.drivers.LambdaCommon import LambdaCommon  # noqa: E402
from services.lambda_.drivers.LambdaCodeSigningConfig import LambdaCodeSigningConfig  # noqa: E402

ACCT = '111122223333'
REGION = 'us-east-1'
UUID = '12345678-1234-1234-1234-123456789012'
CSC_ARN = f'arn:aws:lambda:{REGION}:{ACCT}:code-signing-config:csc-0123456789abcdef0'


def _client(svc):
    return boto3.client(svc, region_name=REGION, aws_access_key_id='x', aws_secret_access_key='x')


def _fn(name='fn1', role='r', **kw):
    f = {'FunctionName': name, 'FunctionArn': f'arn:aws:lambda:{REGION}:{ACCT}:function:{name}',
         'Role': f'arn:aws:iam::{ACCT}:role/{role}', 'PackageType': 'Zip', 'Runtime': 'python3.12',
         'Architectures': ['x86_64']}
    f.update(kw)
    return f


@pytest.fixture(autouse=True)
def _fresh_scan():
    Config.init()
    yield
    Config.init()


def _ok(stubber):
    stubber.assert_no_pending_responses()


# ---------------- per-function data shared by several checks ----------------
def test_code_signing_config_fetched_once():
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_response('get_function_code_signing_config',
                        {'CodeSigningConfigArn': CSC_ARN, 'FunctionName': 'fn1'},
                        {'FunctionName': 'fn1'})
        st.add_response('get_code_signing_config',
                        {'CodeSigningConfig': {
                            'CodeSigningConfigId': 'csc-0123456789abcdef0', 'CodeSigningConfigArn': CSC_ARN,
                            'AllowedPublishers': {'SigningProfileVersionArns': ['arn:aws:signer:x']},
                            'CodeSigningPolicies': {'UntrustedArtifactOnDeployment': 'Warn'},
                            'LastModified': '2024-01-01T00:00:00Z'}},
                        {'CodeSigningConfigArn': CSC_ARN})
        d = LambdaCommon(_fn(), lam, None, {})
        d._check_code_signing_disabled()
        d._checkLambdaCodeSigningWarnOnly()
        _ok(st)
    assert 'lambdaCodeSigningDisabled' not in d.results
    assert d.results['lambdaCodeSigningWarnOnly'][0] == -1


def test_code_signing_config_error_fetched_once_and_handled_by_both():
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_client_error('get_function_code_signing_config', 'AccessDeniedException')
        d = LambdaCommon(_fn(), lam, None, {})
        d._check_code_signing_disabled()
        d._checkLambdaCodeSigningWarnOnly()
        _ok(st)
    assert 'lambdaCodeSigningDisabled' not in d.results
    assert d.results['lambdaCodeSigningWarnOnly'] == [0, 'Unable to evaluate (AccessDeniedException)']


def test_function_configuration_and_event_source_mappings_fetched_once():
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_response('list_event_source_mappings', {'EventSourceMappings': [
            {'UUID': UUID, 'EventSourceArn': f'arn:aws:kinesis:{REGION}:{ACCT}:stream/s',
             'MaximumBatchingWindowInSeconds': 0, 'FunctionResponseTypes': []}]},
            {'FunctionName': 'fn1'})
        st.add_response('get_function_configuration', {'FunctionName': 'fn1', 'Timeout': 3},
                        {'FunctionName': 'fn1'})
        cw = MagicMock()
        cw.describe_alarms_for_metric.return_value = {'MetricAlarms': []}
        Config.set('CWClient', cw)
        Config.set('SQSClient', MagicMock())
        d = LambdaCommon(_fn(), lam, None, {})
        d._check_sqs_visibility_timeout()
        d._check_dead_letter_queue_disabled()
        d._check_partial_batch_response()
        d._check_batching_window()
        d._check_iterator_age_alarm()
        _ok(st)
    assert d.results['lambdaDeadLetterQueueDisabled'] == [-1, 'Disabled']
    assert d.results['lambdaPartialBatchResponseDisabled'][0] == -1
    assert d.results['lambdaBatchingWindowNotConfigured'][0] == -1
    assert d.results['lambdaNoIteratorAgeAlarm'] == [-1, 'No IteratorAge alarm']
    assert 'lambdaSQSVisibilityTimeout' not in d.results


def test_event_source_mappings_error_cached_and_each_check_still_handles_it(capsys):
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_client_error('list_event_source_mappings', 'AccessDeniedException')
        d = LambdaCommon(_fn(), lam, None, {})
        d._check_partial_batch_response()
        d._check_batching_window()
        d._check_iterator_age_alarm()
        d._check_sqs_visibility_timeout()
        _ok(st)
    out = capsys.readouterr().out
    for msg in ('Error checking partial batch response', 'Error checking batching window',
                'Error checking IteratorAge alarm', 'Error checking SQS visibility timeout'):
        assert msg in out
    assert d.results == {}


def test_function_concurrency_fetched_once():
    lam = _client('lambda')
    with Stubber(lam) as st:
        st.add_response('get_function_concurrency', {}, {'FunctionName': 'fn1'})
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {'Datapoints': [{'Sum': 4.0}]}
        Config.set('CWClient', cw)
        d = LambdaCommon(_fn(), lam, None, {})
        d._check_provisioned_concurrency()
        d._check_reserved_concurrency_for_throttling()
        _ok(st)
    assert d.results['lambdaReservedConcurrencyDisabled'] == [-1, 'Disabled']
    assert d.results['lambdaNoReservedConcurrencyForThrottling'] == [-1, 'Throttled 4 times in last 7 days']


# ---------------- data shared by several functions ----------------
def test_shared_role_described_once_per_scan():
    iam = _client('iam')
    with Stubber(iam) as st:
        st.add_client_error('get_role', 'NoSuchEntity', expected_params={'RoleName': 'shared'})
        st.add_response('list_role_policies', {'PolicyNames': ['p']}, {'RoleName': 'shared'})
        st.add_response('list_attached_role_policies', {'AttachedPolicies': []}, {'RoleName': 'shared'})
        st.add_response('get_role_policy', {
            'RoleName': 'shared', 'PolicyName': 'p',
            'PolicyDocument': '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'},
            {'RoleName': 'shared', 'PolicyName': 'p'})
        drivers = [LambdaCommon(_fn(name=n, role='shared'), _client('lambda'), iam, {}) for n in ('a', 'b', 'c')]
        for d in drivers:
            d._check_missing_role()
            d._check_role_permissions()
        _ok(st)
    for d in drivers:
        assert d.results['lambdaMissingRole'] == [-1, '']
        assert d.results['lambdaRoleTooPermissive'] == [-1, 'Role has wildcard permissions']


def test_get_role_other_error_still_raised_for_each_function():
    iam = MagicMock()
    iam.get_role.side_effect = botocore.exceptions.ClientError(
        {'Error': {'Code': 'AccessDenied', 'Message': 'x'}}, 'GetRole')
    for n in ('a', 'b'):
        d = LambdaCommon(_fn(name=n, role='shared'), _client('lambda'), iam, {})
        with pytest.raises(botocore.exceptions.ClientError):
            d._check_missing_role()
    assert iam.get_role.call_count == 1


def test_sqs_queue_described_once_across_functions():
    sqs = MagicMock()
    sqs.meta.region_name = REGION
    sqs.get_queue_url.return_value = {'QueueUrl': 'https://sqs/q1'}
    sqs.get_queue_attributes.return_value = {'Attributes': {'VisibilityTimeout': '30'}}
    Config.set('SQSClient', sqs)
    results = []
    for n in ('a', 'b'):
        lam = _client('lambda')
        with Stubber(lam) as st:
            st.add_response('list_event_source_mappings', {'EventSourceMappings': [
                {'UUID': UUID, 'EventSourceArn': f'arn:aws:sqs:{REGION}:{ACCT}:q1'}]}, {'FunctionName': n})
            st.add_response('get_function_configuration', {'FunctionName': n, 'Timeout': 10},
                            {'FunctionName': n})
            d = LambdaCommon(_fn(name=n), lam, None, {})
            d._check_sqs_visibility_timeout()
            _ok(st)
        results.append(d.results['lambdaSQSVisibilityTimeout'])
    assert sqs.get_queue_url.call_count == 1
    assert sqs.get_queue_attributes.call_count == 1
    assert results == [[-1, 'Function timeout: 10s, SQS visibility: 30s']] * 2


def _profile(status='Active', version='0000000001'):
    return {'profileName': 'prof', 'profileVersion': version,
            'profileVersionArn': f'arn:aws:signer:{REGION}:{ACCT}:/signing-profiles/prof/{version}',
            'platformId': 'AWSLambda-SHA384-ECDSA', 'status': status}


def _csc(i, versions):
    return {'CodeSigningConfigId': f'csc-{i:017d}',
            'CodeSigningConfigArn': f'arn:aws:lambda:{REGION}:{ACCT}:code-signing-config:csc-{i:017d}',
            'AllowedPublishers': {'SigningProfileVersionArns': [
                f'arn:aws:signer:{REGION}:{ACCT}:/signing-profiles/prof/{v}' for v in versions]}}


def test_signing_profile_described_once_per_scan():
    sig = _client('signer')
    with Stubber(sig) as st:
        st.add_response('get_signing_profile', _profile('Revoked'), {'profileName': 'prof'})
        a = LambdaCodeSigningConfig(_csc(1, ['0000000001', '0000000002']), sig)
        a._checkSignerProfileInvalid()
        b = LambdaCodeSigningConfig(_csc(2, ['0000000001']), sig)
        b._checkSignerProfileInvalid()
        _ok(st)
    assert a.results['signerProfileInvalid'] == [-1, 'Trusts invalid signing profile version(s): prof/0000000001 (Revoked)']
    assert b.results['signerProfileInvalid'] == [-1, 'Trusts invalid signing profile version(s): prof/0000000001 (Revoked)']


def test_signing_profile_not_found_cached_and_still_flagged():
    sig = _client('signer')
    with Stubber(sig) as st:
        st.add_client_error('get_signing_profile', 'ResourceNotFoundException')
        for i in (1, 2):
            d = LambdaCodeSigningConfig(_csc(i, ['0000000001']), sig)
            d._checkSignerProfileInvalid()
            assert d.results['signerProfileInvalid'][0] == -1
        _ok(st)

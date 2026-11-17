"""Stubber tests for CloudFormation WAFS2027 check paths the emulator cannot
produce: a DRIFTED StackSet (the emulator's drift detection always reports
IN_SYNC), AccessDenied on hook/StackSet listing, and name heuristics for
cfnPlaintextSecretParams. Real boto3 clients wrapped by botocore Stubber, so
request/response shapes are validated against the service model. No network.
"""
import os
import sys
from datetime import datetime, timezone

import boto3
from botocore.stub import Stubber, ANY

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.cloudformation.Cloudformation import Cloudformation  # noqa: E402
from services.cloudformation.drivers.CloudformationCommon import CloudformationCommon  # noqa: E402
from services.cloudformation.drivers.CloudformationStackSet import CloudformationStackSet  # noqa: E402
from services.cloudformation.drivers.CloudformationStack import (  # noqa: E402
    CloudformationStack, plaintextSecretParams)


def _client():
    return boto3.client('cloudformation', region_name='us-east-1',
                        aws_access_key_id='x', aws_secret_access_key='x')


class _BareCloudformation(Cloudformation):
    """Skips Service.__init__ (no Config bootstrap) and its __del__ reporting."""
    def __del__(self):
        pass


def _svc(client):
    s = _BareCloudformation.__new__(_BareCloudformation)
    s.cfnClient = client
    s.region = 'us-east-1'
    s.tags = []
    return s


def _run(driver, method):
    getattr(driver, method)()
    return driver.results


HOOK_ARN = 'arn:aws:cloudformation:us-east-1:111122223333:type/hook/Org-Guard-Hook'


def _hookPosture(config):
    c = _client()
    with Stubber(c) as st:
        st.add_response('list_types', {'TypeSummaries': [
            {'Type': 'HOOK', 'TypeName': 'Org::Guard::Hook', 'TypeArn': HOOK_ARN}]},
            {'Type': 'HOOK', 'Visibility': 'PRIVATE', 'DeprecatedStatus': 'LIVE'})
        st.add_response('batch_describe_type_configurations', {
            'Errors': [], 'UnprocessedTypeConfigurations': [],
            'TypeConfigurations': [{'TypeArn': HOOK_ARN, 'Alias': 'default',
                                    'Configuration': config}]},
            {'TypeConfigurationIdentifiers': [{'TypeArn': HOOK_ARN}]})
        return _svc(c).getHookPosture()


def test_hooks_disabled_flag_then_enabled_fixed():
    off = '{"CloudFormationConfiguration":{"HookConfiguration":{"HookInvocationStatus":"DISABLED"}}}'
    on = '{"CloudFormationConfiguration":{"HookConfiguration":{"HookInvocationStatus":"ENABLED","TargetOperations":["STACK"]}}}'
    assert _run(CloudformationCommon(_hookPosture(off)), '_checkCfnNoProactiveHooks')['cfnNoProactiveHooks'][0] == -1
    assert _run(CloudformationCommon(_hookPosture(on)), '_checkCfnNoProactiveHooks')['cfnNoProactiveHooks'][0] == 1


def test_hooks_legacy_target_stacks_none_is_not_enabled():
    cfg = '{"CloudFormationConfiguration":{"HookConfiguration":{"HookInvocationStatus":"ENABLED","TargetStacks":"NONE"}}}'
    assert not CloudformationCommon.hookConfigEnabled(cfg)


def test_hooks_access_denied_is_unable_to_evaluate():
    c = _client()
    with Stubber(c) as st:
        st.add_client_error('list_types', 'AccessDenied', 'no')
        detail = _svc(c).getHookPosture()
    res = _run(CloudformationCommon(detail), '_checkCfnNoProactiveHooks')['cfnNoProactiveHooks']
    assert res == [0, 'Unable to evaluate (AccessDenied)']


def _stackSet(details, instances=1):
    c = _client()
    with Stubber(c) as st:
        st.add_response('list_stack_sets', {'Summaries': [
            {'StackSetName': 'baseline', 'StackSetId': 'baseline:1', 'Status': 'ACTIVE'}]},
            {'Status': 'ACTIVE', 'CallAs': 'SELF'})
        st.add_response('describe_stack_set', {'StackSet': {
            'StackSetName': 'baseline', 'StackSetId': 'baseline:1', 'Status': 'ACTIVE',
            'StackSetDriftDetectionDetails': details}},
            {'StackSetName': 'baseline', 'CallAs': 'SELF'})
        st.add_response('list_stack_instances', {'Summaries': [
            {'StackSetId': 'baseline:1', 'Region': 'us-east-1', 'Account': '111122223333'}] * instances},
            {'StackSetName': 'baseline', 'CallAs': 'SELF', 'MaxResults': 1})
        st.add_client_error('list_stack_sets', 'ValidationError', 'not a delegated admin',
                            expected_params={'Status': 'ACTIVE', 'CallAs': 'DELEGATED_ADMIN'})
        sets, err = _svc(c).getStackSets()
    assert err is None and len(sets) == 1
    return _run(CloudformationStackSet(sets[0]), '_checkCfnStackSetDrift')['cfnStackSetDrift']


def test_stackset_drifted_flag_then_in_sync_fixed():
    ts = datetime(2026, 11, 1, tzinfo=timezone.utc)
    drifted = _stackSet({'DriftStatus': 'DRIFTED', 'DriftDetectionStatus': 'COMPLETED',
                         'LastDriftCheckTimestamp': ts, 'TotalStackInstancesCount': 3,
                         'DriftedStackInstancesCount': 1})
    assert drifted[0] == -1 and '1 of 3' in drifted[1]
    insync = _stackSet({'DriftStatus': 'IN_SYNC', 'DriftDetectionStatus': 'COMPLETED',
                        'LastDriftCheckTimestamp': ts, 'TotalStackInstancesCount': 3,
                        'InSyncStackInstancesCount': 3, 'FailedStackInstancesCount': 0})
    assert insync[0] == 1


def test_stackset_never_checked_without_instances_is_info():
    assert _stackSet({'DriftStatus': 'NOT_CHECKED'}, instances=0)[0] == 0
    assert _stackSet({'DriftStatus': 'NOT_CHECKED'}, instances=1)[0] == -1


def test_stackset_list_access_denied():
    c = _client()
    with Stubber(c) as st:
        st.add_client_error('list_stack_sets', 'AccessDenied', 'no')
        st.add_client_error('list_stack_sets', 'AccessDenied', 'no')
        sets, err = _svc(c).getStackSets()
    assert sets == [] and err == 'AccessDenied'


def test_plaintext_secret_name_heuristics():
    stack = {'Parameters': [
        {'ParameterKey': 'MasterUserPassword', 'ParameterValue': 'p@ss'},
        {'ParameterKey': 'GitHubToken', 'ParameterValue': 'ghp_x'},
        {'ParameterKey': 'ApiKey', 'ParameterValue': '****'},                 # NoEcho
        {'ParameterKey': 'DbSecretArn', 'ParameterValue': 'arn:aws:secretsmanager:x'},
        {'ParameterKey': 'PasswordLength', 'ParameterValue': '16'},
        {'ParameterKey': 'SecretName', 'ParameterValue': 'prod/db'},
        {'ParameterKey': 'TokenParam', 'ParameterValue': '/a/b', 'ResolvedValue': 'v'},
        {'ParameterKey': 'ClientSecret', 'ParameterValue': ''},
        {'ParameterKey': 'Environment', 'ParameterValue': 'prod'},
    ]}
    assert sorted(plaintextSecretParams(stack)) == ['GitHubToken', 'MasterUserPassword']
    drv = CloudformationStack(dict(stack, StackName='s'), None)
    res = _run(drv, '_checkCfnPlaintextSecretParams')['cfnPlaintextSecretParams']
    assert res[0] == -1 and 'p@ss' not in res[1] and 'ghp_x' not in res[1]

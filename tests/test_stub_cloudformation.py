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
        {'ParameterKey': 'TokenParam', 'ParameterValue': '/a/b', 'ResolvedValue': 'v'},  # too short
        {'ParameterKey': 'ClientSecret', 'ParameterValue': ''},
        {'ParameterKey': 'Environment', 'ParameterValue': 'prod'},
    ]}
    assert sorted(plaintextSecretParams(stack)) == ['GitHubToken', 'MasterUserPassword']
    drv = CloudformationStack(dict(stack, StackName='s'), None)
    res = _run(drv, '_checkCfnPlaintextSecretParams')['cfnPlaintextSecretParams']
    assert res[0] == -1 and 'p@ss' not in res[1] and 'ghp_x' not in res[1]


def test_plaintext_secret_metadata_names_not_flagged():
    """Review round 1: names that only DESCRIBE a secret (AWS Config
    conformance-pack parameters among them) must not be flagged, and short
    forms of credential names must be."""
    benign = {
        'MaxPasswordAge': '90', 'PasswordReusePrevention': '24',
        'IamPasswordPolicyParamMaxPasswordAge': '90',
        'IamPasswordPolicyParamPasswordReusePrevention': '24',
        'IamPasswordPolicyParamRequireSymbols': 'true',
        'ApiKeySource': 'HEADER', 'TokenValidityUnits': 'hours',
        'SecretRotationSchedule': 'rate(30 days)',
        'TokenSigningAlgorithm': 'RS256', 'PasswordHashAlgorithm': 'bcrypt',
        'SecretsManagerSecretPrefix': 'app/', 'KmsKeyForSecrets': 'alias/x',
        'DatabaseSecret': 'prod/db', 'PasswordValid': 'yes-really',
        'DbPasswordSecretArn': 'arn:aws:secretsmanager:x', 'SecretName': 'prod/db',
        'AccessKeyId': 'AKIAEXAMPLEEXAMPLE', 'Bypass': 'something-long',
    }
    stack = {'Parameters': [{'ParameterKey': k, 'ParameterValue': v}
                            for k, v in benign.items()]}
    assert plaintextSecretParams(stack) == []
    res = _run(CloudformationStack(dict(stack, StackName='s'), None),
               '_checkCfnPlaintextSecretParams')['cfnPlaintextSecretParams']
    assert res[0] == 1

    secrets = {'Pwd': 'hunter2!', 'DbPass': 'hunter2!', 'AdminPass': 'hunter2!',
               'db_password': 'hunter2!', 'dbpassword': 'hunter2!',
               'Password1': 'hunter2!', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG',
               'ClientSecret': 'Zx9-abc_def', 'SlackApiKey': 'fake-api-key-value',
               'DatabaseSecret': 'S3cr3tValue!', 'DBPasswordValue': 'hunter2!'}
    stack = {'Parameters': [{'ParameterKey': k, 'ParameterValue': v}
                            for k, v in secrets.items()]}
    assert sorted(plaintextSecretParams(stack)) == sorted(secrets)


def test_stackset_failed_detection_is_unable_to_evaluate():
    ts = datetime(2026, 11, 1, tzinfo=timezone.utc)
    res = _stackSet({'DriftStatus': 'NOT_CHECKED', 'DriftDetectionStatus': 'FAILED',
                     'LastDriftCheckTimestamp': ts})
    assert res[0] == 0 and 'Unable to evaluate' in res[1]


def test_hooks_cloud_control_only_is_not_enabled_and_warn_is_noted():
    cc = '{"CloudFormationConfiguration":{"HookConfiguration":{"HookInvocationStatus":"ENABLED","TargetOperations":["CLOUD_CONTROL"]}}}'
    assert not CloudformationCommon.hookConfigEnabled(cc)
    assert _run(CloudformationCommon(_hookPosture(cc)), '_checkCfnNoProactiveHooks')['cfnNoProactiveHooks'][0] == -1
    warn = '{"CloudFormationConfiguration":{"HookConfiguration":{"HookInvocationStatus":"ENABLED","FailureMode":"WARN","TargetOperations":["RESOURCE"]}}}'
    res = _run(CloudformationCommon(_hookPosture(warn)), '_checkCfnNoProactiveHooks')['cfnNoProactiveHooks']
    assert res[0] == 1 and 'WARN' in res[1]


def test_plaintext_secret_ssm_typed_resolved_value_is_evaluated():
    """Review finding: an AWS::SSM::Parameter::Value<String> parameter carries
    the SSM NAME in ParameterValue and the plain-text VALUE in ResolvedValue,
    which DescribeStacks returns to anyone allowed to call it. The value
    heuristic must run on ResolvedValue (old code skipped it -> false PASS)."""
    exposed = {'Parameters': [
        {'ParameterKey': 'DbPassword', 'ParameterValue': '/app/db/password',
         'ResolvedValue': 'hunter2-not-real'},
        {'ParameterKey': 'Env', 'ParameterValue': 'prod'},
    ]}
    assert plaintextSecretParams(exposed) == ['DbPassword']
    res = _run(CloudformationStack(dict(exposed, StackName='s'), None),
               '_checkCfnPlaintextSecretParams')['cfnPlaintextSecretParams']
    assert res[0] == -1
    assert 'DbPassword' in res[1] and 'plain-text SSM String parameter' in res[1]
    assert 'hunter2' not in res[1] and '/app/db/password' not in res[1]

    ## Fixed: the stack resolves the secret through a dynamic reference, so no
    ## secret-like parameter is left.
    fixed = {'Parameters': [{'ParameterKey': 'Env', 'ParameterValue': 'prod'}]}
    res = _run(CloudformationStack(dict(fixed, StackName='s'), None),
               '_checkCfnPlaintextSecretParams')['cfnPlaintextSecretParams']
    assert res[0] == 1

    ## SSM-typed parameters whose resolved value is clearly not a secret stay PASS.
    benign = {'Parameters': [
        {'ParameterKey': 'ApiToken', 'ParameterValue': '/app/flag', 'ResolvedValue': 'true'},
        {'ParameterKey': 'DbSecret', 'ParameterValue': '/app/arn',
         'ResolvedValue': 'arn:aws:secretsmanager:us-east-1:111122223333:secret:db'},
        {'ParameterKey': 'AdminPassword', 'ParameterValue': '/app/masked',
         'ResolvedValue': '****'},
    ]}
    assert plaintextSecretParams(benign) == []


def test_plaintext_secret_mixed_direct_and_ssm_message():
    stack = {'StackName': 's', 'Parameters': [
        {'ParameterKey': 'GitHubToken', 'ParameterValue': 'ghp_notreal'},
        {'ParameterKey': 'DbPassword', 'ParameterValue': '/app/db/password',
         'ResolvedValue': 'hunter2-not-real'},
    ]}
    res = _run(CloudformationStack(stack, None),
               '_checkCfnPlaintextSecretParams')['cfnPlaintextSecretParams']
    assert res[0] == -1 and 'GitHubToken' in res[1] and 'DbPassword' in res[1]
    assert 'NoEcho' in res[1] and 'ResolvedValue' in res[1]


def test_old_stack_with_ssm_resolved_secret_is_interesting():
    """_isInteresting keeps an old stack whose SSM-resolved secret is exposed."""
    svc = _svc(_client())
    stack = {'StackName': 'old', 'StackStatus': 'CREATE_COMPLETE',
             'DriftInformation': {'StackDriftStatus': 'NOT_CHECKED'},
             'Parameters': [{'ParameterKey': 'DbPassword',
                             'ParameterValue': '/app/db/password',
                             'ResolvedValue': 'hunter2-not-real'}]}
    assert svc._isInteresting(stack) is True

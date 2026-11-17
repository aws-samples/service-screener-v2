"""Flag -> fix -> re-run tests for the WAFS2027 CloudFormation checks.

Runs against the local AWS Emulator only (see tests/emulator/README.md).
"""
import json
import time

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

SIMPLE_TEMPLATE = json.dumps({'Resources': {'T': {'Type': 'AWS::SNS::Topic'}}})


def _waitStack(cfn, name, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        st = cfn.describe_stacks(StackName=name)['Stacks'][0]['StackStatus']
        if not st.endswith('IN_PROGRESS'):
            return st
        time.sleep(1)
    raise AssertionError(f'stack {name} did not settle')


# --------------------------------------------------------------------------- #
# cfnPlaintextSecretParams
# --------------------------------------------------------------------------- #
def _paramTemplate(noEcho):
    return json.dumps({
        'Parameters': {
            'DbPassword': {'Type': 'String', 'NoEcho': noEcho},
            'DbPasswordLength': {'Type': 'String'},
            'Env': {'Type': 'String'},
        },
        'Resources': {'T': {'Type': 'AWS::SNS::Topic'}},
    })


def test_cfn_plaintext_secret_params(emu, uid):
    cfn = emu.client('cloudformation')
    name = f'ss-cfnsec-{uid}'
    params = [{'ParameterKey': 'DbPassword', 'ParameterValue': 'hunter2-not-real'},
              {'ParameterKey': 'DbPasswordLength', 'ParameterValue': '24'},
              {'ParameterKey': 'Env', 'ParameterValue': 'test'}]
    try:
        def misconfigure():
            cfn.create_stack(StackName=name, TemplateBody=_paramTemplate(False),
                             Parameters=params)
            _waitStack(cfn, name)

        def fix():
            cfn.update_stack(StackName=name, TemplateBody=_paramTemplate(True),
                             Parameters=params)
            _waitStack(cfn, name)
            p = {x['ParameterKey']: x['ParameterValue'] for x in
                 cfn.describe_stacks(StackName=name)['Stacks'][0]['Parameters']}
            assert p['DbPassword'] == '****'

        before, _ = assertFlagFixCycle(emu, 'cloudformation', 'cfnPlaintextSecretParams',
                                       f'Stack::{name}', misconfigure, fix)
        msgs = runCheck(emu, 'cloudformation', 'cfnPlaintextSecretParams', name).results
        assert all('hunter2' not in json.dumps(v) for v in msgs.values())
    finally:
        try:
            cfn.delete_stack(StackName=name)
        except Exception:
            pass


def test_cfn_plaintext_secret_ssm_typed_param_not_flagged(emu, uid):
    """An SSM parameter-type parameter holds a parameter NAME (ResolvedValue set)."""
    cfn, ssm = emu.client('cloudformation'), emu.client('ssm')
    name, pname = f'ss-cfnssm-{uid}', f'/ss-test/{uid}/token'
    ssm.put_parameter(Name=pname, Value='x', Type='String')
    try:
        cfn.create_stack(StackName=name, TemplateBody=json.dumps({
            'Parameters': {'ApiToken': {'Type': 'AWS::SSM::Parameter::Value<String>'}},
            'Resources': {'T': {'Type': 'AWS::SNS::Topic'}}}),
            Parameters=[{'ParameterKey': 'ApiToken', 'ParameterValue': pname}])
        _waitStack(cfn, name)
        st = runCheck(emu, 'cloudformation', 'cfnPlaintextSecretParams', f'Stack::{name}').statuses()
        assert st and all(s == 1 for s in st.values()), st
    finally:
        try:
            cfn.delete_stack(StackName=name)
        finally:
            ssm.delete_parameter(Name=pname)


# --------------------------------------------------------------------------- #
# cfnStackSetDrift
# --------------------------------------------------------------------------- #
def test_cfn_stack_set_drift_never_checked(emu, uid):
    cfn = emu.client('cloudformation')
    acct = emu.client('sts').get_caller_identity()['Account']
    name = f'ss-cfnss-{uid}'
    region = emu.region_name
    cfn.create_stack_set(StackSetName=name, TemplateBody=SIMPLE_TEMPLATE)
    try:
        # Zero instances: drift detection is not applicable -> INFO, not FAIL.
        st = runCheck(emu, 'cloudformation', 'cfnStackSetDrift', f'StackSet::{name}').statuses()
        assert st and all(s == 0 for s in st.values()), st

        def misconfigure():
            cfn.create_stack_instances(StackSetName=name, Accounts=[acct], Regions=[region])
            time.sleep(2)

        def fix():
            cfn.detect_stack_set_drift(StackSetName=name)
            end = time.time() + 30
            while time.time() < end:
                d = cfn.describe_stack_set(StackSetName=name)['StackSet'][
                    'StackSetDriftDetectionDetails']
                if d.get('DriftDetectionStatus') != 'IN_PROGRESS' and d.get('LastDriftCheckTimestamp'):
                    break
                time.sleep(1)

        _, after = assertFlagFixCycle(emu, 'cloudformation', 'cfnStackSetDrift',
                                      f'StackSet::{name}', misconfigure, fix)
        assert all(s == 1 for s in after.values()), after
    finally:
        try:
            cfn.delete_stack_instances(StackSetName=name, Accounts=[acct], Regions=[region],
                                       RetainStacks=False)
            time.sleep(2)
        except Exception:
            pass
        cfn.delete_stack_set(StackSetName=name)


# --------------------------------------------------------------------------- #
# cfnNoProactiveHooks (account level). Restores pre-existing hook state.
# --------------------------------------------------------------------------- #
def _hookCfg(status):
    return json.dumps({'CloudFormationConfiguration': {'HookConfiguration': {
        'HookInvocationStatus': status, 'FailureMode': 'WARN',
        'TargetOperations': ['STACK']}}})


def test_cfn_no_proactive_hooks(emu, uid):
    cfn = emu.client('cloudformation')
    existing = cfn.list_types(Type='HOOK', Visibility='PRIVATE').get('TypeSummaries', [])
    if existing:
        pytest.skip('emulator account already has hooks; this test needs a clean slate')
    guard = [t for t in cfn.list_types(Type='HOOK', Visibility='PUBLIC')['TypeSummaries']
             if t['TypeName'] == 'AWS::Hooks::GuardHook'][0]
    alias = f'SsTest::Guard{uid}::Hook'
    state = {}
    try:
        def misconfigure():
            # Activated but HookInvocationStatus DISABLED -> still no proactive control.
            state['arn'] = cfn.activate_type(Type='HOOK', TypeName=guard['TypeName'],
                                             PublisherId=guard['PublisherId'],
                                             TypeNameAlias=alias)['Arn']
            cfn.set_type_configuration(TypeArn=state['arn'], Configuration=_hookCfg('DISABLED'))

        def fix():
            cfn.set_type_configuration(TypeArn=state['arn'], Configuration=_hookCfg('ENABLED'))

        _, after = assertFlagFixCycle(emu, 'cloudformation', 'cfnNoProactiveHooks',
                                      'CloudFormation::Account', misconfigure, fix)
        assert all(s == 1 for s in after.values()), after
    finally:
        if state.get('arn'):
            cfn.deactivate_type(Arn=state['arn'])

    # With no hook at all the check must fail again.
    st = runCheck(emu, 'cloudformation', 'cfnNoProactiveHooks', 'CloudFormation::Account').statuses()
    assert st and all(s == -1 for s in st.values()), st

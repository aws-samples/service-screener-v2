"""FIS flag -> fix -> re-run test against the local AWS Emulator.

fisNoRecentExperiment is account/region-scoped. FIS experiment history cannot
be deleted, so the misconfigured state ("no experiment in the last 90 days")
only exists on an emulator that has never run an FIS experiment. When an
earlier run already left an experiment behind, the flag half cannot be
re-created; that case is skipped here and the deterministic flag/fix cycle is
covered by tests/test_stub_fis.py.
"""
import json

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Principal': {'Service': 'fis.amazonaws.com'},
    'Action': 'sts:AssumeRole'}]})


def test_fis_no_recent_experiment(emu, uid):
    fis = emu.client('fis')
    iam = emu.client('iam')
    if fis.list_experiments().get('experiments'):
        pytest.skip('Emulator already has FIS experiment history; flag state not reproducible '
                    '(see tests/test_stub_fis.py)')

    role = f'ss-fis-{uid}'
    roleArn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    templateId = None
    experimentId = None
    try:
        def misconfigure():
            nonlocal templateId
            ## A template alone does not count: nothing has been exercised.
            templateId = fis.create_experiment_template(
                clientToken=f'tpl-{uid}', description='ss test', roleArn=roleArn,
                stopConditions=[{'source': 'none'}], targets={},
                actions={'wait': {'actionId': 'aws:fis:wait',
                                  'parameters': {'duration': 'PT1M'}}},
            )['experimentTemplate']['id']

        def fix():
            nonlocal experimentId
            experimentId = fis.start_experiment(
                clientToken=f'exp-{uid}', experimentTemplateId=templateId)['experiment']['id']

        assertFlagFixCycle(emu, 'fis', 'fisNoRecentExperiment', 'Account', misconfigure, fix)
        msg = list(runCheck(emu, 'fis', 'fisNoRecentExperiment', 'Account').results.values())[0]
        assert msg['fisNoRecentExperiment'][0] == 1
    finally:
        if experimentId:
            try:
                fis.stop_experiment(id=experimentId)
            except Exception:
                pass
        if templateId:
            try:
                fis.delete_experiment_template(id=templateId)
            except Exception:
                pass
        iam.delete_role(RoleName=role)

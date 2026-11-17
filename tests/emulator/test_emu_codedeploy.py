"""Flag -> fix -> re-run tests for codedeploy.codedeployNoAutoRollback.

The emulator does not implement batch_get_deployment_groups (NotImplemented),
so these runs exercise the scanner's per-group get_deployment_group fallback.
The batch path itself is covered in tests/test_stub_codedeploy.py.
"""
from tests.emulator.conftest import assertFlagFixCycle

ROLE = 'arn:aws:iam::000000000000:role/ss-codedeploy-test'


def _withGroup(emu, uid, body):
    cd = emu.client('codedeploy')
    app = f'ss-cd-{uid}'
    group = f'dg-{uid}'
    cd.create_application(applicationName=app, computePlatform='Server')
    try:
        cd.create_deployment_group(applicationName=app, deploymentGroupName=group,
                                   serviceRoleArn=ROLE)
        body(cd, app, group)
    finally:
        try:
            cd.delete_deployment_group(applicationName=app, deploymentGroupName=group)
        except Exception:
            pass
        cd.delete_application(applicationName=app)


def _setRollback(cd, app, group, enabled, events):
    cd.update_deployment_group(
        applicationName=app, currentDeploymentGroupName=group,
        autoRollbackConfiguration={'enabled': enabled, 'events': events})


def test_codedeploy_rollback_disabled_flag_fix(emu, uid):
    def body(cd, app, group):
        assertFlagFixCycle(
            emu, 'codedeploy', 'codedeployNoAutoRollback', f'{app}/{group}',
            lambda: _setRollback(cd, app, group, False, []),
            lambda: _setRollback(cd, app, group, True, ['DEPLOYMENT_FAILURE']))
    _withGroup(emu, uid, body)


def test_codedeploy_rollback_alarm_only_flag_fix(emu, uid):
    """Rollback enabled only on alarm: a failed deployment is not rolled back."""
    def body(cd, app, group):
        assertFlagFixCycle(
            emu, 'codedeploy', 'codedeployNoAutoRollback', f'{app}/{group}',
            lambda: _setRollback(cd, app, group, True, ['DEPLOYMENT_STOP_ON_ALARM']),
            lambda: _setRollback(cd, app, group, True,
                                 ['DEPLOYMENT_FAILURE', 'DEPLOYMENT_STOP_ON_ALARM']))
    _withGroup(emu, uid, body)

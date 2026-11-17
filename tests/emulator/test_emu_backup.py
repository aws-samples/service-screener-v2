"""Flag -> fix -> re-run tests for the WAFS2027 AWS Backup checks (emulator).

Checks whose flag/fix states the emulator cannot produce (cross-account copy
destinations, deletable job history, vault notifications, restore testing
plans) are covered by tests/test_stub_backup.py; here we additionally run
them end to end against the emulator to prove they never report a false PASS
or a false FAIL when the data is unreadable.
"""
import json
import time

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ROLE = 'arn:aws:iam::000000000000:role/ss-backup-test'


def _acct(emu):
    return emu.client('sts').get_caller_identity()['Account']


def _vaultArn(emu, name):
    return f"arn:aws:backup:us-east-1:{_acct(emu)}:backup-vault:{name}"


def _deletePlan(b, planId):
    try:
        for s in b.list_backup_selections(BackupPlanId=planId).get('BackupSelectionsList', []):
            b.delete_backup_selection(BackupPlanId=planId, SelectionId=s['SelectionId'])
    except Exception:
        pass
    try:
        b.delete_backup_plan(BackupPlanId=planId)
    except Exception:
        pass


def _deleteVault(b, name):
    try:
        b.delete_backup_vault_lock_configuration(BackupVaultName=name)
    except Exception:
        pass
    try:
        for rp in b.list_recovery_points_by_backup_vault(BackupVaultName=name).get('RecoveryPoints', []):
            b.delete_recovery_point(BackupVaultName=name, RecoveryPointArn=rp['RecoveryPointArn'])
    except Exception:
        pass
    _retry(lambda: b.delete_backup_vault(BackupVaultName=name))


def _retry(fn, attempts=20, delay=0.5):
    """Run a cleanup call, retrying while the resource is still in a
    transitional state (e.g. a vault in 'Creating' state, or a framework
    with CREATE_IN_PROGRESS raising ConflictException)."""
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as e:
            code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            if code not in ('InvalidRequestException', 'ConflictException'):
                return
            time.sleep(delay)


def _rule(vault, **extra):
    r = {'RuleName': 'daily', 'TargetBackupVaultName': vault,
         'ScheduleExpression': 'cron(0 5 ? * * *)'}
    r.update(extra)
    return r


# --------------------------------------------------------------------------- #
# backupPlanNotTargetingProtectedVault
# --------------------------------------------------------------------------- #
def test_plan_not_targeting_protected_vault(emu, uid):
    b = emu.client('backup')
    vault, plan = f'ss-v-{uid}', f'ss-p-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    planId = None
    try:
        def misconfigure():
            nonlocal planId
            planId = b.create_backup_plan(BackupPlan={
                'BackupPlanName': plan,
                'Rules': [_rule(vault, Lifecycle={'DeleteAfterDays': 90})]})['BackupPlanId']

        def fix():
            b.put_backup_vault_lock_configuration(BackupVaultName=vault, MinRetentionDays=35)

        assertFlagFixCycle(emu, 'backup', 'backupPlanNotTargetingProtectedVault', f'Plan::{plan}',
                           misconfigure, fix)
    finally:
        if planId:
            _deletePlan(b, planId)
        _deleteVault(b, vault)


# --------------------------------------------------------------------------- #
# backupRetentionBelowDetectionWindow (plan and vault)
# --------------------------------------------------------------------------- #
def test_retention_below_detection_window_plan(emu, uid):
    b = emu.client('backup')
    vault, plan = f'ss-v-{uid}', f'ss-p-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    planId = None
    try:
        def misconfigure():
            nonlocal planId
            planId = b.create_backup_plan(BackupPlan={
                'BackupPlanName': plan,
                'Rules': [_rule(vault, Lifecycle={'DeleteAfterDays': 7})]})['BackupPlanId']

        def fix():
            # Keep the short daily rule; add a monthly rule kept for a year.
            b.update_backup_plan(BackupPlanId=planId, BackupPlan={
                'BackupPlanName': plan,
                'Rules': [_rule(vault, Lifecycle={'DeleteAfterDays': 7}),
                          dict(_rule(vault, Lifecycle={'DeleteAfterDays': 365}),
                               RuleName='monthly', ScheduleExpression='cron(0 5 1 * ? *)')]})

        assertFlagFixCycle(emu, 'backup', 'backupRetentionBelowDetectionWindow', f'Plan::{plan}',
                           misconfigure, fix)
    finally:
        if planId:
            _deletePlan(b, planId)
        _deleteVault(b, vault)


def test_retention_below_detection_window_vault_lock(emu, uid):
    b = emu.client('backup')
    vault = f'ss-v-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    try:
        def misconfigure():
            b.put_backup_vault_lock_configuration(BackupVaultName=vault, MinRetentionDays=7)

        def fix():
            b.put_backup_vault_lock_configuration(BackupVaultName=vault, MinRetentionDays=35)

        assertFlagFixCycle(emu, 'backup', 'backupRetentionBelowDetectionWindow', f'Vault::{vault}',
                           misconfigure, fix)
    finally:
        _deleteVault(b, vault)


# --------------------------------------------------------------------------- #
# backupMalwareScanDisabled
# --------------------------------------------------------------------------- #
def test_malware_scan_disabled(emu, uid):
    b, iam = emu.client('backup'), emu.client('iam')
    vault, plan, roleName = f'ss-v-{uid}', f'ss-p-{uid}', f'ss-backup-role-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    roleArn = iam.create_role(RoleName=roleName, AssumeRolePolicyDocument=json.dumps({
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'backup.amazonaws.com'},
                       'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
    planId = None
    rule = _rule(vault, Lifecycle={'DeleteAfterDays': 90})
    try:
        def misconfigure():
            nonlocal planId
            planId = b.create_backup_plan(BackupPlan={'BackupPlanName': plan, 'Rules': [rule]})['BackupPlanId']
            b.create_backup_selection(BackupPlanId=planId, BackupSelection={
                'SelectionName': f'sel{uid}', 'IamRoleArn': roleArn,
                'Resources': [f'arn:aws:ec2:us-east-1:{_acct(emu)}:volume/vol-0123456789abcdef0']})

        def fix():
            b.update_backup_plan(BackupPlanId=planId, BackupPlan={
                'BackupPlanName': plan,
                'Rules': [dict(rule, ScanActions=[{'MalwareScanner': 'GUARDDUTY', 'ScanMode': 'INCREMENTAL_SCAN'}])],
                'ScanSettings': [{'MalwareScanner': 'GUARDDUTY', 'ResourceTypes': ['EBS'],
                                  'ScannerRoleArn': roleArn}]})

        assertFlagFixCycle(emu, 'backup', 'backupMalwareScanDisabled', f'Plan::{plan}', misconfigure, fix)
    finally:
        if planId:
            _deletePlan(b, planId)
        _deleteVault(b, vault)
        try:
            iam.delete_role(RoleName=roleName)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# backupPlanNoCrossAccountCopy (account level)
# --------------------------------------------------------------------------- #
def test_plan_no_cross_account_copy(emu, uid):
    """The emulator rejects CopyActions to another account ('Invalid backup
    vault ARN'), so the fix here uses the other accepted isolation path - a
    rule targeting a logically air-gapped vault. The cross-account branch is
    covered by tests/test_stub_backup.py."""
    b = emu.client('backup')
    vault, lag, plan = f'ss-v-{uid}', f'ss-lag-{uid}', f'ss-p-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    b.create_logically_air_gapped_backup_vault(BackupVaultName=lag, MinRetentionDays=35, MaxRetentionDays=365)
    others = b.list_backup_plans()['BackupPlansList']
    assert not others, (f'emulator already has {len(others)} backup plan(s); the account-level '
                        'result would be ambiguous - run against a clean emulator')
    planId = None
    try:
        def misconfigure():
            nonlocal planId
            planId = b.create_backup_plan(BackupPlan={
                'BackupPlanName': plan,
                'Rules': [_rule(vault, Lifecycle={'DeleteAfterDays': 90})]})['BackupPlanId']

        def fix():
            b.update_backup_plan(BackupPlanId=planId, BackupPlan={
                'BackupPlanName': plan,
                'Rules': [_rule(vault, Lifecycle={'DeleteAfterDays': 90},
                                CopyActions=[{'DestinationBackupVaultArn': _vaultArn(emu, lag),
                                              'Lifecycle': {'DeleteAfterDays': 90}}])]})

        assertFlagFixCycle(emu, 'backup', 'backupPlanNoCrossAccountCopy', 'Account::us-east-1',
                           misconfigure, fix)
    finally:
        if planId:
            _deletePlan(b, planId)
        _deleteVault(b, vault)
        _deleteVault(b, lag)


def test_plan_cross_account_copy_other_region_air_gapped_vault(emu, uid):
    """A copy to a logically air-gapped vault of this account in another
    Region (a common DR setup) is isolation: resolved through the cached
    describe_backup_vault lookup, not only this Region's vault list."""
    b = emu.client('backup')
    west = emu.client('backup', region_name='us-west-2')
    assert west.meta.endpoint_url.startswith('https://127.0.0.1:'), west.meta.endpoint_url
    vault, plan = f'ss-v-{uid}', f'ss-p-{uid}'
    drStd, drLag = f'ss-dr-{uid}', f'ss-drlag-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    west.create_backup_vault(BackupVaultName=drStd)
    west.create_logically_air_gapped_backup_vault(BackupVaultName=drLag, MinRetentionDays=35,
                                                  MaxRetentionDays=365)
    others = b.list_backup_plans()['BackupPlansList']
    assert not others, (f'emulator already has {len(others)} backup plan(s); the account-level '
                        'result would be ambiguous - run against a clean emulator')
    acct = _acct(emu)

    def westArn(name):
        return f'arn:aws:backup:us-west-2:{acct}:backup-vault:{name}'

    def body(dest):
        return {'BackupPlanName': plan, 'Rules': [_rule(
            vault, Lifecycle={'DeleteAfterDays': 90},
            CopyActions=[{'DestinationBackupVaultArn': westArn(dest),
                          'Lifecycle': {'DeleteAfterDays': 90}}])]}
    planId = None
    try:
        def misconfigure():
            nonlocal planId
            planId = b.create_backup_plan(BackupPlan=body(drStd))['BackupPlanId']

        def fix():
            b.update_backup_plan(BackupPlanId=planId, BackupPlan=body(drLag))

        assertFlagFixCycle(emu, 'backup', 'backupPlanNoCrossAccountCopy', 'Account::us-east-1',
                           misconfigure, fix)
        res = runCheck(emu, 'backup', 'backupPlanNoCrossAccountCopy', 'Account::us-east-1')
        assert all(s == 1 for s in res.statuses().values()), res.results
    finally:
        if planId:
            _deletePlan(b, planId)
        _deleteVault(b, vault)
        _deleteVault(west, drStd)
        _deleteVault(west, drLag)


# --------------------------------------------------------------------------- #
# backupJobsFailing / backupRestoreJobsFailing - flag end to end.
# Job history cannot be deleted, so the fix half is in test_stub_backup.py.
# --------------------------------------------------------------------------- #
def test_backup_jobs_failing_flags_failed_job(emu, uid):
    b = emu.client('backup')
    vault = f'ss-v-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    try:
        # A backup of a table that does not exist fails asynchronously.
        jobId = b.start_backup_job(
            BackupVaultName=vault, IamRoleArn=ROLE,
            ResourceArn=f'arn:aws:dynamodb:us-east-1:{_acct(emu)}:table/ss-missing-{uid}')['BackupJobId']
        for _ in range(30):
            if b.describe_backup_job(BackupJobId=jobId)['State'] in ('FAILED', 'ABORTED', 'EXPIRED', 'COMPLETED'):
                break
            time.sleep(1)
        assert b.describe_backup_job(BackupJobId=jobId)['State'] == 'FAILED'
        res = runCheck(emu, 'backup', 'backupJobsFailing', 'Account::us-east-1')
        st = res.statuses()
        assert st and all(s == -1 for s in st.values()), (st, res.results)
        assert f'ss-missing-{uid}' in json.dumps(res.results)
    finally:
        _deleteVault(b, vault)


def test_restore_jobs_failing_flags_failed_restore(emu, uid):
    b = emu.client('backup')
    vault = f'ss-v-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    try:
        jobId = b.start_backup_job(
            BackupVaultName=vault, IamRoleArn=ROLE,
            ResourceArn=f'arn:aws:ec2:us-east-1:{_acct(emu)}:volume/vol-{uid}0000000')['BackupJobId']
        for _ in range(30):
            job = b.describe_backup_job(BackupJobId=jobId)
            if job['State'] == 'COMPLETED':
                break
            time.sleep(1)
        rid = b.start_restore_job(RecoveryPointArn=job['RecoveryPointArn'], IamRoleArn=ROLE,
                                  ResourceType='EBS', Metadata={'availabilityZone': 'us-east-1a'})['RestoreJobId']
        for _ in range(30):
            if b.describe_restore_job(RestoreJobId=rid)['Status'] in ('FAILED', 'COMPLETED', 'ABORTED'):
                break
            time.sleep(1)
        status = b.describe_restore_job(RestoreJobId=rid)['Status']
        res = runCheck(emu, 'backup', 'backupRestoreJobsFailing', 'Account::us-east-1')
        st = res.statuses()
        if status == 'FAILED':
            assert st and all(s == -1 for s in st.values()), (st, res.results)
            assert rid in json.dumps(res.results)
        else:
            # Make the restore fail validation instead.
            b.put_restore_validation_result(RestoreJobId=rid, ValidationStatus='FAILED',
                                            ValidationStatusMessage='ss test')
            st = runCheck(emu, 'backup', 'backupRestoreJobsFailing', 'Account::us-east-1').statuses()
            assert st and all(s == -1 for s in st.values()), st
    finally:
        _deleteVault(b, vault)


# --------------------------------------------------------------------------- #
# backupNoFailureAlerting - emulator lacks get_backup_vault_notifications.
# --------------------------------------------------------------------------- #
def test_no_failure_alerting_eventbridge(emu, uid):
    """Without readable vault notifications and without a rule the check must
    be 'unable to evaluate' (0), never a FAIL or PASS; an enabled EventBridge
    rule for aws.backup with a target turns it into PASS. The -1 path is in
    tests/test_stub_backup.py."""
    b, ev = emu.client('backup'), emu.client('events')
    vault, rule = f'ss-v-{uid}', f'ss-backup-alert-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    try:
        st = runCheck(emu, 'backup', 'backupNoFailureAlerting', 'Account::us-east-1').statuses()
        assert st and all(s == 0 for s in st.values()), st

        # A targeted rule that only matches COMPLETED jobs is not failure alerting.
        ev.put_rule(Name=rule, State='ENABLED', EventPattern=json.dumps({
            'source': ['aws.backup'], 'detail-type': ['Backup Job State Change'],
            'detail': {'state': ['COMPLETED']}}))
        ev.put_targets(Rule=rule, Targets=[{'Id': '1', 'Arn': 'arn:aws:sns:us-east-1:000000000000:ss-alerts'}])
        st = runCheck(emu, 'backup', 'backupNoFailureAlerting', 'Account::us-east-1').statuses()
        assert st and all(s == 0 for s in st.values()), st
        ev.remove_targets(Rule=rule, Ids=['1'])

        ev.put_rule(Name=rule, State='ENABLED', EventPattern=json.dumps({
            'source': ['aws.backup'], 'detail-type': ['Backup Job State Change'],
            'detail': {'state': ['FAILED', 'ABORTED', 'EXPIRED']}}))
        # Rule without a target is not alerting.
        st = runCheck(emu, 'backup', 'backupNoFailureAlerting', 'Account::us-east-1').statuses()
        assert st and all(s == 0 for s in st.values()), st

        ev.put_targets(Rule=rule, Targets=[{'Id': '1', 'Arn': 'arn:aws:sns:us-east-1:000000000000:ss-alerts'}])
        st = runCheck(emu, 'backup', 'backupNoFailureAlerting', 'Account::us-east-1').statuses()
        assert st and all(s == 1 for s in st.values()), st
    finally:
        try:
            ev.remove_targets(Rule=rule, Ids=['1'])
        except Exception:
            pass
        try:
            ev.delete_rule(Name=rule)
        except Exception:
            pass
        _deleteVault(b, vault)


# --------------------------------------------------------------------------- #
# backupNoRestoreTestingPlan - emulator lacks list_restore_testing_plans.
# --------------------------------------------------------------------------- #
def test_no_restore_testing_plan_unevaluable(emu, uid):
    b = emu.client('backup')
    vault, plan = f'ss-v-{uid}', f'ss-p-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    planId = b.create_backup_plan(BackupPlan={
        'BackupPlanName': plan, 'Rules': [_rule(vault, Lifecycle={'DeleteAfterDays': 90})]})['BackupPlanId']
    try:
        res = runCheck(emu, 'backup', 'backupNoRestoreTestingPlan', 'Account::us-east-1')
        st = res.statuses()
        assert st and all(s == 0 for s in st.values()), st
        assert 'Unable to evaluate' in json.dumps(res.results)
    finally:
        _deletePlan(b, planId)
        _deleteVault(b, vault)


# --------------------------------------------------------------------------- #
# backupVaultNoAccessPolicy - public (Principal "*") vault access policy
# --------------------------------------------------------------------------- #
def _publicPolicy(vault_arn, condition=None):
    stmt = {'Sid': 'AnyoneCopyIn', 'Effect': 'Allow', 'Principal': {'AWS': ['*']},
            'Action': 'backup:CopyIntoBackupVault', 'Resource': '*'}
    if condition:
        stmt['Condition'] = condition
    return json.dumps({'Version': '2012-10-17', 'Statement': [stmt]})


def test_vault_access_policy_public(emu, uid):
    b = emu.client('backup')
    vault = f'ss-v-{uid}'
    arn = b.create_backup_vault(BackupVaultName=vault)['BackupVaultArn']
    acct = _acct(emu)
    try:
        def misconfigure():
            # An IfExists condition does not restrict callers that lack the key.
            b.put_backup_vault_access_policy(BackupVaultName=vault, Policy=_publicPolicy(
                arn, {'StringEqualsIfExists': {'aws:PrincipalAccount': acct}}))

        def fix():
            b.put_backup_vault_access_policy(BackupVaultName=vault, Policy=_publicPolicy(
                arn, {'StringEquals': {'aws:PrincipalAccount': acct}}))

        before, _ = assertFlagFixCycle(emu, 'backup', 'backupVaultNoAccessPolicy', f'Vault::{vault}',
                                       misconfigure, fix)
        res = runCheck(emu, 'backup', 'backupVaultNoAccessPolicy', f'Vault::{vault}')
        assert all(s == 1 for s in res.statuses().values()), res.statuses()
    finally:
        try:
            b.delete_backup_vault_access_policy(BackupVaultName=vault)
        except Exception:
            pass
        _deleteVault(b, vault)


# --------------------------------------------------------------------------- #
# airGappedVaultNoMpa
# --------------------------------------------------------------------------- #
def test_air_gapped_vault_no_mpa(emu, uid):
    b = emu.client('backup')
    vault = f'ss-lag-{uid}'
    team = f'arn:aws:mpa:us-east-1:{_acct(emu)}:approval-team/ss-{uid}'
    b.create_logically_air_gapped_backup_vault(BackupVaultName=vault, MinRetentionDays=7,
                                               MaxRetentionDays=35)
    try:
        def misconfigure():
            pass  # a new air-gapped vault has no MPA team

        def fix():
            b.associate_backup_vault_mpa_approval_team(BackupVaultName=vault, MpaApprovalTeamArn=team)

        assertFlagFixCycle(emu, 'backup', 'airGappedVaultNoMpa', f'Vault::{vault}', misconfigure, fix)
        res = runCheck(emu, 'backup', 'airGappedVaultNoMpa', f'Vault::{vault}')
        assert all(s == 1 for s in res.statuses().values()), res.statuses()
    finally:
        try:
            b.disassociate_backup_vault_mpa_approval_team(BackupVaultName=vault)
        except Exception:
            pass
        _deleteVault(b, vault)


def test_air_gapped_mpa_not_applicable_to_standard_vault(emu, uid):
    """MPA only applies to logically air-gapped vaults: a standard vault gets
    no airGappedVaultNoMpa row at all (no per-vault 'not applicable' noise)."""
    b = emu.client('backup')
    vault = f'ss-v-{uid}'
    b.create_backup_vault(BackupVaultName=vault)
    try:
        res = runCheck(emu, 'backup', 'airGappedVaultNoMpa', f'Vault::{vault}')
        assert not res.statuses(), res.results
    finally:
        _deleteVault(b, vault)


# --------------------------------------------------------------------------- #
# backupAuditFrameworkMissing (list_report_plans is NotImplemented in the
# emulator; the check treats report plans as informational only)
# --------------------------------------------------------------------------- #
def test_audit_framework_missing(emu, uid):
    b = emu.client('backup')
    vault, plan, fw = f'ss-v-{uid}', f'ss-p-{uid}', f'ss_fw_{uid}'.replace('-', '_')
    b.create_backup_vault(BackupVaultName=vault)
    planId = b.create_backup_plan(BackupPlan={
        'BackupPlanName': plan, 'Rules': [_rule(vault, Lifecycle={'DeleteAfterDays': 90})]})['BackupPlanId']
    assert not b.list_frameworks().get('Frameworks'), 'private emulator expected to have no frameworks'
    try:
        def misconfigure():
            pass  # no framework exists

        def fix():
            b.create_framework(FrameworkName=fw, FrameworkControls=[
                {'ControlName': 'BACKUP_RECOVERY_POINT_ENCRYPTED'}])

        assertFlagFixCycle(emu, 'backup', 'backupAuditFrameworkMissing', 'Account::us-east-1',
                           misconfigure, fix)
    finally:
        _retry(lambda: b.delete_framework(FrameworkName=fw))
        _deletePlan(b, planId)
        _deleteVault(b, vault)

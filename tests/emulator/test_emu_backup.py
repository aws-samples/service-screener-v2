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
    try:
        b.delete_backup_vault(BackupVaultName=name)
    except Exception:
        pass


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

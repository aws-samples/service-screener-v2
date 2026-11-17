"""Flag -> fix -> re-run tests (botocore Stubber) for WAFS2027 AWS Backup checks.

Why Stubber and not the emulator:
- backupJobsFailing / backupRestoreJobsFailing: job history cannot be deleted,
  so the 'fixed' state (no failed job in the window) cannot be produced after
  the misconfigured one. The emulator tests flag end to end; the fix half
  is here.
- backupNoFailureAlerting: the emulator does not implement
  get_backup_vault_notifications / put_backup_vault_notifications.
- backupNoRestoreTestingPlan: the emulator does not implement
  list_restore_testing_plans / list_restore_testing_selections.
- backupPlanNoCrossAccountCopy: the emulator rejects CopyActions whose
  destination is in another account, so the cross-account PASS path can only
  be exercised with API-shaped responses.
- Plan-level branches the emulator cannot create (vaults in other accounts,
  DELETE_AFTER_COPY lifecycles) are driven with API-shaped plan dicts.

Every client is a real boto3 client wrapped in botocore.stub.Stubber, so
request parameters and response shapes are validated against the real API
model; nothing is sent over the network.
"""
import os
import sys
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import ANY, Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.backup.drivers.BackupAccount import BackupAccount  # noqa: E402
from services.backup.drivers.BackupPlan import BackupPlan  # noqa: E402
from services.backup.drivers.BackupVault import BackupVault  # noqa: E402

ACCT = '111111111111'
OTHER = '222222222222'
REGION = 'us-east-1'
NOW = datetime.now(timezone.utc)


def _client(svc):
    return boto3.client(svc, region_name=REGION, aws_access_key_id='testing',
                        aws_secret_access_key='testing', aws_session_token='testing',
                        endpoint_url=f'https://{svc}.{REGION}.amazonaws.com')


@pytest.fixture
def clients():
    c = {s: _client(s) for s in ('backup', 'events', 'cloudwatch')}
    stubs = {s: Stubber(cl) for s, cl in c.items()}
    for st in stubs.values():
        st.activate()
    yield c, stubs
    for st in stubs.values():
        st.deactivate()


def _vaultArn(name, acct=ACCT, region=REGION):
    return f'arn:aws:backup:{region}:{acct}:backup-vault:{name}'


def _account(plans=None, vaults=None):
    return {'_name': REGION, '_region': REGION, '_accountId': ACCT,
            '_vaults': vaults if vaults is not None else [{'_name': 'v1', '_vaultType': 'BACKUP_VAULT'}],
            '_plans': plans if plans is not None else [{'_id': 'p1', '_name': 'plan1', '_rules': []}]}


def _drv(clients, account=None):
    c, _ = clients
    return BackupAccount(account or _account(), c['backup'],
                         eventsClient=c['events'], cloudwatchClient=c['cloudwatch'])


def _run(drv, method, key):
    drv.results = {}
    getattr(drv, method)()
    return drv.results[key]


def _err(stub, op, code, params=None):
    stub.add_client_error(op, service_error_code=code, service_message=code,
                          http_status_code=400, expected_params=params)


# --------------------------------------------------------------------------- #
# backupJobsFailing
# --------------------------------------------------------------------------- #
def _stubJobs(stub, failed=(), copyFailed=()):
    for state in ('FAILED', 'ABORTED', 'EXPIRED'):
        jobs = [j for j in failed if j['State'] == state]
        stub.add_response('list_backup_jobs', {'BackupJobs': jobs},
                          {'ByState': state, 'ByCreatedAfter': ANY})
    stub.add_response('list_copy_jobs', {'CopyJobs': list(copyFailed)},
                      {'ByState': 'FAILED', 'ByCreatedAfter': ANY})


def test_backup_jobs_failing_flag_fix(clients):
    _, stubs = clients
    drv = _drv(clients)
    _stubJobs(stubs['backup'], failed=[{
        'BackupJobId': 'j1', 'State': 'FAILED', 'CreationDate': NOW,
        'ResourceArn': f'arn:aws:dynamodb:{REGION}:{ACCT}:table/orders',
        'StatusMessage': 'Access denied'}])
    r = _run(drv, '_checkBackupJobsFailing', 'backupJobsFailing')
    assert r[0] == -1 and 'orders' in r[1] and 'backup:FAILED=1' in r[1], r

    _stubJobs(stubs['backup'])
    r = _run(drv, '_checkBackupJobsFailing', 'backupJobsFailing')
    assert r[0] == 1, r
    stubs['backup'].assert_no_pending_responses()


def test_backup_jobs_failing_copy_job_and_expired(clients):
    _, stubs = clients
    drv = _drv(clients)
    _stubJobs(stubs['backup'],
              failed=[{'BackupJobId': 'j2', 'State': 'EXPIRED', 'CreationDate': NOW,
                       'ResourceArn': f'arn:aws:ec2:{REGION}:{ACCT}:volume/vol-1'}],
              copyFailed=[{'CopyJobId': 'c1', 'State': 'FAILED', 'CreationDate': NOW,
                           'ResourceArn': f'arn:aws:rds:{REGION}:{ACCT}:db:prod'}])
    r = _run(drv, '_checkBackupJobsFailing', 'backupJobsFailing')
    assert r[0] == -1 and 'copy:FAILED=1' in r[1] and 'backup:EXPIRED=1' in r[1], r


def test_backup_jobs_failing_access_denied_is_not_pass(clients):
    _, stubs = clients
    _err(stubs['backup'], 'list_backup_jobs', 'AccessDeniedException')
    r = _run(_drv(clients), '_checkBackupJobsFailing', 'backupJobsFailing')
    assert r == [0, 'Unable to evaluate (AccessDeniedException)'], r


# --------------------------------------------------------------------------- #
# backupRestoreJobsFailing
# --------------------------------------------------------------------------- #
def _restore(jid, status, validation=None):
    j = {'RestoreJobId': jid, 'Status': status, 'CreationDate': NOW,
         'RecoveryPointArn': f'arn:aws:backup:{REGION}:{ACCT}:recovery-point:{jid}'}
    if validation:
        j['ValidationStatus'] = validation
    return j


def test_restore_jobs_failing_flag_fix(clients):
    _, stubs = clients
    drv = _drv(clients)
    stubs['backup'].add_response('list_restore_jobs', {'RestoreJobs': [
        _restore('r1', 'FAILED'), _restore('r2', 'COMPLETED')]}, {'ByCreatedAfter': ANY})
    r = _run(drv, '_checkBackupRestoreJobsFailing', 'backupRestoreJobsFailing')
    assert r[0] == -1 and 'r1' in r[1] and 'r2' not in r[1], r

    stubs['backup'].add_response('list_restore_jobs', {'RestoreJobs': [
        _restore('r3', 'COMPLETED', 'SUCCESSFUL')]}, {'ByCreatedAfter': ANY})
    r = _run(drv, '_checkBackupRestoreJobsFailing', 'backupRestoreJobsFailing')
    assert r[0] == 1, r


def test_restore_validation_failed_flags(clients):
    _, stubs = clients
    stubs['backup'].add_response('list_restore_jobs', {'RestoreJobs': [
        _restore('r4', 'COMPLETED', 'FAILED')]}, {'ByCreatedAfter': ANY})
    r = _run(_drv(clients), '_checkBackupRestoreJobsFailing', 'backupRestoreJobsFailing')
    assert r[0] == -1 and 'validation' in r[1], r


def test_restore_jobs_unreadable(clients):
    _, stubs = clients
    _err(stubs['backup'], 'list_restore_jobs', 'AccessDeniedException')
    r = _run(_drv(clients), '_checkBackupRestoreJobsFailing', 'backupRestoreJobsFailing')
    assert r[0] == 0 and 'Unable to evaluate' in r[1], r


# --------------------------------------------------------------------------- #
# backupPlanNoCrossAccountCopy
# --------------------------------------------------------------------------- #
def _plan(rules, name='plan1', pid='p1'):
    return {'_id': pid, '_name': name, '_rules': rules}


def test_cross_account_copy_flag_fix(clients):
    sameAcct = [{'RuleName': 'r', 'TargetBackupVaultName': 'v1',
                 'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('dr', region='us-west-2')}]}]
    r = _run(_drv(clients, _account(plans=[_plan(sameAcct)])),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == -1, r

    crossAcct = [{'RuleName': 'r', 'TargetBackupVaultName': 'v1',
                  'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('central', acct=OTHER)}]}]
    r = _run(_drv(clients, _account(plans=[_plan(sameAcct), _plan(crossAcct, 'plan2', 'p2')])),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == 1 and OTHER in r[1], r


def test_cross_account_copy_checkpointed_plan_is_fetched(clients):
    _, stubs = clients
    stubs['backup'].add_response('get_backup_plan', {
        'BackupPlan': {'BackupPlanName': 'plan1', 'Rules': [{
            'RuleName': 'r', 'TargetBackupVaultName': 'v1',
            'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('central', acct=OTHER)}]}]},
        'BackupPlanId': 'p1'}, {'BackupPlanId': 'p1'})
    r = _run(_drv(clients, _account(plans=[{'_id': 'p1', '_name': 'plan1'}])),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == 1, r

    _err(stubs['backup'], 'get_backup_plan', 'AccessDeniedException', {'BackupPlanId': 'p1'})
    r = _run(_drv(clients, _account(plans=[{'_id': 'p1', '_name': 'plan1'}])),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == 0 and 'Unable to evaluate' in r[1], r


def test_cross_account_copy_lag_counts_as_isolation(clients):
    vaults = [{'_name': 'v1', '_vaultType': 'BACKUP_VAULT'},
              {'_name': 'lag', '_vaultType': 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'}]
    rules = [{'RuleName': 'r', 'TargetBackupVaultName': 'v1',
              'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('lag')}]}]
    r = _run(_drv(clients, _account(plans=[_plan(rules)], vaults=vaults)),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == 1 and 'air-gapped' in r[1], r
    # Same name in another Region is not the local LAG vault.
    rules[0]['CopyActions'][0]['DestinationBackupVaultArn'] = _vaultArn('lag', region='eu-west-1')
    r = _run(_drv(clients, _account(plans=[_plan(rules)], vaults=vaults)),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == -1, r


# --------------------------------------------------------------------------- #
# backupNoFailureAlerting
# --------------------------------------------------------------------------- #
def _noAlerting(stubs):
    _err(stubs['backup'], 'get_backup_vault_notifications', 'ResourceNotFoundException',
         {'BackupVaultName': 'v1'})
    stubs['events'].add_response('list_rules', {'Rules': []}, {})
    stubs['cloudwatch'].add_response('describe_alarms', {'MetricAlarms': []}, {'AlarmTypes': ['MetricAlarm']})


def test_no_failure_alerting_flag_fix_vault_notifications(clients):
    _, stubs = clients
    drv = _drv(clients)
    _noAlerting(stubs)
    r = _run(drv, '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == -1, r

    stubs['backup'].add_response('get_backup_vault_notifications', {
        'BackupVaultName': 'v1', 'SNSTopicArn': f'arn:aws:sns:{REGION}:{ACCT}:backup-alerts',
        'BackupVaultEvents': ['BACKUP_JOB_FAILED', 'COPY_JOB_FAILED']}, {'BackupVaultName': 'v1'})
    r = _run(drv, '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == 1 and 'vault v1' in r[1], r
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_no_failure_alerting_fix_eventbridge(clients):
    _, stubs = clients
    _err(stubs['backup'], 'get_backup_vault_notifications', 'ResourceNotFoundException',
         {'BackupVaultName': 'v1'})
    stubs['events'].add_response('list_rules', {'Rules': [
        {'Name': 'disabled', 'State': 'DISABLED', 'EventPattern': '{"source":["aws.backup"]}',
         'EventBusName': 'default'},
        {'Name': 'other', 'State': 'ENABLED', 'EventPattern': '{"source":["aws.ec2"]}',
         'EventBusName': 'default'},
        {'Name': 'backup-fail', 'State': 'ENABLED', 'EventBusName': 'default',
         'EventPattern': '{"source":["aws.backup"],"detail":{"state":["FAILED"]}}'}]}, {})
    stubs['events'].add_response('list_targets_by_rule', {'Targets': [
        {'Id': '1', 'Arn': f'arn:aws:sns:{REGION}:{ACCT}:t'}]},
        {'Rule': 'backup-fail', 'EventBusName': 'default'})
    r = _run(_drv(clients), '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == 1 and 'backup-fail' in r[1], r


def test_no_failure_alerting_fix_cloudwatch_alarm(clients):
    _, stubs = clients
    _err(stubs['backup'], 'get_backup_vault_notifications', 'ResourceNotFoundException',
         {'BackupVaultName': 'v1'})
    stubs['events'].add_response('list_rules', {'Rules': []}, {})
    stubs['cloudwatch'].add_response('describe_alarms', {'MetricAlarms': [
        {'AlarmName': 'no-actions', 'Namespace': 'AWS/Backup', 'MetricName': 'NumberOfBackupJobsFailed',
         'ActionsEnabled': True, 'AlarmActions': []},
        {'AlarmName': 'backup-failed', 'Namespace': 'AWS/Backup', 'MetricName': 'NumberOfBackupJobsFailed',
         'ActionsEnabled': True, 'AlarmActions': [f'arn:aws:sns:{REGION}:{ACCT}:t']}]},
        {'AlarmTypes': ['MetricAlarm']})
    r = _run(_drv(clients), '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == 1 and 'backup-failed' in r[1], r


def test_no_failure_alerting_unreadable_is_not_fail(clients):
    _, stubs = clients
    _err(stubs['backup'], 'get_backup_vault_notifications', 'AccessDeniedException',
         {'BackupVaultName': 'v1'})
    stubs['events'].add_response('list_rules', {'Rules': []}, {})
    stubs['cloudwatch'].add_response('describe_alarms', {'MetricAlarms': []}, {'AlarmTypes': ['MetricAlarm']})
    r = _run(_drv(clients), '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == 0 and 'Unable to evaluate' in r[1], r


# --------------------------------------------------------------------------- #
# backupNoRestoreTestingPlan
# --------------------------------------------------------------------------- #
def _rtp(name):
    return {'CreationTime': NOW, 'RestoreTestingPlanArn': f'arn:aws:backup:{REGION}:{ACCT}:restore-testing-plan:{name}',
            'RestoreTestingPlanName': name, 'ScheduleExpression': 'cron(0 5 ? * * *)'}


def test_no_restore_testing_plan_flag_fix(clients):
    _, stubs = clients
    drv = _drv(clients)
    stubs['backup'].add_response('list_restore_testing_plans', {'RestoreTestingPlans': []}, {})
    r = _run(drv, '_checkBackupNoRestoreTestingPlan', 'backupNoRestoreTestingPlan')
    assert r[0] == -1, r

    # A plan with no selection is still a finding.
    stubs['backup'].add_response('list_restore_testing_plans', {'RestoreTestingPlans': [_rtp('weekly')]}, {})
    stubs['backup'].add_response('list_restore_testing_selections', {'RestoreTestingSelections': []},
                                 {'RestoreTestingPlanName': 'weekly'})
    r = _run(drv, '_checkBackupNoRestoreTestingPlan', 'backupNoRestoreTestingPlan')
    assert r[0] == -1 and 'weekly' in r[1], r

    stubs['backup'].add_response('list_restore_testing_plans', {'RestoreTestingPlans': [_rtp('weekly')]}, {})
    stubs['backup'].add_response('list_restore_testing_selections', {'RestoreTestingSelections': [{
        'CreationTime': NOW, 'IamRoleArn': f'arn:aws:iam::{ACCT}:role/r', 'ProtectedResourceType': 'EBS',
        'RestoreTestingPlanName': 'weekly', 'RestoreTestingSelectionName': 'ebs'}]},
        {'RestoreTestingPlanName': 'weekly'})
    r = _run(drv, '_checkBackupNoRestoreTestingPlan', 'backupNoRestoreTestingPlan')
    assert r[0] == 1, r


def test_no_restore_testing_plan_unreadable(clients):
    _, stubs = clients
    _err(stubs['backup'], 'list_restore_testing_plans', 'AccessDeniedException')
    r = _run(_drv(clients), '_checkBackupNoRestoreTestingPlan', 'backupNoRestoreTestingPlan')
    assert r == [0, 'Unable to evaluate (AccessDeniedException)'], r


# --------------------------------------------------------------------------- #
# Plan / vault level branches the emulator cannot create
# --------------------------------------------------------------------------- #
def _planDrv(rules, selections=None, scan=None, vaults=None):
    vaults = vaults or {}

    def lookup(nameOrArn):
        name = nameOrArn.split(':')[-1]
        return (vaults[name], None) if name in vaults else (None, 'vault not found')

    plan = {'_id': 'p1', '_name': 'plan1', '_rules': rules,
            '_selections': selections or [], '_scanSettings': scan or []}
    return BackupPlan(plan, _client('backup'), vaultLookup=lookup, accountId=ACCT, region=REGION)


def test_protected_vault_other_account_is_info_not_fail():
    rules = [{'RuleName': 'r', 'TargetBackupVaultName': 'plain',
              'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('central', acct=OTHER)}]}]
    d = _planDrv(rules, vaults={'plain': {'Locked': False, 'VaultType': 'BACKUP_VAULT'}})
    d._checkBackupPlanNotTargetingProtectedVault()
    assert d.results['backupPlanNotTargetingProtectedVault'][0] == 0

    rules[0]['CopyActions'] = []
    d = _planDrv(rules, vaults={'plain': {'Locked': False, 'VaultType': 'BACKUP_VAULT'}})
    d._checkBackupPlanNotTargetingProtectedVault()
    assert d.results['backupPlanNotTargetingProtectedVault'][0] == -1

    rules[0]['TargetLogicallyAirGappedBackupVaultArn'] = _vaultArn('lag')
    d = _planDrv(rules, vaults={'plain': {'Locked': False, 'VaultType': 'BACKUP_VAULT'}})
    d._checkBackupPlanNotTargetingProtectedVault()
    assert d.results['backupPlanNotTargetingProtectedVault'][0] == 1


def test_retention_copy_and_delete_after_copy():
    key = 'backupRetentionBelowDetectionWindow'
    # Source deleted after copy; copy kept 14 days -> below floor.
    rules = [{'RuleName': 'r', 'TargetBackupVaultName': 'v',
              'Lifecycle': {'DeleteAfterEvent': 'DELETE_AFTER_COPY'},
              'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('dr'), 'Lifecycle': {'DeleteAfterDays': 14}}]}]
    d = _planDrv(rules)
    d._checkBackupRetentionBelowDetectionWindow()
    assert d.results[key][0] == -1, d.results
    # Copy kept 120 days -> fine.
    rules[0]['CopyActions'][0]['Lifecycle']['DeleteAfterDays'] = 120
    d = _planDrv(rules)
    d._checkBackupRetentionBelowDetectionWindow()
    assert d.results[key][0] == 1, d.results
    # Copy without explicit lifecycle and short rule -> not evaluable, never FAIL.
    rules = [{'RuleName': 'r', 'TargetBackupVaultName': 'v', 'Lifecycle': {'DeleteAfterDays': 7},
              'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('dr')}]}]
    d = _planDrv(rules)
    d._checkBackupRetentionBelowDetectionWindow()
    assert d.results[key][0] == 0, d.results
    # DeleteAfterDays -1 == keep forever.
    rules = [{'RuleName': 'r', 'TargetBackupVaultName': 'v', 'Lifecycle': {'DeleteAfterDays': -1}}]
    d = _planDrv(rules)
    d._checkBackupRetentionBelowDetectionWindow()
    assert d.results[key][0] == 1, d.results


def test_retention_vault_lock_without_min():
    v = BackupVault({'_name': 'v', '_locked': True, '_minRetentionDays': None,
                     '_vaultType': 'BACKUP_VAULT'}, _client('backup'))
    v._checkBackupRetentionBelowDetectionWindow()
    assert v.results['backupRetentionBelowDetectionWindow'][0] == -1
    v = BackupVault({'_name': 'v', '_locked': False, '_vaultType': 'BACKUP_VAULT'}, _client('backup'))
    v._checkBackupRetentionBelowDetectionWindow()
    assert v.results['backupRetentionBelowDetectionWindow'][0] == 0


def test_malware_selection_scope():
    key = 'backupMalwareScanDisabled'
    rules = [{'RuleName': 'r', 'TargetBackupVaultName': 'v'}]
    # Tag-only selection: types unknown -> INFO, not FAIL.
    d = _planDrv(rules, selections=[{'SelectionName': 's', 'ListOfTags': [
        {'ConditionType': 'STRINGEQUALS', 'ConditionKey': 'backup', 'ConditionValue': 'yes'}]}])
    d._checkBackupMalwareScanDisabled()
    assert d.results[key][0] == 0
    # Only DynamoDB -> not applicable.
    d = _planDrv(rules, selections=[{'Resources': [f'arn:aws:dynamodb:{REGION}:{ACCT}:table/t']}])
    d._checkBackupMalwareScanDisabled()
    assert d.results[key][0] == 0
    # Wildcard selection covers EC2/EBS/S3 -> FAIL without scanning.
    d = _planDrv(rules, selections=[{'Resources': ['*']}])
    d._checkBackupMalwareScanDisabled()
    assert d.results[key][0] == -1
    # S3 bucket with scanning configured -> PASS.
    d = _planDrv([dict(rules[0], ScanActions=[{'MalwareScanner': 'GUARDDUTY', 'ScanMode': 'FULL_SCAN'}])],
                 selections=[{'Resources': ['arn:aws:s3:::my-bucket']}],
                 scan=[{'MalwareScanner': 'GUARDDUTY', 'ResourceTypes': ['S3'],
                        'ScannerRoleArn': f'arn:aws:iam::{ACCT}:role/s'}])
    d._checkBackupMalwareScanDisabled()
    assert d.results[key][0] == 1


def test_lookup_vault_cross_region_uses_describe():
    """Backup._lookupVault reads same-account vaults in other Regions with
    describe_backup_vault (read-only) and caches the answer."""
    from botocore.config import Config as BConfig
    from services.backup.Backup import Backup

    remote = _client('backup')
    stub = Stubber(remote)
    stub.add_response('describe_backup_vault', {
        'BackupVaultName': 'dr', 'BackupVaultArn': _vaultArn('dr', region='us-west-2'),
        'VaultType': 'BACKUP_VAULT', 'Locked': True, 'MinRetentionDays': 35},
        {'BackupVaultName': 'dr'})
    stub.activate()

    class _Sess:
        def __init__(self):
            self.calls = []

        def client(self, svc, region_name=None, config=None):
            self.calls.append((svc, region_name))
            return remote

    class _Backup(Backup):
        def __del__(self):   # skip Service.__del__ reporting for this bare instance
            pass

    svc = _Backup.__new__(_Backup)
    svc.region, svc.ssBoto, svc.bConfig = REGION, _Sess(), BConfig(region_name=REGION)
    svc._vaultIndex = {'local': {'BackupVaultName': 'local', 'Locked': False}}
    svc._remoteVaultCache, svc._remoteBackupClients = {}, {}

    assert svc._lookupVault('local')[0]['BackupVaultName'] == 'local'
    assert svc._lookupVault(_vaultArn('missing')) == (None, 'vault not found')
    summary, reason = svc._lookupVault(_vaultArn('dr', region='us-west-2'))
    assert reason is None and summary['Locked'] is True
    # Cached - a second API call would make the Stubber raise.
    assert svc._lookupVault(_vaultArn('dr', region='us-west-2'))[0]['Locked'] is True
    assert svc.ssBoto.calls == [('backup', 'us-west-2')]
    stub.assert_no_pending_responses()
    stub.deactivate()

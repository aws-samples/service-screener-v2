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

Every client is a real boto3 client wrapped in an active
botocore.stub.Stubber, so request parameters and response shapes are
validated against the real API model, and an unexpected API call raises
locally instead of being sent anywhere. Clients point at an unroutable
loopback endpoint (https://127.0.0.1:1) as a second safety net: no request
can ever reach a real AWS endpoint.
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


# Never a real AWS endpoint: loopback port 1 (nothing listens there).
SAFE_ENDPOINT = 'https://127.0.0.1:1'
_ACTIVE_STUBS = []


def _rawClient(svc):
    """Real boto3 client on the loopback safety endpoint. The caller must
    wrap it in an active Stubber before use."""
    return boto3.client(svc, region_name=REGION, aws_access_key_id='testing',
                        aws_secret_access_key='testing', aws_session_token='testing',
                        endpoint_url=SAFE_ENDPOINT)


def _client(svc):
    """Client for drivers whose checks under test must not call the API:
    an active Stubber with no queued responses makes any call fail locally."""
    c = _rawClient(svc)
    st = Stubber(c)
    st.activate()
    _ACTIVE_STUBS.append(st)
    return c


@pytest.fixture(autouse=True)
def _deactivateStubs():
    yield
    while _ACTIVE_STUBS:
        _ACTIVE_STUBS.pop().deactivate()


@pytest.fixture
def clients():
    c = {s: _rawClient(s) for s in ('backup', 'events', 'cloudwatch')}
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


def _drv(clients, account=None, vaultLookup=None):
    c, _ = clients
    return BackupAccount(account or _account(), c['backup'],
                         eventsClient=c['events'], cloudwatchClient=c['cloudwatch'],
                         vaultLookup=vaultLookup)


def _lookupFrom(vaults):
    """vaultLookup stand-in for Backup._lookupVault: {arn: summary | 'ERR:code'}."""
    calls = []

    def lookup(arn):
        calls.append(arn)
        v = vaults.get(arn)
        if v is None:
            return None, 'vault not found'
        if isinstance(v, str):
            return None, v[4:]
        return v, None
    lookup.calls = calls
    return lookup


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


def test_restore_validation_timed_out_is_noted_not_failed(clients):
    _, stubs = clients
    stubs['backup'].add_response('list_restore_jobs', {'RestoreJobs': [
        _restore('r5', 'COMPLETED', 'TIMED_OUT')]}, {'ByCreatedAfter': ANY})
    r = _run(_drv(clients), '_checkBackupRestoreJobsFailing', 'backupRestoreJobsFailing')
    assert r[0] == 1 and 'TIMED_OUT' in r[1], r


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
    dr = _vaultArn('dr', region='us-west-2')
    lookup = _lookupFrom({dr: {'BackupVaultName': 'dr', 'VaultType': 'BACKUP_VAULT', 'Locked': False}})
    sameAcct = [{'RuleName': 'r', 'TargetBackupVaultName': 'v1',
                 'CopyActions': [{'DestinationBackupVaultArn': dr}]}]
    r = _run(_drv(clients, _account(plans=[_plan(sameAcct)]), lookup),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == -1, r

    crossAcct = [{'RuleName': 'r', 'TargetBackupVaultName': 'v1',
                  'CopyActions': [{'DestinationBackupVaultArn': _vaultArn('central', acct=OTHER)}]}]
    r = _run(_drv(clients, _account(plans=[_plan(sameAcct), _plan(crossAcct, 'plan2', 'p2')]), lookup),
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


def test_cross_account_copy_other_region_lag_counts_as_isolation(clients):
    """A copy to a same-account logically air-gapped vault in another Region
    is isolation (resolved with the cached describe_backup_vault lookup); a
    same-named standard vault there is not; an unreadable one is not
    evaluable, never a FAIL."""
    vaults = [{'_name': 'v1', '_vaultType': 'BACKUP_VAULT'},
              {'_name': 'lag', '_vaultType': 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'}]
    remote = _vaultArn('lag', region='eu-west-1')
    rules = [{'RuleName': 'r', 'TargetBackupVaultName': 'v1',
              'CopyActions': [{'DestinationBackupVaultArn': remote}]}]
    key, m = 'backupPlanNoCrossAccountCopy', '_checkBackupPlanNoCrossAccountCopy'
    acct = _account(plans=[_plan(rules)], vaults=vaults)

    lookup = _lookupFrom({remote: {'BackupVaultName': 'lag', 'VaultType': 'BACKUP_VAULT'}})
    r = _run(_drv(clients, acct, lookup), m, key)
    assert r[0] == -1 and lookup.calls == [remote], r

    lookup = _lookupFrom({remote: {'BackupVaultName': 'lag',
                                   'VaultType': 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'}})
    r = _run(_drv(clients, acct, lookup), m, key)
    assert r[0] == 1 and 'air-gapped' in r[1], r

    lookup = _lookupFrom({remote: 'ERR:AccessDeniedException'})
    r = _run(_drv(clients, acct, lookup), m, key)
    assert r[0] == 0 and 'AccessDeniedException' in r[1], r
    # No lookup available at all -> not evaluable either.
    r = _run(_drv(clients, acct), m, key)
    assert r[0] == 0, r


def test_unreadable_plan_is_kept_for_account_checks(clients):
    """Backup._discoverPlans keeps a stub for a plan whose get_backup_plan
    fails, so backupPlanNoCrossAccountCopy reports 'Unable to evaluate'
    rather than FAILing on the readable plans alone."""
    from services.backup.Backup import Backup
    client = _rawClient('backup')
    stub = Stubber(client)
    stub.add_response('list_backup_plans', {'BackupPlansList': [
        {'BackupPlanId': 'p1', 'BackupPlanName': 'readable'},
        {'BackupPlanId': 'p2', 'BackupPlanName': 'secret'}]}, {})
    stub.add_response('get_backup_plan', {'BackupPlanId': 'p1', 'BackupPlan': {
        'BackupPlanName': 'readable', 'Rules': [{'RuleName': 'r', 'TargetBackupVaultName': 'v1'}]}},
        {'BackupPlanId': 'p1'})
    stub.add_response('list_backup_selections', {'BackupSelectionsList': []}, {'BackupPlanId': 'p1'})
    _err(stub, 'get_backup_plan', 'AccessDeniedException', {'BackupPlanId': 'p2'})
    svc = type('_BackupDiscovery', (), {
        '_discoverPlans': Backup._discoverPlans, '_describePlan': Backup._describePlan,
        '_listSelections': Backup._listSelections, '_logClientError': Backup._logClientError,
        'registerItems': lambda self, objType, items, idFn=None: list(items),
        'backupClient': client,
    })()
    with stub:
        plans = svc._discoverPlans()
    stub.assert_no_pending_responses()
    assert [p['_name'] for p in plans] == ['readable', 'secret']
    assert plans[1].get('_unreadable') and '_rules' not in plans[1]

    _, stubs = clients
    _err(stubs['backup'], 'get_backup_plan', 'AccessDeniedException', {'BackupPlanId': 'p2'})
    r = _run(_drv(clients, _account(plans=plans)),
             '_checkBackupPlanNoCrossAccountCopy', 'backupPlanNoCrossAccountCopy')
    assert r[0] == 0 and 'secret' in r[1], r


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

    stubs['events'].add_response('list_rules', {'Rules': []}, {})
    stubs['cloudwatch'].add_response('describe_alarms', {'MetricAlarms': []}, {'AlarmTypes': ['MetricAlarm']})
    stubs['backup'].add_response('get_backup_vault_notifications', {
        'BackupVaultName': 'v1', 'SNSTopicArn': f'arn:aws:sns:{REGION}:{ACCT}:backup-alerts',
        'BackupVaultEvents': ['BACKUP_JOB_FAILED', 'COPY_JOB_FAILED']}, {'BackupVaultName': 'v1'})
    r = _run(drv, '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == 1 and 'vault notifications' in r[1], r
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_no_failure_alerting_fix_eventbridge(clients):
    _, stubs = clients
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
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_no_failure_alerting_eventbridge_rule_must_match_failures(clients):
    """Enabled aws.backup rules that cannot match a failed job event
    (COMPLETED-only state filter, plan/vault change detail-types) are not
    failure alerting."""
    _, stubs = clients
    stubs['events'].add_response('list_rules', {'Rules': [
        {'Name': 'completed-only', 'State': 'ENABLED', 'EventBusName': 'default',
         'EventPattern': '{"source":["aws.backup"],"detail-type":["Backup Job State Change"],'
                         '"detail":{"state":["COMPLETED"]}}'},
        {'Name': 'plan-changes', 'State': 'ENABLED', 'EventBusName': 'default',
         'EventPattern': '{"source":["aws.backup"],"detail-type":["Backup Plan State Change"]}'},
        {'Name': 'not-failed', 'State': 'ENABLED', 'EventBusName': 'default',
         'EventPattern': '{"source":["aws.backup"],"detail":{"state":[{"anything-but":'
                         '["FAILED","ABORTED","EXPIRED"]}]}}'}]}, {})
    stubs['cloudwatch'].add_response('describe_alarms', {'MetricAlarms': []}, {'AlarmTypes': ['MetricAlarm']})
    _err(stubs['backup'], 'get_backup_vault_notifications', 'ResourceNotFoundException',
         {'BackupVaultName': 'v1'})
    r = _run(_drv(clients), '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == -1, r

    # Fix: a rule whose state filter admits FAILED (anything-but COMPLETED).
    stubs['events'].add_response('list_rules', {'Rules': [
        {'Name': 'not-completed', 'State': 'ENABLED', 'EventBusName': 'default',
         'EventPattern': '{"source":["aws.backup"],"detail-type":["Copy Job State Change"],'
                         '"detail":{"state":[{"anything-but":"COMPLETED"}]}}'}]}, {})
    stubs['events'].add_response('list_targets_by_rule', {'Targets': [
        {'Id': '1', 'Arn': f'arn:aws:sns:{REGION}:{ACCT}:t'}]},
        {'Rule': 'not-completed', 'EventBusName': 'default'})
    r = _run(_drv(clients), '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == 1 and 'not-completed' in r[1], r
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_no_failure_alerting_vault_notifications_must_cover_every_target_vault(clients):
    """One notifying vault does not cover jobs written to another vault;
    vaults no backup rule writes to are not required to notify."""
    _, stubs = clients
    vaults = [{'_name': n, '_vaultType': 'BACKUP_VAULT'} for n in ('v1', 'v2', 'unused')]
    plans = [_plan([{'RuleName': 'a', 'TargetBackupVaultName': 'v1'},
                    {'RuleName': 'b', 'TargetBackupVaultName': 'v2'}])]
    notif = {'BackupVaultName': 'v1', 'SNSTopicArn': f'arn:aws:sns:{REGION}:{ACCT}:t',
             'BackupVaultEvents': ['BACKUP_JOB_FAILED']}

    def accountWide():
        stubs['events'].add_response('list_rules', {'Rules': []}, {})
        stubs['cloudwatch'].add_response('describe_alarms', {'MetricAlarms': []},
                                         {'AlarmTypes': ['MetricAlarm']})

    accountWide()
    stubs['backup'].add_response('get_backup_vault_notifications', notif, {'BackupVaultName': 'v1'})
    _err(stubs['backup'], 'get_backup_vault_notifications', 'ResourceNotFoundException',
         {'BackupVaultName': 'v2'})
    r = _run(_drv(clients, _account(plans=plans, vaults=vaults)),
             '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == -1 and 'v2' in r[1], r

    accountWide()
    stubs['backup'].add_response('get_backup_vault_notifications', notif, {'BackupVaultName': 'v1'})
    stubs['backup'].add_response('get_backup_vault_notifications', dict(notif, BackupVaultName='v2'),
                                 {'BackupVaultName': 'v2'})
    r = _run(_drv(clients, _account(plans=plans, vaults=vaults)),
             '_checkBackupNoFailureAlerting', 'backupNoFailureAlerting')
    assert r[0] == 1, r
    for s in stubs.values():
        s.assert_no_pending_responses()


def test_no_failure_alerting_fix_cloudwatch_alarm(clients):
    _, stubs = clients
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

    remote = _rawClient('backup')
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


# --------------------------------------------------------------------------- #
# backupVaultNoAccessPolicy (public policy) - unreadable-policy path and
# policy shapes the emulator does not reject but are worth pinning down.
# The AccessDenied branch of get_backup_vault_access_policy cannot be produced
# on the emulator (it has no IAM enforcement), so it is driven here through
# Backup._describeVault with a stubbed client.
# --------------------------------------------------------------------------- #
def _describeVaultWithPolicy(policyOrCode, mpaTeam=None, vaultType='BACKUP_VAULT'):
    from services.backup.Backup import Backup
    client = _rawClient('backup')
    stub = Stubber(client)
    desc = {'BackupVaultName': 'v1', 'BackupVaultArn': _vaultArn('v1'), 'VaultType': vaultType,
            'NumberOfRecoveryPoints': 0, 'Locked': False}
    if mpaTeam:
        desc['MpaApprovalTeamArn'] = mpaTeam
    stub.add_response('describe_backup_vault', desc, {'BackupVaultName': 'v1'})
    if isinstance(policyOrCode, str) and policyOrCode.startswith('ERR:'):
        _err(stub, 'get_backup_vault_access_policy', policyOrCode[4:], {'BackupVaultName': 'v1'})
    else:
        stub.add_response('get_backup_vault_access_policy',
                          {'BackupVaultName': 'v1', 'BackupVaultArn': _vaultArn('v1'),
                           'Policy': policyOrCode}, {'BackupVaultName': 'v1'})
    stub.add_response('list_recovery_points_by_backup_vault', {'RecoveryPoints': []},
                      {'BackupVaultName': 'v1', 'MaxResults': ANY})
    # Borrow the discovery methods without constructing a Service (whose
    # __init__/__del__ touch global scan state).
    svc = type('_BackupDiscovery', (), {
        'RECOVERY_POINT_SAMPLE_LIMIT': Backup.RECOVERY_POINT_SAMPLE_LIMIT,
        '_describeVault': Backup._describeVault,
        '_listRecoveryPoints': Backup._listRecoveryPoints,
        '_logClientError': Backup._logClientError,
        'backupClient': client,
    })()
    with stub:
        detail = svc._describeVault('v1', {'BackupVaultName': 'v1'})
    stub.assert_no_pending_responses()
    return detail


def _vaultResult(detail, method, key):
    d = BackupVault(detail, _client('backup'))
    getattr(d, method)()
    return d.results.get(key)


def _pol(stmt):
    import json
    return json.dumps({'Version': '2012-10-17', 'Statement': stmt})


def test_vault_policy_public_flag_fix_stub():
    key, m = 'backupVaultNoAccessPolicy', '_checkBackupVaultNoAccessPolicy'
    public = {'Effect': 'Allow', 'Principal': '*', 'Action': 'backup:*', 'Resource': '*'}
    assert _vaultResult(_describeVaultWithPolicy(_pol([public])), m, key)[0] == -1
    scoped = dict(public, Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-abc123'}})
    assert _vaultResult(_describeVaultWithPolicy(_pol([scoped])), m, key)[0] == 1


def test_vault_policy_public_variants_flag():
    key, m = 'backupVaultNoAccessPolicy', '_checkBackupVaultNoAccessPolicy'
    base = {'Effect': 'Allow', 'Action': 'backup:CopyIntoBackupVault', 'Resource': '*'}
    flagged = [
        dict(base, NotPrincipal={'AWS': f'arn:aws:iam::{ACCT}:root'}),
        dict(base, Principal={'AWS': ['*']},
             Condition={'StringLike': {'aws:PrincipalOrgID': '*'}}),
        dict(base, Principal={'AWS': '*'},
             Condition={'StringNotEquals': {'aws:PrincipalAccount': OTHER}}),
    ]
    for stmt in flagged:
        assert _vaultResult(_describeVaultWithPolicy(_pol([stmt])), m, key)[0] == -1, stmt
    # Deny-only policy with wildcard principal is not public.
    deny = {'Effect': 'Deny', 'Principal': '*', 'Action': 'backup:DeleteRecoveryPoint', 'Resource': '*'}
    assert _vaultResult(_describeVaultWithPolicy(_pol([deny])), m, key)[0] == 1


def test_vault_policy_unreadable_is_not_fail():
    r = _vaultResult(_describeVaultWithPolicy('ERR:AccessDeniedException'),
                     '_checkBackupVaultNoAccessPolicy', 'backupVaultNoAccessPolicy')
    assert r[0] == 0 and 'Unable to evaluate (AccessDeniedException)' in r[1]
    r = _vaultResult(_describeVaultWithPolicy('ERR:ResourceNotFoundException'),
                     '_checkBackupVaultNoAccessPolicy', 'backupVaultNoAccessPolicy')
    assert r[0] == -1


# --------------------------------------------------------------------------- #
# airGappedVaultNoMpa (also covered end to end on the emulator)
# --------------------------------------------------------------------------- #
def test_air_gapped_vault_no_mpa_stub():
    lag = 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'
    key, m = 'airGappedVaultNoMpa', '_checkAirGappedVaultNoMpa'
    assert _vaultResult(_describeVaultWithPolicy('ERR:ResourceNotFoundException', vaultType=lag),
                        m, key)[0] == -1
    team = f'arn:aws:mpa:{REGION}:{ACCT}:approval-team/t1'
    assert _vaultResult(_describeVaultWithPolicy('ERR:ResourceNotFoundException', mpaTeam=team,
                                                 vaultType=lag), m, key)[0] == 1
    # Standard vault: MPA not applicable -> no result row at all.
    assert _vaultResult(_describeVaultWithPolicy('ERR:ResourceNotFoundException'), m, key) is None


# --------------------------------------------------------------------------- #
# backupAuditFrameworkMissing - the emulator does not implement
# list_report_plans, and cannot produce FAILED deployments or paginated
# list_frameworks responses.
# --------------------------------------------------------------------------- #
def _fw(name, status):
    return {'FrameworkName': name, 'FrameworkArn': f'arn:aws:backup:{REGION}:{ACCT}:framework:{name}-x',
            'NumberOfControls': 1, 'CreationTime': NOW, 'DeploymentStatus': status}


def test_audit_framework_missing_flag_fix(clients):
    _, stubs = clients
    key, m = 'backupAuditFrameworkMissing', '_checkBackupAuditFrameworkMissing'
    stubs['backup'].add_response('list_frameworks', {'Frameworks': []}, {})
    assert _run(_drv(clients), m, key)[0] == -1
    # A framework whose deployment failed does not evaluate anything.
    stubs['backup'].add_response('list_frameworks', {'Frameworks': [_fw('f1', 'FAILED')]}, {})
    r = _run(_drv(clients), m, key)
    assert r[0] == -1 and 'FAILED' in r[1]
    # Fix: deployed framework on the second page.
    stubs['backup'].add_response('list_frameworks',
                                 {'Frameworks': [_fw('f1', 'FAILED')], 'NextToken': 't'}, {})
    stubs['backup'].add_response('list_frameworks', {'Frameworks': [_fw('f2', 'COMPLETED')]},
                                 {'NextToken': 't'})
    stubs['backup'].add_response('list_report_plans', {'ReportPlans': []}, {})
    r = _run(_drv(clients), m, key)
    assert r[0] == 1 and 'f2' in r[1]


def test_audit_framework_unreadable_and_no_plans(clients):
    _, stubs = clients
    key, m = 'backupAuditFrameworkMissing', '_checkBackupAuditFrameworkMissing'
    _err(stubs['backup'], 'list_frameworks', 'AccessDeniedException', {})
    r = _run(_drv(clients), m, key)
    assert r[0] == 0 and 'Unable to evaluate' in r[1]
    assert _run(_drv(clients, _account(plans=[])), m, key)[0] == 0

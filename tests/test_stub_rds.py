"""Stubber-based flag -> fix tests for RDS paths the AWS Emulator cannot exercise.

Why not the emulator:
- describe_db_snapshot_attributes is NotImplemented in the emulator, so instance
  snapshot sharing (rdsSnapshotSharedExternally) is driven here with real boto3 clients
  wrapped by botocore.stub.Stubber (real API shapes). Cluster snapshot sharing is covered
  by tests/emulator/test_emu_rds.py.
- The emulator never populates instance-level EnabledCloudwatchLogsExports and returns no
  MARIADB_AUDIT_PLUGIN option groups, so the instance and MySQL/MariaDB audit-plugin paths of
  rdsLogExportsDisabled are driven here.
- The emulator always returns rds.force_ssl with a value, so the unset / engine-default path
  of MSSQLorPG__TransportEncrpytionDisabled is driven here.
- Org-account caching and AWS Backup snapshot listing use Stubber to assert exact API calls. The driver constructor (engine-version, CA and
  parameter lookups) is bypassed; only the check method under test runs.
No network calls are made: Stubber intercepts every request.
"""
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.rds.drivers.RdsSnapshot import RdsSnapshot  # noqa: E402
from services.rds.drivers.RdsMariadb import RdsMariadb  # noqa: E402
from services.rds.drivers.RdsPostgres import RdsPostgres  # noqa: E402
from services.rds.drivers.RdsMssql import RdsMssql  # noqa: E402
from services.rds.Rds import Rds  # noqa: E402

ACCT = '123456789012'
OTHER = '111122223333'


def _client():
    return boto3.client('rds', region_name='us-east-1', aws_access_key_id='testing',
                        aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')


def _snapAttrs(values):
    return {'DBSnapshotAttributesResult': {'DBSnapshotIdentifier': 'snap1',
                                           'DBSnapshotAttributes': [{'AttributeName': 'restore',
                                                                     'AttributeValues': values}]}}


def _runShared(values, orgAccounts=None, error=None, coveredInstances=None):
    rds = _client()
    with Stubber(rds) as st:
        if error:
            st.add_client_error('describe_db_snapshot_attributes', service_error_code=error)
        else:
            st.add_response('describe_db_snapshot_attributes', _snapAttrs(values), {'DBSnapshotIdentifier': 'snap1'})
        d = RdsSnapshot({'DBSnapshotIdentifier': 'snap1', 'DBInstanceIdentifier': 'db1', 'Engine': 'postgres',
                         'Encrypted': True}, False, rds, ACCT, orgAccounts, coveredInstances, None)
        d._checkRdsSnapshotSharedExternally()
        st.assert_no_pending_responses()
    return d.results['rdsSnapshotSharedExternally']


def test_instance_snapshot_shared_flag_fix():
    assert _runShared([OTHER, ACCT])[0] == -1            # misconfigured: restorable by another account
    assert _runShared([])[0] == 1                        # fixed: share removed


def test_instance_snapshot_shared_inside_org_not_flagged():
    assert _runShared([OTHER], orgAccounts={ACCT, OTHER})[0] == 1
    assert _runShared([OTHER, '999999999999'], orgAccounts={ACCT, OTHER})[0] == -1


def test_instance_snapshot_public_flag_fix():
    # SnapshotRDSIsPublic only covers snapshots of DBs that still exist, so a
    # public snapshot must fail here (regression: it used to PASS).
    res = _runShared(['all'])
    assert res[0] == -1 and 'Public' in res[1]
    res = _runShared(['all', OTHER], orgAccounts={ACCT})
    assert res[0] == -1 and OTHER in res[1]
    assert _runShared([ACCT])[0] == 1                    # fixed: public access removed


def test_instance_snapshot_public_live_source_not_duplicated():
    # Source DB still exists and SnapshotRDSIsPublic evaluates it: the public
    # snapshot is reported there only, not a second time under this key.
    res = _runShared(['all'], coveredInstances={'db1'})
    assert res[0] == 0 and 'SnapshotRDSIsPublic' in res[1]
    # a specific external account is still this check's own finding
    res = _runShared(['all', OTHER], orgAccounts={ACCT}, coveredInstances={'db1'})
    assert res[0] == -1 and OTHER in res[1] and 'Public:' not in res[1]
    # a different (deleted) source is not covered -> still FAIL
    assert _runShared(['all'], coveredInstances={'other-db'})[0] == -1


def _runClusterShared(values, engine, coveredClusters):
    rds = _client()
    with Stubber(rds) as st:
        st.add_response('describe_db_cluster_snapshot_attributes',
                        {'DBClusterSnapshotAttributesResult': {
                            'DBClusterSnapshotIdentifier': 'csnap1',
                            'DBClusterSnapshotAttributes': [{'AttributeName': 'restore', 'AttributeValues': values}]}},
                        {'DBClusterSnapshotIdentifier': 'csnap1'})
        d = RdsSnapshot({'DBClusterSnapshotIdentifier': 'csnap1', 'DBClusterIdentifier': 'cl1', 'Engine': engine,
                         'StorageEncrypted': True}, True, rds, ACCT, None, None, coveredClusters)
        d._checkRdsSnapshotSharedExternally()
        st.assert_no_pending_responses()
    return d.results['rdsSnapshotSharedExternally']


def test_cluster_snapshot_public_dedup_aurora_vs_multiaz():
    # Aurora cluster still evaluated by SnapshotRDSIsPublic -> not duplicated
    assert _runClusterShared(['all'], 'aurora-postgresql', {'cl1'})[0] == 0
    # Multi-AZ DB cluster snapshot (non-Aurora engine): SnapshotRDSIsPublic never
    # looks at it, even though the cluster exists -> FAIL here, then fix
    assert _runClusterShared(['all'], 'postgres', {'cl1'})[0] == -1
    assert _runClusterShared([], 'postgres', {'cl1'})[0] == 1


def test_awsbackup_snapshot_unencrypted_flag_fix_and_not_shared_checked():
    # AWS Backup-managed DB snapshots are evaluated for encryption; they cannot
    # be shared directly, so no attribute call / sharing result.
    rds = _client()
    with Stubber(rds) as st:
        d = RdsSnapshot({'DBSnapshotIdentifier': 'awsbackup:job-1', 'SnapshotType': 'awsbackup', 'Encrypted': False},
                        False, rds, ACCT)
        d._checkRdsSnapshotSharedExternally()
        d._checkRdsSnapshotUnencrypted()
        st.assert_no_pending_responses()
    assert 'rdsSnapshotSharedExternally' not in d.results
    assert d.results['rdsSnapshotUnencrypted'][0] == -1
    d = RdsSnapshot({'DBSnapshotIdentifier': 'awsbackup:job-2', 'SnapshotType': 'awsbackup', 'Encrypted': True},
                    False, None, ACCT)
    d._checkRdsSnapshotUnencrypted()
    assert d.results['rdsSnapshotUnencrypted'][0] == 1


class _RdsNoInit(Rds):
    # Bypass Service.__init__ (session/config) and its reporting __del__.
    def __del__(self):
        pass


def _rdsService(rdsClient, orgClient=None):
    o = object.__new__(_RdsNoInit)
    o.rdsClient = rdsClient
    o.orgClient = orgClient
    o.tags = None
    return o


def test_get_manual_snapshots_includes_awsbackup():
    rds = _client()
    with Stubber(rds) as st:
        st.add_response('describe_db_snapshots', {'DBSnapshots': [{'DBSnapshotIdentifier': 'm1', 'Engine': 'mysql'}]},
                        {'SnapshotType': 'manual'})
        st.add_response('describe_db_snapshots',
                        {'DBSnapshots': [{'DBSnapshotIdentifier': 'awsbackup:job-1', 'Engine': 'postgres',
                                          'SnapshotType': 'awsbackup'}]},
                        {'SnapshotType': 'awsbackup'})
        st.add_response('describe_db_cluster_snapshots',
                        {'DBClusterSnapshots': [{'DBClusterSnapshotIdentifier': 'c1', 'Engine': 'aurora-mysql'},
                                                {'DBClusterSnapshotIdentifier': 'd1', 'Engine': 'docdb'}]},
                        {'SnapshotType': 'manual'})
        snaps = _rdsService(rds).getManualSnapshots()
        st.assert_no_pending_responses()
    names = sorted(s.get('DBSnapshotIdentifier') or s.get('DBClusterSnapshotIdentifier') for s, _ in snaps)
    assert names == ['awsbackup:job-1', 'c1', 'm1']


def test_get_org_accounts_cached_per_account():
    org = boto3.client('organizations', region_name='us-east-1', aws_access_key_id='testing',
                       aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')
    with Stubber(org) as st:
        st.add_response('list_accounts', {'Accounts': [{'Id': ACCT}, {'Id': OTHER}]}, {})
        svc = _rdsService(None, org)
        assert svc.getOrgAccounts(ACCT) == {ACCT, OTHER}
        assert svc.getOrgAccounts(ACCT) == {ACCT, OTHER}    # second region: no API call
        st.assert_no_pending_responses()
    with Stubber(org) as st:
        st.add_client_error('list_accounts', service_error_code='AWSOrganizationsNotInUseException')
        svc = _rdsService(None, org)
        assert svc.getOrgAccounts(OTHER) is None
        assert svc.getOrgAccounts(OTHER) is None            # failure cached too
        st.assert_no_pending_responses()


def test_instance_snapshot_shared_unreadable_is_info():
    assert _runShared(None, error='AccessDenied') == [0, 'Unable to evaluate (AccessDenied)']


def test_instance_snapshot_unencrypted_flag_fix():
    d = RdsSnapshot({'DBSnapshotIdentifier': 's', 'Encrypted': False}, False, None, ACCT)
    d._checkRdsSnapshotUnencrypted()
    assert d.results['rdsSnapshotUnencrypted'][0] == -1
    d = RdsSnapshot({'DBSnapshotIdentifier': 's', 'Encrypted': True}, False, None, ACCT)
    d._checkRdsSnapshotUnencrypted()
    assert d.results['rdsSnapshotUnencrypted'][0] == 1


def _driver(cls, engine, db, rdsClient=None, params=None):
    d = object.__new__(cls)
    d.init()
    d.db = db
    d.rdsClient = rdsClient or _client()
    d.isCluster = 'DBInstanceIdentifier' not in db
    d._resourceName = db.get('DBInstanceIdentifier') or db.get('DBClusterIdentifier')
    d.dbParams = params or {}
    d.setEngine(engine)
    return d


@pytest.fixture(autouse=True)
def _config():
    Config.init()


def test_postgres_instance_log_exports_flag_fix():
    d = _driver(RdsPostgres, 'postgres', {'DBInstanceIdentifier': 'pg1', 'Engine': 'postgres'})
    d._checkRdsLogExportsDisabled()
    assert d.results['rdsLogExportsDisabled'][0] == -1
    d = _driver(RdsPostgres, 'postgres', {'DBInstanceIdentifier': 'pg1', 'Engine': 'postgres',
                                          'EnabledCloudwatchLogsExports': ['postgresql', 'upgrade']})
    d._checkRdsLogExportsDisabled()
    assert d.results['rdsLogExportsDisabled'][0] == 1


def test_cluster_member_instance_is_evaluated_on_cluster():
    d = _driver(RdsPostgres, 'aurora-postgresql', {'DBInstanceIdentifier': 'apg1', 'Engine': 'aurora-postgresql',
                                                   'DBClusterIdentifier': 'apg'})
    d._checkRdsLogExportsDisabled()
    d._checkRdsSecureTransportNotRequired()
    assert d.results == {}


def _mariadbWithAudit(exports):
    rds = _client()
    db = {'DBInstanceIdentifier': 'mdb1', 'Engine': 'mariadb', 'EnabledCloudwatchLogsExports': exports,
          'OptionGroupMemberships': [{'OptionGroupName': 'og-audit', 'Status': 'in-sync'}]}
    with Stubber(rds) as st:
        st.add_response('describe_option_groups',
                        {'OptionGroupsList': [{'OptionGroupName': 'og-audit',
                                               'Options': [{'OptionName': 'MARIADB_AUDIT_PLUGIN'}]}]},
                        {'OptionGroupName': 'og-audit'})
        d = _driver(RdsMariadb, 'mariadb', db, rds)
        d._checkRdsLogExportsDisabled()
    return d.results['rdsLogExportsDisabled']


def test_mariadb_audit_plugin_requires_audit_export_flag_fix():
    res = _mariadbWithAudit(['error'])
    assert res[0] == -1 and 'audit' in res[1]
    assert _mariadbWithAudit(['error', 'audit'])[0] == 1


def _mariadbOptionGroupDenied(exports):
    rds = _client()
    db = {'DBInstanceIdentifier': 'mdb2', 'Engine': 'mariadb', 'EnabledCloudwatchLogsExports': exports,
          'OptionGroupMemberships': [{'OptionGroupName': 'og-x', 'Status': 'in-sync'}]}
    with Stubber(rds) as st:
        st.add_client_error('describe_option_groups', service_error_code='AccessDenied')
        d = _driver(RdsMariadb, 'mariadb', db, rds)
        d._checkRdsLogExportsDisabled()
    return d.results['rdsLogExportsDisabled']


def test_mariadb_option_group_unreadable_is_not_a_pass():
    # error log missing is a definite FAIL regardless of the audit plugin
    assert _mariadbOptionGroupDenied([])[0] == -1
    # error exported but audit requirement unknown -> not evaluable, never PASS
    assert _mariadbOptionGroupDenied(['error'])[0] == 0
    assert 'AccessDenied' in _mariadbOptionGroupDenied(['error'])[1]
    # both exported -> requirement met whatever the plugin status
    assert _mariadbOptionGroupDenied(['error', 'audit'])[0] == 1


def test_mariadb_secure_transport_flag_fix():
    db = {'DBInstanceIdentifier': 'mdb3', 'Engine': 'mariadb', 'EngineVersion': '10.11.9'}
    d = _driver(RdsMariadb, 'mariadb', db, params={})
    d._checkRdsSecureTransportNotRequired()
    assert d.results['rdsSecureTransportNotRequired'][0] == -1
    d = _driver(RdsMariadb, 'mariadb', db, params={'require_secure_transport': 'ON'})
    d._checkRdsSecureTransportNotRequired()
    assert d.results['rdsSecureTransportNotRequired'][0] == 1


def _secureTransport(engine, version, params):
    db = {'DBInstanceIdentifier': 'mdbv', 'Engine': engine, 'EngineVersion': version}
    d = _driver(RdsMariadb, engine, db, params=params)
    d._checkRdsSecureTransportNotRequired()
    return d.results['rdsSecureTransportNotRequired']


def test_mariadb_secure_transport_version_aware_default():
    # 10.5 - 11.4: default OFF -> unset flags, ON fixes
    assert _secureTransport('mariadb', '11.4.5', {})[0] == -1
    assert _secureTransport('mariadb', '10.6.20', {})[0] == -1
    assert _secureTransport('mariadb', '10.6.20', {'require_secure_transport': '1'})[0] == 1
    # 11.8+: default ON -> unset is a PASS, explicit OFF flags
    assert _secureTransport('mariadb', '11.8.3', {})[0] == 1
    assert _secureTransport('mariadb', '11.8.3', {'require_secure_transport': 'OFF'})[0] == -1
    # < 10.5: parameter not supported -> not evaluable
    assert _secureTransport('mariadb', '10.4.34', {})[0] == 0
    # MySQL default OFF for every version
    assert _secureTransport('mysql', '8.4.3', {})[0] == -1


def test_mysql_general_log_only_flags_when_enabled():
    db = {'DBInstanceIdentifier': 'my1', 'Engine': 'mysql'}
    d = _driver(RdsMariadb, 'mysql', db, params={'general_log': '1'})
    d._checkEnableLogs()
    assert d.results['MYSQL__LogsGeneral'][0] == -1
    d = _driver(RdsMariadb, 'mysql', db, params={'general_log': '0'})
    d._checkEnableLogs()
    assert 'MYSQL__LogsGeneral' not in d.results


def _forceSsl(cls, engine, version, params, member=False):
    db = {'Engine': engine, 'EngineVersion': version}
    if engine.startswith('aurora') and not member:
        db['DBClusterIdentifier'] = 'cl'
    else:
        db['DBInstanceIdentifier'] = 'i1'
        if member:
            db['DBClusterIdentifier'] = 'cl'
    d = _driver(cls, engine, db, params=params)
    d._checkSSLParams()
    return d.results.get('MSSQLorPG__TransportEncrpytionDisabled')


def test_force_ssl_unset_uses_documented_engine_default():
    # The emulator always returns rds.force_ssl with a value, so the unset path
    # (parameter not returned) is driven here.
    # RDS for PostgreSQL: default 0 for 14 and older -> FAIL; fix by setting 1
    assert _forceSsl(RdsPostgres, 'postgres', '14.12', {})[0] == -1
    assert _forceSsl(RdsPostgres, 'postgres', '14.12', {'rds.force_ssl': '1'})[0] == 1
    assert _forceSsl(RdsPostgres, 'postgres', '15.8', {})[0] == 1
    assert _forceSsl(RdsPostgres, 'postgres', '16.4', {'rds.force_ssl': '0'})[0] == -1
    # Aurora PostgreSQL cluster: default 0 for 16 and older, 1 for 17+
    assert _forceSsl(RdsPostgres, 'aurora-postgresql', '16.6', {})[0] == -1
    assert _forceSsl(RdsPostgres, 'aurora-postgresql', '16.6', {'rds.force_ssl': '1'})[0] == 1
    assert _forceSsl(RdsPostgres, 'aurora-postgresql', '17.4', {})[0] == 1
    # Aurora member instance: evaluated on the cluster parameter group instead
    assert _forceSsl(RdsPostgres, 'aurora-postgresql', '16.6', {}, member=True) is None
    # SQL Server unset: not evaluable, never a silent PASS
    assert _forceSsl(RdsMssql, 'sqlserver', '16.00.4135.4.v1', {})[0] == 0
    assert _forceSsl(RdsMssql, 'sqlserver', '16.00.4135.4.v1', {'rds.force_ssl': '0'})[0] == -1

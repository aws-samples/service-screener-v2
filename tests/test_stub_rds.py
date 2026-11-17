"""Stubber-based flag -> fix tests for RDS paths the AWS Emulator cannot exercise.

Why not the emulator:
- describe_db_snapshot_attributes is NotImplemented in the emulator, so instance
  snapshot sharing (rdsSnapshotSharedExternally) is driven here with real boto3 clients
  wrapped by botocore.stub.Stubber (real API shapes). Cluster snapshot sharing is covered
  by tests/emulator/test_emu_rds.py.
- The emulator never populates instance-level EnabledCloudwatchLogsExports and returns no
  MARIADB_AUDIT_PLUGIN option groups, so the instance and MySQL/MariaDB audit-plugin paths of
  rdsLogExportsDisabled are driven here. The driver constructor (engine-version, CA and
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

ACCT = '123456789012'
OTHER = '111122223333'


def _client():
    return boto3.client('rds', region_name='us-east-1', aws_access_key_id='testing',
                        aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')


def _snapAttrs(values):
    return {'DBSnapshotAttributesResult': {'DBSnapshotIdentifier': 'snap1',
                                           'DBSnapshotAttributes': [{'AttributeName': 'restore',
                                                                     'AttributeValues': values}]}}


def _runShared(values, orgAccounts=None, error=None):
    rds = _client()
    with Stubber(rds) as st:
        if error:
            st.add_client_error('describe_db_snapshot_attributes', service_error_code=error)
        else:
            st.add_response('describe_db_snapshot_attributes', _snapAttrs(values), {'DBSnapshotIdentifier': 'snap1'})
        d = RdsSnapshot({'DBSnapshotIdentifier': 'snap1', 'Encrypted': True}, False, rds, ACCT, orgAccounts)
        d._checkRdsSnapshotSharedExternally()
        st.assert_no_pending_responses()
    return d.results['rdsSnapshotSharedExternally']


def test_instance_snapshot_shared_flag_fix():
    assert _runShared([OTHER, ACCT])[0] == -1            # misconfigured: restorable by another account
    assert _runShared([])[0] == 1                        # fixed: share removed


def test_instance_snapshot_shared_inside_org_not_flagged():
    assert _runShared([OTHER], orgAccounts={ACCT, OTHER})[0] == 1
    assert _runShared([OTHER, '999999999999'], orgAccounts={ACCT, OTHER})[0] == -1


def test_instance_snapshot_public_only_left_to_existing_check():
    assert _runShared(['all'])[0] == 1                   # reported by SnapshotRDSIsPublic


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


def test_mariadb_option_group_unreadable_still_requires_error_log():
    rds = _client()
    db = {'DBInstanceIdentifier': 'mdb2', 'Engine': 'mariadb', 'EnabledCloudwatchLogsExports': ['error'],
          'OptionGroupMemberships': [{'OptionGroupName': 'og-x', 'Status': 'in-sync'}]}
    with Stubber(rds) as st:
        st.add_client_error('describe_option_groups', service_error_code='AccessDenied')
        d = _driver(RdsMariadb, 'mariadb', db, rds)
        d._checkRdsLogExportsDisabled()
    assert d.results['rdsLogExportsDisabled'][0] == 1


def test_mariadb_secure_transport_flag_fix():
    db = {'DBInstanceIdentifier': 'mdb3', 'Engine': 'mariadb'}
    d = _driver(RdsMariadb, 'mariadb', db, params={})
    d._checkRdsSecureTransportNotRequired()
    assert d.results['rdsSecureTransportNotRequired'][0] == -1
    d = _driver(RdsMariadb, 'mariadb', db, params={'require_secure_transport': 'ON'})
    d._checkRdsSecureTransportNotRequired()
    assert d.results['rdsSecureTransportNotRequired'][0] == 1


def test_mysql_general_log_only_flags_when_enabled():
    db = {'DBInstanceIdentifier': 'my1', 'Engine': 'mysql'}
    d = _driver(RdsMariadb, 'mysql', db, params={'general_log': '1'})
    d._checkEnableLogs()
    assert d.results['MYSQL__LogsGeneral'][0] == -1
    d = _driver(RdsMariadb, 'mysql', db, params={'general_log': '0'})
    d._checkEnableLogs()
    assert 'MYSQL__LogsGeneral' not in d.results

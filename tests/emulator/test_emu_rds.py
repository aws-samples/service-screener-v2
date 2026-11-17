"""Flag -> fix -> re-run tests for the WAFS2027 RDS checks against the local AWS Emulator.

Emulator gaps (covered by tests/test_stub_rds.py instead):
- Instance-level EnabledCloudwatchLogsExports is never populated (create/modify ignored),
  so rdsLogExportsDisabled is tested here on Aurora clusters only.
- describe_db_snapshot_attributes / modify_db_snapshot_attribute are NotImplemented, so
  rdsSnapshotSharedExternally is tested here on DB cluster snapshots only.
"""
import pytest

from tests.emulator.conftest import assertFlagFixCycle

PWD = 'Passw0rd!123456'
WAIT = {'Delay': 2, 'MaxAttempts': 90}


@pytest.fixture
def sg(emu, uid):
    # Every DB must reference a real SG: Rds.advise() describes them.
    ec2 = emu.client('ec2')
    gid = ec2.create_security_group(GroupName=f'ss-rds-sg-{uid}', Description='ss test')['GroupId']
    yield gid
    try:
        ec2.delete_security_group(GroupId=gid)
    except Exception:
        pass


def _quiet(fn, **kw):
    try:
        fn(**kw)
    except Exception:
        pass


def _createInstance(rds, name, sg, engine='postgres', **kw):
    rds.create_db_instance(DBInstanceIdentifier=name, Engine=engine, DBInstanceClass='db.t3.micro',
                           MasterUsername='ssuser', MasterUserPassword=PWD, AllocatedStorage=20,
                           VpcSecurityGroupIds=[sg], **kw)
    rds.get_waiter('db_instance_available').wait(DBInstanceIdentifier=name, WaiterConfig=WAIT)


def _deleteInstance(rds, name):
    _quiet(rds.delete_db_instance, DBInstanceIdentifier=name, SkipFinalSnapshot=True)
    _quiet(rds.get_waiter('db_instance_deleted').wait, DBInstanceIdentifier=name, WaiterConfig=WAIT)


CLUSTER_FAMILY = {'aurora-postgresql': 'aurora-postgresql17', 'aurora-mysql': 'aurora-mysql8.0'}


def _createCluster(rds, name, sg, engine='aurora-postgresql', **kw):
    # The emulator has no default.* cluster parameter groups (real AWS does),
    # so give each cluster its own group unless the test supplies one.
    if 'DBClusterParameterGroupName' not in kw:
        cpg = name + '-cpg'
        rds.create_db_cluster_parameter_group(DBClusterParameterGroupName=cpg, Description='ss test',
                                              DBParameterGroupFamily=CLUSTER_FAMILY[engine])
        kw['DBClusterParameterGroupName'] = cpg
    rds.create_db_cluster(DBClusterIdentifier=name, Engine=engine, MasterUsername='ssuser',
                          MasterUserPassword=PWD, VpcSecurityGroupIds=[sg], **kw)
    rds.get_waiter('db_cluster_available').wait(DBClusterIdentifier=name, WaiterConfig=WAIT)


def _deleteCluster(rds, name):
    _quiet(rds.delete_db_cluster, DBClusterIdentifier=name, SkipFinalSnapshot=True)
    _quiet(rds.get_waiter('db_cluster_deleted').wait, DBClusterIdentifier=name, WaiterConfig=WAIT)
    _quiet(rds.delete_db_cluster_parameter_group, DBClusterParameterGroupName=name + '-cpg')


# ---------------- rdsLogExportsDisabled ----------------
@pytest.mark.parametrize('engine,logType', [('aurora-postgresql', 'postgresql'), ('aurora-mysql', 'audit')])
def test_rds_log_exports_cluster(emu, uid, sg, engine, logType):
    rds = emu.client('rds')
    name = f'ss-rdslog-{uid}'
    try:
        def misconfigure():
            _createCluster(rds, name, sg, engine=engine)   # no log exports

        def fix():
            rds.modify_db_cluster(DBClusterIdentifier=name, ApplyImmediately=True,
                                  CloudwatchLogsExportConfiguration={'EnableLogTypes': [logType]})

        assertFlagFixCycle(emu, 'rds', 'rdsLogExportsDisabled', name, misconfigure, fix)
    finally:
        _deleteCluster(rds, name)


# ---------------- rdsSecureTransportNotRequired ----------------
def test_rds_secure_transport_mysql_instance(emu, uid, sg):
    rds = emu.client('rds')
    name = f'ss-rdstls-{uid}'
    pg = f'ss-rdstls-pg-{uid}'
    rds.create_db_parameter_group(DBParameterGroupName=pg, DBParameterGroupFamily='mysql8.0', Description='ss test')
    try:
        def misconfigure():
            # require_secure_transport left at engine default (OFF)
            _createInstance(rds, name, sg, engine='mysql', EngineVersion='8.0.40', DBParameterGroupName=pg)

        def fix():
            rds.modify_db_parameter_group(DBParameterGroupName=pg, Parameters=[
                {'ParameterName': 'require_secure_transport', 'ParameterValue': '1', 'ApplyMethod': 'immediate'}])

        assertFlagFixCycle(emu, 'rds', 'rdsSecureTransportNotRequired', name, misconfigure, fix)
    finally:
        _deleteInstance(rds, name)
        _quiet(rds.delete_db_parameter_group, DBParameterGroupName=pg)


def test_rds_secure_transport_aurora_mysql_cluster(emu, uid, sg):
    rds = emu.client('rds')
    name = f'ss-rdstlsc-{uid}'
    cpg = f'ss-rdstlsc-cpg-{uid}'
    rds.create_db_cluster_parameter_group(DBClusterParameterGroupName=cpg, DBParameterGroupFamily='aurora-mysql8.0',
                                          Description='ss test')
    try:
        def misconfigure():
            rds.modify_db_cluster_parameter_group(DBClusterParameterGroupName=cpg, Parameters=[
                {'ParameterName': 'require_secure_transport', 'ParameterValue': 'OFF', 'ApplyMethod': 'immediate'}])
            _createCluster(rds, name, sg, engine='aurora-mysql', DBClusterParameterGroupName=cpg)

        def fix():
            rds.modify_db_cluster_parameter_group(DBClusterParameterGroupName=cpg, Parameters=[
                {'ParameterName': 'require_secure_transport', 'ParameterValue': 'ON', 'ApplyMethod': 'immediate'}])

        assertFlagFixCycle(emu, 'rds', 'rdsSecureTransportNotRequired', name, misconfigure, fix)
    finally:
        _deleteCluster(rds, name)
        _quiet(rds.delete_db_cluster_parameter_group, DBClusterParameterGroupName=cpg)


# ---------------- rdsSnapshotUnencrypted ----------------
def test_rds_snapshot_unencrypted_instance(emu, uid, sg):
    rds = emu.client('rds')
    db = f'ss-rdssnapdb-{uid}'
    snap = f'ss-rdssnap-{uid}'
    key = emu.client('kms').create_key(Description='ss test')['KeyMetadata']['KeyId']
    try:
        def misconfigure():
            _createInstance(rds, db, sg, StorageEncrypted=False)
            rds.create_db_snapshot(DBInstanceIdentifier=db, DBSnapshotIdentifier=snap)
            rds.get_waiter('db_snapshot_available').wait(DBSnapshotIdentifier=snap, WaiterConfig=WAIT)

        def fix():
            # Encrypted copy replaces the unencrypted snapshot (same name prefix).
            rds.copy_db_snapshot(SourceDBSnapshotIdentifier=snap, TargetDBSnapshotIdentifier=snap + '-enc', KmsKeyId=key)
            rds.get_waiter('db_snapshot_available').wait(DBSnapshotIdentifier=snap + '-enc', WaiterConfig=WAIT)
            rds.delete_db_snapshot(DBSnapshotIdentifier=snap)

        assertFlagFixCycle(emu, 'rds', 'rdsSnapshotUnencrypted', snap, misconfigure, fix)
    finally:
        for s in (snap, snap + '-enc'):
            _quiet(rds.delete_db_snapshot, DBSnapshotIdentifier=s)
        _deleteInstance(rds, db)
        _quiet(emu.client('kms').schedule_key_deletion, KeyId=key, PendingWindowInDays=7)


def test_rds_snapshot_unencrypted_cluster(emu, uid, sg):
    rds = emu.client('rds')
    cl = f'ss-rdscsnapdb-{uid}'
    snap = f'ss-rdscsnap-{uid}'
    key = emu.client('kms').create_key(Description='ss test')['KeyMetadata']['KeyId']
    try:
        def misconfigure():
            _createCluster(rds, cl, sg, StorageEncrypted=False)
            rds.create_db_cluster_snapshot(DBClusterIdentifier=cl, DBClusterSnapshotIdentifier=snap)
            rds.get_waiter('db_cluster_snapshot_available').wait(DBClusterSnapshotIdentifier=snap, WaiterConfig=WAIT)

        def fix():
            rds.copy_db_cluster_snapshot(SourceDBClusterSnapshotIdentifier=snap,
                                         TargetDBClusterSnapshotIdentifier=snap + '-enc', KmsKeyId=key)
            rds.get_waiter('db_cluster_snapshot_available').wait(DBClusterSnapshotIdentifier=snap + '-enc', WaiterConfig=WAIT)
            rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap)

        assertFlagFixCycle(emu, 'rds', 'rdsSnapshotUnencrypted', snap, misconfigure, fix)
    finally:
        for s in (snap, snap + '-enc'):
            _quiet(rds.delete_db_cluster_snapshot, DBClusterSnapshotIdentifier=s)
        _deleteCluster(rds, cl)
        _quiet(emu.client('kms').schedule_key_deletion, KeyId=key, PendingWindowInDays=7)


# ---------------- rdsSnapshotSharedExternally ----------------
def test_rds_cluster_snapshot_shared_externally(emu, uid, sg):
    rds = emu.client('rds')
    cl = f'ss-rdsshdb-{uid}'
    snap = f'ss-rdsshsnap-{uid}'
    other = '111122223333'
    try:
        _createCluster(rds, cl, sg)
        rds.create_db_cluster_snapshot(DBClusterIdentifier=cl, DBClusterSnapshotIdentifier=snap)
        rds.get_waiter('db_cluster_snapshot_available').wait(DBClusterSnapshotIdentifier=snap, WaiterConfig=WAIT)

        def misconfigure():
            rds.modify_db_cluster_snapshot_attribute(DBClusterSnapshotIdentifier=snap, AttributeName='restore',
                                                     ValuesToAdd=[other])

        def fix():
            rds.modify_db_cluster_snapshot_attribute(DBClusterSnapshotIdentifier=snap, AttributeName='restore',
                                                     ValuesToRemove=[other])

        assertFlagFixCycle(emu, 'rds', 'rdsSnapshotSharedExternally', snap, misconfigure, fix)
    finally:
        _quiet(rds.delete_db_cluster_snapshot, DBClusterSnapshotIdentifier=snap)
        _deleteCluster(rds, cl)


def test_rds_public_cluster_snapshot_after_source_deleted(emu, uid, sg):
    # Regression: restore=all used to PASS here on the assumption that
    # SnapshotRDSIsPublic covers it, but that check only inspects snapshots of
    # live DBs/clusters. Delete the source cluster, then flag -> fix.
    rds = emu.client('rds')
    cl = f'ss-rdspubdb-{uid}'
    snap = f'ss-rdspubsnap-{uid}'
    try:
        def misconfigure():
            _createCluster(rds, cl, sg)
            rds.create_db_cluster_snapshot(DBClusterIdentifier=cl, DBClusterSnapshotIdentifier=snap)
            rds.get_waiter('db_cluster_snapshot_available').wait(DBClusterSnapshotIdentifier=snap, WaiterConfig=WAIT)
            _deleteCluster(rds, cl)
            rds.modify_db_cluster_snapshot_attribute(DBClusterSnapshotIdentifier=snap, AttributeName='restore',
                                                     ValuesToAdd=['all'])

        def fix():
            rds.modify_db_cluster_snapshot_attribute(DBClusterSnapshotIdentifier=snap, AttributeName='restore',
                                                     ValuesToRemove=['all'])

        assertFlagFixCycle(emu, 'rds', 'rdsSnapshotSharedExternally', snap, misconfigure, fix)
    finally:
        _quiet(rds.delete_db_cluster_snapshot, DBClusterSnapshotIdentifier=snap)
        _deleteCluster(rds, cl)


# ---------------- auroraNoGlobalDatabase ----------------
def test_aurora_no_global_database(emu, uid, sg):
    rds = emu.client('rds')
    cl = f'ss-rdsglob-{uid}'
    gc = f'ss-rdsglobgc-{uid}'
    arn = {}
    try:
        def misconfigure():
            _createCluster(rds, cl, sg)
            arn['v'] = rds.describe_db_clusters(DBClusterIdentifier=cl)['DBClusters'][0]['DBClusterArn']

        def fix():
            rds.create_global_cluster(GlobalClusterIdentifier=gc, SourceDBClusterIdentifier=arn['v'])

        assertFlagFixCycle(emu, 'rds', 'auroraNoGlobalDatabase', cl, misconfigure, fix)
    finally:
        if 'v' in arn:
            _quiet(rds.remove_from_global_cluster, GlobalClusterIdentifier=gc, DbClusterIdentifier=arn['v'])
        _quiet(rds.delete_global_cluster, GlobalClusterIdentifier=gc)
        _deleteCluster(rds, cl)

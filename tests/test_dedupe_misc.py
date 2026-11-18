"""De-duplicated AWS reads in dynamodb / rds / redshift / guardduty / ecs drivers.

Each test proves a read that several checks (or several resources) used to
make is now made once per driver instance (_memo) or once per scan
(_sharedMemo), while every affected check still produces its result.
No network: clients are MagicMocks or Stubber-wrapped real clients.
"""
import os
import sys
import threading
import time
from unittest.mock import MagicMock

import boto3
import botocore.exceptions
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.dynamodb.drivers.DynamoDbCommon import DynamoDbCommon  # noqa: E402
import services.rds.drivers.RdsCommon as rdsCommonModule  # noqa: E402
from services.rds.drivers.RdsMysql import RdsMysql  # noqa: E402
from services.rds.drivers.RdsMysqlAurora import RdsMysqlAurora  # noqa: E402
from services.redshift.drivers.RedshiftCluster import RedshiftCluster  # noqa: E402
from services.guardduty.drivers.GuarddutyDriver import GuarddutyDriver  # noqa: E402
from services.ecs.drivers.EcsTaskDefinition import EcsTaskDefinition  # noqa: E402

ACCT = '123456789012'
REGION = 'us-east-1'


@pytest.fixture(autouse=True)
def _config(monkeypatch):
    Config.init()  # also clears the scan-wide _sharedMemo store
    Config.set('stsInfo', {'Account': ACCT})
    # RDS instance-class lookup reads EC2/pricing data; not under test here.
    monkeypatch.setattr(rdsCommonModule, 'aws_parseInstanceFamily', lambda *a, **k: {
        'prefixDetail': {'family': 'm', 'version': '5'},
        'specification': {'vcpu': 2, 'memoryInGiB': 8}})
    yield
    Config.init()


def _clientError(code, op='Op'):
    return botocore.exceptions.ClientError({'Error': {'Code': code, 'Message': code}}, op)


def _mockClient(region=REGION):
    c = MagicMock()
    c.meta.region_name = region
    c.meta.partition = 'aws'
    return c


def _real(service):
    return boto3.client(service, region_name=REGION, aws_access_key_id='testing',
                        aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')


# ---------------------------------------------------------------------- #
# DynamoDB
# ---------------------------------------------------------------------- #
TABLE_ARN = 'arn:aws:dynamodb:us-east-1:%s:table/t1' % ACCT


def _table(**extra):
    t = {'TableName': 't1', 'TableArn': TABLE_ARN, 'DeletionProtectionEnabled': True,
         'BillingModeSummary': {'BillingMode': 'PROVISIONED'}}
    t.update(extra)
    return {'Table': t}


def _ddb(ddb=None, cw=None, aas=None, tagsResp=None, table=None):
    return DynamoDbCommon(table or _table(), ddb or _mockClient(), cw or _mockClient(), _mockClient(),
                          aas or _mockClient(), _mockClient(), _mockClient(), tagsResp=tagsResp)


def test_dynamodb_scaling_policies_read_once_for_both_checks():
    aas = _real('application-autoscaling')
    with Stubber(aas) as st:
        # Exactly one queued response: a second call would raise.
        st.add_response('describe_scaling_policies', {'ScalingPolicies': [
            {'PolicyARN': 'arn:p1', 'PolicyName': 'p1', 'ServiceNamespace': 'dynamodb',
             'ResourceId': 'table/t1', 'ScalableDimension': 'dynamodb:table:WriteCapacityUnits',
             'PolicyType': 'TargetTrackingScaling', 'CreationTime': '2024-01-01T00:00:00Z',
             'TargetTrackingScalingPolicyConfiguration': {'TargetValue': 90.0}}]},
            {'ServiceNamespace': 'dynamodb', 'ResourceId': 'table/t1'})
        d = _ddb(aas=aas)
        d._check_autoscaling_status()
        d._check_autoscaling_aggresiveness()
        st.assert_no_pending_responses()
    assert 'autoscalingStatus' not in d.results
    assert d.results['autoScalingHighUtil'] == [-1, 'WCU = 90.0']
    # RCU target 0 -> low util is reported for RCU first, then not overwritten by WCU
    assert d.results['autoScalingLowUtil'] == [-1, 'RCU = 0']


def test_dynamodb_scaling_policies_none_reported_by_status_check():
    aas = _mockClient()
    aas.describe_scaling_policies.return_value = {'ScalingPolicies': []}
    d = _ddb(aas=aas)
    d._check_autoscaling_status()
    d._check_autoscaling_aggresiveness()
    assert aas.describe_scaling_policies.call_count == 1
    assert d.results['autoScalingStatus'][0] == -1


def test_dynamodb_consumed_wcu_metric_read_once():
    cw = _mockClient()

    def gms(**kw):
        if kw['MetricName'] == 'ConsumedWriteCapacityUnits':
            return {'Datapoints': [{'Average': 0.9}, {'Average': 0.1}]}
        return {'Datapoints': [{'Average': 0.95}]}
    cw.get_metric_statistics.side_effect = gms
    d = _ddb(cw=cw, table=_table(BillingModeSummary={'BillingMode': 'PAY_PER_REQUEST'}))
    d._check_capacity_mode()
    d._check_service_limit_wcu_rcu()
    names = [c.kwargs['MetricName'] for c in cw.get_metric_statistics.call_args_list]
    assert names.count('ConsumedWriteCapacityUnits') == 1
    assert names.count('ConsumedReadCapacityUnits') == 1
    assert d.results['capacityModeProvisioned'] == [-1, 'PAY_PER_REQUEST']
    assert d.results['wcuServiceLimit'] == [-1, 'WCU limit > 1 in past 7 days.']
    assert d.results['rcuServiceLimit'] == [-1, 'RCU limit > 1 in past 7 days.']


def test_dynamodb_tags_read_once_for_both_checks():
    ddb = _real('dynamodb')
    with Stubber(ddb) as st:
        st.add_response('list_tags_of_resource', {'Tags': [{'Key': 'criticality', 'Value': 'high'}]},
                        {'ResourceArn': TABLE_ARN})
        d = _ddb(ddb=ddb)
        d._check_resources_for_tags()
        d._checkDynamodbNoMultiRegionReplica()
        st.assert_no_pending_responses()
    assert 'resourcesWithoutTags' not in d.results
    res = d.results['dynamodbNoMultiRegionReplica']
    assert res[0] == -1 and 'criticality=high' in res[1]


def test_dynamodb_tags_second_page_still_fetched():
    ddb = _real('dynamodb')
    with Stubber(ddb) as st:
        st.add_response('list_tags_of_resource', {'Tags': [], 'NextToken': 'n1'}, {'ResourceArn': TABLE_ARN})
        st.add_response('list_tags_of_resource', {'Tags': [{'Key': 'tier', 'Value': 'critical'}]},
                        {'ResourceArn': TABLE_ARN, 'NextToken': 'n1'})
        d = _ddb(ddb=ddb)
        d._check_resources_for_tags()
        d._checkDynamodbNoMultiRegionReplica()
        st.assert_no_pending_responses()
    assert d.results['resourcesWithoutTags'] == [-1, '']
    assert d.results['dynamodbNoMultiRegionReplica'][0] == -1


def test_dynamodb_tags_from_service_tag_filter_not_refetched():
    ddb = _real('dynamodb')
    with Stubber(ddb) as st:  # nothing queued: any call fails
        d = _ddb(ddb=ddb, tagsResp={'Tags': []})
        d._check_resources_for_tags()
        d._checkDynamodbNoMultiRegionReplica()
        st.assert_no_pending_responses()
    assert d.results['resourcesWithoutTags'] == [-1, '']
    assert d.results['dynamodbNoMultiRegionReplica'][0] == 0


def test_dynamodb_tags_error_reaches_both_except_blocks():
    ddb = _mockClient()
    ddb.list_tags_of_resource.side_effect = _clientError('AccessDeniedException')
    d = _ddb(ddb=ddb)
    d._check_resources_for_tags()
    d._checkDynamodbNoMultiRegionReplica()
    assert ddb.list_tags_of_resource.call_count == 1
    assert 'resourcesWithoutTags' not in d.results
    assert d.results['dynamodbNoMultiRegionReplica'] == [0, 'Unable to evaluate (AccessDeniedException)']


# ---------------------------------------------------------------------- #
# RDS
# ---------------------------------------------------------------------- #
def _rdsClient(engineVersions=True):
    rds = _mockClient()
    rds.describe_db_engine_versions.return_value = {
        'DBEngineVersions': [{'Engine': 'mysql', 'EngineVersion': '8.0.35'}] if engineVersions else []}
    rds.describe_certificates.return_value = {'Certificates': []}
    rds.describe_db_parameters.return_value = {'Parameters': [
        {'ParameterName': 'sync_binlog', 'ParameterValue': '1', 'IsModifiable': True}]}
    rds.describe_db_cluster_parameters.return_value = {'Parameters': [
        {'ParameterName': 'require_secure_transport', 'ParameterValue': 'ON', 'IsModifiable': True}]}
    return rds


def _mysqlDb(name):
    return {'DBInstanceIdentifier': name, 'Engine': 'mysql', 'EngineVersion': '8.0.35',
            'DBInstanceClass': 'db.m5.large', 'DBParameterGroups': [{'DBParameterGroupName': 'pg1'}],
            'CACertificateIdentifier': 'rds-ca-x', 'TagList': []}


def _auroraInstance(name):
    return {'DBInstanceIdentifier': name, 'DBClusterIdentifier': 'c1', 'Engine': 'aurora-mysql',
            'EngineVersion': '8.0.35', 'DBInstanceClass': 'db.r6g.large',
            'DBParameterGroups': [{'DBParameterGroupName': 'pg-aurora'}],
            'CACertificateIdentifier': 'rds-ca-x', 'TagList': []}


def test_rds_parameter_group_read_once_per_scan():
    rds = _rdsClient()
    a = RdsMysql(_mysqlDb('db1'), rds, _mockClient(), _mockClient())
    b = RdsMysql(_mysqlDb('db2'), rds, _mockClient(), _mockClient())
    # Each driver loads parameters twice (RdsCommon + RdsMysql __init__); was 4 calls.
    assert rds.describe_db_parameters.call_count == 1
    assert a.dbParams == b.dbParams == {'sync_binlog': '1'}
    a.dbParams['sync_binlog'] = 'changed'
    assert b.dbParams['sync_binlog'] == '1'


def test_rds_parameter_group_pagination_and_cluster_params():
    rds = _rdsClient()
    rds.describe_db_parameters.side_effect = [
        {'Parameters': [{'ParameterName': 'a', 'ParameterValue': '1', 'IsModifiable': True}], 'Marker': 'm'},
        {'Parameters': [{'ParameterName': 'b', 'ParameterValue': '2', 'IsModifiable': True},
                        {'ParameterName': 'c', 'ParameterValue': '3', 'IsModifiable': False},
                        {'ParameterName': 'd', 'IsModifiable': True}]},
    ]
    a = RdsMysql(_mysqlDb('db1'), rds, _mockClient(), _mockClient())
    assert a.dbParams == {'a': '1', 'b': '2'}
    assert rds.describe_db_parameters.call_count == 2
    assert rds.describe_db_parameters.call_args_list[1].kwargs == {'DBParameterGroupName': 'pg1', 'Marker': 'm'}

    cluster = {'DBClusterIdentifier': 'c1', 'Engine': 'aurora-mysql', 'EngineVersion': '8.0.35',
               'DBClusterParameterGroup': 'cpg', 'TagList': [], 'DBClusterMembers': []}
    c = RdsMysqlAurora(cluster, rds, _mockClient(), _mockClient())
    RdsMysqlAurora(dict(cluster, DBClusterIdentifier='c2'), rds, _mockClient(), _mockClient())
    assert rds.describe_db_cluster_parameters.call_count == 1
    assert c.dbParams == {'require_secure_transport': 'ON'}


def test_rds_parameter_group_shared_per_region():
    east, west = _rdsClient(), _rdsClient()
    west.meta.region_name = 'us-west-2'
    RdsMysql(_mysqlDb('db1'), east, _mockClient(), _mockClient())
    RdsMysql(_mysqlDb('db1'), west, _mockClient(), _mockClient())
    assert east.describe_db_parameters.call_count == 1
    assert west.describe_db_parameters.call_count == 1


def test_rds_cluster_level_reads_shared_by_member_instances():
    rds = _rdsClient()
    rds.describe_db_clusters.return_value = {'DBClusters': [{'DBClusterMembers': [{'DBInstanceIdentifier': 'i1'}]}]}
    rds.describe_db_cluster_snapshots.side_effect = lambda **kw: (
        {'DBClusterSnapshots': [{'DBClusterSnapshotIdentifier': 'pub'}]} if kw['SnapshotType'] == 'public'
        else {'DBClusterSnapshots': [{'SnapshotCreateTime': __import__('datetime').datetime(2000, 1, 1, tzinfo=__import__('datetime').timezone.utc)}] * 6})
    drivers = []
    for name in ('i1', 'i2', 'i3'):
        d = RdsMysqlAurora(_auroraInstance(name), rds, _mockClient(), _mockClient())
        d.setEngine('aurora-mysql')
        d._checkClusterSize()
        d._checkPublicSnapshot()
        d._checkOldSnapshots()
        drivers.append(d)
    assert rds.describe_db_clusters.call_count == 1
    types = [c.kwargs['SnapshotType'] for c in rds.describe_db_cluster_snapshots.call_args_list]
    assert types.count('public') == 1 and types.count('manual') == 1
    for d in drivers:
        assert d.results['Aurora__ClusterSize'] == [-1, 1]
        assert d.results['SnapshotRDSIsPublic'] == [-1, 'At least 1']
        assert d.results['ManualSnapshotTooMany'] == [-1, 6]
        assert d.results['ManualSnapshotTooOld'][0] == -1


def test_rds_unknown_engine_version_read_once():
    rds = _rdsClient(engineVersions=False)
    a = RdsMysql(_mysqlDb('db1'), rds, _mockClient(), _mockClient())
    b = RdsMysql(_mysqlDb('db2'), rds, _mockClient(), _mockClient())
    assert rds.describe_db_engine_versions.call_count == 1
    for d in (a, b):
        assert d.results['EngineVersionMinor'] == [-1, '**DEPRECIATED**']
        assert d.results['EngineVersionMajor'] == [-1, '**DEPRECIATED**']


def test_rds_orderable_options_error_read_once():
    rds = _rdsClient()
    rds.describe_orderable_db_instance_options.side_effect = _clientError('InvalidParameterCombination')
    out = []
    for name in ('db1', 'db2'):
        d = RdsMysql(_mysqlDb(name), rds, _mockClient(), _mockClient())
        d._checkIsInstanceLatestGeneration()
        out.append(d.results['LatestInstanceGeneration'])
    assert rds.describe_orderable_db_instance_options.call_count == 1
    assert out == [[-1, '_ERROR_'], [-1, '_ERROR_']]


def test_rds_orderable_options_success_still_evaluated():
    rds = _rdsClient()
    rds.describe_orderable_db_instance_options.side_effect = [
        {'OrderableDBInstanceOptions': [{'DBInstanceClass': 'db.m7.large'}], 'Marker': 'm'},
        {'OrderableDBInstanceOptions': [{'DBInstanceClass': 'db.m7.xlarge'}]},
    ]
    d = RdsMysql(_mysqlDb('db1'), rds, _mockClient(), _mockClient())
    d._checkIsInstanceLatestGeneration()
    assert rds.describe_orderable_db_instance_options.call_count == 2
    assert d.results['LatestInstanceGeneration'] == [-1, 'db.m5.large']


# ---------------------------------------------------------------------- #
# Redshift
# ---------------------------------------------------------------------- #
def _rsCluster(name):
    return {'ClusterIdentifier': name, 'ClusterParameterGroups': [{'ParameterGroupName': 'rpg'}]}


def test_redshift_parameter_group_and_event_subscriptions_read_once_per_scan():
    rs = _mockClient()
    rs.describe_cluster_parameters.return_value = {'Parameters': [
        {'ParameterName': 'wlm_json_configuration', 'ParameterValue': '[{"rules": [{"rule_name": "r"}]}]'}]}
    rs.describe_event_subscriptions.return_value = {'EventSubscriptionsList': [
        {'CustSubscriptionId': 'sub1', 'SourceIdsList': ['a']}]}
    a = RedshiftCluster(_rsCluster('a'), rs)
    b = RedshiftCluster(_rsCluster('b'), rs)
    for d in (a, b):
        d._checkEventNotifications()
        d._checkQueryMonitoringRules()
    assert rs.describe_cluster_parameters.call_count == 1
    assert rs.describe_event_subscriptions.call_count == 1
    assert a.results['EventNotifications'] == [1, 'Event notifications configured: sub1']
    assert b.results['EventNotifications'][0] == -1
    assert a.results['QueryMonitoringRules'][0] == b.results['QueryMonitoringRules'][0] == 1


def test_redshift_event_subscriptions_error_reaches_each_cluster():
    rs = _mockClient()
    rs.describe_cluster_parameters.return_value = {'Parameters': []}
    rs.describe_event_subscriptions.side_effect = _clientError('AccessDenied')
    out = []
    for name in ('a', 'b'):
        d = RedshiftCluster(_rsCluster(name), rs)
        d._checkEventNotifications()
        out.append(d.results['EventNotifications'])
    assert rs.describe_event_subscriptions.call_count == 1
    assert out == [[0, 'Unable to check event subscriptions: AccessDenied']] * 2


# ---------------------------------------------------------------------- #
# GuardDuty
# ---------------------------------------------------------------------- #
def _gdDriver(gd):
    return GuarddutyDriver('det1', gd, REGION)


def test_guardduty_get_detector_once_under_concurrent_checks():
    gd = _mockClient()

    def getDetector(**kw):
        time.sleep(0.05)
        return {'Status': 'ENABLED', 'DataSources': {},
                'Features': [{'Name': 'S3_DATA_EVENTS', 'Status': 'ENABLED'},
                             {'Name': 'RDS_LOGIN_EVENTS', 'Status': 'DISABLED'},
                             {'Name': 'RUNTIME_MONITORING', 'Status': 'ENABLED',
                              'AdditionalConfiguration': [{'Name': 'EC2_AGENT_MANAGEMENT', 'Status': 'ENABLED'}]}]}
    gd.get_detector.side_effect = getDetector
    d = _gdDriver(gd)
    checks = ['_checkGuard_duty_settings', '_checkS3ProtectionDisabled', '_checkRdsProtectionDisabled',
              '_checkEc2RuntimeMonitoringDisabled', '_checkRuntimeMonitoringDisabled',
              '_checkLambdaProtectionDisabled']
    ts = [threading.Thread(target=getattr(d, c)) for c in checks]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert gd.get_detector.call_count == 1
    assert d.results['Settings'] == [-1, {'isEnabled': 'ENABLED', 'Settings': {}}]
    assert d.results['S3ProtectionDisabled'][0] == 1
    assert d.results['RdsProtectionDisabled'][0] == -1
    assert d.results['Ec2RuntimeMonitoringDisabled'][0] == 1
    assert d.results['LambdaProtectionDisabled'][0] == 0


def test_guardduty_get_detector_failure_read_once():
    gd = _mockClient()
    gd.get_detector.side_effect = _clientError('AccessDeniedException')
    d = _gdDriver(gd)
    d._checkGuard_duty_settings()
    d._checkS3ProtectionDisabled()
    d._checkGuardDutyNoSnapshotPreservation()
    assert gd.get_detector.call_count == 1
    assert 'Settings' not in d.results
    assert d.results['S3ProtectionDisabled'][0] == 0
    assert d.results['guardDutyNoSnapshotPreservation'] == [0, 'Unable to evaluate (GetDetector failed)']


# ---------------------------------------------------------------------- #
# ECS
# ---------------------------------------------------------------------- #
SECRET = 'arn:aws:secretsmanager:us-east-1:%s:secret:db-AbCdEf' % ACCT
GONE = 'arn:aws:secretsmanager:us-east-1:%s:secret:gone-XyZ' % ACCT


def _taskDef(family, secrets, roleArn=None):
    td = {'family': family, 'revision': 1,
          'containerDefinitions': [{'name': 'c%d' % i, 'secrets': [{'name': 's', 'valueFrom': vf}]}
                                   for i, vf in enumerate(secrets)]}
    if roleArn:
        td['taskRoleArn'] = roleArn
    return td


def test_ecs_secret_and_parameter_probes_shared_across_task_definitions():
    sm, ssm = _mockClient(), _mockClient()

    def describeSecret(SecretId):
        if 'gone' in SecretId:
            raise _clientError('ResourceNotFoundException')
        return {'ARN': SecretId, 'Name': 'db'}
    sm.describe_secret.side_effect = describeSecret
    ssm.get_parameter.return_value = {'Parameter': {'Name': '/app/pw', 'Value': 'secret-value'}}
    refs = [SECRET, SECRET + ':password::', GONE, '/app/pw', '/app/pw']
    out = []
    for fam in ('f1', 'f2'):
        d = EcsTaskDefinition(_taskDef(fam, refs), sm, ssm, False)
        d._checkEcsTaskDefinitionSecretReferences()
        out.append(d.results['ecsTaskDefinitionSecretReferences'])
    assert sm.describe_secret.call_count == 2  # SECRET base + GONE, once each per scan
    assert ssm.get_parameter.call_count == 1
    assert out[0] == out[1]
    assert out[0][0] == -1 and out[0][1].startswith('1 broken secret reference(s): c2:s')


"""Flag -> fix -> re-run tests for WAFS2027 DynamoDB checks against the local AWS Emulator.

Notes on emulator behaviour (mirrors real DynamoDB):
- PutResourcePolicy rejects any policy with a public ("*") principal, so the wildcard path of
  dynamodbResourcePolicyPublic is covered by tests/test_stub_dynamodb.py. Here we drive the
  cross-account-without-aws:PrincipalOrgID path.
- Resource policies and tags are eventually consistent; the helpers poll until visible.
"""
import json
import time

from tests.emulator.conftest import assertFlagFixCycle

OTHER_ACCOUNT = '222222222222'


def _createTable(ddb, name, **extra):
    ddb.create_table(TableName=name,
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     BillingMode='PAY_PER_REQUEST', **extra)
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})
    return ddb.describe_table(TableName=name)['Table']


def _waitFor(predicate, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return
        time.sleep(1)
    raise AssertionError('emulator state did not converge')


def _waitActive(ddb, name, wantReplicas=None):
    def ok():
        t = ddb.describe_table(TableName=name)['Table']
        if t['TableStatus'] != 'ACTIVE':
            return False
        reps = t.get('Replicas') or []
        if wantReplicas is None:
            return True
        return bool(reps) == wantReplicas and all(r.get('ReplicaStatus') == 'ACTIVE' for r in reps)
    _waitFor(ok, timeout=120)


def _deleteTable(ddb, name):
    try:
        _waitActive(ddb, name)
        ddb.delete_table(TableName=name)
    except Exception:
        pass


def _policy(arn, condition=None):
    stmt = {'Sid': 'CrossAccountRead', 'Effect': 'Allow',
            'Principal': {'AWS': f'arn:aws:iam::{OTHER_ACCOUNT}:root'},
            'Action': ['dynamodb:GetItem', 'dynamodb:Query'], 'Resource': arn}
    if condition:
        stmt['Condition'] = condition
    return json.dumps({'Version': '2012-10-17', 'Statement': [stmt]})


def _putPolicyAndWait(ddb, arn, doc, marker):
    ddb.put_resource_policy(ResourceArn=arn, Policy=doc)

    def visible():
        try:
            return marker in ddb.get_resource_policy(ResourceArn=arn)['Policy']
        except ddb.exceptions.PolicyNotFoundException:
            return False
    _waitFor(visible)


def test_dynamodb_resource_policy_cross_account_unscoped(emu, uid):
    ddb = emu.client('dynamodb')
    name = f'ss-rp-{uid}'
    arn = _createTable(ddb, name)['TableArn']
    try:
        def misconfigure():
            _putPolicyAndWait(ddb, arn, _policy(arn), OTHER_ACCOUNT)

        def fix():
            _putPolicyAndWait(ddb, arn, _policy(arn, {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123def4'}}),
                              'aws:PrincipalOrgID')

        before, after = assertFlagFixCycle(emu, 'dynamodb', 'dynamodbResourcePolicyPublic', name, misconfigure, fix)
        assert set(after.values()) == {1}
    finally:
        try:
            ddb.delete_resource_policy(ResourceArn=arn)
        except Exception:
            pass
        _deleteTable(ddb, name)


def test_dynamodb_resource_policy_stream_cross_account(emu, uid):
    ddb = emu.client('dynamodb')
    name = f'ss-rps-{uid}'
    table = _createTable(ddb, name, StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'KEYS_ONLY'})
    streamArn = table['LatestStreamArn']
    try:
        def misconfigure():
            _putPolicyAndWait(ddb, streamArn, _policy(streamArn).replace('dynamodb:GetItem', 'dynamodb:GetRecords')
                              .replace('"dynamodb:Query"', '"dynamodb:DescribeStream"'), OTHER_ACCOUNT)

        def fix():
            ddb.delete_resource_policy(ResourceArn=streamArn)

            def gone():
                try:
                    ddb.get_resource_policy(ResourceArn=streamArn)
                    return False
                except ddb.exceptions.PolicyNotFoundException:
                    return True
            _waitFor(gone)

        assertFlagFixCycle(emu, 'dynamodb', 'dynamodbResourcePolicyPublic', name, misconfigure, fix)
    finally:
        try:
            ddb.delete_resource_policy(ResourceArn=streamArn)
        except Exception:
            pass
        _deleteTable(ddb, name)


def test_dynamodb_no_multi_region_replica(emu, uid):
    ddb = emu.client('dynamodb')
    name = f'ss-rep-{uid}'
    arn = _createTable(ddb, name)['TableArn']
    try:
        def misconfigure():
            ddb.tag_resource(ResourceArn=arn, Tags=[{'Key': 'Criticality', 'Value': 'High'}])
            _waitFor(lambda: any(t['Key'] == 'Criticality'
                                 for t in ddb.list_tags_of_resource(ResourceArn=arn).get('Tags', [])))

        def fix():
            ddb.update_table(TableName=name, ReplicaUpdates=[{'Create': {'RegionName': 'us-west-2'}}])
            _waitActive(ddb, name, wantReplicas=True)

        before, after = assertFlagFixCycle(emu, 'dynamodb', 'dynamodbNoMultiRegionReplica', name, misconfigure, fix)
        assert set(after.values()) == {1}
    finally:
        try:
            _waitActive(ddb, name)
            if ddb.describe_table(TableName=name)['Table'].get('Replicas'):
                ddb.update_table(TableName=name, ReplicaUpdates=[{'Delete': {'RegionName': 'us-west-2'}}])
                _waitActive(ddb, name, wantReplicas=False)
        except Exception:
            pass
        _deleteTable(ddb, name)

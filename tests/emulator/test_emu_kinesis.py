"""Flag -> fix -> re-run tests for kinesisResourcePolicyPublic against the AWS Emulator."""
import json
import time

from tests.emulator.conftest import assertFlagFixCycle, runCheck

CHECK = 'kinesisResourcePolicyPublic'


def _createStream(kin, name):
    kin.create_stream(StreamName=name, ShardCount=1)
    for _ in range(30):
        summ = kin.describe_stream_summary(StreamName=name)['StreamDescriptionSummary']
        if summ.get('StreamStatus') == 'ACTIVE':
            break
        time.sleep(0.5)
    return summ['StreamARN']


def _policy(arn, principal, condition=None):
    stmt = {'Sid': 'Share', 'Effect': 'Allow', 'Principal': principal,
            'Action': ['kinesis:DescribeStreamSummary', 'kinesis:GetRecords',
                       'kinesis:GetShardIterator', 'kinesis:ListShards'],
            'Resource': arn}
    if condition:
        stmt['Condition'] = condition
    return json.dumps({'Version': '2012-10-17', 'Statement': [stmt]})


def _cleanup(kin, name):
    try:
        kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except Exception:
        pass


def test_kinesis_stream_policy_wildcard_principal(emu, uid):
    kin = emu.client('kinesis')
    name = f'ss-test-{uid}'
    arn = _createStream(kin, name)
    try:
        def misconfigure():
            kin.put_resource_policy(ResourceARN=arn, Policy=_policy(arn, {'AWS': ['*']}))

        def fix():
            kin.put_resource_policy(ResourceARN=arn, Policy=_policy(
                arn, {'AWS': 'arn:aws:iam::111122223333:root'}))

        assertFlagFixCycle(emu, 'kinesis', CHECK, name, misconfigure, fix)
    finally:
        _cleanup(kin, name)


def test_kinesis_stream_policy_wildcard_scoped_by_org_condition(emu, uid):
    """Principal '*' restricted with aws:PrincipalOrgID is not public."""
    kin = emu.client('kinesis')
    name = f'ss-test-{uid}'
    arn = _createStream(kin, name)
    try:
        def misconfigure():
            kin.put_resource_policy(ResourceARN=arn, Policy=_policy(arn, '*'))

        def fix():
            kin.put_resource_policy(ResourceARN=arn, Policy=_policy(
                arn, '*', {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123def4'}}))

        assertFlagFixCycle(emu, 'kinesis', CHECK, name, misconfigure, fix)
    finally:
        _cleanup(kin, name)


def test_kinesis_consumer_policy_wildcard_principal(emu, uid):
    kin = emu.client('kinesis')
    name = f'ss-test-{uid}'
    arn = _createStream(kin, name)
    try:
        consumerArn = kin.register_stream_consumer(
            StreamARN=arn, ConsumerName=f'c-{uid}')['Consumer']['ConsumerARN']

        def misconfigure():
            kin.put_resource_policy(ResourceARN=consumerArn, Policy=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': '*'},
                               'Action': ['kinesis:DescribeStreamConsumer',
                                          'kinesis:SubscribeToShard'],
                               'Resource': consumerArn}]}))

        def fix():
            kin.delete_resource_policy(ResourceARN=consumerArn)

        assertFlagFixCycle(emu, 'kinesis', CHECK, name, misconfigure, fix)
        kin.put_resource_policy(ResourceARN=consumerArn, Policy=json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': '*'},
                           'Action': 'kinesis:SubscribeToShard', 'Resource': consumerArn}]}))
        res = runCheck(emu, 'kinesis', CHECK, name)
        assert all(s == -1 for s in res.statuses().values())
    finally:
        _cleanup(kin, name)


def test_kinesis_no_policy_passes(emu, uid):
    kin = emu.client('kinesis')
    name = f'ss-test-{uid}'
    _createStream(kin, name)
    try:
        statuses = runCheck(emu, 'kinesis', CHECK, name).statuses()
        assert statuses and all(s == 1 for s in statuses.values()), statuses
    finally:
        _cleanup(kin, name)

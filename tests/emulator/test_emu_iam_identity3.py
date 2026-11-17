"""Flag -> fix -> re-run tests (AWS Emulator) for the WAFS2027 IAM identity
checks of chunk 3 that the emulator can drive end to end:

- mfaDeactivationNotAlerted (EventBridge rule path and CloudTrail metric
  filter + alarm path)
- resourceExplorerNoAggregatorIndex
- roleSharedAcrossComponents
- dataStoreNoClassificationTag (S3 via the tagging API / GetBucketTagging, EFS)

costAllocationTagsNotActivated (ce.list_cost_allocation_tags not implemented),
drRegionQuotaParity (single-Region emulator, quotas cannot be raised),
iamUserLongTermAccessKey and longTermKeyNotContained (the emulator caches the
IAM credential report, so users/keys created by a test never appear in it) are
tested with botocore Stubber in tests/test_stub_iam_identity3.py.
"""
import io
import json
import zipfile

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ACCOUNT = '000000000000'
REGION = 'us-east-1'


def _doc(statements):
    return json.dumps({'Version': '2012-10-17', 'Statement': statements})


def _serviceTrust(*services):
    return _doc([{'Effect': 'Allow', 'Principal': {'Service': list(services)}, 'Action': 'sts:AssumeRole'}])


def _quiet(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# mfaDeactivationNotAlerted
# --------------------------------------------------------------------------- #
MFA_PATTERN = json.dumps({'source': ['aws.iam'], 'detail-type': ['AWS API Call via CloudTrail'],
                          'detail': {'eventSource': ['iam.amazonaws.com'], 'eventName': ['DeactivateMFADevice']}})


def test_mfa_deactivation_eventbridge_rule(emu, uid):
    events, sns = emu.client('events'), emu.client('sns')
    rule = f'ss-test-mfa-{uid}'
    topic = sns.create_topic(Name=f'ss-test-mfa-{uid}')['TopicArn']
    try:
        def misconfigure():
            # Rule exists but has no target: nobody is alerted.
            events.put_rule(Name=rule, EventPattern=MFA_PATTERN, State='ENABLED')

        def fix():
            events.put_targets(Rule=rule, Targets=[{'Id': 'sns', 'Arn': topic}])

        _, after = assertFlagFixCycle(emu, 'iam', 'mfaDeactivationNotAlerted', 'Account', misconfigure, fix)
        assert list(after.values()) == [1], after
    finally:
        _quiet(events.remove_targets, Rule=rule, Ids=['sns'])
        _quiet(events.delete_rule, Name=rule)
        _quiet(sns.delete_topic, TopicArn=topic)


def test_mfa_deactivation_rule_for_other_event_not_counted(emu, uid):
    events, sns = emu.client('events'), emu.client('sns')
    rule = f'ss-test-mfa-other-{uid}'
    topic = sns.create_topic(Name=f'ss-test-mfa-other-{uid}')['TopicArn']
    try:
        events.put_rule(Name=rule, State='ENABLED', EventPattern=json.dumps(
            {'source': ['aws.iam'], 'detail': {'eventName': ['CreateUser']}}))
        events.put_targets(Rule=rule, Targets=[{'Id': 'sns', 'Arn': topic}])
        res = runCheck(emu, 'iam', 'mfaDeactivationNotAlerted', 'Account').statuses()
        assert list(res.values()) == [-1], res
    finally:
        _quiet(events.remove_targets, Rule=rule, Ids=['sns'])
        _quiet(events.delete_rule, Name=rule)
        _quiet(sns.delete_topic, TopicArn=topic)


def test_mfa_deactivation_metric_filter_alarm(emu, uid):
    s3, ct, logs, cw, sns, iam = (emu.client(x) for x in ('s3', 'cloudtrail', 'logs', 'cloudwatch', 'sns', 'iam'))
    bucket, trail, group = f'ss-test-trail-{uid}', f'ss-test-trail-{uid}', f'ss-test-trail-{uid}'
    role, metric, alarm = f'ss-test-ct-{uid}', f'MfaDeactivation{uid}', f'ss-test-mfa-{uid}'
    topic = sns.create_topic(Name=f'ss-test-mfa-alarm-{uid}')['TopicArn']
    try:
        s3.create_bucket(Bucket=bucket)
        s3.put_bucket_policy(Bucket=bucket, Policy=_doc([
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:GetBucketAcl',
             'Resource': f'arn:aws:s3:::{bucket}'},
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:PutObject',
             'Resource': f'arn:aws:s3:::{bucket}/AWSLogs/{ACCOUNT}/*',
             'Condition': {'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control'}}}]))
        roleArn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=_serviceTrust('cloudtrail.amazonaws.com'))['Role']['Arn']
        logs.create_log_group(logGroupName=group)
        groupArn = f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{group}:*'
        ct.create_trail(Name=trail, S3BucketName=bucket, IncludeGlobalServiceEvents=True,
                        CloudWatchLogsLogGroupArn=groupArn, CloudWatchLogsRoleArn=roleArn)
        def misconfigure():
            logs.put_metric_filter(logGroupName=group, filterName='mfa', filterPattern='{ $.eventName = DeactivateMFADevice }',
                                   metricTransformations=[{'metricName': metric, 'metricNamespace': 'CISBenchmark', 'metricValue': '1'}])
            # Alarm without any action: nobody is notified.
            cw.put_metric_alarm(AlarmName=alarm, MetricName=metric, Namespace='CISBenchmark', Statistic='Sum', Period=300,
                                EvaluationPeriods=1, Threshold=1, ComparisonOperator='GreaterThanOrEqualToThreshold')

        def fix():
            cw.put_metric_alarm(AlarmName=alarm, MetricName=metric, Namespace='CISBenchmark', Statistic='Sum', Period=300,
                                EvaluationPeriods=1, Threshold=1, ComparisonOperator='GreaterThanOrEqualToThreshold',
                                AlarmActions=[topic])

        _, after = assertFlagFixCycle(emu, 'iam', 'mfaDeactivationNotAlerted', 'Account', misconfigure, fix)
        assert list(after.values()) == [1], after
    finally:
        _quiet(cw.delete_alarms, AlarmNames=[alarm])
        _quiet(logs.delete_metric_filter, logGroupName=group, filterName='mfa')
        _quiet(ct.delete_trail, Name=trail)
        _quiet(logs.delete_log_group, logGroupName=group)
        _quiet(iam.delete_role, RoleName=role)
        _quiet(s3.delete_bucket_policy, Bucket=bucket)
        _quiet(s3.delete_bucket, Bucket=bucket)
        _quiet(sns.delete_topic, TopicArn=topic)


# --------------------------------------------------------------------------- #
# resourceExplorerNoAggregatorIndex
# --------------------------------------------------------------------------- #
def test_resource_explorer_aggregator(emu):
    re2 = emu.client('resource-explorer-2')
    original = re2.list_indexes().get('Indexes', [])
    for i in original:
        re2.delete_index(Arn=i['Arn'])
    arn = None
    try:
        def misconfigure():
            nonlocal arn
            arn = re2.create_index()['Arn']   # LOCAL index only

        def fix():
            re2.update_index_type(Arn=arn, Type='AGGREGATOR')

        assertFlagFixCycle(emu, 'iam', 'resourceExplorerNoAggregatorIndex', 'Account', misconfigure, fix)
    finally:
        for i in re2.list_indexes().get('Indexes', []):
            _quiet(re2.delete_index, Arn=i['Arn'])
        for i in original:   # restore the original setting
            _quiet(re2.create_index)
            if i.get('Type') == 'AGGREGATOR':
                for j in re2.list_indexes().get('Indexes', []):
                    _quiet(re2.update_index_type, Arn=j['Arn'], Type='AGGREGATOR')


# --------------------------------------------------------------------------- #
# roleSharedAcrossComponents
# --------------------------------------------------------------------------- #
def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('index.py', 'def handler(e, c):\n    return 1\n')
    return buf.getvalue()


SFN_DEF = json.dumps({'StartAt': 'P', 'States': {'P': {'Type': 'Pass', 'End': True}}})


def test_role_shared_lambda_and_state_machine(emu, uid):
    iam, lam, sfn = emu.client('iam'), emu.client('lambda'), emu.client('stepfunctions')
    shared, own = f'ss-test-shared-{uid}', f'ss-test-own-{uid}'
    sharedArn = iam.create_role(RoleName=shared, AssumeRolePolicyDocument=_serviceTrust(
        'lambda.amazonaws.com', 'states.amazonaws.com'))['Role']['Arn']
    ownArn = iam.create_role(RoleName=own, AssumeRolePolicyDocument=_serviceTrust('states.amazonaws.com'))['Role']['Arn']
    fn, smArn = f'ss-test-fn-{uid}', None
    try:
        def misconfigure():
            nonlocal smArn
            lam.create_function(FunctionName=fn, Runtime='python3.12', Role=sharedArn, Handler='index.handler',
                                Code={'ZipFile': _zip()})
            smArn = sfn.create_state_machine(name=f'ss-test-sm-{uid}', definition=SFN_DEF, roleArn=sharedArn)['stateMachineArn']

        def fix():
            sfn.update_state_machine(stateMachineArn=smArn, roleArn=ownArn)

        _, after = assertFlagFixCycle(emu, 'iam', 'roleSharedAcrossComponents', 'Account', misconfigure, fix)
        assert list(after.values()) == [1], after
    finally:
        if smArn:
            _quiet(sfn.delete_state_machine, stateMachineArn=smArn)
        _quiet(lam.delete_function, FunctionName=fn)
        _quiet(iam.delete_role, RoleName=shared)
        _quiet(iam.delete_role, RoleName=own)


def test_role_shared_by_lambdas_only_not_flagged(emu, uid):
    """Lambda-only reuse is lambda.lambdaRoleReused's finding - not reported twice."""
    iam, lam = emu.client('iam'), emu.client('lambda')
    role = f'ss-test-lonly-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=_serviceTrust('lambda.amazonaws.com'))['Role']['Arn']
    fns = [f'ss-test-fn-a-{uid}', f'ss-test-fn-b-{uid}']
    try:
        for f in fns:
            lam.create_function(FunctionName=f, Runtime='python3.12', Role=arn, Handler='index.handler',
                                Code={'ZipFile': _zip()})
        res = runCheck(emu, 'iam', 'roleSharedAcrossComponents', 'Account').statuses()
        assert list(res.values()) == [1], res
    finally:
        for f in fns:
            _quiet(lam.delete_function, FunctionName=f)
        _quiet(iam.delete_role, RoleName=role)


# --------------------------------------------------------------------------- #
# dataStoreNoClassificationTag
# --------------------------------------------------------------------------- #
def test_data_store_classification_s3(emu_fresh, uid):
    emu = emu_fresh  # account-wide check: needs an empty account
    s3 = emu.client('s3')
    bucket = f'ss-test-class-{uid}'
    try:
        def misconfigure():
            s3.create_bucket(Bucket=bucket)
            s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [{'Key': 'Owner', 'Value': 'team-a'}]})

        def fix():
            s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [
                {'Key': 'Owner', 'Value': 'team-a'}, {'Key': 'DataClassification', 'Value': 'Confidential'}]})

        before, after = assertFlagFixCycle(emu, 'iam', 'dataStoreNoClassificationTag', 'Account', misconfigure, fix)
        assert list(after.values()) == [1], after
    finally:
        _quiet(s3.delete_bucket, Bucket=bucket)


def test_data_store_classification_efs(emu_fresh, uid):
    emu = emu_fresh  # account-wide check: needs an empty account
    """EFS tags come from DescribeFileSystems. (DynamoDB tags are not
    persisted by the emulator; the DynamoDB never-tagged path is covered in
    tests/test_stub_iam_identity3.py.)"""
    efs = emu.client('efs')
    fsId = None
    try:
        def misconfigure():
            nonlocal fsId
            fsId = efs.create_file_system(CreationToken=f'ss-test-{uid}',
                                          Tags=[{'Key': 'Name', 'Value': f'ss-test-{uid}'}])['FileSystemId']

        def fix():
            efs.tag_resource(ResourceId=fsId, Tags=[{'Key': 'data_classification', 'Value': 'restricted'}])

        _, after = assertFlagFixCycle(emu, 'iam', 'dataStoreNoClassificationTag', 'Account', misconfigure, fix)
        assert list(after.values()) == [1], after
    finally:
        if fsId:
            _quiet(efs.delete_file_system, FileSystemId=fsId)

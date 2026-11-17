"""Flag -> fix -> re-run tests for secretsmanager.secretChangeNotMonitored
against the local AWS Emulator. The check is account/region-level and reports
under the 'Secretsmanager::Account' resource; it runs only when the region
holds at least one secret, so each test creates one."""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck

CHECK = 'secretChangeNotMonitored'
RES = 'Secretsmanager::Account'


def _secret(emu, uid):
    sm = emu.client('secretsmanager')
    name = f'ss-test-{uid}'
    sm.create_secret(Name=name, SecretString='x')
    return sm, name


def _cleanupSecret(sm, name):
    try:
        sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    except Exception:
        pass


def _pattern(names):
    return json.dumps({
        'source': ['aws.secretsmanager'],
        'detail-type': ['AWS API Call via CloudTrail'],
        'detail': {'eventSource': ['secretsmanager.amazonaws.com'], 'eventName': names},
    })


def test_eventbridge_rule_without_target_then_with_target(emu, uid):
    sm, name = _secret(emu, uid)
    ev = emu.client('events')
    sns = emu.client('sns')
    rule = f'ss-sm-{uid}'
    topic = sns.create_topic(Name=f'ss-sm-{uid}')['TopicArn']
    try:
        def misconfigure():
            # A matching rule with no target alerts nobody.
            ev.put_rule(Name=rule, EventPattern=_pattern(['DeleteSecret', 'PutResourcePolicy']), State='ENABLED')

        def fix():
            ev.put_targets(Rule=rule, Targets=[{'Id': '1', 'Arn': topic}])

        assertFlagFixCycle(emu, 'secretsmanager', CHECK, RES, misconfigure, fix)
    finally:
        try:
            ev.remove_targets(Rule=rule, Ids=['1'])
        except Exception:
            pass
        try:
            ev.delete_rule(Name=rule)
        except Exception:
            pass
        sns.delete_topic(TopicArn=topic)
        _cleanupSecret(sm, name)


def test_eventbridge_partial_coverage_flags_then_full_passes(emu, uid):
    sm, name = _secret(emu, uid)
    ev = emu.client('events')
    sns = emu.client('sns')
    rule = f'ss-sm-{uid}'
    topic = sns.create_topic(Name=f'ss-sm-{uid}')['TopicArn']
    try:
        def misconfigure():
            # Only deletion is covered; policy changes go unnoticed. A
            # disabled catch-all rule must not count either.
            ev.put_rule(Name=rule, EventPattern=_pattern(['DeleteSecret']), State='ENABLED')
            ev.put_targets(Rule=rule, Targets=[{'Id': '1', 'Arn': topic}])
            ev.put_rule(Name=rule + '-off', EventPattern=json.dumps({'source': ['aws.secretsmanager']}),
                        State='DISABLED')
            ev.put_targets(Rule=rule + '-off', Targets=[{'Id': '1', 'Arn': topic}])

        def fix():
            ev.put_rule(Name=rule, EventPattern=json.dumps({
                'source': ['aws.secretsmanager'],
                'detail': {'eventName': [{'prefix': 'Delete'}, 'PutResourcePolicy']}}), State='ENABLED')

        before, _ = assertFlagFixCycle(emu, 'secretsmanager', CHECK, RES, misconfigure, fix)
        msg = runCheck(emu, 'secretsmanager', CHECK, RES).results[RES][CHECK][1]
        assert 'DeleteSecret' in msg and 'PutResourcePolicy' in msg
    finally:
        for r in (rule, rule + '-off'):
            try:
                ev.remove_targets(Rule=r, Ids=['1'])
            except Exception:
                pass
            try:
                ev.delete_rule(Name=r)
            except Exception:
                pass
        sns.delete_topic(TopicArn=topic)
        _cleanupSecret(sm, name)


def test_cloudtrail_metric_filter_needs_alarm(emu, uid):
    sm, name = _secret(emu, uid)
    s3 = emu.client('s3')
    logs = emu.client('logs')
    iam = emu.client('iam')
    ct = emu.client('cloudtrail')
    cw = emu.client('cloudwatch')
    sns = emu.client('sns')
    acct = emu.client('sts').get_caller_identity()['Account']
    bucket, lg, role, trail = f'ss-ct-{uid}', f'ss-ct-{uid}', f'ss-ct-{uid}', f'ss-ct-{uid}'
    alarm, ns, metric = f'ss-sm-{uid}', f'SS/{uid}', 'SecretChanges'
    topic = sns.create_topic(Name=f'ss-sm-{uid}')['TopicArn']
    s3.create_bucket(Bucket=bucket)
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
            'Version': '2012-10-17',
            'Statement': [
                {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
                 'Action': 's3:GetBucketAcl', 'Resource': f'arn:aws:s3:::{bucket}'},
                {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
                 'Action': 's3:PutObject', 'Resource': f'arn:aws:s3:::{bucket}/AWSLogs/{acct}/*',
                 'Condition': {'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control'}}}]}))
        logs.create_log_group(logGroupName=lg)
        lgArn = logs.describe_log_groups(logGroupNamePrefix=lg)['logGroups'][0]['arn']
        roleArn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        ct.create_trail(Name=trail, S3BucketName=bucket, IsMultiRegionTrail=True,
                        CloudWatchLogsLogGroupArn=lgArn, CloudWatchLogsRoleArn=roleArn)
        ct.start_logging(Name=trail)

        def misconfigure():
            # Metric filter exists but no alarm watches the metric.
            logs.put_metric_filter(
                logGroupName=lg, filterName='secret-changes',
                filterPattern='{ ($.eventSource = secretsmanager.amazonaws.com) && '
                              '(($.eventName = DeleteSecret) || ($.eventName = PutResourcePolicy)) }',
                metricTransformations=[{'metricName': metric, 'metricNamespace': ns, 'metricValue': '1'}])

        def fix():
            cw.put_metric_alarm(AlarmName=alarm, MetricName=metric, Namespace=ns, Statistic='Sum',
                                Period=300, EvaluationPeriods=1, Threshold=1,
                                ComparisonOperator='GreaterThanOrEqualToThreshold', AlarmActions=[topic])

        assertFlagFixCycle(emu, 'secretsmanager', CHECK, RES, misconfigure, fix)
    finally:
        for fn in (lambda: cw.delete_alarms(AlarmNames=[alarm]),
                   lambda: ct.delete_trail(Name=trail),
                   lambda: logs.delete_log_group(logGroupName=lg),
                   lambda: iam.delete_role(RoleName=role),
                   lambda: s3.delete_bucket_policy(Bucket=bucket),
                   lambda: s3.delete_bucket(Bucket=bucket),
                   lambda: sns.delete_topic(TopicArn=topic)):
            try:
                fn()
            except Exception:
                pass
        _cleanupSecret(sm, name)

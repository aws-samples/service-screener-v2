"""Flag -> fix -> re-run tests for the WAFS2027 CloudWatch checks (chunk 1).

Account-level checks report under the resource 'Account::us-east-1'. Each test
restores the account-level state it changes in `finally`.
"""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck, REGION

ACCOUNT_RES = f'Account::{REGION}'


def _cycle(emu, check, resource, misconfigure, fix):
    """Flag -> fix -> re-run, and require an explicit PASS (1) after the fix."""
    before, after = assertFlagFixCycle(emu, 'cloudwatch', check, resource, misconfigure, fix)
    assert set(after.values()) == {1}, runCheck(emu, 'cloudwatch', check, resource).results
    return before, after


def _acct(emu):
    return emu.client('sts').get_caller_identity()['Account']


def _quiet(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        pass


def _logsKey(emu, uid):
    """KMS key whose policy lets CloudWatch Logs use it (required by AssociateKmsKey)."""
    acct = _acct(emu)
    policy = {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{acct}:root'}, 'Action': 'kms:*', 'Resource': '*'},
        {'Effect': 'Allow', 'Principal': {'Service': f'logs.{REGION}.amazonaws.com'},
         'Action': ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
         'Resource': '*',
         'Condition': {'ArnLike': {'kms:EncryptionContext:aws:logs:arn': f'arn:aws:logs:{REGION}:{acct}:*'}}}]}
    return emu.client('kms').create_key(Description=f'ss-test-{uid}', Policy=json.dumps(policy))['KeyMetadata']['Arn']


def _trailWithLogGroup(emu, uid, lgName):
    """Create a bucket + trail delivering to CloudWatch Logs group lgName."""
    acct = _acct(emu)
    s3 = emu.client('s3')
    ct = emu.client('cloudtrail')
    iam = emu.client('iam')
    bucket = f'ss-ct-{uid}'
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        'Version': '2012-10-17',
        'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
             'Action': 's3:GetBucketAcl', 'Resource': f'arn:aws:s3:::{bucket}'},
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
             'Action': 's3:PutObject', 'Resource': f'arn:aws:s3:::{bucket}/AWSLogs/{acct}/*',
             'Condition': {'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control'}}}]}))
    role = iam.create_role(RoleName=f'ss-ct-{uid}', AssumeRolePolicyDocument=json.dumps({
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
                       'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
    lgArn = f'arn:aws:logs:{REGION}:{acct}:log-group:{lgName}:*'
    ct.create_trail(Name=f'ss-trail-{uid}', S3BucketName=bucket,
                    CloudWatchLogsLogGroupArn=lgArn, CloudWatchLogsRoleArn=role)

    def cleanup():
        _quiet(ct.delete_trail, Name=f'ss-trail-{uid}')
        _quiet(iam.delete_role, RoleName=f'ss-ct-{uid}')
        _quiet(s3.delete_bucket_policy, Bucket=bucket)
        try:
            for o in s3.list_objects_v2(Bucket=bucket).get('Contents', []):
                s3.delete_object(Bucket=bucket, Key=o['Key'])
        except Exception:
            pass
        _quiet(s3.delete_bucket, Bucket=bucket)
    return cleanup


def test_cw_cross_account_observability(emu, uid):
    oam = emu.client('oam')
    sinkName = f'ss-sink-{uid}'
    created = {}
    try:
        def misconfigure():
            assert not oam.list_links()['Items']
            assert not oam.list_sinks()['Items'], 'pre-existing OAM sink in emulator'

        def fix():
            created['arn'] = oam.create_sink(Name=sinkName)['Arn']

        _cycle(emu, 'cwCrossAccountObservabilityNotLinked', ACCOUNT_RES,
                           misconfigure, fix)
    finally:
        if created.get('arn'):
            _quiet(oam.delete_sink, Identifier=created['arn'])


def test_cw_trail_log_group_not_kms_encrypted(emu, uid):
    logs = emu.client('logs')
    kms = emu.client('kms')
    lg = f'/ss/trail/{uid}'
    logs.create_log_group(logGroupName=lg)
    cleanupTrail = None
    keyId = None
    try:
        def misconfigure():
            nonlocal cleanupTrail
            cleanupTrail = _trailWithLogGroup(emu, uid, lg)

        def fix():
            nonlocal keyId
            keyId = _logsKey(emu, uid)
            logs.associate_kms_key(logGroupName=lg, kmsKeyId=keyId)

        _cycle(emu, 'cwLogGroupNotKmsEncrypted', ACCOUNT_RES,
                                           misconfigure, fix)
    finally:
        if cleanupTrail:
            cleanupTrail()
        _quiet(logs.delete_log_group, logGroupName=lg)
        if keyId:
            _quiet(kms.schedule_key_deletion, KeyId=keyId, PendingWindowInDays=7)


def test_cw_flow_log_group_not_kms_encrypted(emu, uid):
    logs = emu.client('logs')
    kms = emu.client('kms')
    ec2 = emu.client('ec2')
    iam = emu.client('iam')
    lg = f'/ss/flow/{uid}'
    logs.create_log_group(logGroupName=lg)
    vpc = ec2.create_vpc(CidrBlock='10.77.0.0/16')['Vpc']['VpcId']
    role = iam.create_role(RoleName=f'ss-fl-{uid}', AssumeRolePolicyDocument=json.dumps({
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'vpc-flow-logs.amazonaws.com'},
                       'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
    flowIds = []
    keyId = None
    try:
        def misconfigure():
            r = ec2.create_flow_logs(ResourceIds=[vpc], ResourceType='VPC', TrafficType='ALL',
                                     LogDestinationType='cloud-watch-logs', LogGroupName=lg,
                                     DeliverLogsPermissionArn=role)
            flowIds.extend(r.get('FlowLogIds', []))

        def fix():
            nonlocal keyId
            keyId = _logsKey(emu, uid)
            logs.associate_kms_key(logGroupName=lg, kmsKeyId=keyId)

        _cycle(emu, 'cwLogGroupNotKmsEncrypted', ACCOUNT_RES, misconfigure, fix)
    finally:
        if flowIds:
            _quiet(ec2.delete_flow_logs, FlowLogIds=flowIds)
        _quiet(ec2.delete_vpc, VpcId=vpc)
        _quiet(iam.delete_role, RoleName=f'ss-fl-{uid}')
        _quiet(logs.delete_log_group, logGroupName=lg)
        if keyId:
            _quiet(kms.schedule_key_deletion, KeyId=keyId, PendingWindowInDays=7)


DP_POLICY = {
    'Name': 'ss-dp', 'Description': '', 'Version': '2021-06-01',
    'Statement': [
        {'Sid': 'audit', 'DataIdentifier': ['arn:aws:dataprotection::aws:data-identifier/EmailAddress'],
         'Operation': {'Audit': {'FindingsDestination': {}}}},
        {'Sid': 'redact', 'DataIdentifier': ['arn:aws:dataprotection::aws:data-identifier/EmailAddress'],
         'Operation': {'Deidentify': {'MaskConfig': {}}}}]}


def test_cw_logs_no_data_protection_policy(emu, uid):
    logs = emu.client('logs')
    lg = f'/ss/dp/{uid}'
    logs.create_log_group(logGroupName=lg)
    try:
        def misconfigure():
            assert not logs.describe_account_policies(policyType='DATA_PROTECTION_POLICY')['accountPolicies']

        def fix():
            logs.put_data_protection_policy(logGroupIdentifier=lg, policyDocument=json.dumps(DP_POLICY))

        _cycle(emu, 'cwLogsNoDataProtectionPolicy', ACCOUNT_RES, misconfigure, fix)
    finally:
        _quiet(logs.delete_data_protection_policy, logGroupIdentifier=lg)
        _quiet(logs.delete_log_group, logGroupName=lg)


def test_cw_logs_account_data_protection_policy(emu, uid):
    logs = emu.client('logs')
    lg = f'/ss/dpa/{uid}'
    name = f'ss-dp-{uid}'
    logs.create_log_group(logGroupName=lg)
    try:
        def fix():
            logs.put_account_policy(policyName=name, policyType='DATA_PROTECTION_POLICY', scope='ALL',
                                    policyDocument=json.dumps(DP_POLICY))

        _cycle(emu, 'cwLogsNoDataProtectionPolicy', ACCOUNT_RES, lambda: None, fix)
    finally:
        _quiet(logs.delete_account_policy, policyName=name, policyType='DATA_PROTECTION_POLICY')
        _quiet(logs.delete_log_group, logGroupName=lg)


def test_detection_disable_no_alarm_eventbridge(emu, uid):
    gd = emu.client('guardduty')
    ev = emu.client('events')
    sns = emu.client('sns')
    rule = f'ss-detect-{uid}'
    state = {}
    try:
        def misconfigure():
            state['det'] = gd.create_detector(Enable=True)['DetectorId']

        def fix():
            state['topic'] = sns.create_topic(Name=f'ss-detect-{uid}')['TopicArn']
            ev.put_rule(Name=rule, State='ENABLED', EventPattern=json.dumps({
                'source': ['aws.guardduty', 'aws.securityhub', 'aws.access-analyzer'],
                'detail-type': ['AWS API Call via CloudTrail'],
                'detail': {'eventName': ['DeleteDetector', 'DisassociateFromAdministratorAccount',
                                         'DisableSecurityHub', 'DeleteAnalyzer']}}))
            ev.put_targets(Rule=rule, Targets=[{'Id': '1', 'Arn': state['topic']}])

        _cycle(emu, 'detectionDisableNoAlarm', ACCOUNT_RES, misconfigure, fix)
    finally:
        _quiet(ev.remove_targets, Rule=rule, Ids=['1'])
        _quiet(ev.delete_rule, Name=rule)
        if state.get('topic'):
            _quiet(sns.delete_topic, TopicArn=state['topic'])
        if state.get('det'):
            _quiet(gd.delete_detector, DetectorId=state['det'])


def test_detection_disable_no_alarm_rule_without_target_not_credited(emu, uid):
    """A matching rule with no target alerts nobody, so it must not count."""
    gd = emu.client('guardduty')
    ev = emu.client('events')
    rule = f'ss-detect-nt-{uid}'
    det = gd.create_detector(Enable=True)['DetectorId']
    try:
        ev.put_rule(Name=rule, State='ENABLED', EventPattern=json.dumps({'source': ['aws.guardduty']}))
        res = runCheck(emu, 'cloudwatch', 'detectionDisableNoAlarm', ACCOUNT_RES)
        assert res.statuses() == {ACCOUNT_RES: -1}, res.results
    finally:
        _quiet(ev.delete_rule, Name=rule)
        _quiet(gd.delete_detector, DetectorId=det)


def test_detection_disable_no_alarm_metric_filter(emu, uid):
    aa = emu.client('accessanalyzer')
    logs = emu.client('logs')
    cw = emu.client('cloudwatch')
    sns = emu.client('sns')
    lg = f'/ss/trail-mf/{uid}'
    analyzer = f'ss-aa-{uid}'
    alarm = f'ss-aa-alarm-{uid}'
    logs.create_log_group(logGroupName=lg)
    cleanupTrail = _trailWithLogGroup(emu, uid, lg)
    topic = sns.create_topic(Name=f'ss-aa-{uid}')['TopicArn']
    try:
        def misconfigure():
            aa.create_analyzer(analyzerName=analyzer, type='ACCOUNT')

        def fix():
            logs.put_metric_filter(logGroupName=lg, filterName=f'ss-aa-{uid}',
                                   filterPattern='{ ($.eventSource = access-analyzer.amazonaws.com) && '
                                                 '($.eventName = DeleteAnalyzer) }',
                                   metricTransformations=[{'metricName': f'AADeleted{uid}',
                                                           'metricNamespace': 'CloudTrailMetrics',
                                                           'metricValue': '1'}])
            cw.put_metric_alarm(AlarmName=alarm, Namespace='CloudTrailMetrics', MetricName=f'AADeleted{uid}',
                                Statistic='Sum', Period=300, EvaluationPeriods=1, Threshold=1,
                                ComparisonOperator='GreaterThanOrEqualToThreshold', AlarmActions=[topic])

        _cycle(emu, 'detectionDisableNoAlarm', ACCOUNT_RES, misconfigure, fix)
    finally:
        _quiet(cw.delete_alarms, AlarmNames=[alarm])
        _quiet(logs.delete_metric_filter, logGroupName=lg, filterName=f'ss-aa-{uid}')
        _quiet(aa.delete_analyzer, analyzerName=analyzer)
        _quiet(sns.delete_topic, TopicArn=topic)
        cleanupTrail()
        _quiet(logs.delete_log_group, logGroupName=lg)


def test_logs_resource_policy_public(emu, uid):
    logs = emu.client('logs')
    acct = _acct(emu)
    name = f'ss-rp-{uid}'
    try:
        def misconfigure():
            logs.put_resource_policy(policyName=name, policyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': '*'},
                               'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                               'Resource': f'arn:aws:logs:{REGION}:{acct}:log-group:*'}]}))

        def fix():
            logs.put_resource_policy(policyName=name, policyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'route53.amazonaws.com'},
                               'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'],
                               'Resource': f'arn:aws:logs:{REGION}:{acct}:log-group:*',
                               'Condition': {'StringEquals': {'aws:SourceAccount': acct}}}]}))

        _cycle(emu, 'logsResourcePolicyPublic', ACCOUNT_RES, misconfigure, fix)
    finally:
        _quiet(logs.delete_resource_policy, policyName=name)


def test_cw_alarm_actions_disabled(emu, uid):
    cw = emu.client('cloudwatch')
    sns = emu.client('sns')
    alarm = f'ss-disabled-{uid}'
    topic = sns.create_topic(Name=f'ss-alarm-{uid}')['TopicArn']
    try:
        def misconfigure():
            cw.put_metric_alarm(AlarmName=alarm, Namespace='AWS/EC2', MetricName='CPUUtilization',
                                Statistic='Average', Period=300, EvaluationPeriods=1, Threshold=90,
                                ComparisonOperator='GreaterThanThreshold', AlarmActions=[topic],
                                ActionsEnabled=False)

        def fix():
            cw.enable_alarm_actions(AlarmNames=[alarm])

        _cycle(emu, 'cwAlarmActionsDisabled', f'Alarm::{alarm}', misconfigure, fix)
    finally:
        _quiet(cw.delete_alarms, AlarmNames=[alarm])
        _quiet(sns.delete_topic, TopicArn=topic)


def test_cw_logs_centralization_rule_missing(emu, uid):
    oa = emu.client('observabilityadmin')
    name = f'ss-central-{uid}'
    acct = _acct(emu)
    created = {}
    try:
        def misconfigure():
            assert not oa.list_centralization_rules_for_organization(AllRegions=True)['CentralizationRuleSummaries']

        def fix():
            created['arn'] = oa.create_centralization_rule_for_organization(RuleName=name, Rule={
                'Source': {'Regions': [REGION],
                           'SourceLogsConfiguration': {'LogGroupSelectionCriteria': '*',
                                                       'EncryptedLogGroupStrategy': 'SKIP'}},
                'Destination': {'Region': REGION, 'Account': acct}})['RuleArn']

        _cycle(emu, 'cwLogsCentralizationRuleMissing', ACCOUNT_RES, misconfigure, fix)
    finally:
        if created.get('arn'):
            _quiet(oa.delete_centralization_rule_for_organization, RuleIdentifier=created['arn'])


def test_cw_no_anomaly_detection(emu, uid):
    logs = emu.client('logs')
    cw = emu.client('cloudwatch')
    lg = f'/ss/trail-ad/{uid}'
    metric = f'RootUse{uid}'
    logs.create_log_group(logGroupName=lg)
    cleanupTrail = None
    try:
        def misconfigure():
            nonlocal cleanupTrail
            cleanupTrail = _trailWithLogGroup(emu, uid, lg)
            logs.put_metric_filter(logGroupName=lg, filterName=f'ss-root-{uid}',
                                   filterPattern='{ $.userIdentity.type = "Root" }',
                                   metricTransformations=[{'metricName': metric,
                                                           'metricNamespace': 'CloudTrailMetrics',
                                                           'metricValue': '1'}])

        def fix():
            cw.put_anomaly_detector(SingleMetricAnomalyDetector={
                'Namespace': 'CloudTrailMetrics', 'MetricName': metric, 'Stat': 'Sum'})

        _cycle(emu, 'cwNoAnomalyDetection', ACCOUNT_RES, misconfigure, fix)
    finally:
        _quiet(cw.delete_anomaly_detector, SingleMetricAnomalyDetector={
            'Namespace': 'CloudTrailMetrics', 'MetricName': metric, 'Stat': 'Sum'})
        _quiet(logs.delete_metric_filter, logGroupName=lg, filterName=f'ss-root-{uid}')
        if cleanupTrail:
            cleanupTrail()
        _quiet(logs.delete_log_group, logGroupName=lg)

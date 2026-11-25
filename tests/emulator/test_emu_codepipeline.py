"""Flag -> fix -> re-run tests for services/codepipeline against the AWS Emulator."""
import copy
import json

from tests.emulator.conftest import assertFlagFixCycle

TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Principal': {'Service': 'codepipeline.amazonaws.com'},
    'Action': 'sts:AssumeRole'}]})
ADMIN_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
ADMIN_DOC = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Action': '*:*', 'Resource': '*'}]})
SCOPED_DOC = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:PutObject'], 'Resource': 'arn:aws:s3:::b/*'}]})


def _src(bucket):
    return {'name': 'Source', 'actions': [{
        'name': 'Src', 'actionTypeId': {'category': 'Source', 'owner': 'AWS', 'provider': 'S3', 'version': '1'},
        'configuration': {'S3Bucket': bucket, 'S3ObjectKey': 'src.zip'},
        'outputArtifacts': [{'name': 'out'}]}]}


def _deploy(bucket, roleArn=None, rollback=False):
    action = {'name': 'Publish', 'actionTypeId': {'category': 'Deploy', 'owner': 'AWS', 'provider': 'S3', 'version': '1'},
              'configuration': {'BucketName': bucket, 'Extract': 'true'},
              'inputArtifacts': [{'name': 'out'}]}
    if roleArn:
        action['roleArn'] = roleArn
    stage = {'name': 'Release', 'actions': [action]}
    if rollback:
        stage['onFailure'] = {'result': 'ROLLBACK'}
    return stage


def _verify(project):
    return {'name': 'Verify', 'actions': [{
        'name': 'Check', 'actionTypeId': {'category': 'Test', 'owner': 'AWS', 'provider': 'CodeBuild', 'version': '1'},
        'configuration': {'ProjectName': project}, 'inputArtifacts': [{'name': 'out'}]}]}


class Env:
    def __init__(self, emu, uid):
        self.iam = emu.client('iam')
        self.cp = emu.client('codepipeline')
        self.s3 = emu.client('s3')
        self.name = f'ss-cp-{uid}'
        self.role = f'ss-cp-role-{uid}'
        self.actionRole = f'ss-cp-act-{uid}'
        self.bucket = f'ss-cp-art-{uid}'
        self.roleArn = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
        self.actionRoleArn = self.iam.create_role(RoleName=self.actionRole, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
        self.s3.create_bucket(Bucket=self.bucket)

    def create(self, stages, pipelineType='V2'):
        self.cp.create_pipeline(pipeline={
            'name': self.name, 'roleArn': self.roleArn, 'pipelineType': pipelineType,
            'artifactStore': {'type': 'S3', 'location': self.bucket}, 'stages': stages})
        return self.cp.get_pipeline(name=self.name)['metadata']['pipelineArn']

    def update(self, stages):
        p = copy.deepcopy(self.cp.get_pipeline(name=self.name)['pipeline'])
        p['stages'] = stages
        self.cp.update_pipeline(pipeline=p)

    def cleanup(self):
        for fn in (lambda: self.cp.delete_pipeline(name=self.name),):
            try:
                fn()
            except Exception:
                pass
        for role in (self.role, self.actionRole):
            try:
                for p in self.iam.list_attached_role_policies(RoleName=role)['AttachedPolicies']:
                    self.iam.detach_role_policy(RoleName=role, PolicyArn=p['PolicyArn'])
                for n in self.iam.list_role_policies(RoleName=role)['PolicyNames']:
                    self.iam.delete_role_policy(RoleName=role, PolicyName=n)
                self.iam.delete_role(RoleName=role)
            except Exception:
                pass
        try:
            self.s3.delete_bucket(Bucket=self.bucket)
        except Exception:
            pass


def test_codepipeline_role_admin_managed(emu, uid):
    env = Env(emu, uid)
    try:
        env.create([_src(env.bucket), _deploy(env.bucket, rollback=True)])

        def misconfigure():
            env.iam.attach_role_policy(RoleName=env.role, PolicyArn=ADMIN_ARN)

        def fix():
            env.iam.detach_role_policy(RoleName=env.role, PolicyArn=ADMIN_ARN)
            env.iam.put_role_policy(RoleName=env.role, PolicyName='scoped', PolicyDocument=SCOPED_DOC)

        assertFlagFixCycle(emu, 'codepipeline', 'pipelineRoleOverprivileged', env.name, misconfigure, fix)
    finally:
        env.cleanup()


def test_codepipeline_action_role_admin_inline(emu, uid):
    env = Env(emu, uid)
    try:
        env.create([_src(env.bucket), _deploy(env.bucket, roleArn=env.actionRoleArn, rollback=True)])

        def misconfigure():
            env.iam.put_role_policy(RoleName=env.actionRole, PolicyName='admin', PolicyDocument=ADMIN_DOC)

        def fix():
            env.iam.put_role_policy(RoleName=env.actionRole, PolicyName='admin', PolicyDocument=SCOPED_DOC)

        assertFlagFixCycle(emu, 'codepipeline', 'pipelineRoleOverprivileged', env.name, misconfigure, fix)
    finally:
        env.cleanup()


def test_codepipeline_customer_managed_admin(emu, uid):
    env = Env(emu, uid)
    pol = env.iam.create_policy(PolicyName=f'ss-cp-admin-{uid}', PolicyDocument=ADMIN_DOC)['Policy']['Arn']
    try:
        env.create([_src(env.bucket), _deploy(env.bucket, rollback=True)])

        def misconfigure():
            env.iam.attach_role_policy(RoleName=env.role, PolicyArn=pol)

        def fix():
            env.iam.detach_role_policy(RoleName=env.role, PolicyArn=pol)

        assertFlagFixCycle(emu, 'codepipeline', 'pipelineRoleOverprivileged', env.name, misconfigure, fix)
    finally:
        env.cleanup()
        env.iam.delete_policy(PolicyArn=pol)


def test_codepipeline_no_stage_rollback(emu, uid):
    env = Env(emu, uid)
    try:
        env.create([_src(env.bucket), _deploy(env.bucket, rollback=True)])

        def misconfigure():
            env.update([_src(env.bucket), _deploy(env.bucket, rollback=False)])

        def fix():
            env.update([_src(env.bucket), _deploy(env.bucket, rollback=True)])

        assertFlagFixCycle(emu, 'codepipeline', 'codepipelineNoStageRollback', env.name, misconfigure, fix)
    finally:
        env.cleanup()


def test_codepipeline_no_notification_codestar(emu, uid):
    env = Env(emu, uid)
    cs = emu.client('codestar-notifications')
    sns = emu.client('sns')
    topic = sns.create_topic(Name=f'ss-cp-topic-{uid}')['TopicArn']
    state = {}
    try:
        arn = env.create([_src(env.bucket), _deploy(env.bucket, rollback=True)])

        def misconfigure():
            ## Rule on the pipeline but only for success events: must not count.
            state['succ'] = cs.create_notification_rule(
                Name=f'ss-cp-ok-{uid}', Resource=arn, DetailType='BASIC',
                EventTypeIds=['codepipeline-pipeline-pipeline-execution-succeeded'],
                Targets=[{'TargetType': 'SNS', 'TargetAddress': topic}])['Arn']

        def fix():
            state['fail'] = cs.create_notification_rule(
                Name=f'ss-cp-fail-{uid}', Resource=arn, DetailType='BASIC',
                EventTypeIds=['codepipeline-pipeline-pipeline-execution-failed'],
                Targets=[{'TargetType': 'SNS', 'TargetAddress': topic}])['Arn']

        assertFlagFixCycle(emu, 'codepipeline', 'pipelineNoEventNotification', env.name, misconfigure, fix)
    finally:
        for a in state.values():
            try:
                cs.delete_notification_rule(Arn=a)
            except Exception:
                pass
        sns.delete_topic(TopicArn=topic)
        env.cleanup()


def test_codepipeline_no_notification_eventbridge(emu, uid):
    env = Env(emu, uid)
    ev = emu.client('events')
    sns = emu.client('sns')
    topic = sns.create_topic(Name=f'ss-cp-topic-{uid}')['TopicArn']
    rule = f'ss-cp-rule-{uid}'
    try:
        env.create([_src(env.bucket), _deploy(env.bucket, rollback=True)])

        def misconfigure():
            ## Rule for a different pipeline: must not count.
            ev.put_rule(Name=rule, State='ENABLED', EventPattern=json.dumps({
                'source': ['aws.codepipeline'],
                'detail-type': ['CodePipeline Pipeline Execution State Change'],
                'detail': {'pipeline': ['some-other-pipeline'], 'state': ['FAILED']}}))
            ev.put_targets(Rule=rule, Targets=[{'Id': 't1', 'Arn': topic}])

        def fix():
            ev.put_rule(Name=rule, State='ENABLED', EventPattern=json.dumps({
                'source': ['aws.codepipeline'],
                'detail-type': ['CodePipeline Pipeline Execution State Change'],
                'detail': {'pipeline': [env.name], 'state': ['FAILED']}}))

        assertFlagFixCycle(emu, 'codepipeline', 'pipelineNoEventNotification', env.name, misconfigure, fix)
    finally:
        try:
            ev.remove_targets(Rule=rule, Ids=['t1'])
            ev.delete_rule(Name=rule)
        except Exception:
            pass
        sns.delete_topic(TopicArn=topic)
        env.cleanup()


def test_codepipeline_no_security_test_action(emu, uid):
    env = Env(emu, uid)
    try:
        env.create([_src(env.bucket), _deploy(env.bucket, rollback=True)])

        def misconfigure():
            pass  # Source -> Release only, no test step

        def fix():
            env.update([_src(env.bucket), _verify(f'proj-{uid}'), _deploy(env.bucket, rollback=True)])

        assertFlagFixCycle(emu, 'codepipeline', 'pipelineNoSecurityTestAction', env.name, misconfigure, fix)
    finally:
        env.cleanup()

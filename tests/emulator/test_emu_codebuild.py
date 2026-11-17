"""Flag -> fix -> re-run tests for the WAFS2027 CodeBuild checks against the local AWS Emulator."""
import json

from tests.emulator.conftest import assertFlagFixCycle

TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Principal': {'Service': 'codebuild.amazonaws.com'},
    'Action': 'sts:AssumeRole'}]})
ADMIN_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
ENV = {'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0',
       'computeType': 'BUILD_GENERAL1_SMALL'}
BUILDSPEC_NO_REPORTS = 'version: 0.2\nphases:\n  build:\n    commands:\n      - echo build\n'
BUILDSPEC_REPORTS = BUILDSPEC_NO_REPORTS + 'reports:\n  unit:\n    files:\n      - "report.xml"\n'


def _role(iam, name):
    return iam.create_role(RoleName=name, AssumeRolePolicyDocument=TRUST)['Role']['Arn']


def _cleanupRole(iam, name):
    try:
        for p in iam.list_attached_role_policies(RoleName=name)['AttachedPolicies']:
            iam.detach_role_policy(RoleName=name, PolicyArn=p['PolicyArn'])
        for p in iam.list_role_policies(RoleName=name)['PolicyNames']:
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
    except Exception:
        pass


def _noSourceProject(cb, name, roleArn, buildspec=BUILDSPEC_NO_REPORTS):
    cb.create_project(name=name, source={'type': 'NO_SOURCE', 'buildspec': buildspec},
                      artifacts={'type': 'NO_ARTIFACTS'}, environment=ENV, serviceRole=roleArn)


def test_cb_service_role_admin_managed(emu, uid):
    iam, cb = emu.client('iam'), emu.client('codebuild')
    role, project = f'ss-cb-role-{uid}', f'ss-cb-adm-{uid}'
    arn = _role(iam, role)
    try:
        _noSourceProject(cb, project, arn)
        assertFlagFixCycle(
            emu, 'codebuild', 'cbServiceRoleOverprivileged', project,
            lambda: iam.attach_role_policy(RoleName=role, PolicyArn=ADMIN_ARN),
            lambda: iam.detach_role_policy(RoleName=role, PolicyArn=ADMIN_ARN))
    finally:
        try:
            cb.delete_project(name=project)
        except Exception:
            pass
        _cleanupRole(iam, role)


def test_cb_service_role_admin_inline_and_customer_managed(emu, uid):
    iam, cb = emu.client('iam'), emu.client('codebuild')
    role, project = f'ss-cb-role-{uid}', f'ss-cb-inl-{uid}'
    arn = _role(iam, role)
    adminDoc = json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': '*:*', 'Resource': '*'}]})
    scopedDoc = json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': '*'},
        {'Effect': 'Allow', 'Action': '*', 'Resource': 'arn:aws:s3:::only-this-bucket/*'}]})
    cmArn = iam.create_policy(PolicyName=f'ss-cb-cm-{uid}', PolicyDocument=adminDoc)['Policy']['Arn']
    try:
        _noSourceProject(cb, project, arn)

        def misconfigure():
            iam.put_role_policy(RoleName=role, PolicyName='inline', PolicyDocument=adminDoc)
            iam.attach_role_policy(RoleName=role, PolicyArn=cmArn)

        def fix():
            iam.detach_role_policy(RoleName=role, PolicyArn=cmArn)
            iam.put_role_policy(RoleName=role, PolicyName='inline', PolicyDocument=scopedDoc)

        assertFlagFixCycle(emu, 'codebuild', 'cbServiceRoleOverprivileged', project, misconfigure, fix)
    finally:
        try:
            cb.delete_project(name=project)
        except Exception:
            pass
        _cleanupRole(iam, role)
        try:
            iam.delete_policy(PolicyArn=cmArn)
        except Exception:
            pass


def test_cb_webhook_unfiltered(emu, uid):
    """create_webhook needs an account-level GitHub source credential; one is
    imported only if none exists, and removed again in finally."""
    iam, cb = emu.client('iam'), emu.client('codebuild')
    role, project = f'ss-cb-role-{uid}', f'ss-cb-wh-{uid}'
    arn = _role(iam, role)
    existing = [c for c in cb.list_source_credentials().get('sourceCredentialsInfos', [])
                if c.get('serverType') == 'GITHUB']
    importedArn = None
    if not existing:
        importedArn = cb.import_source_credentials(
            token='emulator-fake-token', serverType='GITHUB',
            authType='PERSONAL_ACCESS_TOKEN')['arn']
    try:
        cb.create_project(name=project,
                          source={'type': 'GITHUB', 'location': 'https://github.com/example/repo.git'},
                          artifacts={'type': 'NO_ARTIFACTS'}, environment=ENV, serviceRole=arn)

        def misconfigure():
            cb.create_webhook(projectName=project, filterGroups=[[
                {'type': 'EVENT', 'pattern': 'PUSH, PULL_REQUEST_CREATED, PULL_REQUEST_UPDATED'}]])

        def fix():
            cb.update_webhook(projectName=project, filterGroups=[[
                {'type': 'EVENT', 'pattern': 'PUSH, PULL_REQUEST_CREATED, PULL_REQUEST_UPDATED'},
                {'type': 'ACTOR_ACCOUNT_ID', 'pattern': '^(1234567|7654321)$'}]])

        assertFlagFixCycle(emu, 'codebuild', 'cbWebhookUnfiltered', project, misconfigure, fix)
    finally:
        try:
            cb.delete_webhook(projectName=project)
        except Exception:
            pass
        try:
            cb.delete_project(name=project)
        except Exception:
            pass
        if importedArn:
            try:
                cb.delete_source_credentials(arn=importedArn)
            except Exception:
                pass
        _cleanupRole(iam, role)


def test_cb_project_no_test_reports(emu, uid):
    iam, cb = emu.client('iam'), emu.client('codebuild')
    role, project = f'ss-cb-role-{uid}', f'ss-cb-rep-{uid}'
    arn = _role(iam, role)
    try:
        _noSourceProject(cb, project, arn, BUILDSPEC_REPORTS)
        assertFlagFixCycle(
            emu, 'codebuild', 'cbProjectNoTestReports', project,
            lambda: cb.update_project(name=project, source={'type': 'NO_SOURCE', 'buildspec': BUILDSPEC_NO_REPORTS}),
            lambda: cb.update_project(name=project, source={'type': 'NO_SOURCE', 'buildspec': BUILDSPEC_REPORTS}))
    finally:
        try:
            cb.delete_project(name=project)
        except Exception:
            pass
        _cleanupRole(iam, role)

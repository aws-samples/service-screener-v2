"""Flag -> fix -> re-run tests for the WAFS2027 ECS checks against the local AWS Emulator."""
import json
import time

from tests.emulator.conftest import assertFlagFixCycle

TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Principal': {'Service': 'ecs-tasks.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})
SCOPED = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': 'arn:aws:s3:::example-bucket/*'}]})
ADMIN_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'


def _container():
    return [{'name': 'app', 'image': 'public.ecr.aws/nginx/nginx:1.27', 'memory': 128, 'essential': True}]


def test_ecs_task_role_overprivileged_managed_admin(emu, uid):
    iam, ecs = emu.client('iam'), emu.client('ecs')
    role, family = f'ss-ecs-task-{uid}', f'ss-td-{uid}'
    roleArn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    try:
        def misconfigure():
            iam.attach_role_policy(RoleName=role, PolicyArn=ADMIN_ARN)
            ecs.register_task_definition(family=family, taskRoleArn=roleArn, containerDefinitions=_container())

        def fix():
            iam.detach_role_policy(RoleName=role, PolicyArn=ADMIN_ARN)
            iam.put_role_policy(RoleName=role, PolicyName='scoped', PolicyDocument=SCOPED)

        assertFlagFixCycle(emu, 'ecs', 'ecsTaskRoleOverprivileged', f'TaskDef::{family}:', misconfigure, fix)
    finally:
        _cleanupRole(iam, role)
        _cleanupTaskDefs(ecs, family)


def test_ecs_task_role_overprivileged_inline_wildcard(emu, uid):
    iam, ecs = emu.client('iam'), emu.client('ecs')
    role, family = f'ss-ecs-task-{uid}', f'ss-td-{uid}'
    roleArn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    try:
        def misconfigure():
            iam.put_role_policy(RoleName=role, PolicyName='broad', PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': {'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'}}))
            ecs.register_task_definition(family=family, taskRoleArn=roleArn, containerDefinitions=_container())

        def fix():
            iam.put_role_policy(RoleName=role, PolicyName='broad', PolicyDocument=SCOPED)

        assertFlagFixCycle(emu, 'ecs', 'ecsTaskRoleOverprivileged', f'TaskDef::{family}:', misconfigure, fix)
    finally:
        _cleanupRole(iam, role)
        _cleanupTaskDefs(ecs, family)


def test_ecs_exec_enabled_services(emu, uid):
    ecs, iam = emu.client('ecs'), emu.client('iam')
    cluster, family, svc, role = f'ss-cl-{uid}', f'ss-td-{uid}', f'ss-svc-{uid}', f'ss-ecs-task-{uid}'
    ecs.create_cluster(clusterName=cluster)
    roleArn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    try:
        # ECS Exec requires a task role (it uses SSM messages channels).
        tdArn = ecs.register_task_definition(family=family, taskRoleArn=roleArn, containerDefinitions=_container())[
            'taskDefinition']['taskDefinitionArn']

        def misconfigure():
            ecs.create_service(cluster=cluster, serviceName=svc, taskDefinition=tdArn, desiredCount=0,
                               launchType='EC2', enableExecuteCommand=True)

        def fix():
            ecs.update_service(cluster=cluster, service=svc, enableExecuteCommand=False)

        assertFlagFixCycle(emu, 'ecs', 'ecsExecEnabledServices', f'Service::{cluster}/{svc}', misconfigure, fix)
    finally:
        try:
            ecs.delete_service(cluster=cluster, service=svc, force=True)
        except Exception:
            pass
        _cleanupTaskDefs(ecs, family)
        _deleteCluster(ecs, cluster)
        _cleanupRole(iam, role)


def test_ecs_container_agent_outdated(emu, uid):
    """The emulator registers EC2 instances launched with ECS_CLUSTER user data as container
    instances running agent 1.89.x, while the public AL2023 recommended parameter reports a newer
    agent (1.97.x) - more than the 2-minor-release tolerance, so the cluster is flagged. Fix =
    retire the outdated instance (deregister + terminate), as a rolling AMI replacement would."""
    ecs, ec2, ssm = emu.client('ecs'), emu.client('ec2'), emu.client('ssm')
    cluster = f'ss-cl-{uid}'
    ecs.create_cluster(clusterName=cluster)
    ami = json.loads(ssm.get_parameter(
        Name='/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended')['Parameter']['Value'])['image_id']
    state = {}
    try:
        def misconfigure():
            r = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType='t3.micro',
                                  UserData=f'#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n')
            state['iid'] = r['Instances'][0]['InstanceId']
            for _ in range(30):
                arns = ecs.list_container_instances(cluster=cluster)['containerInstanceArns']
                if arns:
                    state['ci'] = arns
                    return
                time.sleep(1)
            raise AssertionError('container instance never registered')

        def fix():
            for a in state.get('ci', []):
                ecs.deregister_container_instance(cluster=cluster, containerInstance=a, force=True)
            ec2.terminate_instances(InstanceIds=[state['iid']])

        assertFlagFixCycle(emu, 'ecs', 'ecsContainerAgentOutdated', f'Cluster::{cluster}', misconfigure, fix)
    finally:
        for a in state.get('ci', []):
            try:
                ecs.deregister_container_instance(cluster=cluster, containerInstance=a, force=True)
            except Exception:
                pass
        if state.get('iid'):
            try:
                ec2.terminate_instances(InstanceIds=[state['iid']])
            except Exception:
                pass
        _deleteCluster(ecs, cluster)


def _cleanupRole(iam, role):
    try:
        for p in iam.list_attached_role_policies(RoleName=role).get('AttachedPolicies', []):
            iam.detach_role_policy(RoleName=role, PolicyArn=p['PolicyArn'])
        for n in iam.list_role_policies(RoleName=role).get('PolicyNames', []):
            iam.delete_role_policy(RoleName=role, PolicyName=n)
        iam.delete_role(RoleName=role)
    except Exception:
        pass


def _cleanupTaskDefs(ecs, family):
    try:
        for arn in ecs.list_task_definitions(familyPrefix=family).get('taskDefinitionArns', []):
            ecs.deregister_task_definition(taskDefinition=arn)
    except Exception:
        pass


def _deleteCluster(ecs, cluster):
    try:
        ecs.delete_cluster(cluster=cluster)
    except Exception:
        pass

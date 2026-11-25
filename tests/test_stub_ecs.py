"""Stubber tests for WAFS2027 ECS checks - edge cases the emulator cannot produce
(AccessDenied on IAM reads, agentUpdateStatus=FAILED, unreadable SSM agent parameter,
customer-managed policies with Allow+NotAction). Real boto3 clients wrapped by
botocore.stub.Stubber so request/response shapes are validated against the API model.
No network calls are made."""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.ecs.drivers.EcsTaskDefinition import EcsTaskDefinition  # noqa: E402
from services.ecs.drivers.EcsCluster import EcsCluster  # noqa: E402
from services.ecs.drivers.EcsService import EcsService  # noqa: E402

KW = dict(region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
ROLE_ARN = 'arn:aws:iam::111122223333:role/app/ss-task-role'
CL_ARN = 'arn:aws:ecs:us-east-1:111122223333:cluster/c1'


def _td():
    return {'family': 'f', 'revision': 1, 'taskRoleArn': ROLE_ARN, 'containerDefinitions': []}


def _runRole(setup):
    iam = boto3.client('iam', **KW)
    with Stubber(iam) as st:
        setup(st)
        d = EcsTaskDefinition(_td(), None, None, False, iam_client=iam)
        d._checkEcsTaskRoleOverprivileged()
        st.assert_no_pending_responses()
    return d.results['ecsTaskRoleOverprivileged']


def _lists(st, attached, inline):
    st.add_response('list_attached_role_policies', {'AttachedPolicies': attached, 'IsTruncated': False},
                    {'RoleName': 'ss-task-role'})
    st.add_response('list_role_policies', {'PolicyNames': inline, 'IsTruncated': False}, {'RoleName': 'ss-task-role'})


def _cmp(st, arn, doc):
    st.add_response('get_policy', {'Policy': {'PolicyName': 'cmp', 'Arn': arn, 'DefaultVersionId': 'v2'}},
                    {'PolicyArn': arn})
    st.add_response('get_policy_version', {'PolicyVersion': {'Document': doc, 'VersionId': 'v2'}},
                    {'PolicyArn': arn, 'VersionId': 'v2'})


def test_task_role_fullaccess_managed_flagged_then_scoped_passes():
    r = _runRole(lambda st: _lists(st, [{'PolicyName': 'AmazonS3FullAccess',
                                         'PolicyArn': 'arn:aws:iam::aws:policy/AmazonS3FullAccess'}], []))
    assert r[0] == -1 and 'AmazonS3FullAccess' in r[1]
    arn = 'arn:aws:iam::111122223333:policy/scoped'

    def fixed(st):
        _lists(st, [{'PolicyName': 'scoped', 'PolicyArn': arn}], [])
        _cmp(st, arn, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}')
    assert _runRole(fixed)[0] == 1


def test_task_role_customer_notaction_flagged():
    arn = 'arn:aws:iam::111122223333:policy/cmp'

    def setup(st):
        _lists(st, [{'PolicyName': 'cmp', 'PolicyArn': arn}], [])
        _cmp(st, arn, '{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}')
    assert _runRole(setup)[0] == -1


def test_task_role_access_denied_is_not_pass():
    r = _runRole(lambda st: st.add_client_error('list_attached_role_policies', 'AccessDenied'))
    assert r == [0, 'Unable to evaluate (AccessDenied)']


def test_task_role_partial_read_failure_is_not_pass():
    def setup(st):
        _lists(st, [], ['p1'])
        st.add_client_error('get_role_policy', 'AccessDenied')
    assert _runRole(setup)[0] == 0


def test_task_role_absent_is_info():
    d = EcsTaskDefinition({'family': 'f', 'revision': 1}, None, None, False, iam_client=None)
    d._checkEcsTaskRoleOverprivileged()
    assert d.results['ecsTaskRoleOverprivileged'][0] == 0


def _runAgent(instances, latest=('1.97.0', None)):
    ecs = boto3.client('ecs', **KW)
    with Stubber(ecs) as st:
        arns = [i['containerInstanceArn'] for i in instances]
        st.add_response('list_container_instances', {'containerInstanceArns': arns}, {'cluster': CL_ARN})
        if arns:
            st.add_response('describe_container_instances', {'containerInstances': instances, 'failures': []},
                            {'cluster': CL_ARN, 'containerInstances': arns})
        d = EcsCluster({'clusterArn': CL_ARN, 'clusterName': 'c1'}, [], ecs_client=ecs, latest_agent=latest)
        d._checkEcsContainerAgentOutdated()
    return d.results['ecsContainerAgentOutdated']


def _ci(n, ver, upd=None, status='ACTIVE'):
    c = {'containerInstanceArn': f'arn:aws:ecs:us-east-1:111122223333:container-instance/c1/{n}',
         'ec2InstanceId': f'i-{n}', 'status': status, 'versionInfo': {'agentVersion': ver}}
    if upd:
        c['agentUpdateStatus'] = upd
    return c


def test_agent_outdated_flag_then_fixed():
    assert _runAgent([_ci('a', '1.89.3')])[0] == -1
    assert _runAgent([_ci('a', '1.96.1')])[0] == 1   # within tolerance
    assert _runAgent([_ci('a', '1.97.0')])[0] == 1


def test_agent_update_failed_flagged():
    r = _runAgent([_ci('a', '1.97.0', upd='FAILED')])
    assert r[0] == -1 and 'FAILED' in r[1]


def test_agent_latest_unavailable_is_not_pass():
    assert _runAgent([_ci('a', '1.89.3')], latest=(None, 'AccessDeniedException')) == \
        [0, 'Unable to evaluate (AccessDeniedException)']


def test_agent_no_instances_and_inactive_ignored():
    assert _runAgent([])[0] == 0
    assert _runAgent([_ci('a', '1.10.0', status='INACTIVE')])[0] == 0


def test_agent_list_access_denied():
    ecs = boto3.client('ecs', **KW)
    with Stubber(ecs) as st:
        st.add_client_error('list_container_instances', 'AccessDeniedException')
        d = EcsCluster({'clusterArn': CL_ARN, 'clusterName': 'c1'}, [], ecs_client=ecs, latest_agent=('1.97.0', None))
        d._checkEcsContainerAgentOutdated()
    assert d.results['ecsContainerAgentOutdated'] == [0, 'Unable to evaluate (AccessDeniedException)']


def _svc(**kw):
    s = {'serviceName': 's', 'serviceArn': 'arn:aws:ecs:us-east-1:111122223333:service/c1/s'}
    s.update(kw)
    return EcsService(s, {'clusterName': 'c1'}, {}, {}, {}, None)


def test_exec_enabled_production_tag():
    d = _svc(enableExecuteCommand=True, tags=[{'key': 'Environment', 'value': 'Production'}])
    d._checkEcsExecEnabledServices()
    assert d.results['ecsExecEnabledServices'][0] == -1
    assert 'production-tagged' in d.results['ecsExecEnabledServices'][1]
    d = _svc(enableExecuteCommand=False)
    d._checkEcsExecEnabledServices()
    assert d.results['ecsExecEnabledServices'][0] == 1


def test_agent_update_in_place_flag_then_pass():
    """In-place remediation of the SAME container instance (the emulator raises
    NoUpdateAvailableException, so it cannot do this): agent 1.89.3 vs latest 1.97.0 -> FAIL;
    UpdateContainerAgent starts the update; once DescribeContainerInstances reports
    agentUpdateStatus UPDATED and agent 1.97.0 the re-scan -> PASS. While the update is still
    in progress (UPDATING, old version) the instance stays flagged."""
    old = _ci('a', '1.89.3')
    r = _runAgent([old])
    assert r[0] == -1 and 'i-a (1.89.3)' in r[1]

    ecs = boto3.client('ecs', **KW)
    with Stubber(ecs) as st:
        st.add_response('update_container_agent',
                        {'containerInstance': dict(old, agentUpdateStatus='PENDING')},
                        {'cluster': CL_ARN, 'containerInstance': old['containerInstanceArn']})
        resp = ecs.update_container_agent(cluster=CL_ARN, containerInstance=old['containerInstanceArn'])
        st.assert_no_pending_responses()
    assert resp['containerInstance']['agentUpdateStatus'] == 'PENDING'

    assert _runAgent([_ci('a', '1.89.3', upd='UPDATING')])[0] == -1
    assert _runAgent([_ci('a', '1.97.0', upd='UPDATED')]) == \
        [1, 'All 1 container instance(s) within 2 minor releases of agent 1.97.0']

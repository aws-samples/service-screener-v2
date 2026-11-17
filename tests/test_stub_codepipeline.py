"""
Stubber tests for services/codepipeline paths the emulator cannot produce:
AccessDenied on IAM / notification APIs (the emulator does not evaluate IAM),
cross-account action roles (single-account emulator) and a V1 pipeline.
Real boto3 clients wrapped by botocore.stub.Stubber keep real API shapes.
"""
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.codepipeline.Codepipeline import CodepipelineShared  # noqa: E402
from services.codepipeline.drivers.CodepipelinePipeline import CodepipelinePipeline  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

ACCT = '111122223333'
ARN = f'arn:aws:codepipeline:us-east-1:{ACCT}:pl'
ROLE = f'arn:aws:iam::{ACCT}:role/pl-role'


def _clients():
    kw = dict(region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')
    return boto3.client('iam', **kw), boto3.client('codestar-notifications', **kw), boto3.client('events', **kw)


def _pipeline(stages=None, roleArn=ROLE, pipelineType='V2'):
    p = {'name': 'pl', 'roleArn': roleArn, 'stages': stages or [
        {'name': 'Source', 'actions': [{'name': 's', 'actionTypeId': {
            'category': 'Source', 'owner': 'AWS', 'provider': 'S3', 'version': '1'}}]},
        {'name': 'Release', 'actions': [{'name': 'd', 'actionTypeId': {
            'category': 'Deploy', 'owner': 'AWS', 'provider': 'S3', 'version': '1'}}]}]}
    if pipelineType:
        p['pipelineType'] = pipelineType
    return p


def _run(driver, method):
    getattr(driver, method)()
    return driver.results


def test_role_access_denied_is_unevaluable_and_admin_flags():
    iam, csn, ev = _clients()
    with Stubber(iam) as st:
        st.add_client_error('list_attached_role_policies', 'AccessDenied')
        d = CodepipelinePipeline(_pipeline(), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
        r = _run(d, '_checkPipelineRoleOverprivileged')['pipelineRoleOverprivileged']
        assert r[0] == 0 and 'AccessDenied' in r[1]

    iam, csn, ev = _clients()
    with Stubber(iam) as st:
        st.add_response('list_attached_role_policies', {'AttachedPolicies': [
            {'PolicyName': 'AdministratorAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]})
        st.add_response('list_role_policies', {'PolicyNames': []})
        d = CodepipelinePipeline(_pipeline(), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
        assert _run(d, '_checkPipelineRoleOverprivileged')['pipelineRoleOverprivileged'][0] == -1

    iam, csn, ev = _clients()
    with Stubber(iam) as st:
        st.add_response('list_attached_role_policies', {'AttachedPolicies': [
            {'PolicyName': 'AWSCodePipeline_FullAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AWSCodePipeline_FullAccess'}]})
        st.add_response('list_role_policies', {'PolicyNames': []})
        d = CodepipelinePipeline(_pipeline(), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
        assert _run(d, '_checkPipelineRoleOverprivileged')['pipelineRoleOverprivileged'][0] == 1


def test_cross_account_action_role_not_passed():
    iam, csn, ev = _clients()
    stages = _pipeline()['stages']
    stages[1]['actions'][0]['roleArn'] = 'arn:aws:iam::999999999999:role/deployer'
    with Stubber(iam) as st:
        st.add_response('list_attached_role_policies', {'AttachedPolicies': []})
        st.add_response('list_role_policies', {'PolicyNames': []})
        d = CodepipelinePipeline(_pipeline(stages), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
        r = _run(d, '_checkPipelineRoleOverprivileged')['pipelineRoleOverprivileged']
        assert r[0] == 0 and 'cross-account' in r[1]


def test_v1_pipeline_rollback_flags_and_v2_rollback_passes():
    iam, csn, ev = _clients()
    d = CodepipelinePipeline(_pipeline(pipelineType=None), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
    assert _run(d, '_checkCodepipelineNoStageRollback')['codepipelineNoStageRollback'][0] == -1
    stages = _pipeline()['stages']
    stages[1]['onFailure'] = {'result': 'FAIL', 'conditions': [{'result': 'ROLLBACK', 'rules': []}]}
    d = CodepipelinePipeline(_pipeline(stages), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
    assert _run(d, '_checkCodepipelineNoStageRollback')['codepipelineNoStageRollback'][0] == 1


def test_notification_access_denied_is_unevaluable():
    iam, csn, ev = _clients()
    with Stubber(csn) as s1, Stubber(ev) as s2:
        s1.add_client_error('list_notification_rules', 'AccessDeniedException')
        s2.add_response('list_rules', {'Rules': []})
        d = CodepipelinePipeline(_pipeline(), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
        r = _run(d, '_checkPipelineNoEventNotification')['pipelineNoEventNotification']
        assert r[0] == 0 and 'AccessDenied' in r[1]

    iam, csn, ev = _clients()
    with Stubber(csn) as s1, Stubber(ev) as s2:
        s1.add_response('list_notification_rules', {'NotificationRules': []})
        s2.add_response('list_rules', {'Rules': [{'Name': 'r', 'State': 'ENABLED', 'EventPattern':
                                                  '{"source":["aws.codepipeline"]}'}]})
        s2.add_response('list_targets_by_rule', {})
        d = CodepipelinePipeline(_pipeline(), {'pipelineArn': ARN}, CodepipelineShared(iam, csn, ev))
        ## Rule without targets delivers nothing -> FAIL
        assert _run(d, '_checkPipelineNoEventNotification')['pipelineNoEventNotification'][0] == -1

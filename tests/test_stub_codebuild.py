"""
Stubber tests for the WAFS2027 CodeBuild checks, covering paths the local AWS
Emulator cannot reach:
  - cbProjectNoTestReports for buildspecs kept in source: the evidence comes from
    list_reports_for_report_group / batch_get_reports, which the emulator
    reports as NotImplemented.
  - cbServiceRoleOverprivileged with a permissions boundary (the emulator's
    get_role does not return PermissionsBoundary) and AccessDenied handling.
  - cbWebhookUnfiltered pullRequestBuildPolicy / exclude-filter variants (pure
    config; driven directly with a batch_get_projects-shaped dict).
Each test uses real boto3 clients wrapped in botocore Stubber (real API shapes)
and asserts -1 for the misconfigured response and not -1 for the fixed one.
No network calls are made.
"""
import datetime
import json
import urllib.parse
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.codebuild.Codebuild import Codebuild  # noqa: E402
from services.codebuild.drivers.CodebuildProject import CodebuildProject  # noqa: E402

ACCT = '111122223333'
ROLE_ARN = f'arn:aws:iam::{ACCT}:role/cb-role'
RG_ARN = f'arn:aws:codebuild:us-east-1:{ACCT}:report-group/shared-tests'
REPORT_ARN = f'arn:aws:codebuild:us-east-1:{ACCT}:report/shared-tests:abc'
NOW = datetime.datetime(2026, 1, 1)


def _client(name):
    return boto3.session.Session(
        aws_access_key_id='x', aws_secret_access_key='x', region_name='us-east-1'
    ).client(name)


def _project(**extra):
    p = {'name': 'app', 'serviceRole': ROLE_ARN,
         'source': {'type': 'GITHUB', 'location': 'https://github.com/o/r.git',
                    'buildspec': 'buildspec.yml'},
         'environment': {}, '_tags': [], '_region': 'us-east-1'}
    p.update(extra)
    return p


# ---------------------------------------------------------------- reports
class _IndexOnly(Codebuild):
    """Codebuild without Service.__init__/__del__ (which bootstrap a scan and
    write run artefacts); only _getReportIndex is exercised."""
    def __del__(self):
        pass


def _reportIndex(executionProject, linkageError=None):
    cb = _client('codebuild')
    st = Stubber(cb)
    st.add_response('list_report_groups', {'reportGroups': [RG_ARN]})
    if linkageError:
        st.add_client_error('list_reports_for_report_group', linkageError)
    else:
        st.add_response('list_reports_for_report_group', {'reports': [REPORT_ARN]},
                        {'reportGroupArn': RG_ARN, 'sortOrder': 'DESCENDING',
                         'maxResults': Codebuild.REPORT_SAMPLE_PER_GROUP})
        st.add_response('batch_get_reports', {'reports': [{
            'arn': REPORT_ARN, 'reportGroupArn': RG_ARN,
            'executionId': f'arn:aws:codebuild:us-east-1:{ACCT}:build/{executionProject}:1f2e'}]},
            {'reportArns': [REPORT_ARN]})
    svc = _IndexOnly.__new__(_IndexOnly)
    svc.cbClient = cb
    svc._reportIndex = None
    with st:
        index = svc._getReportIndex()
        st.assert_no_pending_responses()
    return index


def _reportsResult(index):
    obj = CodebuildProject(_project(), None, reportIndexFn=lambda: index)
    obj._checkCbProjectNoTestReports()
    return obj.results['cbProjectNoTestReports'][0]


def test_reports_source_buildspec_flag_fix():
    assert _reportsResult(_reportIndex('other-project')) == -1
    assert _reportsResult(_reportIndex('app')) == 1


def test_reports_linkage_not_readable_is_unable_to_evaluate():
    index = _reportIndex('x', linkageError='NotImplemented')
    obj = CodebuildProject(_project(), None, reportIndexFn=lambda: index)
    obj._checkCbProjectNoTestReports()
    assert obj.results['cbProjectNoTestReports'] == [0, 'Unable to evaluate (NotImplemented)']


def test_reports_batch_execution_id_parsed():
    assert Codebuild._projectFromExecutionId(
        f'arn:aws:codebuild:us-east-1:{ACCT}:build-batch/my-proj:9') == 'my-proj'


# ---------------------------------------------------------------- service role
def _roleResult(boundaryArn, boundaryIsAdmin):
    iam = _client('iam')
    st = Stubber(iam)
    role = {'Path': '/', 'RoleName': 'cb-role', 'RoleId': 'AROAEXAMPLEEXAMPLE1',
            'Arn': ROLE_ARN, 'CreateDate': NOW}
    if boundaryArn:
        role['PermissionsBoundary'] = {'PermissionsBoundaryType': 'Policy',
                                       'PermissionsBoundaryArn': boundaryArn}
    st.add_response('get_role', {'Role': role}, {'RoleName': 'cb-role'})
    st.add_response('list_attached_role_policies', {'AttachedPolicies': [
        {'PolicyName': 'AdministratorAccess',
         'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}], 'IsTruncated': False})
    st.add_response('list_role_policies', {'PolicyNames': [], 'IsTruncated': False})
    if boundaryArn and ':aws:policy/' not in boundaryArn:
        st.add_response('get_policy', {'Policy': {'Arn': boundaryArn, 'DefaultVersionId': 'v1'}})
        doc = ({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
               if boundaryIsAdmin else
               {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]})
        st.add_response('get_policy_version', {'PolicyVersion': {'Document': urllib.parse.quote(json.dumps(doc)), 'VersionId': 'v1'}})
    obj = CodebuildProject(_project(), None, iamClient=iam)
    with st:
        obj._checkCbServiceRoleOverprivileged()
        st.assert_no_pending_responses()
    return obj.results['cbServiceRoleOverprivileged']


def test_role_admin_with_admin_boundary_flags_and_scoped_boundary_does_not():
    bnd = f'arn:aws:iam::{ACCT}:policy/boundary'
    assert _roleResult(bnd, True)[0] == -1
    assert _roleResult(bnd, False)[0] == 0
    assert _roleResult(None, False)[0] == -1


def test_role_access_denied_is_unable_to_evaluate():
    iam = _client('iam')
    st = Stubber(iam)
    st.add_client_error('get_role', 'AccessDenied')
    obj = CodebuildProject(_project(), None, iamClient=iam)
    with st:
        obj._checkCbServiceRoleOverprivileged()
    assert obj.results['cbServiceRoleOverprivileged'][0] == 0
    assert 'Unable to evaluate (AccessDenied)' in obj.results['cbServiceRoleOverprivileged'][1]


def test_role_admin_only_on_scoped_resource_is_not_admin():
    assert CodebuildProject._documentIsAdmin({'Statement': [
        {'Effect': 'Allow', 'Action': '*', 'Resource': 'arn:aws:s3:::b/*'}]}) is False
    assert CodebuildProject._documentIsAdmin({'Statement': {
        'Effect': 'Allow', 'Action': ['*'], 'Resource': ['*']}}) is True


# ---------------------------------------------------------------- webhook
def _webhook(webhook):
    cb = _client('codebuild')
    st = Stubber(cb)
    st.add_response('batch_get_projects', {'projects': [{
        'name': 'app', 'arn': f'arn:aws:codebuild:us-east-1:{ACCT}:project/app',
        'source': {'type': 'GITHUB', 'location': 'https://github.com/o/r.git'},
        'webhook': webhook}]})
    with st:
        project = cb.batch_get_projects(names=['app'])['projects'][0]
    obj = CodebuildProject(project, cb)
    obj._checkCbWebhookUnfiltered()
    return obj.results['cbWebhookUnfiltered'][0]


PR = {'type': 'EVENT', 'pattern': 'PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED'}


def test_webhook_empty_filter_groups_flag_then_comment_approval_fix():
    assert _webhook({'url': 'https://x', 'filterGroups': []}) == -1
    assert _webhook({'url': 'https://x', 'filterGroups': [],
                     'pullRequestBuildPolicy': {'requiresCommentApproval': 'ALL_PULL_REQUESTS'}}) == 1


def test_webhook_actor_exclude_is_not_a_restriction():
    excl = {'type': 'ACTOR_ACCOUNT_ID', 'pattern': '^999$', 'excludeMatchedPattern': True}
    incl = {'type': 'ACTOR_ACCOUNT_ID', 'pattern': '^123$'}
    assert _webhook({'url': 'https://x', 'filterGroups': [[PR, excl]]}) == -1
    assert _webhook({'url': 'https://x', 'filterGroups': [[PR, incl]]}) == 1


def test_webhook_push_and_merged_only_pass():
    assert _webhook({'url': 'https://x', 'filterGroups': [
        [{'type': 'EVENT', 'pattern': 'PUSH'}],
        [{'type': 'EVENT', 'pattern': 'PULL_REQUEST_MERGED'}]]}) == 1
    ## EVENT exclude of PUSH only still matches PR events.
    assert _webhook({'url': 'https://x', 'filterGroups': [
        [{'type': 'EVENT', 'pattern': 'PUSH', 'excludeMatchedPattern': True}]]}) == -1


def test_no_webhook_is_info():
    obj = CodebuildProject(_project(), None)
    obj._checkCbWebhookUnfiltered()
    assert obj.results['cbWebhookUnfiltered'][0] == 0

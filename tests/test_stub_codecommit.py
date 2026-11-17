"""Stubber tests for codecommit.codecommitNoApprovalRule paths the emulator cannot produce.

The emulator (like CodeCommit) rejects templates with NumberOfApprovalsNeeded 0 at create
time and never returns AccessDenied, so the "not evaluable" and malformed-content paths are
driven here with a real boto3 codecommit client wrapped by botocore.stub.Stubber.
"""
import json
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.codecommit.drivers.CodecommitRepository import CodecommitRepository  # noqa: E402

KEY = 'codecommitNoApprovalRule'


def _client():
    return boto3.client('codecommit', region_name='us-east-1',
                        aws_access_key_id='x', aws_secret_access_key='x')


def _tpl(name, content):
    return {'approvalRuleTemplate': {'approvalRuleTemplateName': name,
                                     'approvalRuleTemplateContent': content}}


def _run(cc, repo):
    d = CodecommitRepository(repo, cc, {})
    d._checkNoApprovalRule()
    return d.results[KEY]


def test_access_denied_is_not_evaluable():
    cc = _client()
    with Stubber(cc) as st:
        st.add_client_error('list_associated_approval_rule_templates_for_repository',
                            service_error_code='AccessDeniedException', http_status_code=400)
        r = _run(cc, {'repositoryName': 'r1', 'defaultBranch': 'main'})
    assert r[0] == 0 and 'AccessDeniedException' in r[1]


def test_flag_wrong_branch_then_fixed():
    cc = _client()
    repo = {'repositoryName': 'r1', 'defaultBranch': 'main'}
    bad = json.dumps({'Version': '2018-11-08', 'DestinationReferences': ['refs/heads/dev'],
                      'Statements': [{'Type': 'Approvers', 'NumberOfApprovalsNeeded': 1}]})
    good = json.dumps({'Version': '2018-11-08', 'DestinationReferences': ['refs/heads/main'],
                       'Statements': [{'Type': 'Approvers', 'NumberOfApprovalsNeeded': 1}]})
    for content, expectFail in ((bad, True), (good, False)):
        with Stubber(cc) as st:
            st.add_response('list_associated_approval_rule_templates_for_repository',
                            {'approvalRuleTemplateNames': ['t1']}, {'repositoryName': 'r1'})
            st.add_response('get_approval_rule_template', _tpl('t1', content),
                            {'approvalRuleTemplateName': 't1'})
            r = _run(cc, repo)
        assert (r[0] == -1) is expectFail, r


def test_zero_approvals_fails_and_unreadable_template_is_not_evaluable():
    cc = _client()
    zero = json.dumps({'Version': '2018-11-08',
                       'Statements': [{'Type': 'Approvers', 'NumberOfApprovalsNeeded': 0}]})
    with Stubber(cc) as st:
        st.add_response('list_associated_approval_rule_templates_for_repository',
                        {'approvalRuleTemplateNames': ['t0']}, {'repositoryName': 'r1'})
        st.add_response('get_approval_rule_template', _tpl('t0', zero), {'approvalRuleTemplateName': 't0'})
        assert _run(cc, {'repositoryName': 'r1'})[0] == -1
    with Stubber(cc) as st:
        st.add_response('list_associated_approval_rule_templates_for_repository',
                        {'approvalRuleTemplateNames': ['t2']}, {'repositoryName': 'r1'})
        st.add_client_error('get_approval_rule_template', service_error_code='AccessDeniedException',
                            http_status_code=400)
        r = _run(cc, {'repositoryName': 'r1'})
        assert r[0] == 0 and 'Unable to evaluate' in r[1]


def test_pagination_of_associated_templates():
    cc = _client()
    one = json.dumps({'Version': '2018-11-08',
                      'Statements': [{'Type': 'Approvers', 'NumberOfApprovalsNeeded': 1}]})
    with Stubber(cc) as st:
        st.add_response('list_associated_approval_rule_templates_for_repository',
                        {'approvalRuleTemplateNames': [], 'nextToken': 'n1'}, {'repositoryName': 'r1'})
        st.add_response('list_associated_approval_rule_templates_for_repository',
                        {'approvalRuleTemplateNames': ['t1']}, {'repositoryName': 'r1', 'nextToken': 'n1'})
        st.add_response('get_approval_rule_template', _tpl('t1', one), {'approvalRuleTemplateName': 't1'})
        assert _run(cc, {'repositoryName': 'r1', 'defaultBranch': 'main'})[0] == 1

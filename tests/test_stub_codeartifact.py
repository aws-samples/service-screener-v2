"""
botocore Stubber tests for CodeArtifact driver edge cases that the emulator
flag/fix tests (tests/emulator/test_emu_codeartifact.py) do not cover:
condition-scoped policies, unreadable policies (AccessDenied), format-aware
package origin evaluation, and list_domains failure for codeartifactNotUsed.
Real boto3 clients wrapped in Stubber validate request/response shapes; no
network calls are made.
"""
import json
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.codeartifact.drivers.CodeartifactAccount import CodeartifactAccount  # noqa: E402
from services.codeartifact.drivers.CodeartifactDomain import CodeartifactDomain  # noqa: E402
from services.codeartifact.drivers.CodeartifactRepository import CodeartifactRepository  # noqa: E402

ACCT = '111122223333'
DOMAIN = {'name': 'dom', 'owner': ACCT, 'arn': f'arn:aws:codeartifact:us-east-1:{ACCT}:domain/dom',
          'status': 'Active'}


def _client():
    return boto3.session.Session(aws_access_key_id='x', aws_secret_access_key='x',
                                 region_name='us-east-1').client('codeartifact')


def _repo(name, upstreams=(), conns=(), formats=()):
    return {'name': name, 'domainName': 'dom', 'domainOwner': ACCT, 'administratorAccount': ACCT,
            'arn': f'arn:aws:codeartifact:us-east-1:{ACCT}:repository/dom/{name}',
            '_upstreams': list(upstreams), '_externalConnections': list(conns),
            '_externalFormats': list(formats), '_describeError': None}


def _policyResp(arn, stmt):
    return {'policy': {'resourceArn': arn, 'revision': 'r1',
                       'document': json.dumps({'Version': '2012-10-17', 'Statement': [stmt]})}}


BROAD = {'Effect': 'Allow', 'Principal': '*', 'Action': 'codeartifact:*', 'Resource': '*'}


def _domainResult(resp=None, error=None):
    c = _client()
    with Stubber(c) as st:
        if error:
            st.add_client_error('get_domain_permissions_policy', service_error_code=error)
        else:
            st.add_response('get_domain_permissions_policy', resp,
                            {'domain': 'dom', 'domainOwner': ACCT})
        d = CodeartifactDomain(DOMAIN, c)
        d._checkCodeartifactRepoPolicyBroad()
    return d.results['codeartifactRepoPolicyBroad'][0]


def test_domain_policy_flag_then_org_scoped_fix():
    assert _domainResult(_policyResp(DOMAIN['arn'], BROAD)) == -1
    scoped = dict(BROAD, Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-abc123def4'}})
    assert _domainResult(_policyResp(DOMAIN['arn'], scoped)) == 1
    acct = dict(BROAD, Condition={'StringEquals': {'aws:PrincipalAccount': ACCT}})
    assert _domainResult(_policyResp(DOMAIN['arn'], acct)) == 1


def test_domain_policy_wildcard_condition_value_still_flags():
    weak = dict(BROAD, Condition={'StringLike': {'aws:PrincipalOrgID': '*'}})
    assert _domainResult(_policyResp(DOMAIN['arn'], weak)) == -1


def test_domain_policy_unreadable_is_not_pass():
    assert _domainResult(error='AccessDeniedException') == 0
    assert _domainResult(error='ResourceNotFoundException') == 1


def _originResult(repo, index, packages):
    c = _client()
    with Stubber(c) as st:
        st.add_response('list_packages', {'packages': packages},
                        {'domain': 'dom', 'domainOwner': ACCT, 'repository': repo['name'],
                         'publish': 'ALLOW', 'upstream': 'ALLOW', 'maxResults': 1000})
        r = CodeartifactRepository(repo, c, index)
        r._checkCodeartifactPackageOriginUnrestricted()
    return r.results['codeartifactPackageOriginUnrestricted'][0]


def _pkg(fmt, name, publish='ALLOW', upstream='ALLOW'):
    return {'format': fmt, 'package': name,
            'originConfiguration': {'restrictions': {'publish': publish, 'upstream': upstream}}}


def test_origin_format_aware_flag_and_fix():
    up = _repo('pypi-store', conns=['public:pypi'], formats=['pypi'])
    down = _repo('internal', upstreams=['pypi-store'])
    index = {(ACCT, 'dom', r['name']): r for r in (up, down)}
    # pypi package with publish+upstream ALLOW and a reachable public:pypi -> flag
    assert _originResult(down, index, [_pkg('pypi', 'acme-lib')]) == -1
    # npm package cannot be substituted from public:pypi -> not a finding
    assert _originResult(down, index, [_pkg('npm', 'acme-lib')]) == 1
    # fixed: no package matches the ALLOW/ALLOW filter
    assert _originResult(down, index, []) == 1


def test_origin_unknown_upstream_is_conservative():
    down = _repo('internal', upstreams=['not-scanned'])
    assert _originResult(down, {}, [_pkg('npm', 'acme-lib')]) == -1


def test_origin_no_external_connection_passes_without_api_call():
    repo = _repo('solo')
    r = CodeartifactRepository(repo, _client(), {(ACCT, 'dom', 'solo'): repo})
    r._checkCodeartifactPackageOriginUnrestricted()
    assert r.results['codeartifactPackageOriginUnrestricted'][0] == 1


def test_not_used_states():
    def res(**kw):
        d = dict({'_region': 'us-east-1', '_domains': [], '_domainError': None, '_repositoryCount': 0}, **kw)
        a = CodeartifactAccount(d)
        a._checkCodeartifactNotUsed()
        return a.results['codeartifactNotUsed'][0]
    assert res() == -1
    assert res(_domains=[DOMAIN]) == 1
    assert res(_repositoryCount=2) == 1  # repos in a domain owned by another account
    assert res(_domainError='AccessDeniedException') == 0

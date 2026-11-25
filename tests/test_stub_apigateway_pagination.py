"""ApiGatewayRest reads every page of its collection calls.

GetResources, GetAuthorizers, GetDomainNames, GetBasePathMappings and
GetUsagePlans return 25 items per page by default and carry 'position' when
more exist. The driver used to read only the first page, so e.g. an
unauthenticated method on resource #26 was never inspected (false PASS).

These tests use a real botocore apigateway client wrapped by Stubber (real API
shapes, no network). Each queues two pages with the offending item on page 2;
with first-page-only reads the FAIL is missed (and the Stubber is left with a
pending response).
"""
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.apigateway.drivers.ApiGatewayRest import ApiGatewayRest  # noqa: E402
from utils.Config import Config  # noqa: E402

API = {'id': 'api1', 'name': 'api-one'}


@pytest.fixture(autouse=True)
def _freshShared():
    Config.init()  # region-level _sharedMemo caches live in Config
    yield
    Config.init()


def _client():
    return boto3.client('apigateway', region_name='us-east-1',
                        aws_access_key_id='x', aws_secret_access_key='x')


def _resource(i, verb='GET'):
    return {'id': f'r{i}', 'path': f'/p{i}', 'resourceMethods': {verb: {}}}


def _queueResources(st, authOfLast):
    page1 = [_resource(i) for i in range(25)]
    st.add_response('get_resources', {'items': page1, 'position': 'pos2'}, {'restApiId': 'api1'})
    st.add_response('get_resources', {'items': [_resource(25)]},
                    {'restApiId': 'api1', 'position': 'pos2'})
    for i in range(25):
        st.add_response('get_method', {'httpMethod': 'GET', 'authorizationType': 'AWS_IAM'},
                        {'restApiId': 'api1', 'resourceId': f'r{i}', 'httpMethod': 'GET'})
    st.add_response('get_method', {'httpMethod': 'GET', 'authorizationType': authOfLast},
                    {'restApiId': 'api1', 'resourceId': 'r25', 'httpMethod': 'GET'})


def test_iam_authentication_sees_method_on_second_page():
    c = _client()
    with Stubber(c) as st:
        _queueResources(st, 'NONE')
        d = ApiGatewayRest(API, c)
        d._checkIAMAuthentication()
        st.assert_no_pending_responses()
    assert d.results['IAMAuthentication'] == [-1, 'Methods without auth: GET /p25']


def test_iam_authentication_fixed_on_second_page_is_not_flagged():
    c = _client()
    with Stubber(c) as st:
        _queueResources(st, 'AWS_IAM')
        d = ApiGatewayRest(API, c)
        d._checkIAMAuthentication()
        st.assert_no_pending_responses()
    assert 'IAMAuthentication' not in d.results


def test_least_privilege_sees_none_auth_method_on_second_page():
    c = _client()
    with Stubber(c) as st:
        st.add_response('get_rest_api', {'id': 'api1', 'name': 'api-one', 'policy': '{"Statement":[1]}'},
                        {'restApiId': 'api1'})
        _queueResources(st, 'NONE')
        st.add_response('get_authorizers', {'items': [{'id': 'a1', 'type': 'TOKEN'}]},
                        {'restApiId': 'api1'})
        d = ApiGatewayRest(API, c)
        d._checkLeastPrivilegeAccess()
        st.assert_no_pending_responses()
    assert d.results['LeastPrivilegeAccess'] == [-1, 'Access control issues: Methods with NONE authorization']


def test_usage_plan_for_api_on_second_page_is_checked():
    c = _client()
    other = [{'id': f'u{i}', 'name': f'other{i}', 'apiStages': [{'apiId': 'zzz', 'stage': 'prod'}]}
             for i in range(25)]
    with Stubber(c) as st:
        st.add_response('get_usage_plans', {'items': other, 'position': 'pos2'}, {})
        st.add_response('get_usage_plans',
                        {'items': [{'id': 'mine', 'name': 'unlimited',
                                    'apiStages': [{'apiId': 'api1', 'stage': 'prod'}]}]},
                        {'position': 'pos2'})
        d = ApiGatewayRest(API, c)
        d._checkUsagePlanThrottling()
        st.assert_no_pending_responses()
    assert d.results['UsagePlanThrottling'] == [-1, 'Usage plans without limits: unlimited']


def test_mutual_tls_domain_and_mapping_on_second_pages():
    c = _client()
    with Stubber(c) as st:
        st.add_response('get_domain_names',
                        {'items': [{'domainName': f'd{i}.example.com'} for i in range(25)],
                         'position': 'dpos'}, {})
        st.add_response('get_domain_names', {'items': [{'domainName': 'mine.example.com'}]},
                        {'position': 'dpos'})
        for i in range(25):
            st.add_response('get_base_path_mappings', {'items': []}, {'domainName': f'd{i}.example.com'})
        st.add_response('get_base_path_mappings',
                        {'items': [{'basePath': f'b{i}', 'restApiId': 'zzz'} for i in range(25)],
                         'position': 'mpos'},
                        {'domainName': 'mine.example.com'})
        st.add_response('get_base_path_mappings', {'items': [{'basePath': 'v1', 'restApiId': 'api1'}]},
                        {'domainName': 'mine.example.com', 'position': 'mpos'})
        d = ApiGatewayRest(API, c)
        d._checkMutualTLS()
        st.assert_no_pending_responses()
    assert d.results['MutualTLS'] == [-1, 'Custom domains without mTLS: mine.example.com']


def test_authorizers_merge_all_pages():
    c = _client()
    with Stubber(c) as st:
        st.add_response('get_authorizers',
                        {'items': [{'id': f'a{i}', 'type': 'TOKEN'} for i in range(25)], 'position': 'p'},
                        {'restApiId': 'api1'})
        st.add_response('get_authorizers', {'items': [{'id': 'c1', 'type': 'COGNITO_USER_POOLS'}]},
                        {'restApiId': 'api1', 'position': 'p'})
        d = ApiGatewayRest(API, c)
        items = d._authorizers()['items']
        st.assert_no_pending_responses()
    assert len(items) == 26 and items[-1]['type'] == 'COGNITO_USER_POOLS'

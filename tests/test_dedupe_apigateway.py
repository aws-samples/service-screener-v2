"""ApiGatewayRest reads each piece of API Gateway / CloudWatch data once.

Per REST API (driver instance): get_stages, get_rest_api, get_resources,
get_method(resource, verb), get_authorizers, describe_alarms_for_metric.
Per scan (shared by every REST API in the region): get_domain_names,
get_base_path_mappings(domain), get_usage_plans, cloudwatch list_dashboards.

Every check's result is compared with the pre-change driver (loaded from
git) run on the same fake responses, so only the call count changes.
"""
import importlib.util
import os
import subprocess  # nosec B404 - reads the original driver from local git
import sys
import tempfile
import threading
from unittest import mock

import boto3
import botocore.exceptions
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.apigateway.drivers.ApiGatewayRest import ApiGatewayRest  # noqa: E402
from utils.Config import Config  # noqa: E402

DRIVER = 'services/apigateway/drivers/ApiGatewayRest.py'
BASE_COMMIT = '5ff30a5'

POLICY = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
          '"Action":"execute-api:Invoke","Resource":"*",'
          '"Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}]}')


def _loadOriginal():
    src = subprocess.check_output(['git', '-C', ROOT, 'show', f'{BASE_COMMIT}:{DRIVER}'])  # nosec B603 B607
    fd, path = tempfile.mkstemp(suffix='.py')
    with os.fdopen(fd, 'wb') as f:
        f.write(src)
    spec = importlib.util.spec_from_file_location('OrigApiGatewayRest', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    os.unlink(path)
    return mod.ApiGatewayRest


def _checks():
    return sorted(m for m in dir(ApiGatewayRest) if m.startswith('_check'))


def _apiClient(apiId, fail=None):
    c = mock.MagicMock()
    c.meta.region_name = 'us-east-1'
    stages = {'item': [
        {'stageName': 'prod', 'methodSettings': {'*/*': {'loggingLevel': 'INFO', 'cachingEnabled': True,
                                                         'throttlingBurstLimit': 10}},
         'tracingEnabled': False, 'variables': {}},
        {'stageName': 'dev', 'methodSettings': {}, 'tracingEnabled': True, 'webAclArn': 'arn:waf',
         'clientCertificateId': 'cc', 'variables': {'a': 'b'}, 'canarySettings': {'percentTraffic': 5}},
    ]}
    c.get_stages.return_value = stages
    c.get_rest_api.return_value = {'id': apiId, 'policy': POLICY,
                                   'endpointConfiguration': {'types': ['PRIVATE'], 'vpcEndpointIds': []}}
    c.get_resources.return_value = {'items': [
        {'id': 'r1', 'path': '/', 'resourceMethods': {'GET': {}, 'OPTIONS': {}}},
        {'id': 'r2', 'path': '/p', 'resourceMethods': {'POST': {}}},
    ]}

    def getMethod(restApiId, resourceId, httpMethod):
        if (resourceId, httpMethod) == ('r2', 'POST'):
            raise botocore.exceptions.ClientError({'Error': {'Code': 'NotFoundException'}}, 'GetMethod')
        return {'authorizationType': 'NONE', 'apiKeyRequired': True, 'requestValidatorId': 'v1'}
    c.get_method.side_effect = getMethod
    c.get_authorizers.return_value = {'items': [{'id': 'a', 'type': 'TOKEN'}]}
    c.get_request_validators.return_value = {'items': [{'id': 'v1'}]}
    c.get_integration_response.return_value = {'responseParameters': {
        'method.response.header.Access-Control-Allow-Origin': "'*'"}}
    c.get_domain_names.return_value = {'items': [{'domainName': 'd1.example.com'},
                                                 {'domainName': 'd2.example.com',
                                                  'mutualTlsAuthentication': {'truststoreUri': 's3://t'}}]}
    c.get_base_path_mappings.side_effect = lambda domainName: {'items': [{'restApiId': 'api1'}, {'restApiId': 'api2'}]}
    c.get_usage_plans.return_value = {'items': [{'id': 'u', 'name': 'plan', 'apiStages': [{'apiId': 'api1'}]}]}
    ## The driver reads collections through get_paginator(op).paginate(); route
    ## each page through the per-operation mock (following 'position') so call
    ## counts and failure injection still apply to get_resources & co.
    def getPaginator(op):
        def paginate(**kwargs):
            pos = None
            while True:
                page = getattr(c, op)(**kwargs, **({'position': pos} if pos else {}))
                yield page
                pos = page.get('position')
                if not pos:
                    return
        return mock.Mock(paginate=paginate)
    c.get_paginator.side_effect = getPaginator
    if fail:
        getattr(c, fail).side_effect = botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}}, fail)
    return c


def _cwClient():
    cw = mock.MagicMock()
    cw.meta.region_name = 'us-east-1'
    cw.list_dashboards.return_value = {'DashboardEntries': [{'DashboardName': 'other'}]}
    cw.describe_alarms_for_metric.return_value = {'MetricAlarms': []}
    return cw


def _runAll(cls, api, client, threaded):
    d = cls(api, client)
    if threaded:
        ts = [threading.Thread(target=lambda m=m: _safe(getattr(d, m))) for m in _checks()]
        [t.start() for t in ts]
        [t.join() for t in ts]
    else:
        for m in _checks():
            _safe(getattr(d, m))
    return d.results


def _safe(fn):
    try:
        fn()
    except Exception:  # runSingleCheck swallows check exceptions the same way
        pass  # nosec B110


API1 = {'id': 'api1', 'name': 'api-one'}
API2 = {'id': 'api2', 'name': 'api-two'}


@pytest.fixture(autouse=True)
def _freshShared():
    Config.init()
    yield
    Config.init()


@pytest.mark.parametrize('fail', [None, 'get_stages', 'get_rest_api', 'get_resources', 'get_authorizers',
                                  'get_domain_names', 'get_base_path_mappings', 'get_usage_plans'])
def test_results_match_original_driver(fail):
    Orig = _loadOriginal()
    cw = _cwClient()
    with mock.patch('boto3.client', return_value=cw):
        want1 = _runAll(Orig, API1, _apiClient('api1', fail), threaded=False)
        want2 = _runAll(Orig, API2, _apiClient('api2', fail), threaded=False)
        Config.init()
        got1 = _runAll(ApiGatewayRest, API1, _apiClient('api1', fail), threaded=True)
        got2 = _runAll(ApiGatewayRest, API2, _apiClient('api2', fail), threaded=True)
    assert got1 == want1
    assert got2 == want2
    assert got1  # the fixture produces findings, so the comparison is meaningful


def test_per_api_reads_happen_once_per_driver():
    c, cw = _apiClient('api1'), _cwClient()
    with mock.patch('boto3.client', return_value=cw):
        _runAll(ApiGatewayRest, API1, c, threaded=True)
    assert c.get_stages.call_count == 1          # 6 checks used to call it
    assert c.get_rest_api.call_count == 1        # 4 checks
    assert c.get_resources.call_count == 1       # 5 checks
    assert c.get_authorizers.call_count == 1     # 3 checks
    keys = [(k['resourceId'], k['httpMethod']) for _, k in c.get_method.call_args_list]
    assert sorted(keys) == [('r1', 'GET'), ('r1', 'OPTIONS'), ('r2', 'POST')]  # once each
    latency = [k for _, k in cw.describe_alarms_for_metric.call_args_list if k['MetricName'] == 'Latency']
    assert len(latency) == 1                     # _checkCloudWatchAlarms + _checkPerformanceMonitoring
    assert len(cw.describe_alarms_for_metric.call_args_list) == 4


def test_region_level_reads_happen_once_per_scan():
    c1, c2, cw = _apiClient('api1'), _apiClient('api2'), _cwClient()
    with mock.patch('boto3.client', return_value=cw):
        r1 = _runAll(ApiGatewayRest, API1, c1, threaded=True)
        r2 = _runAll(ApiGatewayRest, API2, c2, threaded=True)
    assert c1.get_domain_names.call_count + c2.get_domain_names.call_count == 1
    assert c1.get_usage_plans.call_count + c2.get_usage_plans.call_count == 1
    mappings = [k['domainName'] for c in (c1, c2) for _, k in c.get_base_path_mappings.call_args_list]
    assert sorted(mappings) == ['d1.example.com', 'd2.example.com']
    assert cw.list_dashboards.call_count == 1
    assert r1['MutualTLS'] == r2['MutualTLS'] == [-1, 'Custom domains without mTLS: d1.example.com']
    assert r1['UsagePlanThrottling'] == [-1, 'Usage plans without limits: plan']
    assert 'UsagePlanThrottling' not in r2


def test_region_level_cache_is_per_region():
    c1, c2 = _apiClient('api1'), _apiClient('api2')
    c2.meta.region_name = 'eu-west-1'
    ApiGatewayRest(API1, c1)._checkUsagePlanThrottling()
    ApiGatewayRest(API2, c2)._checkUsagePlanThrottling()
    assert c1.get_usage_plans.call_count == 1 and c2.get_usage_plans.call_count == 1


def test_uncaught_stage_error_still_propagates_from_checkStage():
    c = _apiClient('api1', fail='get_stages')
    d = ApiGatewayRest(API1, c)
    with pytest.raises(botocore.exceptions.ClientError):
        d._checkStage()
    d._checkRequestThrottling()
    assert d.results['RequestThrottling'][0] == -1 and 'AccessDeniedException' in d.results['RequestThrottling'][1]
    assert c.get_stages.call_count == 1


def test_real_client_stubber_one_response_each():
    """Real botocore client: exactly one queued response per read; a second
    call would raise from the Stubber and change the results."""
    c = boto3.client('apigateway', region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')
    with Stubber(c) as st:
        st.add_response('get_stages', {'item': [{'stageName': 'prod', 'methodSettings': {},
                                                 'tracingEnabled': True, 'variables': {'k': 'v'}}]},
                        {'restApiId': 'api1'})
        d = ApiGatewayRest(API1, c)
        for m in ('_checkStage', '_checkRequestThrottling', '_checkCanaryDeployment',
                  '_checkStageVariables', '_checkStageLifecycle'):
            getattr(d, m)()
        st.add_response('get_rest_api', {'id': 'api1', 'name': 'api-one',
                                         'endpointConfiguration': {'types': ['PRIVATE']}},
                        {'restApiId': 'api1'})
        for m in ('_checkResourcePolicy', '_checkPrivateAPI', '_checkVPCEndpointAssociation',
                  '_checkVPCAccessRestrictions'):
            getattr(d, m)()
        st.assert_no_pending_responses()
    assert d.results['EncryptionInTransit'] == [-1, 'Stage name: prod']
    assert d.results['WAFWACL'] == [-1, 'Stage name: prod']
    assert d.results['RequestThrottling'] == [-1, 'Stages without throttling: prod']
    assert d.results['CanaryDeployment'] == [0, 'Production stages without canary: prod']
    assert 'StageVariables' not in d.results
    assert d.results['StageLifecycle'] == [0, 'Single stage deployment: prod']
    assert d.results['ResourcePolicy'] == [-1, 'API: api-one']
    assert d.results['PrivateAPI'] == [-1, 'Private API without VPC endpoints: api-one']
    assert d.results['VPCEndpointAssociation'] == [-1, 'Private API: api-one']
    assert d.results['VPCAccessRestrictions'] == [-1, 'Private API without resource policy: api-one']

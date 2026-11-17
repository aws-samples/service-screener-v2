"""Stubber tests for API Gateway v2 checks.

The emulator (like AWS) rejects creating a JWT authorizer with a non-HTTPS
issuer, so that FAIL branch cannot be set up on the emulator; it is driven
here with a real apigatewayv2 client wrapped by botocore Stubber (real API
shapes). The AccessDenied -> 'Unable to evaluate' path is covered the same way.
"""
import os
import sys
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.apigateway.drivers.ApiGatewayCommon import ApiGatewayCommon  # noqa: E402

API = {'ApiId': 'abc123', 'Name': 'stub-http', 'ProtocolType': 'HTTP',
       'RouteSelectionExpression': '$request.method $request.path'}


def _client():
    return boto3.client('apigatewayv2', region_name='us-east-1',
                        aws_access_key_id='x', aws_secret_access_key='x')


def _jwt(issuer, audience):
    return {'AuthorizerId': 'a1', 'Name': 'jwt', 'AuthorizerType': 'JWT',
            'IdentitySource': ['$request.header.Authorization'],
            'JwtConfiguration': {'Issuer': issuer, 'Audience': audience}}


def _runJwt(pages):
    c = _client()
    with Stubber(c) as st:
        token = None
        for p in pages:
            st.add_response('get_authorizers', p, {'ApiId': 'abc123', **({'NextToken': token} if token else {})})
            token = p.get('NextToken')
        d = ApiGatewayCommon(API, c)
        d._checkJwtAuthorizer()
        st.assert_no_pending_responses()
    return d.results.get('apigwV2JwtAuthorizerNoAudience')


def test_jwt_non_https_issuer_flag_then_fix():
    flagged = _runJwt([{'Items': [_jwt('http://idp.example.com', ['client-a'])]}])
    assert flagged[0] == -1 and 'non-HTTPS issuer' in flagged[1]
    fixed = _runJwt([{'Items': [_jwt('https://idp.example.com', ['client-a'])]}])
    assert fixed[0] == 1


def test_jwt_no_audience_on_second_page():
    flagged = _runJwt([{'Items': [_jwt('https://idp.example.com', ['client-a'])], 'NextToken': 't'},
                       {'Items': [_jwt('https://idp.example.com', [])]}])
    assert flagged[0] == -1 and 'no audience' in flagged[1]


def test_jwt_access_denied_is_not_evaluable():
    c = _client()
    with Stubber(c) as st:
        st.add_client_error('get_authorizers', service_error_code='AccessDeniedException', http_status_code=403)
        d = ApiGatewayCommon(API, c)
        d._checkJwtAuthorizer()
    assert d.results['apigwV2JwtAuthorizerNoAudience'] == [0, 'Unable to evaluate (AccessDeniedException)']


def test_route_access_denied_is_not_evaluable():
    c = _client()
    with Stubber(c) as st:
        st.add_client_error('get_routes', service_error_code='AccessDeniedException', http_status_code=403)
        d = ApiGatewayCommon(API, c)
        d._checkRoute()
    assert d.results['AuthorizationType'][0] == 0


def test_get_apis_follows_next_token():
    from services.apigateway.Apigateway import Apigateway
    c = _client()
    # Unbound call on a stand-in object: avoids Service.__init__/__del__ side effects.
    svc = SimpleNamespace(apiv2Client=c, apisv2=[])
    with Stubber(c) as st:
        st.add_response('get_apis', {'Items': [dict(API, ApiId='a1', Name='one')], 'NextToken': 'n'}, {})
        st.add_response('get_apis', {'Items': [dict(API, ApiId='a2', Name='two')]}, {'NextToken': 'n'})
        Apigateway.getApis(svc)
        st.assert_no_pending_responses()
    assert [a['Name'] for a in svc.apisv2] == ['one', 'two']

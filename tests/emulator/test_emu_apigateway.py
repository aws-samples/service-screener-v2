"""Flag -> fix -> re-run tests for API Gateway (v2 HTTP/WebSocket) checks."""
import os
import shutil
import subprocess
import tempfile

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

# Issuer on container loopback: https scheme, never resolves off-box.
ISSUER = 'https://127.0.0.1:1/'


def test_apigw_v2_http_route_no_authorization(emu, uid):
    v2 = emu.client('apigatewayv2')
    name = f'ss-http-{uid}'
    apiId = v2.create_api(Name=name, ProtocolType='HTTP')['ApiId']
    try:
        routeId = v2.create_route(ApiId=apiId, RouteKey='GET /items')['RouteId']
        # CORS preflight route stays NONE throughout: must never be flagged.
        v2.create_route(ApiId=apiId, RouteKey='OPTIONS /items')

        def misconfigure():
            v2.update_route(ApiId=apiId, RouteId=routeId, AuthorizationType='NONE')

        def fix():
            v2.update_route(ApiId=apiId, RouteId=routeId, AuthorizationType='AWS_IAM')

        before, _ = assertFlagFixCycle(emu, 'apigateway', 'AuthorizationType', f'HTTP::{name}', misconfigure, fix)
        res = runCheck(emu, 'apigateway', 'AuthorizationType', f'HTTP::{name}')
        assert all(v['AuthorizationType'][0] == 1 for v in res.results.values())
    finally:
        v2.delete_api(ApiId=apiId)


def test_apigw_v2_websocket_connect_route_no_authorization(emu, uid):
    v2 = emu.client('apigatewayv2')
    name = f'ss-ws-{uid}'
    apiId = v2.create_api(Name=name, ProtocolType='WEBSOCKET',
                          RouteSelectionExpression='$request.body.action')['ApiId']
    try:
        # Non-$connect routes cannot carry an authorizer; they must not keep the check failing.
        v2.create_route(ApiId=apiId, RouteKey='$default')
        state = {}

        def misconfigure():
            # No $connect route at all -> every connection is unauthenticated.
            pass

        def fix():
            state['connect'] = v2.create_route(ApiId=apiId, RouteKey='$connect', AuthorizationType='AWS_IAM')['RouteId']

        assertFlagFixCycle(emu, 'apigateway', 'AuthorizationType', f'WEBSOCKET::{name}', misconfigure, fix)

        def misconfigure2():
            v2.update_route(ApiId=apiId, RouteId=state['connect'], AuthorizationType='NONE')

        def fix2():
            v2.update_route(ApiId=apiId, RouteId=state['connect'], AuthorizationType='AWS_IAM')

        assertFlagFixCycle(emu, 'apigateway', 'AuthorizationType', f'WEBSOCKET::{name}', misconfigure2, fix2)
    finally:
        v2.delete_api(ApiId=apiId)


def test_apigw_v2_jwt_authorizer_no_audience(emu, uid):
    v2 = emu.client('apigatewayv2')
    name = f'ss-jwt-{uid}'
    apiId = v2.create_api(Name=name, ProtocolType='HTTP')['ApiId']
    try:
        authId = v2.create_authorizer(ApiId=apiId, AuthorizerType='JWT', Name=f'jwt-{uid}',
                                      IdentitySource=['$request.header.Authorization'],
                                      JwtConfiguration={'Issuer': ISSUER, 'Audience': ['client-a']})['AuthorizerId']

        def misconfigure():
            v2.update_authorizer(ApiId=apiId, AuthorizerId=authId,
                                 JwtConfiguration={'Issuer': ISSUER, 'Audience': []})

        def fix():
            v2.update_authorizer(ApiId=apiId, AuthorizerId=authId,
                                 JwtConfiguration={'Issuer': ISSUER, 'Audience': ['client-a']})

        assertFlagFixCycle(emu, 'apigateway', 'apigwV2JwtAuthorizerNoAudience', f'HTTP::{name}', misconfigure, fix)
    finally:
        v2.delete_api(ApiId=apiId)


def test_apigw_v2_no_jwt_authorizer_not_reported(emu, uid):
    v2 = emu.client('apigatewayv2')
    name = f'ss-nojwt-{uid}'
    apiId = v2.create_api(Name=name, ProtocolType='HTTP')['ApiId']
    try:
        res = runCheck(emu, 'apigateway', 'apigwV2JwtAuthorizerNoAudience', f'HTTP::{name}')
        assert res.statuses() == {}
    finally:
        v2.delete_api(ApiId=apiId)


def _importSelfSignedCert(acm, domain):
    """Edge domains need an ISSUED certificate; an imported self-signed one is ISSUED."""
    openssl = shutil.which('openssl')
    if not openssl:
        pytest.skip('openssl not available to create a test certificate')
    with tempfile.TemporaryDirectory() as d:
        key, crt = os.path.join(d, 'k.pem'), os.path.join(d, 'c.pem')
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                        '-out', crt, '-days', '2', '-subj', f'/CN={domain}'],
                       check=True, capture_output=True)
        return acm.import_certificate(Certificate=open(crt, 'rb').read(),
                                      PrivateKey=open(key, 'rb').read())['CertificateArn']


def test_apigw_domain_min_tls_version(emu, uid):
    """apigwV2DomainTls10 is covered by the existing MinTLSVersion check: TLS_1_0 is only
    available on edge-optimized domains (regional domains, and therefore every
    apigatewayv2-created domain, only accept TLS_1_2), and edge domains are listed by
    apigateway.get_domain_names, which MinTLSVersion evaluates."""
    v1 = emu.client('apigateway')
    acm = emu.client('acm')
    domain = f'ss-{uid}.example.com'
    arn = _importSelfSignedCert(acm, domain)
    try:
        v1.create_domain_name(domainName=domain, certificateArn=arn,
                              endpointConfiguration={'types': ['EDGE']}, securityPolicy='TLS_1_0')
        try:
            def misconfigure():
                v1.update_domain_name(domainName=domain, patchOperations=[
                    {'op': 'replace', 'path': '/securityPolicy', 'value': 'TLS_1_0'}])

            def fix():
                v1.update_domain_name(domainName=domain, patchOperations=[
                    {'op': 'replace', 'path': '/securityPolicy', 'value': 'TLS_1_2'}])

            # MinTLSVersion only reports a finding (no PASS entry), so check flag then absence.
            misconfigure()
            assert runCheck(emu, 'apigateway', 'MinTLSVersion', f'DOMAIN::{domain}').statuses() == {f'DOMAIN::{domain}': -1}
            fix()
            assert -1 not in runCheck(emu, 'apigateway', 'MinTLSVersion', f'DOMAIN::{domain}').statuses().values()
        finally:
            v1.delete_domain_name(domainName=domain)
    finally:
        try:
            acm.delete_certificate(CertificateArn=arn)
        except Exception:
            pass

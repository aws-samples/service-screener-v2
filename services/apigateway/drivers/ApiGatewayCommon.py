import boto3
import botocore
import constants as _C

from services.Service import Service
from services.Evaluator import Evaluator

class ApiGatewayCommon(Evaluator):
    
    def __init__(self, api, apiClient):
        super().__init__()
        self.apiClient = apiClient
        self.api = api

        self._resourceName = api['Name']

        return

    def _paginate(self, operation, **kwargs):
        items = []
        for page in self.apiClient.get_paginator(operation).paginate(**kwargs):
            items.extend(page.get('Items', []))
        return items
    
    def _checkStage(self):
        resp = self.apiClient.get_stages(
                ApiId = self.api['ApiId'],
            )
        items = resp['Items']
        for stage in items:

            if self.api['ProtocolType'] == 'WEBSOCKET':           
                if stage['DefaultRouteSettings']['LoggingLevel'] != 'INFO' or 'ERROR':
                    self.results['ExecutionLogging'] = [-1, "Stage name: " + stage['StageName']]
            try:
                accesslogs = stage['AccessLogSettings']
            except KeyError:
                self.results['AccessLogging'] = [-1, "Stage name: " + stage['StageName']]
        return

    def _checkRoute(self):
        ## HTTP APIs: every route carries its own AuthorizationType; NONE means
        ## the route is reachable without authorization. CORS preflight
        ## (OPTIONS) routes must stay unauthenticated, so they are skipped.
        ## WebSocket APIs: authorization can only be attached to the $connect
        ## route (it gates the whole connection); other routes always report
        ## NONE, so only $connect is evaluated. A WebSocket API without a
        ## $connect route accepts every connection unauthenticated.
        try:
            routes = self._paginate('get_routes', ApiId=self.api['ApiId'])
        except botocore.exceptions.ClientError as e:
            self.results['AuthorizationType'] = [0, 'Unable to evaluate (' + e.response['Error']['Code'] + ')']
            return

        isWebSocket = self.api.get('ProtocolType') == 'WEBSOCKET'
        evaluated = []
        unauthorized = []
        for route in routes:
            routeKey = route.get('RouteKey', '')
            if isWebSocket:
                if routeKey != '$connect':
                    continue
            elif routeKey.upper().startswith('OPTIONS '):
                continue
            evaluated.append(routeKey)
            if route.get('AuthorizationType', 'NONE') == 'NONE':
                unauthorized.append(routeKey)

        if isWebSocket and not evaluated:
            self.results['AuthorizationType'] = [-1, "No $connect route: connections are not authorized"]
        elif unauthorized:
            self.results['AuthorizationType'] = [-1, "Route key: " + ", ".join(unauthorized)]
        elif evaluated:
            self.results['AuthorizationType'] = [1, "All routes specify an authorization type"]
        return

    def _checkJwtAuthorizer(self):
        ## JWT authorizers exist only on HTTP APIs. Without an audience list
        ## API Gateway cannot verify the token was issued for this API (any
        ## token from the same issuer is accepted); a non-HTTPS issuer means
        ## the signing keys are not fetched over an authenticated channel.
        if self.api.get('ProtocolType') != 'HTTP':
            return
        try:
            authorizers = self._paginate('get_authorizers', ApiId=self.api['ApiId'])
        except botocore.exceptions.ClientError as e:
            self.results['apigwV2JwtAuthorizerNoAudience'] = [0, 'Unable to evaluate (' + e.response['Error']['Code'] + ')']
            return

        jwtAuthorizers = [a for a in authorizers if a.get('AuthorizerType') == 'JWT']
        if not jwtAuthorizers:
            return

        issues = []
        for auth in jwtAuthorizers:
            name = auth.get('Name', auth.get('AuthorizerId', 'unknown'))
            jwtConfig = auth.get('JwtConfiguration') or {}
            problems = []
            if not [aud for aud in (jwtConfig.get('Audience') or []) if aud]:
                problems.append('no audience')
            issuer = jwtConfig.get('Issuer') or ''
            if not issuer.lower().startswith('https://'):
                problems.append('non-HTTPS issuer')
            if problems:
                issues.append(f"{name} ({', '.join(problems)})")

        if issues:
            self.results['apigwV2JwtAuthorizerNoAudience'] = [-1, "JWT authorizers: " + "; ".join(issues)]
        else:
            self.results['apigwV2JwtAuthorizerNoAudience'] = [1, f"{len(jwtAuthorizers)} JWT authorizer(s) restrict audience and use an HTTPS issuer"]
        return

import botocore

from utils.Tools import _pi
from services.Service import Service

from services.resiliencehub.drivers.ResiliencehubApp import ResiliencehubApp
from services.resiliencehub.drivers.ResiliencehubCommon import ResiliencehubCommon


class Resiliencehub(Service):
    """
    AWS Resilience Hub scanner.

    Per application (ResiliencehubApp):
      - resilienceHubAssessmentStale  (list_app_assessments)
      - resilienceHubDriftOrBreach    (describe_app compliance / drift status)
    Per account/region (ResiliencehubCommon):
      - resilienceHubNoPolicy         (describe_app policyArn, list_resiliency_policies)

    Read-only calls only: list_apps, describe_app, list_app_assessments,
    list_resiliency_policies. None of the list operations has a boto3
    paginator, so nextToken is followed manually.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## Hard cap on pages read from any single list call, so an account with a
    ## very long assessment history cannot turn one check into a long scan.
    PAGE_CAP = 20

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.rhClient = ssBoto.client('resiliencehub', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def _errCode(self, e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def _listAll(self, method, key, **kwargs):
        """Follow nextToken for a resiliencehub list call. Raises ClientError."""
        items, token, pages = [], None, 0
        while pages < self.PAGE_CAP:
            if token:
                kwargs['nextToken'] = token
            resp = getattr(self.rhClient, method)(**kwargs)
            items += resp.get(key, []) or []
            pages += 1
            token = resp.get('nextToken')
            if not token:
                break
        return items

    def getResources(self):
        """Return (apps, appsErrorCode). Each app is the describe_app output
        (falling back to the list_apps summary with '_describeError' set)."""
        try:
            summaries = self._listAll('list_apps', 'appSummaries')
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_apps', e)
            return [], self._errCode(e)

        apps = []
        for s in summaries:
            if s.get('status') == 'Deleting':
                continue
            arn = s.get('appArn')
            app = dict(s)
            try:
                app = self.rhClient.describe_app(appArn=arn).get('app') or dict(s)
            except botocore.exceptions.ClientError as e:
                self._logClientError(f'describe_app({arn})', e)
                app['_describeError'] = self._errCode(e)

            ## Optional --filters tag filtering (describe_app returns a tag map).
            if self.tags:
                if '_describeError' in app:
                    continue
                tags = self.convertKeyPairTagToTagFormat(app.get('tags') or {})
                if not self.resourceHasTags(tags):
                    continue
            apps.append(app)
        return apps, None

    def _listPolicies(self):
        try:
            return self._listAll('list_resiliency_policies', 'resiliencyPolicies'), None
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_resiliency_policies', e)
            return None, self._errCode(e)

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        try:
            apps, appsError = self.getResources()
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Resilience Hub not available in region {self.region}: {e}")
            return objs

        for app in apps:
            name = app.get('name') or (app.get('appArn') or 'unknown').split('/')[-1]
            _pi('Resiliencehub', f"App: {name}")
            try:
                obj = ResiliencehubApp(app, self.rhClient)
                obj.run(self.__class__)
                objs[f"App::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Resilience Hub app {name}: {e}")

        policies, policiesError = self._listPolicies() if appsError is None else (None, None)
        detail = {
            '_region': self.region,
            '_apps': apps,
            '_appsError': appsError,
            '_policies': policies,
            '_policiesError': policiesError,
        }
        try:
            obj = ResiliencehubCommon(detail)
            obj.run(self.__class__)
            objs['ResilienceHub::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing Resilience Hub account checks in {self.region}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = self._errCode(error)
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Resiliencehub {where}: {code} - {msg}")

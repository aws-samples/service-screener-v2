from services.Evaluator import Evaluator


class ResiliencehubCommon(Evaluator):
    """
    Account/region-scoped AWS Resilience Hub checks.

    Input (from services/resiliencehub/Resiliencehub.py.advise):
      '_region', '_apps' (describe_app output per app), '_appsError',
      '_policies' (list_resiliency_policies or None), '_policiesError'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    def __init__(self, detail):
        super().__init__()
        self.detail = detail
        self._resourceName = 'Account'
        self.apps = detail.get('_apps') or []
        self.policies = detail.get('_policies')

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('appCount', str(len(self.apps)))
        self.addII('policyCount', 'N/A' if self.policies is None else str(len(self.policies)))

    def _appName(self, app):
        return app.get('name') or (app.get('appArn') or 'unknown').split('/')[-1]

    # 1. Resilience Hub applications without a resiliency policy
    def _checkResilienceHubNoPolicy(self):
        key = 'resilienceHubNoPolicy'
        if self.detail.get('_appsError'):
            self.results[key] = [0, f"Unable to evaluate ({self.detail['_appsError']})"]
            return

        polErr = self.detail.get('_policiesError')
        polNote = (f'; resiliency policies could not be listed ({polErr})' if polErr
                   else f'; {len(self.policies or [])} resiliency policy(ies) defined')

        if not self.apps:
            self.results[key] = [
                0, 'No Resilience Hub applications in this region - not evaluated' + polNote
            ]
            return

        missing, unknown = [], []
        for app in self.apps:
            if '_describeError' in app:
                ## list_apps summary does not carry policyArn; it does report
                ## MissingPolicy once the app has been assessed.
                if app.get('complianceStatus') == 'MissingPolicy':
                    missing.append(self._appName(app))
                else:
                    unknown.append(f"{self._appName(app)} ({app['_describeError']})")
            elif not app.get('policyArn'):
                missing.append(self._appName(app))

        if missing:
            shown = ', '.join(missing[:5]) + (' ...' if len(missing) > 5 else '')
            self.results[key] = [
                -1,
                f'{len(missing)} of {len(self.apps)} Resilience Hub application(s) have no resiliency '
                f'policy (no RTO/RPO targets to assess against): {shown}' + polNote
            ]
        elif unknown:
            self.results[key] = [
                0, 'Unable to evaluate (describe_app failed for: ' + ', '.join(unknown[:5]) + ')'
            ]
        else:
            self.results[key] = [
                1, f'All {len(self.apps)} Resilience Hub application(s) have a resiliency policy' + polNote
            ]

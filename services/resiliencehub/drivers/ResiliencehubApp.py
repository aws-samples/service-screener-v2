import datetime

import botocore

from services.Evaluator import Evaluator


class ResiliencehubApp(Evaluator):
    """
    Per-application AWS Resilience Hub checks.

    Input:
      app      -- describe_app 'app' structure (or the list_apps summary with
                  '_describeError' when describe_app failed).
      rhClient -- resiliencehub client, used for list_app_assessments.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ## An assessment older than this no longer reflects the application: the
    ## resources, configuration and policy may all have changed since.
    STALE_DAYS = 30
    PAGE_CAP = 5

    def __init__(self, app, rhClient):
        super().__init__()
        self.app = app
        self.rhClient = rhClient
        self.appArn = app.get('appArn')
        self._resourceName = app.get('name') or (self.appArn or 'unknown').split('/')[-1]

        self.addII('appArn', self.appArn or 'N/A')
        self.addII('complianceStatus', app.get('complianceStatus') or 'N/A')
        self.addII('driftStatus', app.get('driftStatus') or 'N/A')
        self.addII('assessmentSchedule', app.get('assessmentSchedule') or 'N/A')
        self.addII('hasPolicy', 'yes' if app.get('policyArn') else 'no')

    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    @staticmethod
    def _aware(ts):
        if ts is None:
            return None
        if ts.tzinfo is None:
            return ts.replace(tzinfo=datetime.timezone.utc)
        return ts

    def _listAssessments(self, **filters):
        items, token, pages = [], None, 0
        while pages < self.PAGE_CAP:
            kwargs = dict(appArn=self.appArn, reverseOrder=True, **filters)
            if token:
                kwargs['nextToken'] = token
            resp = self.rhClient.list_app_assessments(**kwargs)
            items += resp.get('assessmentSummaries', []) or []
            pages += 1
            token = resp.get('nextToken')
            if not token:
                break
        return items

    # 1. Last successful assessment is missing or older than STALE_DAYS
    def _checkResilienceHubAssessmentStale(self):
        key = 'resilienceHubAssessmentStale'
        try:
            successes = self._listAssessments(assessmentStatus=['Success'])
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f'Unable to evaluate ({self._errCode(e)})']
            return

        ## Do not trust the server-side filter / ordering blindly: keep only
        ## Success rows and take the latest completion time.
        times = []
        for a in successes:
            if a.get('assessmentStatus') != 'Success':
                continue
            ts = self._aware(a.get('endTime') or a.get('startTime'))
            if ts:
                times.append(ts)

        if not times:
            try:
                recent = self._listAssessments()
            except botocore.exceptions.ClientError as e:
                self.results[key] = [0, f'Unable to evaluate ({self._errCode(e)})']
                return
            running = [a for a in recent if a.get('assessmentStatus') in ('Pending', 'InProgress')]
            successFound = [a for a in recent if a.get('assessmentStatus') == 'Success']
            if successFound:
                ## Filtered call missed a Success the unfiltered one returned.
                times = [self._aware(a.get('endTime') or a.get('startTime')) for a in successFound]
                times = [t for t in times if t]
            elif running and len(running) == len(recent):
                self.results[key] = [0, 'First assessment is still in progress']
                return
            else:
                failed = len([a for a in recent if a.get('assessmentStatus') == 'Failed'])
                detail = f' ({failed} failed assessment(s))' if failed else ''
                self.results[key] = [
                    -1,
                    f'Application has never completed a successful resiliency assessment{detail} - '
                    'its ability to meet RTO/RPO targets is unknown'
                ]
                return
            if not times:
                self.results[key] = [0, 'Unable to evaluate (assessment time not reported)']
                return

        latest = max(times)
        age = (datetime.datetime.now(datetime.timezone.utc) - latest).days
        schedule = self.app.get('assessmentSchedule') or 'Disabled'
        if age > self.STALE_DAYS:
            self.results[key] = [
                -1,
                f'Last successful assessment completed {age} day(s) ago '
                f'({latest.strftime("%Y-%m-%d")}), older than {self.STALE_DAYS} days; '
                f'assessment schedule: {schedule}'
            ]
        else:
            self.results[key] = [
                1,
                f'Last successful assessment completed {age} day(s) ago; assessment schedule: {schedule}'
            ]

    # 2. Application is in policy breach or has drifted
    def _checkResilienceHubDriftOrBreach(self):
        key = 'resilienceHubDriftOrBreach'
        compliance = self.app.get('complianceStatus')
        drift = self.app.get('driftStatus')

        problems = []
        if compliance == 'PolicyBreached':
            problems.append('the last assessment found the resiliency policy RTO/RPO targets are breached')
        if drift == 'Detected':
            problems.append('drift was detected since the last successful assessment')
        if problems:
            self.results[key] = [-1, 'Application: ' + '; '.join(problems)]
            return

        if compliance == 'PolicyMet':
            note = '' if drift == 'NotDetected' else f' (drift status: {drift or "unknown"})'
            self.results[key] = [1, f'Resiliency policy met{note}']
            return

        reasons = {
            'NotAssessed': 'application has not been assessed',
            'MissingPolicy': 'no resiliency policy attached (see resilienceHubNoPolicy)',
            'ChangesDetected': 'application changed since the last assessment; re-run the assessment',
            'NotApplicable': 'compliance not applicable to this application',
        }
        reason = reasons.get(compliance) or 'compliance status {}'.format(compliance or 'unknown')
        self.results[key] = [0, 'Not evaluable: ' + reason]

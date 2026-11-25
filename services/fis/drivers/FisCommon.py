import datetime

from services.Evaluator import Evaluator


class FisCommon(Evaluator):
    """
    Account/region-scoped AWS Fault Injection Service checks.

    Input:
      detail -- from services/fis/Fis.py.getResources:
        '_region', '_experiments' (list of ExperimentSummary or None when the
        list call failed), '_experimentsError', '_experimentsCapped',
        '_templateCount'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    WINDOW_DAYS = 90

    ## Experiment states showing a fault-injection run actually happened or is
    ## underway. 'failed' (typically target resolution / permission failure
    ## before any fault was injected) and 'cancelled' (never started) do not
    ## demonstrate that resilience was exercised.
    EXERCISED_STATES = ('pending', 'initiating', 'running', 'completed',
                        'stopping', 'stopped')

    def __init__(self, detail):
        super().__init__()
        self.detail = detail
        self._resourceName = 'Account'
        self.experiments = detail.get('_experiments')
        self.error = detail.get('_experimentsError')
        self.capped = bool(detail.get('_experimentsCapped'))
        self.templateCount = detail.get('_templateCount')

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('experimentCount',
                   'N/A' if self.experiments is None else str(len(self.experiments)))
        self.addII('experimentTemplateCount',
                   'N/A' if self.templateCount is None else str(self.templateCount))

    @staticmethod
    def _asUtc(ts):
        if not isinstance(ts, datetime.datetime):
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)
        return ts.astimezone(datetime.timezone.utc)

    def _checkFisNoRecentExperiment(self):
        key = 'fisNoRecentExperiment'
        if self.experiments is None:
            self.results[key] = [0, f"Unable to evaluate ({self.error or 'Unknown'})"]
            return

        cutoff = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(days=self.WINDOW_DAYS))
        recent, recentUnexercised = [], []
        for exp in self.experiments:
            created = self._asUtc(exp.get('creationTime'))
            if created is None or created < cutoff:
                continue
            status = ((exp.get('state') or {}).get('status') or '').lower()
            if status in self.EXERCISED_STATES:
                recent.append(exp)
            else:
                recentUnexercised.append(status or 'unknown')

        if recent:
            latest = max(self._asUtc(e.get('creationTime')) for e in recent)
            self.results[key] = [
                1,
                f"{len(recent)} FIS experiment(s) run in the last "
                f"{self.WINDOW_DAYS} days (latest {latest.date().isoformat()})"
            ]
            return

        if self.capped:
            self.results[key] = [
                0,
                f"Unable to evaluate (experiment list exceeded "
                f"{len(self.experiments)} entries without a run in the last "
                f"{self.WINDOW_DAYS} days)"
            ]
            return

        templates = ('unknown number of' if self.templateCount is None
                     else str(self.templateCount))
        extra = ''
        if recentUnexercised:
            extra = (f"; {len(recentUnexercised)} recent experiment(s) ended "
                     f"without running ({', '.join(sorted(set(recentUnexercised)))})")
        self.results[key] = [
            -1,
            f"No AWS FIS experiment has run in this region in the last "
            f"{self.WINDOW_DAYS} days ({templates} experiment template(s) "
            f"defined{extra})"
        ]

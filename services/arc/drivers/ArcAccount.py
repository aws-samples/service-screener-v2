from services.Evaluator import Evaluator


class ArcAccount(Evaluator):
    """
    Account-wide ARC checks (run once per scan).

    Input detail (services/arc/Arc.py getResources):
      '_plans' / '_planError'       -- arc-region-switch list_plans
      '_clusters' / '_clusterError' -- route53-recovery-control-config list_clusters
    A list is None when it could not be read; the matching *Error holds the code.

    Status contract: -1 FAIL, 1 PASS, 0 INFO / not evaluable.
    """

    def __init__(self, detail):
        super().__init__()
        self.detail = detail
        self._resourceName = 'Account'
        self.plans = detail.get('_plans')
        self.clusters = detail.get('_clusters')
        self.planError = detail.get('_planError')
        self.clusterError = detail.get('_clusterError')

        self.addII('regionSwitchPlanCount', 'N/A' if self.plans is None else str(len(self.plans)))
        self.addII('routingControlClusterCount', 'N/A' if self.clusters is None else str(len(self.clusters)))

    def _checkRegionSwitchPlanMissing(self):
        key = 'regionSwitchPlanMissing'
        plans = self.plans or []
        clusters = self.clusters or []

        if plans or clusters:
            parts = []
            if plans:
                parts.append(f"{len(plans)} Region switch plan(s)")
            if clusters:
                parts.append(f"{len(clusters)} routing control cluster(s)")
            self.results[key] = [1, "ARC multi-Region recovery orchestration exists: " + ', '.join(parts)]
            return

        ## Absence can only be asserted when BOTH sources were read successfully.
        errs = []
        if self.plans is None:
            errs.append(f"list_plans: {self.planError}")
        if self.clusters is None:
            errs.append(f"list_clusters: {self.clusterError}")
        if errs:
            self.results[key] = [0, f"Unable to evaluate ({'; '.join(errs)})"]
            return

        self.results[key] = [
            -1,
            "No ARC Region switch plan and no ARC routing control cluster exist in this account. "
            "If any workload here is deployed across Regions, Region failover is not orchestrated "
            "by ARC and depends on ad-hoc manual steps"
        ]

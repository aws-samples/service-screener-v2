from services.Evaluator import Evaluator


class ArcRegionSwitchPlan(Evaluator):
    """
    Per-plan ARC Region switch checks.

    Input:
      plan       -- AbbreviatedPlan from arc-region-switch list_plans
      executions -- merged list_plan_executions items from every Region of the plan
      errors     -- {region: errorCode} for Regions whose executions could not be read

    Status contract: -1 FAIL, 1 PASS, 0 INFO / not evaluable.
    """

    SUCCESS_STATES = ('completed', 'completedWithExceptions', 'completedMonitoringApplicationHealth')
    RUNNING_STATES = ('inProgress', 'pending', 'pendingManualApproval', 'pausedByOperator', 'pausedByFailedStep')

    def __init__(self, plan, executions, errors):
        super().__init__()
        self.plan = plan
        self.executions = executions or []
        self.errors = errors or {}
        self._resourceName = plan.get('name') or plan.get('arn')

        self.addII('planArn', plan.get('arn', 'N/A'))
        self.addII('regions', ', '.join(plan.get('regions') or []) or 'N/A')
        self.addII('recoveryApproach', plan.get('recoveryApproach', 'N/A'))
        self.addII('executionCount', str(len(self.executions)))

    @staticmethod
    def _when(ex):
        t = ex.get('endTime') or ex.get('startTime') or ex.get('updatedAt')
        return t.isoformat() if hasattr(t, 'isoformat') else (str(t) if t else 'unknown time')

    def _checkRegionSwitchPlanNeverExecuted(self):
        key = 'regionSwitchPlanNeverExecuted'
        states = [ex.get('executionState') for ex in self.executions]

        successes = [ex for ex in self.executions if ex.get('executionState') in self.SUCCESS_STATES]
        if successes:
            last = max(successes, key=lambda ex: self._when(ex))
            self.results[key] = [
                1,
                f"{len(successes)} completed execution(s); most recent {last.get('executionAction', '')} "
                f"to {last.get('executionRegion', 'unknown Region')} at {self._when(last)}"
            ]
            return

        if self.errors:
            errs = '; '.join(f"{r}: {c}" for r, c in sorted(self.errors.items()))
            self.results[key] = [0, f"Unable to evaluate ({errs})"]
            return

        running = [s for s in states if s in self.RUNNING_STATES]
        if running or self.plan.get('activePlanExecution'):
            self.results[key] = [
                0,
                "An execution of this plan is in progress and none has completed yet "
                f"(states: {', '.join(sorted(set(running))) or 'active'})"
            ]
            return

        if self.executions:
            self.results[key] = [
                -1,
                f"Plan was executed {len(self.executions)} time(s) but no execution completed "
                f"successfully (states: {', '.join(sorted(set(str(s) for s in states)))}) - the "
                "Region switch has never been proven to work"
            ]
            return

        self.results[key] = [
            -1,
            "Plan has never been executed - the Region switch workflow has not been tested, so "
            "its steps, permissions and recovery time are unproven"
        ]

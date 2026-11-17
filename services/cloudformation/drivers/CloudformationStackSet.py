from datetime import datetime

from services.Evaluator import Evaluator


class CloudformationStackSet(Evaluator):
    """
    Per-StackSet CloudFormation checks. StackSets are only visible from the
    account that administers them (the StackSet administrator, the
    Organizations management account, or a delegated administrator), so a
    member account simply has none to evaluate. The stack instances a StackSet
    deploys INTO an account are ordinary stacks and are covered by the
    per-stack drift checks (cfnDriftDetected / cfnDriftNeverChecked).

    Input (hydrated read-only by services/cloudformation/Cloudformation.py):
      stackSet -- describe_stack_set()['StackSet'] plus
                  '_region', '_instanceCount' (0, 1 meaning "at least one", or
                  None when list_stack_instances failed) and '_describeError'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    def __init__(self, stackSet):
        super().__init__()
        self.stackSet = stackSet
        self.name = stackSet.get('StackSetName', 'unknown')
        self._resourceName = self.name
        self.drift = stackSet.get('StackSetDriftDetectionDetails') or {}

        self.addII('stackSetName', self.name)
        self.addII('region', stackSet.get('_region', 'N/A'))
        self.addII('permissionModel', stackSet.get('PermissionModel', 'N/A'))
        self.addII('driftStatus', self.drift.get('DriftStatus', 'N/A'))

    def _checkCfnStackSetDrift(self):
        key = 'cfnStackSetDrift'
        err = self.stackSet.get('_describeError')
        if err:
            self.results[key] = [0, f"Unable to evaluate ({err})"]
            return

        status = self.drift.get('DriftStatus')
        detection = self.drift.get('DriftDetectionStatus')
        lastCheck = self.drift.get('LastDriftCheckTimestamp')
        instances = self.stackSet.get('_instanceCount')

        if status == 'DRIFTED':
            drifted = self.drift.get('DriftedStackInstancesCount')
            total = self.drift.get('TotalStackInstancesCount')
            self.results[key] = [
                -1,
                f"StackSet '{self.name}' is DRIFTED"
                + (f" ({drifted} of {total} stack instance(s))"
                   if drifted is not None and total else "")
                + f" as of {self._fmt(lastCheck)} — resources deployed by "
                "this StackSet were changed outside CloudFormation, so the "
                "template no longer describes what runs in the target accounts"
            ]
            return

        if detection == 'IN_PROGRESS':
            self.results[key] = [
                0, f"StackSet '{self.name}' drift detection is in progress"
            ]
            return

        if instances == 0:
            self.results[key] = [
                0,
                f"StackSet '{self.name}' has no stack instances — drift "
                "detection is not applicable"
            ]
            return

        if status == 'IN_SYNC' and lastCheck:
            failed = self.drift.get('FailedStackInstancesCount') or 0
            if failed:
                self.results[key] = [
                    0,
                    f"StackSet '{self.name}' last drift check "
                    f"({self._fmt(lastCheck)}) could not check {failed} stack "
                    "instance(s); drift status of those is unknown"
                ]
            else:
                self.results[key] = [
                    1,
                    f"StackSet '{self.name}' is IN_SYNC (last checked "
                    f"{self._fmt(lastCheck)})"
                ]
            return

        ## NOT_CHECKED, or a status with no check timestamp.
        if instances is None:
            self.results[key] = [
                0,
                "Unable to evaluate (stack instances could not be listed) — "
                f"StackSet '{self.name}' drift status is {status or 'not reported'}"
            ]
            return
        if lastCheck:
            ## Drift detection was attempted (FAILED / STOPPED / PARTIAL_SUCCESS
            ## without a status): the drift state is unknown, not a finding.
            self.results[key] = [
                0,
                f"Unable to evaluate (last drift detection "
                f"{detection or 'status unknown'}) — StackSet '{self.name}' "
                f"last drift check ({self._fmt(lastCheck)}) produced no usable "
                f"result (status {status or 'NOT_CHECKED'})"
            ]
            return
        self.results[key] = [
            -1,
            f"StackSet '{self.name}' has never been checked for drift "
            f"(status {status or 'NOT_CHECKED'}) — whether its stack instances "
            "still match the template is unknown"
        ]

    @staticmethod
    def _fmt(value):
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d')
        return str(value) if value else 'never'

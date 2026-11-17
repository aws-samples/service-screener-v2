from services.Evaluator import Evaluator


class CodedeployDeploymentGroup(Evaluator):
    """
    Per deployment group CodeDeploy checks.

    Input:
      group -- a deploymentGroupInfo dict from batch_get_deployment_groups /
               get_deployment_group, plus '_region', optional '_tags', and
               '_error' (error code) when the configuration could not be read.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    def __init__(self, group, cdClient):
        super().__init__()
        self.group = group
        self.cdClient = cdClient
        self._resourceName = '{}/{}'.format(
            group.get('applicationName', 'unknown'),
            group.get('deploymentGroupName', 'unknown'))

        self.addII('region', group.get('_region', 'N/A'))
        if group.get('computePlatform'):
            self.addII('computePlatform', group.get('computePlatform'))

    def _checkCodedeployNoAutoRollback(self):
        key = 'codedeployNoAutoRollback'
        if self.group.get('_error'):
            self.results[key] = [0, f"Unable to evaluate ({self.group['_error']})"]
            return

        cfg = self.group.get('autoRollbackConfiguration') or {}
        enabled = bool(cfg.get('enabled'))
        events = cfg.get('events') or []

        if not enabled or not events:
            self.results[key] = [
                -1,
                "Automatic rollback is not enabled (autoRollbackConfiguration "
                "enabled={}, events={}) - a failed deployment leaves the "
                "partially deployed revision in place".format(
                    enabled, ','.join(events) or 'none')
            ]
            return

        if 'DEPLOYMENT_FAILURE' not in events:
            self.results[key] = [
                -1,
                "Automatic rollback is enabled only for {} - a deployment that "
                "fails is not rolled back automatically (add DEPLOYMENT_FAILURE)"
                .format(','.join(events))
            ]
            return

        self.results[key] = [
            1, "Automatic rollback enabled for {}".format(','.join(events))
        ]

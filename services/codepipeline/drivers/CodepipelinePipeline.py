import re

from services.Evaluator import Evaluator


class CodepipelinePipeline(Evaluator):
    """
    Per-pipeline CodePipeline checks.

    Input:
      pipeline -- get_pipeline()['pipeline']
      metadata -- get_pipeline()['metadata'] (pipelineArn)
      shared   -- services.codepipeline.Codepipeline.CodepipelineShared (lazy,
                  region-wide IAM / notification / EventBridge lookups)

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    FAILURE_EVENT_TYPES = (
        'codepipeline-pipeline-pipeline-execution-failed',
        'codepipeline-pipeline-stage-execution-failed',
        'codepipeline-pipeline-action-execution-failed',
    )
    EVENT_DETAIL_TYPES = (
        'CodePipeline Pipeline Execution State Change',
        'CodePipeline Stage Execution State Change',
        'CodePipeline Action Execution State Change',
    )
    ## Notification targets that still deliver.
    LIVE_TARGET_STATUSES = (None, 'ACTIVE', 'PENDING')

    ## Action providers that are security scanners by definition.
    SECURITY_PROVIDERS = ('InspectorScan',)
    ## Heuristic: names of actions / stages / CodeBuild projects that indicate a
    ## test or security-scan step even when it runs as a Build action.
    SECURITY_NAME_RE = re.compile(
        r'secur|scan|sast|dast|(?<!la)test|lint|audit|vuln|snyk|sonar|'
        r'codeguru|inspector|checkov|trivy|semgrep|cfn-?nag|cfn-?guard|owasp|'
        r'grype|gitleaks|bandit|tfsec|veracode|zap(?![a-z])',
        re.IGNORECASE)

    def __init__(self, pipeline, metadata, shared):
        super().__init__()
        self.pipeline = pipeline or {}
        self.metadata = metadata or {}
        self.shared = shared
        self._resourceName = self.pipeline.get('name')
        self.arn = self.metadata.get('pipelineArn')
        self.stages = self.pipeline.get('stages') or []

        self.addII('pipelineType', self.pipeline.get('pipelineType') or 'V1')
        self.addII('stageCount', str(len(self.stages)))

    # ------------------------------------------------------------------ #
    def _actions(self):
        for stage in self.stages:
            for action in stage.get('actions') or []:
                yield stage, action

    @staticmethod
    def _category(action):
        return (action.get('actionTypeId') or {}).get('category')

    @staticmethod
    def _provider(action):
        return (action.get('actionTypeId') or {}).get('provider')

    def _accountId(self):
        if self.arn and len(self.arn.split(':')) > 4:
            return self.arn.split(':')[4]
        return None

    # ------------------------------------------------------------------ #
    # 1. Pipeline / action service roles with admin permissions (SEC11-BP08)
    # ------------------------------------------------------------------ #
    def _checkPipelineRoleOverprivileged(self):
        from services.codepipeline.Codepipeline import CodepipelineLookupError

        roles = {}
        if self.pipeline.get('roleArn'):
            roles[self.pipeline['roleArn']] = 'pipeline role'
        for stage, action in self._actions():
            if action.get('roleArn') and action['roleArn'] not in roles:
                roles[action['roleArn']] = f"action {stage.get('name')}/{action.get('name')}"

        if not roles:
            self.results['pipelineRoleOverprivileged'] = [0, 'Unable to evaluate (no roleArn on pipeline)']
            return

        acct = self._accountId()
        admin, unreadable, crossAccount = [], [], []
        for roleArn, where in roles.items():
            parts = roleArn.split(':')
            roleAcct = parts[4] if len(parts) > 4 else None
            ## IAM lookups are by role NAME in the scanned account; a role in
            ## another account (cross-account action) cannot be read here.
            if acct and roleAcct and roleAcct != acct:
                crossAccount.append(roleArn)
                continue
            try:
                found = self.shared.roleAdminFindings(roleArn)
            except CodepipelineLookupError as e:
                unreadable.append(e.code)
                continue
            if found:
                admin.append(f"{roleArn.split('/')[-1]} ({where}: {', '.join(found)})")

        if admin:
            self.results['pipelineRoleOverprivileged'] = [
                -1, 'Role(s) with administrator access: ' + '; '.join(admin)]
        elif unreadable:
            self.results['pipelineRoleOverprivileged'] = [
                0, f'Unable to evaluate ({unreadable[0]})']
        elif crossAccount:
            self.results['pipelineRoleOverprivileged'] = [
                0, 'Unable to evaluate (cross-account action role: '
                   + ', '.join(crossAccount) + ')']
        else:
            self.results['pipelineRoleOverprivileged'] = [
                1, f'{len(roles)} pipeline/action role(s) have no administrator-equivalent policy']

    # ------------------------------------------------------------------ #
    # 2. Deploy stages without automatic rollback on failure (SEC11-BP07)
    # ------------------------------------------------------------------ #
    def _checkCodepipelineNoStageRollback(self):
        ## The first stage is always the source stage and cannot roll back.
        deployStages = [
            s for s in self.stages[1:]
            if any(self._category(a) == 'Deploy' for a in s.get('actions') or [])
        ]
        if not deployStages:
            self.results['codepipelineNoStageRollback'] = [
                1, 'No Deploy-category stages; stage rollback not applicable']
            return

        names = [s.get('name') for s in deployStages]
        if (self.pipeline.get('pipelineType') or 'V1') != 'V2':
            self.results['codepipelineNoStageRollback'] = [
                -1, 'V1 pipeline: automatic stage rollback is only available on V2 pipelines; '
                    'deploy stage(s) without rollback: ' + ', '.join(names)]
            return

        missing = []
        for s in deployStages:
            onFailure = s.get('onFailure') or {}
            hasRollback = onFailure.get('result') == 'ROLLBACK' or any(
                (c or {}).get('result') == 'ROLLBACK' for c in onFailure.get('conditions') or [])
            if not hasRollback:
                missing.append(s.get('name'))

        if missing:
            self.results['codepipelineNoStageRollback'] = [
                -1, 'Deploy stage(s) without onFailure ROLLBACK: ' + ', '.join(missing)]
        else:
            self.results['codepipelineNoStageRollback'] = [
                1, 'All deploy stages roll back on failure: ' + ', '.join(names)]

    # ------------------------------------------------------------------ #
    # 3. No failure notification (SEC11-BP08)
    # ------------------------------------------------------------------ #
    def _checkPipelineNoEventNotification(self):
        from services.codepipeline.Codepipeline import CodepipelineLookupError

        errors = []
        try:
            for rule in self.shared.notificationRules():
                if self._notificationRuleCovers(rule):
                    self.results['pipelineNoEventNotification'] = [
                        1, f"Notification rule {rule.get('Name')} notifies on execution failure"]
                    return
        except CodepipelineLookupError as e:
            errors.append(e.code)

        try:
            for ruleName, pattern in self.shared.eventRules():
                if self._eventPatternCovers(pattern):
                    self.results['pipelineNoEventNotification'] = [
                        1, f'EventBridge rule {ruleName} matches failed executions of this pipeline']
                    return
        except CodepipelineLookupError as e:
            errors.append(e.code)

        if errors:
            self.results['pipelineNoEventNotification'] = [0, f'Unable to evaluate ({errors[0]})']
            return
        self.results['pipelineNoEventNotification'] = [
            -1, 'No enabled notification rule or EventBridge rule with a target alerts on '
                'failed executions of this pipeline']

    def _notificationRuleCovers(self, rule):
        if not self.arn or rule.get('Resource') != self.arn:
            return False
        if rule.get('Status') != 'ENABLED':
            return False
        types = [t.get('EventTypeId') for t in rule.get('EventTypes') or []]
        if not any(t in self.FAILURE_EVENT_TYPES for t in types):
            return False
        return any(t.get('TargetStatus') in self.LIVE_TARGET_STATUSES
                   for t in rule.get('Targets') or [])

    def _eventPatternCovers(self, pattern):
        detailTypes = pattern.get('detail-type')
        if detailTypes is not None and not self._matches(detailTypes, self.EVENT_DETAIL_TYPES):
            return False
        resources = pattern.get('resources')
        if resources is not None and not self._matches(resources, [self.arn or '']):
            return False
        detail = pattern.get('detail') or {}
        if not isinstance(detail, dict):
            return False
        if 'pipeline' in detail and not self._matches(detail['pipeline'], [self._resourceName]):
            return False
        if 'state' in detail and not self._matches(detail['state'], ['FAILED']):
            return False
        return True

    @staticmethod
    def _matches(patternValue, candidates):
        """Minimal EventBridge matcher: exact strings, prefix, anything-but.
        Other content filters are treated as matching (cannot be decided
        statically without the event)."""
        values = patternValue if isinstance(patternValue, list) else [patternValue]
        for v in values:
            if isinstance(v, str):
                if v in candidates:
                    return True
            elif isinstance(v, dict):
                if 'prefix' in v and isinstance(v['prefix'], str):
                    if any(c.startswith(v['prefix']) for c in candidates):
                        return True
                elif 'anything-but' in v:
                    excluded = v['anything-but']
                    excluded = excluded if isinstance(excluded, list) else [excluded]
                    if any(c not in excluded for c in candidates):
                        return True
                else:
                    return True
        return False

    # ------------------------------------------------------------------ #
    # 4. No security test action (SEC11-BP03) - heuristic
    # ------------------------------------------------------------------ #
    def _checkPipelineNoSecurityTestAction(self):
        for stage, action in self._actions():
            cat, prov = self._category(action), self._provider(action)
            if cat == 'Test':
                self.results['pipelineNoSecurityTestAction'] = [
                    1, f"Test action {stage.get('name')}/{action.get('name')} ({prov})"]
                return
            if prov in self.SECURITY_PROVIDERS:
                self.results['pipelineNoSecurityTestAction'] = [
                    1, f"Security scan action {stage.get('name')}/{action.get('name')} ({prov})"]
                return
            cfg = action.get('configuration') or {}
            for label in (action.get('name'), stage.get('name'), cfg.get('ProjectName')):
                if isinstance(label, str) and self.SECURITY_NAME_RE.search(label):
                    self.results['pipelineNoSecurityTestAction'] = [
                        1, f"Action {stage.get('name')}/{action.get('name')} appears to run "
                           f"tests or security scanning ('{label}')"]
                    return

        self.results['pipelineNoSecurityTestAction'] = [
            -1, 'No Test-category action, Amazon Inspector scan action, or test/security-scan '
                'named step found in any stage (tests may still run inside a build step)']

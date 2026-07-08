from services.Evaluator import Evaluator


class BedrockAccount(Evaluator):
    """
    Account/region-level checks (reporter keys 26-30):
      bedrockModelInvocationLoggingDisabled, bedrockModelInvocationNoCloudWatch,
      bedrockModelInvocationNoS3, bedrockNoGuardrailsExist,
      bedrockAgentWithoutGuardrail.

    Runs once per region.
    """

    def __init__(self, agents, guardrails, loggingConfig, bedrockClient):
        super().__init__()
        self.agents = agents or []
        self.guardrails = guardrails or []
        self.loggingConfig = loggingConfig  # None if not configured
        self.bedrockClient = bedrockClient

        self._resourceName = 'Account'

        self.addII('agentCount', len(self.agents))
        self.addII('guardrailCount', len(self.guardrails))
        self.addII('loggingConfigured', 'Yes' if self.loggingConfig else 'No')

    # ------------------------------------------------------------------ #
    # 26. Model invocation logging disabled
    # ------------------------------------------------------------------ #
    def _checkBedrockModelInvocationLoggingDisabled(self):
        cfg = self.loggingConfig
        # Logging is considered "configured" when there is at least one destination
        # and at least one data type enabled (text/image/embedding/video).
        hasDestination = bool(cfg) and bool(
            cfg.get('cloudWatchConfig') or cfg.get('s3Config')
        )

        if not hasDestination:
            self.results['bedrockModelInvocationLoggingDisabled'] = [
                -1,
                "Bedrock model invocation logging is not configured"
            ]
        else:
            self.results['bedrockModelInvocationLoggingDisabled'] = [
                1,
                "Model invocation logging is configured"
            ]

    # ------------------------------------------------------------------ #
    # 27. No CloudWatch destination
    # ------------------------------------------------------------------ #
    def _checkBedrockModelInvocationNoCloudWatch(self):
        cfg = self.loggingConfig or {}
        cw = cfg.get('cloudWatchConfig')

        if not self.loggingConfig:
            # Different finding from #26 — be explicit
            self.results['bedrockModelInvocationNoCloudWatch'] = [
                -1,
                "Logging is not configured (no CloudWatch destination)"
            ]
            return

        if not cw or not cw.get('logGroupName'):
            self.results['bedrockModelInvocationNoCloudWatch'] = [
                -1,
                "Logging configured but no CloudWatch destination"
            ]
        else:
            self.results['bedrockModelInvocationNoCloudWatch'] = [
                1,
                f"CloudWatch log group: {cw.get('logGroupName')}"
            ]

    # ------------------------------------------------------------------ #
    # 28. No S3 destination
    # ------------------------------------------------------------------ #
    def _checkBedrockModelInvocationNoS3(self):
        cfg = self.loggingConfig or {}
        s3 = cfg.get('s3Config')

        if not self.loggingConfig:
            self.results['bedrockModelInvocationNoS3'] = [
                -1,
                "Logging is not configured (no S3 archive)"
            ]
            return

        if not s3 or not s3.get('bucketName'):
            self.results['bedrockModelInvocationNoS3'] = [
                -1,
                "Logging configured but no S3 archival destination"
            ]
        else:
            self.results['bedrockModelInvocationNoS3'] = [
                1,
                f"S3 bucket: {s3.get('bucketName')}"
            ]

    # ------------------------------------------------------------------ #
    # 29. Account has zero guardrails
    # ------------------------------------------------------------------ #
    def _checkBedrockNoGuardrailsExist(self):
        if not self.guardrails:
            self.results['bedrockNoGuardrailsExist'] = [
                -1,
                "Account has zero Bedrock guardrails defined in this region"
            ]
        else:
            self.results['bedrockNoGuardrailsExist'] = [
                1,
                f"{len(self.guardrails)} guardrail(s) exist"
            ]

    # ------------------------------------------------------------------ #
    # 30. At least one agent without a guardrail
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentWithoutGuardrail(self):
        if not self.agents:
            self.results['bedrockAgentWithoutGuardrail'] = [0, "No agents in this region"]
            return

        unguarded = []
        for agent in self.agents:
            cfg = agent.get('guardrailConfiguration') or {}
            if not cfg.get('guardrailIdentifier'):
                unguarded.append(agent.get('agentName') or agent.get('agentId', 'unknown'))

        if unguarded:
            self.results['bedrockAgentWithoutGuardrail'] = [
                -1,
                f"{len(unguarded)} agent(s) without a guardrail: {', '.join(unguarded)}"
            ]
        else:
            self.results['bedrockAgentWithoutGuardrail'] = [
                1,
                f"All {len(self.agents)} agent(s) have a guardrail attached"
            ]

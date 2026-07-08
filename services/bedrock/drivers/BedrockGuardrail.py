from services.Evaluator import Evaluator


class BedrockGuardrail(Evaluator):
    """
    Per-guardrail checks (reporter keys 11-20):
      bedrockGuardrailContentFilterDisabled, bedrockGuardrailContentFilterWeak,
      bedrockGuardrailNoPromptAttackFilter, bedrockGuardrailNoPiiDetection,
      bedrockGuardrailNoDeniedTopics, bedrockGuardrailNoWordFilter,
      bedrockGuardrailNoGroundingFilter, bedrockGuardrailNoEncryption,
      bedrockGuardrailStatusFailed, bedrockGuardrailOutputFilterDisabled.

    Input is the full response of bedrock.get_guardrail(...) (DRAFT version).
    """

    EXPECTED_CONTENT_FILTER_TYPES = {
        'SEXUAL', 'VIOLENCE', 'HATE', 'INSULTS', 'MISCONDUCT'
    }

    def __init__(self, guardrail, bedrockClient):
        super().__init__()
        self.guardrail = guardrail
        self.bedrockClient = bedrockClient

        name = guardrail.get('name') or guardrail.get('guardrailId', 'unknown')
        self._resourceName = name

        self.addII('guardrailId', guardrail.get('guardrailId', 'N/A'))
        self.addII('name', name)
        self.addII('status', guardrail.get('status', 'N/A'))
        self.addII('version', guardrail.get('version', 'DRAFT'))
        self.addII('kmsKeyArn', guardrail.get('kmsKeyArn', 'None'))

    # ------------------------------------------------------------------ #
    # Convenience accessors
    # ------------------------------------------------------------------ #
    def _contentFilters(self):
        return (self.guardrail.get('contentPolicy') or {}).get('filters') or []

    def _sensitivePolicy(self):
        return self.guardrail.get('sensitiveInformationPolicy') or {}

    def _topicPolicy(self):
        return self.guardrail.get('topicPolicy') or {}

    def _wordPolicy(self):
        return self.guardrail.get('wordPolicy') or {}

    def _groundingPolicy(self):
        return self.guardrail.get('contextualGroundingPolicy') or {}

    # ------------------------------------------------------------------ #
    # 11. No content filters at all
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailContentFilterDisabled(self):
        filters = self._contentFilters()
        configuredTypes = {f.get('type') for f in filters if f.get('type')}
        # If none of the expected categories are present, the guardrail has effectively no content filtering
        if not (configuredTypes & self.EXPECTED_CONTENT_FILTER_TYPES):
            self.results['bedrockGuardrailContentFilterDisabled'] = [
                -1,
                "No content filters configured for SEXUAL/VIOLENCE/HATE/INSULTS/MISCONDUCT"
            ]
        else:
            self.results['bedrockGuardrailContentFilterDisabled'] = [
                1,
                f"Content filters present: {', '.join(sorted(configuredTypes & self.EXPECTED_CONTENT_FILTER_TYPES))}"
            ]

    # ------------------------------------------------------------------ #
    # 12. Any LOW-strength filter
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailContentFilterWeak(self):
        filters = self._contentFilters()
        weak = []
        for f in filters:
            ftype = f.get('type', 'UNKNOWN')
            if f.get('inputStrength') == 'LOW':
                weak.append(f"{ftype}(input=LOW)")
            if f.get('outputStrength') == 'LOW':
                weak.append(f"{ftype}(output=LOW)")
        if weak:
            self.results['bedrockGuardrailContentFilterWeak'] = [
                -1,
                "Weak filters: " + ", ".join(weak)
            ]
        else:
            self.results['bedrockGuardrailContentFilterWeak'] = [
                1,
                "No LOW-strength content filters"
            ]

    # ------------------------------------------------------------------ #
    # 13. No PROMPT_ATTACK filter
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailNoPromptAttackFilter(self):
        filters = self._contentFilters()
        hasPromptAttack = any(f.get('type') == 'PROMPT_ATTACK' for f in filters)
        if hasPromptAttack:
            self.results['bedrockGuardrailNoPromptAttackFilter'] = [1, "PROMPT_ATTACK filter present"]
        else:
            self.results['bedrockGuardrailNoPromptAttackFilter'] = [
                -1,
                "No PROMPT_ATTACK filter — prompt-injection defense missing"
            ]

    # ------------------------------------------------------------------ #
    # 14. No PII / sensitive information policy
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailNoPiiDetection(self):
        policy = self._sensitivePolicy()
        piiEntities = policy.get('piiEntitiesConfig') or []
        regexes = policy.get('regexesConfig') or []
        if not (piiEntities or regexes):
            self.results['bedrockGuardrailNoPiiDetection'] = [
                -1,
                "No PII entity or regex filters"
            ]
        else:
            self.results['bedrockGuardrailNoPiiDetection'] = [
                1,
                f"{len(piiEntities)} PII entities, {len(regexes)} regex(es)"
            ]

    # ------------------------------------------------------------------ #
    # 15. No denied topics
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailNoDeniedTopics(self):
        topics = (self._topicPolicy().get('topicsConfig') or
                  self._topicPolicy().get('topics') or [])
        if not topics:
            self.results['bedrockGuardrailNoDeniedTopics'] = [-1, "No denied topics configured"]
        else:
            self.results['bedrockGuardrailNoDeniedTopics'] = [1, f"{len(topics)} denied topic(s)"]

    # ------------------------------------------------------------------ #
    # 16. No word policy
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailNoWordFilter(self):
        policy = self._wordPolicy()
        words = policy.get('wordsConfig') or policy.get('words') or []
        managed = policy.get('managedWordListsConfig') or policy.get('managedWordLists') or []
        if not (words or managed):
            self.results['bedrockGuardrailNoWordFilter'] = [-1, "No word policy configured"]
        else:
            self.results['bedrockGuardrailNoWordFilter'] = [
                1,
                f"{len(words)} custom word(s), {len(managed)} managed list(s)"
            ]

    # ------------------------------------------------------------------ #
    # 17. No contextual grounding policy
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailNoGroundingFilter(self):
        policy = self._groundingPolicy()
        filters = policy.get('filtersConfig') or policy.get('filters') or []
        if not filters:
            self.results['bedrockGuardrailNoGroundingFilter'] = [
                -1,
                "No contextual grounding policy"
            ]
        else:
            self.results['bedrockGuardrailNoGroundingFilter'] = [
                1,
                f"{len(filters)} grounding filter(s) configured"
            ]

    # ------------------------------------------------------------------ #
    # 18. No customer-managed KMS key
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailNoEncryption(self):
        kms = self.guardrail.get('kmsKeyArn')
        if kms:
            self.results['bedrockGuardrailNoEncryption'] = [1, f"CMK: {kms}"]
        else:
            self.results['bedrockGuardrailNoEncryption'] = [-1, "Default encryption (no CMK)"]

    # ------------------------------------------------------------------ #
    # 19. Status FAILED
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailStatusFailed(self):
        status = self.guardrail.get('status', 'UNKNOWN')
        if status == 'FAILED':
            self.results['bedrockGuardrailStatusFailed'] = [-1, f"Guardrail status: {status}"]
        else:
            self.results['bedrockGuardrailStatusFailed'] = [1, f"Guardrail status: {status}"]

    # ------------------------------------------------------------------ #
    # 20. Output filter disabled while input enabled
    # ------------------------------------------------------------------ #
    def _checkBedrockGuardrailOutputFilterDisabled(self):
        filters = self._contentFilters()
        mismatches = []
        for f in filters:
            ftype = f.get('type', 'UNKNOWN')
            inputEnabled = f.get('inputEnabled')
            outputEnabled = f.get('outputEnabled')

            # Some SDK versions don't return these fields when both are true; treat missing as enabled.
            inputOn = inputEnabled if inputEnabled is not None else True
            outputOn = outputEnabled if outputEnabled is not None else True

            if inputOn and not outputOn:
                mismatches.append(ftype)

        if mismatches:
            self.results['bedrockGuardrailOutputFilterDisabled'] = [
                -1,
                f"Output filtering disabled for: {', '.join(mismatches)}"
            ]
        else:
            self.results['bedrockGuardrailOutputFilterDisabled'] = [
                1,
                "Input/output filtering aligned"
            ]

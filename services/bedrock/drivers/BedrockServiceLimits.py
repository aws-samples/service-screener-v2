import botocore

from services.Evaluator import Evaluator
from utils.Config import Config


class BedrockServiceLimits(Evaluator):
    """
    Service-quota checks (reporter keys 31-35):
      bedrockServiceLimitAgents, bedrockServiceLimitKnowledgeBases,
      bedrockServiceLimitGuardrails, bedrockServiceLimitAgentActionGroups,
      bedrockServiceLimitTPM.

    All checks follow the SS pattern (cf. DynamoDbGeneric):
      - list_service_quotas(ServiceCode='bedrock') once
      - compare current resource count vs Value
      - flag when usage >= 80%
    """

    USAGE_THRESHOLD = 0.80

    # Bedrock quota names we look for (case-insensitive substring matching to
    # cope with cosmetic name changes between bedrock vs bedrock-agent quota lists).
    AGENT_QUOTA_HINTS = ('agents per account', 'agents per region', 'number of agents')
    KB_QUOTA_HINTS = ('knowledge bases per account', 'knowledge bases per region', 'number of knowledge bases')
    GUARDRAIL_QUOTA_HINTS = ('guardrails per account', 'guardrails per region', 'number of guardrails')
    ACTION_GROUP_QUOTA_HINTS = ('action groups per agent',)

    # Tokens-per-minute quotas vary per model. We pick the maximum on-demand
    # InvokeModel TPM quota across all models and check whether that maximum is
    # still at a "new-account default" level (heuristic: < 200k TPM).
    #
    # AWS renamed these quotas from "On-demand InvokeModel tokens per minute"
    # to "On-demand model inference tokens per minute"; we accept both forms.
    # We exclude "Cross-region" inference quotas which represent a different
    # capacity lane and would skew the heuristic.
    TPM_QUOTA_HINTS = (
        'on-demand model inference tokens per minute',
        'on-demand invokemodel tokens per minute',
    )
    TPM_EXCLUDE_HINTS = ('cross-region',)
    TPM_LOW_DEFAULT_THRESHOLD = 200000

    def __init__(self, agents, guardrails, knowledgeBases, serviceQuotaClient):
        super().__init__()
        self.agents = agents or []
        self.guardrails = guardrails or []
        self.knowledgeBases = knowledgeBases or []
        self.serviceQuotaClient = serviceQuotaClient

        self._resourceName = 'ServiceLimits'

        # bedrock vs bedrock-agent quotas live under different service codes.
        self._bedrockQuotas = self._listQuotas('bedrock')
        self._bedrockAgentQuotas = self._listQuotas('bedrock-agent')

        self.addII('agentCount', len(self.agents))
        self.addII('guardrailCount', len(self.guardrails))
        self.addII('knowledgeBaseCount', len(self.knowledgeBases))

    # ------------------------------------------------------------------ #
    # Quota fetch (cached on Config; one fetch per region per service code)
    # ------------------------------------------------------------------ #
    def _listQuotas(self, serviceCode):
        cacheKey = f"BedrockQuotaCache::{serviceCode}"
        cached = Config.get(cacheKey, None)
        if cached is not None:
            return cached

        quotas = []
        try:
            paginator = self.serviceQuotaClient.get_paginator('list_service_quotas')
            for page in paginator.paginate(ServiceCode=serviceCode):
                quotas.extend(page.get('Quotas', []))
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            if code not in ('AccessDenied', 'AccessDeniedException', 'NoSuchResourceException'):
                msg = e.response.get('Error', {}).get('Message', str(e))
                print(f"service-quotas list_service_quotas({serviceCode}): {code} - {msg}")
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"service-quotas endpoint unavailable ({serviceCode}): {e}")

        Config.set(cacheKey, quotas)
        return quotas

    # ------------------------------------------------------------------ #
    # Quota lookup utilities
    # ------------------------------------------------------------------ #
    def _findQuotasByHints(self, quotaList, hints):
        out = []
        for q in quotaList:
            name = (q.get('QuotaName') or '').lower()
            if any(h in name for h in hints):
                out.append(q)
        return out

    def _findFirstQuotaValue(self, quotaList, hints):
        matches = self._findQuotasByHints(quotaList, hints)
        if not matches:
            return None
        # Take the first match (boto3 returns them in stable order)
        return matches[0].get('Value')

    def _reportUsage(self, checkKey, label, current, quotaValue):
        if quotaValue is None or quotaValue <= 0:
            self.results[checkKey] = [
                0,
                f"{label} quota unavailable; current usage {current}"
            ]
            return

        threshold = int(self.USAGE_THRESHOLD * quotaValue)
        pct = (current / quotaValue) * 100.0
        if current >= threshold:
            self.results[checkKey] = [
                -1,
                f"{label}: {current} of {int(quotaValue)} ({pct:.0f}% of quota)"
            ]
        else:
            self.results[checkKey] = [
                1,
                f"{label}: {current} of {int(quotaValue)} ({pct:.0f}% of quota)"
            ]

    # ------------------------------------------------------------------ #
    # 31. Agents quota
    # ------------------------------------------------------------------ #
    def _checkBedrockServiceLimitAgents(self):
        # Agent quotas may live under either service code depending on region/account
        quotaValue = (
            self._findFirstQuotaValue(self._bedrockAgentQuotas, self.AGENT_QUOTA_HINTS)
            or self._findFirstQuotaValue(self._bedrockQuotas, self.AGENT_QUOTA_HINTS)
        )
        self._reportUsage(
            'bedrockServiceLimitAgents', 'Agents', len(self.agents), quotaValue
        )

    # ------------------------------------------------------------------ #
    # 32. Knowledge bases quota
    # ------------------------------------------------------------------ #
    def _checkBedrockServiceLimitKnowledgeBases(self):
        quotaValue = (
            self._findFirstQuotaValue(self._bedrockAgentQuotas, self.KB_QUOTA_HINTS)
            or self._findFirstQuotaValue(self._bedrockQuotas, self.KB_QUOTA_HINTS)
        )
        self._reportUsage(
            'bedrockServiceLimitKnowledgeBases',
            'Knowledge Bases',
            len(self.knowledgeBases),
            quotaValue,
        )

    # ------------------------------------------------------------------ #
    # 33. Guardrails quota
    # ------------------------------------------------------------------ #
    def _checkBedrockServiceLimitGuardrails(self):
        quotaValue = (
            self._findFirstQuotaValue(self._bedrockQuotas, self.GUARDRAIL_QUOTA_HINTS)
            or self._findFirstQuotaValue(self._bedrockAgentQuotas, self.GUARDRAIL_QUOTA_HINTS)
        )
        self._reportUsage(
            'bedrockServiceLimitGuardrails',
            'Guardrails',
            len(self.guardrails),
            quotaValue,
        )

    # ------------------------------------------------------------------ #
    # 34. Action groups per agent
    # ------------------------------------------------------------------ #
    def _checkBedrockServiceLimitAgentActionGroups(self):
        quotaValue = (
            self._findFirstQuotaValue(self._bedrockAgentQuotas, self.ACTION_GROUP_QUOTA_HINTS)
            or self._findFirstQuotaValue(self._bedrockQuotas, self.ACTION_GROUP_QUOTA_HINTS)
        )

        if quotaValue is None or quotaValue <= 0:
            self.results['bedrockServiceLimitAgentActionGroups'] = [
                0,
                "Action-groups-per-agent quota unavailable"
            ]
            return

        if not self.agents:
            self.results['bedrockServiceLimitAgentActionGroups'] = [
                1,
                "No agents in this region"
            ]
            return

        threshold = int(self.USAGE_THRESHOLD * quotaValue)
        hot = []
        for agent in self.agents:
            count = len(agent.get('_actionGroups') or [])
            if count >= threshold:
                name = agent.get('agentName') or agent.get('agentId', 'unknown')
                hot.append(f"{name}({count}/{int(quotaValue)})")

        if hot:
            self.results['bedrockServiceLimitAgentActionGroups'] = [
                -1,
                f"Agent(s) near action-group limit: {', '.join(hot)}"
            ]
        else:
            self.results['bedrockServiceLimitAgentActionGroups'] = [
                1,
                f"All agents under {int(self.USAGE_THRESHOLD*100)}% of {int(quotaValue)} action-group limit"
            ]

    # ------------------------------------------------------------------ #
    # 35. TPM quota for primary on-demand model
    # ------------------------------------------------------------------ #
    def _checkBedrockServiceLimitTPM(self):
        tpmQuotas = self._findQuotasByHints(self._bedrockQuotas, self.TPM_QUOTA_HINTS)
        # Filter out cross-region inference lanes (different capacity model).
        tpmQuotas = [
            q for q in tpmQuotas
            if not any(ex in (q.get('QuotaName') or '').lower() for ex in self.TPM_EXCLUDE_HINTS)
        ]
        if not tpmQuotas:
            self.results['bedrockServiceLimitTPM'] = [
                0,
                "TPM quota not found in Service Quotas"
            ]
            return

        # Pick the highest TPM quota across all models — this is the "best" lane
        # the account has. If even the highest is low, every model lane is low.
        best = max(tpmQuotas, key=lambda q: q.get('Value') or 0)
        bestName = best.get('QuotaName', 'on-demand InvokeModel TPM')
        bestValue = best.get('Value') or 0

        if bestValue < self.TPM_LOW_DEFAULT_THRESHOLD:
            self.results['bedrockServiceLimitTPM'] = [
                -1,
                f"Highest TPM quota '{bestName}' is {int(bestValue)} (< {self.TPM_LOW_DEFAULT_THRESHOLD})"
            ]
        else:
            self.results['bedrockServiceLimitTPM'] = [
                1,
                f"Highest TPM quota '{bestName}' is {int(bestValue)}"
            ]

import botocore

from services.Evaluator import Evaluator
from services.bedrock.drivers.BedrockAgent import _inspectRoleForBroadPolicies
from utils.Config import Config


class BedrockAgentCore(Evaluator):
    """
    Account/region-level checks for Amazon Bedrock AgentCore (reporter keys 36-50).

    Input is the dict produced by Bedrock.py._collectAgentCore(...), which carries
    the result of:
      - list_agent_runtimes + get_agent_runtime per runtime
      - list_gateways + get_gateway + list_gateway_targets + get_gateway_target
      - list_memories + get_memory
      - list_policy_engines
      - list_oauth2_credential_providers + list_api_key_credential_providers
      - list_workload_identities
      - list_evaluators

    Per-resource findings are aggregated into one result per check key (status/value),
    matching the existing BedrockAccount pattern.
    """

    BROAD_RUNTIME_ACTIONS = {
        '*', 'bedrock:*', 'bedrock-agentcore:*', 'iam:*', 's3:*', 'kms:*'
    }

    NON_OPERATIONAL_STATUSES = {'FAILED', 'CREATE_FAILED', 'DELETE_FAILED'}

    # Credential provider types that constitute genuine outbound authorization
    # to an external tool (vs. just relying on the gateway's own IAM role)
    OUTBOUND_AUTH_TYPES = {'OAUTH', 'API_KEY'}

    USAGE_THRESHOLD = 0.80

    RUNTIME_QUOTA_HINTS = (
        'agent runtimes per account',
        'agent runtimes per region',
        'number of agent runtimes',
    )

    def __init__(self, ac, serviceQuotaClient, iamClient):
        super().__init__()
        self.ac = ac or {}
        self.runtimes = self.ac.get('runtimes') or []
        self.gateways = self.ac.get('gateways') or []          # each carries '_targets'
        self.memories = self.ac.get('memories') or []
        self.policyEngines = self.ac.get('policyEngines') or []
        self.oauthProviders = self.ac.get('oauthProviders') or []
        self.apiKeyProviders = self.ac.get('apiKeyProviders') or []
        self.workloadIdentities = self.ac.get('workloadIdentities') or []
        self.evaluators = self.ac.get('evaluators') or []

        self.serviceQuotaClient = serviceQuotaClient
        self.iamClient = iamClient

        self._resourceName = 'AgentCore'

        self.addII('runtimeCount', len(self.runtimes))
        self.addII('gatewayCount', len(self.gateways))
        self.addII('memoryCount', len(self.memories))
        self.addII('policyEngineCount', len(self.policyEngines))
        self.addII('oauthProviderCount', len(self.oauthProviders))
        self.addII('apiKeyProviderCount', len(self.apiKeyProviders))
        self.addII('evaluatorCount', len(self.evaluators))

    def _hasAnyAgentCoreResource(self):
        return bool(
            self.runtimes or self.gateways or self.memories or self.policyEngines
            or self.oauthProviders or self.apiKeyProviders
            or self.workloadIdentities or self.evaluators
        )

    # ------------------------------------------------------------------ #
    # Runtime checks
    # ------------------------------------------------------------------ #
    def _checkBedrockACRuntimeNoEncryption(self):
        # AgentRuntime in the current bedrock-agentcore-control API does not
        # expose a top-level CMK setting on GetAgentRuntime. We defensively
        # scan the response for any kms/encryption field; if absent we
        # downgrade to INFO so we don't emit false positives, and surface a
        # note pointing to the related per-resource checks (Memory CMK,
        # Gateway CMK, PolicyEngine CMK).
        if not self.runtimes:
            self.results['bedrockACRuntimeNoEncryption'] = [0, "No agent runtimes in this region"]
            return

        none_with_field = True
        missing = []
        for rt in self.runtimes:
            cmk = self._findKmsValue(rt)
            if cmk is None:
                # Field absent entirely on this response
                continue
            none_with_field = False
            if not cmk:
                missing.append(rt.get('agentRuntimeName') or rt.get('agentRuntimeId', 'unknown'))

        if none_with_field:
            self.results['bedrockACRuntimeNoEncryption'] = [
                0,
                "AgentRuntime API does not expose a direct CMK setting; verify CMK on "
                "associated Memory/Gateway/PolicyEngine (see bedrockACMemoryNoEncryption etc.)"
            ]
        elif missing:
            self.results['bedrockACRuntimeNoEncryption'] = [
                -1,
                f"Runtimes without CMK: {', '.join(missing)}"
            ]
        else:
            self.results['bedrockACRuntimeNoEncryption'] = [
                1,
                f"All {len(self.runtimes)} runtime(s) have CMK"
            ]

    def _checkBedrockACRuntimeNoVPC(self):
        if not self.runtimes:
            self.results['bedrockACRuntimeNoVPC'] = [0, "No agent runtimes in this region"]
            return

        public = []
        for rt in self.runtimes:
            nc = rt.get('networkConfiguration') or {}
            mode = nc.get('networkMode')
            if mode != 'VPC':
                public.append(
                    (rt.get('agentRuntimeName') or rt.get('agentRuntimeId', 'unknown'))
                    + f"(mode={mode or 'unknown'})"
                )

        if public:
            self.results['bedrockACRuntimeNoVPC'] = [
                -1,
                f"Runtimes not in VPC: {', '.join(public)}"
            ]
        else:
            self.results['bedrockACRuntimeNoVPC'] = [
                1,
                f"All {len(self.runtimes)} runtime(s) configured in VPC"
            ]

    def _checkBedrockACRuntimeStatusFailed(self):
        if not self.runtimes:
            self.results['bedrockACRuntimeStatusFailed'] = [0, "No agent runtimes in this region"]
            return

        failed = []
        for rt in self.runtimes:
            status = rt.get('status', 'UNKNOWN')
            if status in self.NON_OPERATIONAL_STATUSES:
                failed.append(
                    (rt.get('agentRuntimeName') or rt.get('agentRuntimeId', 'unknown'))
                    + f"({status})"
                )

        if failed:
            self.results['bedrockACRuntimeStatusFailed'] = [
                -1,
                f"Runtimes in non-operational state: {', '.join(failed)}"
            ]
        else:
            self.results['bedrockACRuntimeStatusFailed'] = [
                1,
                f"All {len(self.runtimes)} runtime(s) operational"
            ]

    def _checkBedrockACRuntimeWildcardRole(self):
        if not self.runtimes:
            self.results['bedrockACRuntimeWildcardRole'] = [0, "No agent runtimes in this region"]
            return

        offenders = []
        scoped = 0
        unverified = 0
        for rt in self.runtimes:
            roleArn = rt.get('roleArn')
            name = rt.get('agentRuntimeName') or rt.get('agentRuntimeId', 'unknown')
            if not roleArn:
                unverified += 1
                continue
            roleName = self._roleNameFromArn(roleArn)
            if not roleName:
                unverified += 1
                continue
            findings = _inspectRoleForBroadPolicies(
                self.iamClient, roleName, self.BROAD_RUNTIME_ACTIONS
            )
            if findings:
                offenders.append(f"{name}({'; '.join(findings)})")
            else:
                scoped += 1

        if offenders:
            self.results['bedrockACRuntimeWildcardRole'] = [
                -1,
                f"Overly permissive runtime role(s): {', '.join(offenders)}"
            ]
        elif scoped:
            self.results['bedrockACRuntimeWildcardRole'] = [
                1,
                f"{scoped} runtime role(s) appear scoped"
                + (f"; {unverified} unverified" if unverified else "")
            ]
        else:
            self.results['bedrockACRuntimeWildcardRole'] = [
                0,
                f"Could not verify any runtime role ({unverified} unverified)"
            ]

    def _checkBedrockACRuntimeNoGateway(self):
        if not self.runtimes:
            self.results['bedrockACRuntimeNoGateway'] = [0, "No agent runtimes in this region"]
            return

        # Collect all target ARNs across all gateways. AgentCore gateway targets
        # carry a targetConfiguration; if the configuration references the runtime,
        # we consider it fronted. The exact field path may vary by mode, so we
        # search recursively for the runtime ARN inside each target's config.
        all_targets = []
        for gw in self.gateways:
            all_targets.extend(gw.get('_targets') or [])

        unfronted = []
        for rt in self.runtimes:
            arn = rt.get('agentRuntimeArn', '')
            name = rt.get('agentRuntimeName') or rt.get('agentRuntimeId', 'unknown')
            if not arn:
                unfronted.append(f"{name}(no ARN)")
                continue
            fronted = any(self._dictContainsValue(t.get('targetConfiguration'), arn) for t in all_targets)
            if not fronted:
                unfronted.append(name)

        if unfronted:
            self.results['bedrockACRuntimeNoGateway'] = [
                -1,
                f"Runtime(s) without a fronting gateway target: {', '.join(unfronted)}"
            ]
        else:
            self.results['bedrockACRuntimeNoGateway'] = [
                1,
                f"All {len(self.runtimes)} runtime(s) fronted by a gateway target"
            ]

    # ------------------------------------------------------------------ #
    # Gateway checks
    # ------------------------------------------------------------------ #
    def _checkBedrockACGatewayNoPolicy(self):
        if not self.gateways:
            self.results['bedrockACGatewayNoPolicy'] = [0, "No gateways in this region"]
            return

        offenders = []
        for gw in self.gateways:
            pec = gw.get('policyEngineConfiguration') or {}
            if not pec.get('arn'):
                offenders.append(gw.get('name') or gw.get('gatewayId', 'unknown'))

        if offenders:
            self.results['bedrockACGatewayNoPolicy'] = [
                -1,
                f"Gateways without a policy engine: {', '.join(offenders)}"
            ]
        else:
            self.results['bedrockACGatewayNoPolicy'] = [
                1,
                f"All {len(self.gateways)} gateway(s) have a policy engine"
            ]

    def _checkBedrockACGatewayNoTargets(self):
        if not self.gateways:
            self.results['bedrockACGatewayNoTargets'] = [0, "No gateways in this region"]
            return

        empty = []
        for gw in self.gateways:
            if not (gw.get('_targets') or []):
                empty.append(gw.get('name') or gw.get('gatewayId', 'unknown'))

        if empty:
            self.results['bedrockACGatewayNoTargets'] = [
                -1,
                f"Gateways with zero targets: {', '.join(empty)}"
            ]
        else:
            self.results['bedrockACGatewayNoTargets'] = [
                1,
                f"All {len(self.gateways)} gateway(s) have at least one target"
            ]

    def _checkBedrockACGatewayTargetNoAuth(self):
        if not self.gateways:
            self.results['bedrockACGatewayTargetNoAuth'] = [0, "No gateways in this region"]
            return

        all_targets = []
        for gw in self.gateways:
            for t in (gw.get('_targets') or []):
                t['_gatewayName'] = gw.get('name') or gw.get('gatewayId', 'unknown')
                all_targets.append(t)

        if not all_targets:
            self.results['bedrockACGatewayTargetNoAuth'] = [0, "No gateway targets in this region"]
            return

        no_auth = []
        for t in all_targets:
            cps = t.get('credentialProviderConfigurations') or []
            types = {cp.get('credentialProviderType') for cp in cps if cp.get('credentialProviderType')}
            if not types or not (types & self.OUTBOUND_AUTH_TYPES):
                no_auth.append(
                    f"{t['_gatewayName']}/{t.get('name') or t.get('targetId', 'unknown')}"
                )

        if no_auth:
            self.results['bedrockACGatewayTargetNoAuth'] = [
                -1,
                f"Target(s) without outbound auth (no OAUTH/API_KEY): {', '.join(no_auth)}"
            ]
        else:
            self.results['bedrockACGatewayTargetNoAuth'] = [
                1,
                f"All {len(all_targets)} target(s) have outbound auth configured"
            ]

    # ------------------------------------------------------------------ #
    # Memory checks
    # ------------------------------------------------------------------ #
    def _checkBedrockACMemoryNoEncryption(self):
        if not self.memories:
            self.results['bedrockACMemoryNoEncryption'] = [0, "No memories in this region"]
            return

        offenders = []
        for mem in self.memories:
            inner = mem.get('memory') or mem  # supports both wrapped and flattened forms
            if not inner.get('encryptionKeyArn'):
                offenders.append(inner.get('name') or inner.get('id', 'unknown'))

        if offenders:
            self.results['bedrockACMemoryNoEncryption'] = [
                -1,
                f"Memory store(s) without CMK: {', '.join(offenders)}"
            ]
        else:
            self.results['bedrockACMemoryNoEncryption'] = [
                1,
                f"All {len(self.memories)} memory store(s) have CMK"
            ]

    def _checkBedrockACMemoryNoNamespace(self):
        if not self.memories:
            self.results['bedrockACMemoryNoNamespace'] = [0, "No memories in this region"]
            return

        offenders = []
        for mem in self.memories:
            inner = mem.get('memory') or mem
            strategies = inner.get('strategies') or []
            # A memory is "namespace-scoped" if at least one strategy declares
            # namespaces or namespaceTemplates (e.g., "/users/{actorId}/...").
            scoped = False
            for s in strategies:
                if s.get('namespaces') or s.get('namespaceTemplates'):
                    scoped = True
                    break
            if not scoped:
                offenders.append(inner.get('name') or inner.get('id', 'unknown'))

        if offenders:
            self.results['bedrockACMemoryNoNamespace'] = [
                -1,
                f"Memory store(s) without namespace/actor scoping: {', '.join(offenders)}"
            ]
        else:
            self.results['bedrockACMemoryNoNamespace'] = [
                1,
                f"All {len(self.memories)} memory store(s) use namespace scoping"
            ]

    # ------------------------------------------------------------------ #
    # Policy / Identity / Evaluator checks
    # ------------------------------------------------------------------ #
    def _checkBedrockACNoPolicyEngine(self):
        if not self._hasAnyAgentCoreResource():
            self.results['bedrockACNoPolicyEngine'] = [0, "No AgentCore resources in this region"]
            return

        if not self.policyEngines:
            self.results['bedrockACNoPolicyEngine'] = [
                -1,
                "AgentCore in use but zero policy engines defined (no Cedar-based authorization)"
            ]
        else:
            self.results['bedrockACNoPolicyEngine'] = [
                1,
                f"{len(self.policyEngines)} policy engine(s) defined"
            ]

    def _checkBedrockACNoIdentityProvider(self):
        if not self._hasAnyAgentCoreResource():
            self.results['bedrockACNoIdentityProvider'] = [0, "No AgentCore resources in this region"]
            return

        if not (self.oauthProviders or self.apiKeyProviders):
            self.results['bedrockACNoIdentityProvider'] = [
                -1,
                "No OAuth2 or API key credential providers configured"
            ]
        else:
            self.results['bedrockACNoIdentityProvider'] = [
                1,
                f"{len(self.oauthProviders)} OAuth2 + {len(self.apiKeyProviders)} API-key provider(s)"
            ]

    def _checkBedrockACApiKeyProviderUsed(self):
        if self.apiKeyProviders:
            # Informational — API keys are less secure than OAuth2
            self.results['bedrockACApiKeyProviderUsed'] = [
                0,
                f"{len(self.apiKeyProviders)} API-key provider(s) in use; OAuth2 preferred where possible"
            ]
        else:
            self.results['bedrockACApiKeyProviderUsed'] = [1, "No API-key providers"]

    def _checkBedrockACNoEvaluator(self):
        if not self._hasAnyAgentCoreResource():
            self.results['bedrockACNoEvaluator'] = [0, "No AgentCore resources in this region"]
            return

        if not self.evaluators:
            self.results['bedrockACNoEvaluator'] = [
                -1,
                "AgentCore in use but zero evaluators defined (no behavioral testing)"
            ]
        else:
            self.results['bedrockACNoEvaluator'] = [
                1,
                f"{len(self.evaluators)} evaluator(s) defined"
            ]

    # ------------------------------------------------------------------ #
    # Service-limit check
    # ------------------------------------------------------------------ #
    def _checkBedrockACServiceLimitRuntimes(self):
        # NOTE: the task spec named ServiceCode='bedrock-agentcore-control' but
        # service-quotas exposes AgentCore quotas under 'bedrock-agentcore'
        # (the 'control' variant raises NoSuchResourceException). We try both
        # for forward compatibility.
        quotas = self._listQuotas('bedrock-agentcore') + self._listQuotas('bedrock-agentcore-control')

        quotaValue = None
        for q in quotas:
            name = (q.get('QuotaName') or '').lower()
            if any(h in name for h in self.RUNTIME_QUOTA_HINTS):
                quotaValue = q.get('Value')
                break

        current = len(self.runtimes)
        if quotaValue is None or quotaValue <= 0:
            self.results['bedrockACServiceLimitRuntimes'] = [
                0,
                f"Agent runtime quota unavailable; current usage {current}"
            ]
            return

        threshold = int(self.USAGE_THRESHOLD * quotaValue)
        pct = (current / quotaValue) * 100.0
        if current >= threshold:
            self.results['bedrockACServiceLimitRuntimes'] = [
                -1,
                f"Agent runtimes: {current} of {int(quotaValue)} ({pct:.0f}% of quota)"
            ]
        else:
            self.results['bedrockACServiceLimitRuntimes'] = [
                1,
                f"Agent runtimes: {current} of {int(quotaValue)} ({pct:.0f}% of quota)"
            ]

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _listQuotas(self, serviceCode):
        cacheKey = f"BedrockACQuotaCache::{serviceCode}"
        cached = Config.get(cacheKey, None)
        if cached is not None:
            return cached
        out = []
        try:
            paginator = self.serviceQuotaClient.get_paginator('list_service_quotas')
            for page in paginator.paginate(ServiceCode=serviceCode):
                out.extend(page.get('Quotas', []))
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # NoSuchResourceException means this serviceCode doesn't exist
            # in this region/account — that's expected for 'bedrock-agentcore-control'.
            if code not in ('AccessDenied', 'AccessDeniedException',
                            'NoSuchResourceException'):
                msg = e.response.get('Error', {}).get('Message', str(e))
                print(f"service-quotas ListServiceQuotas({serviceCode}): {code} - {msg}")
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"service-quotas endpoint unavailable ({serviceCode}): {e}")
        Config.set(cacheKey, out)
        return out

    @staticmethod
    def _roleNameFromArn(arn):
        if not arn or ':role/' not in arn:
            return None
        return arn.split(':role/', 1)[1].split('/')[-1]

    @staticmethod
    def _findKmsValue(obj, _depth=0):
        """Recursively search a dict/list for any key matching kms*/encryption*Arn.
        Returns the value (possibly empty string) if any matching field is found,
        else None to signal 'no such field exists' (different from 'field present but empty')."""
        if _depth > 5 or obj is None:
            return None
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower()
                if ('kms' in kl and 'arn' in kl) or ('encryption' in kl and ('key' in kl or 'arn' in kl)):
                    return v if v is not None else ''
            for v in obj.values():
                r = BedrockAgentCore._findKmsValue(v, _depth + 1)
                if r is not None:
                    return r
        elif isinstance(obj, list):
            for v in obj:
                r = BedrockAgentCore._findKmsValue(v, _depth + 1)
                if r is not None:
                    return r
        return None

    @staticmethod
    def _dictContainsValue(obj, needle, _depth=0):
        """Return True if `needle` (string) appears as a string value anywhere
        inside `obj` (dict/list, up to a small depth)."""
        if _depth > 6 or obj is None or not needle:
            return False
        if isinstance(obj, str):
            return needle in obj
        if isinstance(obj, dict):
            return any(
                BedrockAgentCore._dictContainsValue(v, needle, _depth + 1)
                for v in obj.values()
            )
        if isinstance(obj, list):
            return any(
                BedrockAgentCore._dictContainsValue(v, needle, _depth + 1)
                for v in obj
            )
        return False

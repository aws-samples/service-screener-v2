import json
import botocore

from services.Evaluator import Evaluator


class BedrockAgent(Evaluator):
    """
    Per-agent checks (reporter keys 1-10):
      bedrockAgentGuardrailAttached, bedrockAgentIamRoleOverprivileged,
      bedrockAgentNoInstruction, bedrockAgentIdleSessionTimeout,
      bedrockAgentMemoryDisabled, bedrockAgentNoEncryptionKey,
      bedrockAgentNotPrepared, bedrockAgentExcessiveVersions,
      bedrockAgentActionGroupNoSchema, bedrockAgentCollaborationDisabled.
    """

    # Defaults: 600s is the Bedrock default TTL; we flag both default and >3600s.
    DEFAULT_IDLE_TTL = 600
    MAX_REASONABLE_IDLE_TTL = 3600
    MAX_REASONABLE_VERSIONS = 10

    NON_OPERATIONAL_STATUSES = {'NOT_PREPARED', 'FAILED', 'DELETING'}

    BROAD_ACTIONS = {'*', 'bedrock:*', 'iam:*', 's3:*', 'kms:*'}

    def __init__(self, agent, agentClient, iamClient):
        super().__init__()
        self.agent = agent
        self.agentClient = agentClient
        self.iamClient = iamClient

        agentName = agent.get('agentName') or agent.get('agentId', 'unknown')
        self._resourceName = agentName

        self.addII('agentId', agent.get('agentId', 'N/A'))
        self.addII('agentName', agentName)
        self.addII('agentArn', agent.get('agentArn', 'N/A'))
        self.addII('agentStatus', agent.get('agentStatus', 'N/A'))
        self.addII('foundationModel', agent.get('foundationModel', 'N/A'))
        self.addII('agentResourceRoleArn', agent.get('agentResourceRoleArn', 'N/A'))
        self.addII('idleSessionTTLInSeconds', agent.get('idleSessionTTLInSeconds', 'N/A'))

    # ------------------------------------------------------------------ #
    # 1. Guardrail attached
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentGuardrailAttached(self):
        cfg = self.agent.get('guardrailConfiguration') or {}
        guardrailId = cfg.get('guardrailIdentifier')
        if guardrailId:
            self.results['bedrockAgentGuardrailAttached'] = [1, f"Guardrail attached: {guardrailId}"]
        else:
            self.results['bedrockAgentGuardrailAttached'] = [-1, "No guardrail attached"]

    # ------------------------------------------------------------------ #
    # 2. IAM role overprivileged
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentIamRoleOverprivileged(self):
        roleArn = self.agent.get('agentResourceRoleArn')
        if not roleArn:
            self.results['bedrockAgentIamRoleOverprivileged'] = [0, "No execution role to inspect"]
            return

        roleName = self._roleNameFromArn(roleArn)
        if not roleName:
            self.results['bedrockAgentIamRoleOverprivileged'] = [0, f"Could not parse role ARN: {roleArn}"]
            return

        findings = _inspectRoleForBroadPolicies(self.iamClient, roleName, self.BROAD_ACTIONS)
        if findings:
            self.results['bedrockAgentIamRoleOverprivileged'] = [
                -1,
                "Overly permissive: " + "; ".join(findings)
            ]
        else:
            self.results['bedrockAgentIamRoleOverprivileged'] = [1, "Role appears scoped"]

    # ------------------------------------------------------------------ #
    # 3. Empty instruction
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentNoInstruction(self):
        instruction = (self.agent.get('instruction') or '').strip()
        if not instruction:
            self.results['bedrockAgentNoInstruction'] = [-1, "Agent has no instruction (system prompt)"]
        else:
            self.results['bedrockAgentNoInstruction'] = [1, f"Instruction set ({len(instruction)} chars)"]

    # ------------------------------------------------------------------ #
    # 4. Idle session timeout (default or excessively high)
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentIdleSessionTimeout(self):
        ttl = self.agent.get('idleSessionTTLInSeconds')
        if ttl is None:
            self.results['bedrockAgentIdleSessionTimeout'] = [0, "idleSessionTTLInSeconds not reported"]
            return

        try:
            ttlInt = int(ttl)
        except (TypeError, ValueError):
            self.results['bedrockAgentIdleSessionTimeout'] = [0, f"Unparseable TTL value: {ttl}"]
            return

        if ttlInt == self.DEFAULT_IDLE_TTL:
            self.results['bedrockAgentIdleSessionTimeout'] = [
                -1,
                f"Default idleSessionTTL of {ttlInt}s — set deliberately for your cost/security model"
            ]
        elif ttlInt > self.MAX_REASONABLE_IDLE_TTL:
            self.results['bedrockAgentIdleSessionTimeout'] = [
                -1,
                f"idleSessionTTL {ttlInt}s exceeds {self.MAX_REASONABLE_IDLE_TTL}s threshold"
            ]
        else:
            self.results['bedrockAgentIdleSessionTimeout'] = [1, f"idleSessionTTL is {ttlInt}s"]

    # ------------------------------------------------------------------ #
    # 5. Memory disabled
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentMemoryDisabled(self):
        memCfg = self.agent.get('memoryConfiguration') or {}
        enabled = memCfg.get('enabledMemoryTypes') or []
        if not enabled:
            self.results['bedrockAgentMemoryDisabled'] = [-1, "No memory types enabled"]
        else:
            self.results['bedrockAgentMemoryDisabled'] = [1, f"Memory enabled: {', '.join(enabled)}"]

    # ------------------------------------------------------------------ #
    # 6. No customer-managed encryption key
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentNoEncryptionKey(self):
        cmk = self.agent.get('customerEncryptionKeyArn')
        if cmk:
            self.results['bedrockAgentNoEncryptionKey'] = [1, f"CMK: {cmk}"]
        else:
            self.results['bedrockAgentNoEncryptionKey'] = [-1, "No customer-managed KMS key"]

    # ------------------------------------------------------------------ #
    # 7. Status is NOT_PREPARED / FAILED
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentNotPrepared(self):
        status = self.agent.get('agentStatus', 'UNKNOWN')
        if status in self.NON_OPERATIONAL_STATUSES:
            self.results['bedrockAgentNotPrepared'] = [-1, f"Agent status: {status}"]
        else:
            self.results['bedrockAgentNotPrepared'] = [1, f"Agent status: {status}"]

    # ------------------------------------------------------------------ #
    # 8. Excessive versions
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentExcessiveVersions(self):
        versions = self.agent.get('_versions') or []
        # 'DRAFT' is always present and doesn't count toward retained versions
        nonDraft = [v for v in versions if v.get('agentVersion') and v.get('agentVersion') != 'DRAFT']
        count = len(nonDraft)
        if count > self.MAX_REASONABLE_VERSIONS:
            self.results['bedrockAgentExcessiveVersions'] = [
                -1,
                f"{count} retained versions (>{self.MAX_REASONABLE_VERSIONS})"
            ]
        else:
            self.results['bedrockAgentExcessiveVersions'] = [1, f"{count} retained versions"]

    # ------------------------------------------------------------------ #
    # 9. Action group with no schema
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentActionGroupNoSchema(self):
        actionGroups = self.agent.get('_actionGroups') or []
        if not actionGroups:
            self.results['bedrockAgentActionGroupNoSchema'] = [0, "No action groups defined"]
            return

        offending = []
        for ag in actionGroups:
            name = ag.get('actionGroupName', 'unknown')
            apiSchema = ag.get('apiSchema') or {}
            functionSchema = ag.get('functionSchema') or {}
            parentSignature = ag.get('parentActionSignature')

            # Built-in parent action signatures (e.g., AMAZON.UserInput) are considered governed
            if parentSignature:
                continue

            hasApiSchema = bool(apiSchema.get('payload') or apiSchema.get('s3'))
            hasFunctionSchema = bool(functionSchema.get('functions'))

            if not (hasApiSchema or hasFunctionSchema):
                offending.append(name)

        if offending:
            self.results['bedrockAgentActionGroupNoSchema'] = [
                -1,
                f"Action group(s) without schema: {', '.join(offending)}"
            ]
        else:
            self.results['bedrockAgentActionGroupNoSchema'] = [
                1,
                f"All {len(actionGroups)} action group(s) have a schema"
            ]

    # ------------------------------------------------------------------ #
    # 10. Multi-agent collaboration disabled
    # ------------------------------------------------------------------ #
    def _checkBedrockAgentCollaborationDisabled(self):
        collab = self.agent.get('agentCollaboration')
        # 'DISABLED' is the default; SUPERVISOR / SUPERVISOR_ROUTER signal collaboration
        if not collab or collab == 'DISABLED':
            self.results['bedrockAgentCollaborationDisabled'] = [
                -1,
                "Multi-agent collaboration disabled"
            ]
        else:
            self.results['bedrockAgentCollaborationDisabled'] = [
                1,
                f"Collaboration mode: {collab}"
            ]

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _roleNameFromArn(arn):
        if not arn or ':role/' not in arn:
            return None
        return arn.split(':role/', 1)[1].split('/')[-1]


# ---------------------------------------------------------------------- #
# Shared helper: IAM role broad-policy inspection.
# Kept module-private so KnowledgeBase driver can reuse it.
# ---------------------------------------------------------------------- #
def _inspectRoleForBroadPolicies(iamClient, roleName, broadActions):
    """
    Returns a list of findings (strings) for any policy on the role that grants
    wildcard actions or wildcard resources with broad actions.
    Returns [] when the role looks scoped, or when the inspection cannot complete
    (e.g., AccessDenied) — caller treats [] as "pass".
    """
    findings = []
    try:
        # Inline policies
        inline = iamClient.list_role_policies(RoleName=roleName)
        for policyName in inline.get('PolicyNames', []):
            try:
                doc = iamClient.get_role_policy(RoleName=roleName, PolicyName=policyName)
                policyDoc = doc.get('PolicyDocument', {})
                if _statementsAreBroad(policyDoc, broadActions):
                    findings.append(f"inline:{policyName}")
            except botocore.exceptions.ClientError:
                continue

        # Attached managed policies
        attached = iamClient.list_attached_role_policies(RoleName=roleName)
        for p in attached.get('AttachedPolicies', []):
            policyArn = p.get('PolicyArn', '')
            policyName = p.get('PolicyName', policyArn)
            if policyArn.endswith('/AdministratorAccess'):
                findings.append("managed:AdministratorAccess")
                continue
            try:
                pol = iamClient.get_policy(PolicyArn=policyArn)
                versionId = pol.get('Policy', {}).get('DefaultVersionId')
                if not versionId:
                    continue
                ver = iamClient.get_policy_version(PolicyArn=policyArn, VersionId=versionId)
                policyDoc = ver.get('PolicyVersion', {}).get('Document', {})
                if _statementsAreBroad(policyDoc, broadActions):
                    findings.append(f"managed:{policyName}")
            except botocore.exceptions.ClientError:
                continue
    except botocore.exceptions.ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code not in ('AccessDenied', 'AccessDeniedException', 'NoSuchEntity', 'NoSuchEntityException'):
            print(f"IAM inspection error on role {roleName}: {code}")
        # Treat unavailable inspection as no finding
        return []
    return findings


def _statementsAreBroad(policyDoc, broadActions):
    if isinstance(policyDoc, str):
        try:
            policyDoc = json.loads(policyDoc)
        except (ValueError, TypeError):
            return False

    statements = policyDoc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get('Effect') != 'Allow':
            continue

        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        hasWildcardResource = '*' in resources
        actionSet = {a for a in actions if isinstance(a, str)}

        # Pure Action: "*"
        if '*' in actionSet:
            return True

        # Broad service-level wildcards with wildcard resource
        if hasWildcardResource and (actionSet & broadActions):
            return True

    return False

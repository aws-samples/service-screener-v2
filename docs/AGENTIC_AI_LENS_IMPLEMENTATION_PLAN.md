# Service Screener v2 — Agentic AI Lens Implementation Plan

## Executive Summary

Add support for the **AWS Well-Architected Agentic AI Lens** to Service Screener v2 by:
1. Creating a new `bedrock` service module (35 checks across Agents, Guardrails, Knowledge Bases, Account-level, Service Limits)
2. Creating a new `AAIL` (Agentic AI Lens) framework that maps existing + new checks to the lens best practices
3. Phase 3 (extend existing services) — **almost entirely already built** (9/10 checks exist)

---

## Phase 1: New Service — `bedrock` (35 Checks)

### 1.1 Agent Checks (via `bedrock-agent` client → `GetAgent`, `ListAgentActionGroups`, `ListAgentVersions`)

| # | Check Name | Cat | Crit | What it checks | API / Field |
|---|---|---|---|---|---|
| 1 | `bedrockAgentGuardrailAttached` | S | H | Agent has a Guardrail configured | `GetAgent` → `agent.guardrailConfiguration.guardrailIdentifier` not null |
| 2 | `bedrockAgentIamRoleOverprivileged` | S | H | Agent execution role uses `*` resource or `*` action | `GetAgent` → `agent.agentResourceRoleArn` → IAM policy analysis |
| 3 | `bedrockAgentNoInstruction` | O | H | Agent has empty/missing instruction (system prompt) | `GetAgent` → `agent.instruction` is null/empty |
| 4 | `bedrockAgentIdleSessionTimeout` | C | M | Session TTL is default 600s or excessively high (>3600s) | `GetAgent` → `agent.idleSessionTTLInSeconds` |
| 5 | `bedrockAgentMemoryDisabled` | R | M | Agent has no memory configuration (no cross-session learning) | `GetAgent` → `agent.memoryConfiguration.enabledMemoryTypes` is empty/null |
| 6 | `bedrockAgentNoEncryptionKey` | S | M | Agent uses default encryption (no CMK) | `GetAgent` → `agent.customerEncryptionKeyArn` is null |
| 7 | `bedrockAgentNotPrepared` | O | H | Agent status is NOT_PREPARED or FAILED | `GetAgent` → `agent.agentStatus` |
| 8 | `bedrockAgentExcessiveVersions` | C | L | Agent has >10 versions without cleanup | `ListAgentVersions` → count |
| 9 | `bedrockAgentActionGroupNoSchema` | S | M | Action group has no API schema (open-ended tool access) | `ListAgentActionGroups` + `GetAgentActionGroup` → apiSchema |
| 10 | `bedrockAgentCollaborationDisabled` | O | L | Multi-agent collaboration not configured for complex workflows | `GetAgent` → `agent.agentCollaboration` |

### 1.2 Guardrail Checks (via `bedrock` client → `ListGuardrails`, `GetGuardrail`)

| # | Check Name | Cat | Crit | What it checks | API / Field |
|---|---|---|---|---|---|
| 11 | `bedrockGuardrailContentFilterDisabled` | S | H | Guardrail has NO content filters (SEXUAL, VIOLENCE, HATE, INSULTS, MISCONDUCT) | `GetGuardrail` → `contentPolicy.filters` is empty/missing |
| 12 | `bedrockGuardrailContentFilterWeak` | S | M | Content filter strength is LOW for any category | `GetGuardrail` → any filter with `inputStrength == 'LOW'` |
| 13 | `bedrockGuardrailNoPromptAttackFilter` | S | H | No PROMPT_ATTACK filter configured (prompt injection defense) | `GetGuardrail` → no filter with `type='PROMPT_ATTACK'` |
| 14 | `bedrockGuardrailNoPiiDetection` | S | H | No sensitive information policy (PII entities or regex) | `GetGuardrail` → `sensitiveInformationPolicy` is null/empty |
| 15 | `bedrockGuardrailNoDeniedTopics` | S | M | No denied topics configured | `GetGuardrail` → `topicPolicy.topics` is empty/null |
| 16 | `bedrockGuardrailNoWordFilter` | S | L | No word policy (profanity/custom word filters) | `GetGuardrail` → `wordPolicy` is null/empty |
| 17 | `bedrockGuardrailNoGroundingFilter` | R | M | No contextual grounding policy (hallucination prevention) | `GetGuardrail` → `contextualGroundingPolicy` is null/empty |
| 18 | `bedrockGuardrailNoEncryption` | S | M | Guardrail uses default encryption (no CMK) | `GetGuardrail` → `kmsKeyArn` is null |
| 19 | `bedrockGuardrailStatusFailed` | O | H | Guardrail status is FAILED | `GetGuardrail` → `status` |
| 20 | `bedrockGuardrailOutputFilterDisabled` | S | M | Content filter enabled on input but disabled on output | Filters where `inputEnabled=True` but `outputEnabled=False` |

### 1.3 Knowledge Base Checks (via `bedrock-agent` client → `ListKnowledgeBases`, `GetKnowledgeBase`, `ListDataSources`)

| # | Check Name | Cat | Crit | What it checks | API / Field |
|---|---|---|---|---|---|
| 21 | `bedrockKBNoEncryption` | S | H | KB uses default encryption (no CMK) | `GetKnowledgeBase` → `managedKnowledgeBaseConfiguration.serverSideEncryptionConfiguration.kmsKeyArn` null |
| 22 | `bedrockKBStatusFailed` | O | H | Knowledge Base status is FAILED | `GetKnowledgeBase` → `knowledgeBase.status` |
| 23 | `bedrockKBNoDataSources` | R | H | Knowledge Base has zero data sources (empty KB, useless) | `ListDataSources` → count == 0 |
| 24 | `bedrockKBDataSourceSyncStale` | R | M | Data source hasn't been synced in >7 days | `ListIngestionJobs` → most recent job timestamp |
| 25 | `bedrockKBRoleOverprivileged` | S | M | KB execution role uses `*` resource | `GetKnowledgeBase` → `roleArn` → IAM analysis |

### 1.4 Account-Level Checks (via `bedrock` client → `GetModelInvocationLoggingConfiguration`, `ListGuardrails`, `ListAgents`)

| # | Check Name | Cat | Crit | What it checks | API / Field |
|---|---|---|---|---|---|
| 26 | `bedrockModelInvocationLoggingDisabled` | O | H | Model invocation logging not enabled for the account | `GetModelInvocationLoggingConfiguration` → config null/empty |
| 27 | `bedrockModelInvocationNoCloudWatch` | O | M | Logging enabled but no CloudWatch destination | `loggingConfig.cloudWatchConfig` null |
| 28 | `bedrockModelInvocationNoS3` | O | L | Logging enabled but no S3 destination (no long-term archive) | `loggingConfig.s3Config` null |
| 29 | `bedrockNoGuardrailsExist` | S | H | Account has zero guardrails defined | `ListGuardrails` → count == 0 |
| 30 | `bedrockAgentWithoutGuardrail` | S | H | At least one agent exists without a guardrail (cross-check) | `ListAgents` → any without `guardrailConfiguration` |

### 1.5 Service Limit Checks (via `service-quotas` client → `list_service_quotas(ServiceCode='bedrock')`)

Uses the same pattern as DynamoDB/EC2 in SS v2: call `list_service_quotas`, compare current resource count against quota value. Flag when usage > 80%.

| # | Check Name | Cat | Crit | What it checks | Quota / Logic |
|---|---|---|---|---|---|
| 31 | `bedrockServiceLimitAgents` | R | M | Agents approaching account limit (>80% of quota) | Agent quota vs `ListAgents` count |
| 32 | `bedrockServiceLimitKnowledgeBases` | R | M | Knowledge Bases approaching account limit (>80%) | KB quota vs `ListKnowledgeBases` count |
| 33 | `bedrockServiceLimitGuardrails` | R | M | Guardrails approaching account limit (>80%) | Guardrail quota vs `ListGuardrails` count |
| 34 | `bedrockServiceLimitAgentActionGroups` | R | L | Agent approaching action group limit per agent (>80%) | Action group quota vs count per agent |
| 35 | `bedrockServiceLimitTPM` | P | H | Primary model TPM quota is at default/low (new account reduced quota) | On-demand InvokeModel TPM quota value — flag if unusually low |

**Implementation pattern** (from existing `DynamoDbGeneric.py`):
```python
self.serviceQuotaClient = self.ssBoto.client('service-quotas', config=self.bConfig)
results = self.serviceQuotaClient.list_service_quotas(ServiceCode='bedrock')['Quotas']
# Find relevant quota by QuotaCode, compare Value vs actual resource count
# Flag if usage > 80% of quota
```

**Total: 35 checks** (10 Agent, 10 Guardrail, 5 Knowledge Base, 5 Account-level, 5 Service Limits)

---

### 1.6 File Structure

```
services/bedrock/
├── Bedrock.py                    # Main service class
├── bedrock.reporter.json         # 35 check definitions
├── drivers/
│   ├── BedrockAgent.py           # Checks 1-10 (per agent)
│   ├── BedrockGuardrail.py       # Checks 11-20 (per guardrail)
│   ├── BedrockKnowledgeBase.py   # Checks 21-25 (per KB)
│   └── BedrockAccount.py         # Checks 26-30 (account-level, runs once)
│   └── BedrockServiceLimits.py   # Checks 31-35 (service quotas)
└── simulation/
    ├── create_test_resources.sh
    ├── cleanup_test_resources.sh
    └── README.md
```

### 1.6 Implementation Details

**`Bedrock.py`** — Main service class:
```python
class Bedrock(Service):
    def __init__(self, region, ssBoto, ...):
        super().__init__(region, ssBoto, ...)
        self.agentClient = self.ssBoto.client('bedrock-agent', config=self.bConfig)
        self.bedrockClient = self.ssBoto.client('bedrock', config=self.bConfig)

    def getResources(self):
        # 1. list_agents (paginated) → for each: get_agent, list_agent_action_groups, list_agent_versions
        # 2. list_guardrails (paginated) → for each: get_guardrail
        # 3. list_knowledge_bases (paginated) → for each: get_knowledge_base, list_data_sources
        # 4. get_model_invocation_logging_configuration (once)

    def advise(self):
        # Run BedrockAgent driver per agent
        # Run BedrockGuardrail driver per guardrail
        # Run BedrockKnowledgeBase driver per KB
        # Run BedrockAccount driver once
```

**boto3 clients needed:**
- `bedrock-agent` — Agents, Knowledge Bases, Action Groups, Data Sources
- `bedrock` — Guardrails, Model Invocation Logging
- `iam` — For role policy analysis (reuse existing IAM patterns)

**Pagination:** All `list_*` APIs use `nextToken` pattern.

### 1.7 IAM Cross-Check Pattern (for checks #2, #25)

Reuse existing IAM analysis patterns from SS v2:
1. Get role ARN from agent/KB response
2. `iam:ListAttachedRolePolicies` → check for `AdministratorAccess` or overly broad managed policies
3. `iam:ListRolePolicies` → get inline policy names
4. `iam:GetRolePolicy` → check for `"Resource": "*"` with broad actions
5. Flag if `Action: "*"` or `Action: "bedrock:*"` with `Resource: "*"`

### 1.8 Key Implementation Notes

- **Regional service**: Bedrock is regional — agents exist per-region
- **Two clients**: `bedrock-agent` (agents, KBs, data sources) vs `bedrock` (guardrails, logging, models)
- **Agent versions**: `ListAgentVersions` can be expensive — cap at first 20
- **Guardrail DRAFT vs versioned**: Use `GetGuardrail` without version to check DRAFT (latest)
- **Error handling**: `ResourceNotFoundException` for deleted-but-listed resources; `AccessDeniedException` if missing `bedrock:Get*` permissions
- **Register service**: Update `utils/Config.py` service list to include `bedrock`

---

## Phase 2: New Framework — `AAIL` (Agentic AI Lens)

### 2.1 File Structure

```
frameworks/AAIL/
├── AAIL.py              # Framework class (extend Framework base)
├── AAILPageBuilder.py   # Page builder (extend FrameworkPageBuilder)
└── map.json             # Mapping: lens BP IDs → service.checkName
```

### 2.2 Framework map.json Structure

Following the same pattern as `WAFS/map.json`:

```json
{
  "metadata": {
    "originator": "AWS",
    "shortname": "AAIL",
    "fullname": "AWS Well-Architected Framework - Agentic AI Lens",
    "description": "This lens extends the AWS Well-Architected Framework with best practices for agentic AI systems on AWS.",
    "_": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/welcome.html",
    "emptyCheckDefaultMsg": "Manual review required — no automated check available"
  },
  "mapping": { ... }
}
```

### 2.3 Mapping: Lens Best Practices → Service Screener Checks

#### Operational Excellence (AGENTOPS)

| Lens BP | Mapped Checks |
|---|---|
| AGENTOPS01.BP01 (Agent roles & success criteria) | `bedrock.bedrockAgentNoInstruction`, `bedrock.bedrockAgentActionGroupNoSchema` |
| AGENTOPS01.BP02 (Multi-agent handoff with HITL) | `bedrock.bedrockAgentGuardrailAttached`, `bedrock.bedrockAgentCollaborationDisabled` |
| AGENTOPS02.BP02 (Config drift detection) | `bedrock.bedrockAgentExcessiveVersions` |
| AGENTOPS03.BP01 (Agent lifecycle & governance) | `bedrock.bedrockAgentNotPrepared`, `bedrock.bedrockGuardrailStatusFailed` |
| AGENTOPS03.BP03 (Agent-specific scaling & capacity) | `bedrock.bedrockServiceLimitAgents`, `bedrock.bedrockServiceLimitKnowledgeBases`, `bedrock.bedrockServiceLimitGuardrails` |
| AGENTOPS04.BP01 (Tool registry & catalog management) | `bedrock.bedrockAgentActionGroupNoSchema`, `bedrock.bedrockServiceLimitAgentActionGroups` |
| AGENTOPS05.BP01 (End-to-end tracing) | `bedrock.bedrockModelInvocationLoggingDisabled`, `cloudtrail.trailEnabled` |
| AGENTOPS05.BP03 (Structured logging & audit) | `bedrock.bedrockModelInvocationNoCloudWatch`, `cloudwatch.$length` |
| AGENTOPS05.BP04 (Define KPIs) | `cloudwatch.alarmsWithoutSNS`, `cloudwatch.missingCompositeAlarms` |
| AGENTOPS07.BP01 (Consumption monitoring) | `cloudwatch.missingBillingAlarms` |

#### Security (AGENTSEC)

| Lens BP | Mapped Checks |
|---|---|
| AGENTSEC01.BP01 (Memory isolation & integrity) | `dynamodb.encryptionAtRest`, `dynamodb.disabledPointInTimeRecovery`, `bedrock.bedrockAgentMemoryDisabled` |
| AGENTSEC01.BP02 (Validate & sanitize memory inputs) | `bedrock.bedrockGuardrailContentFilterDisabled`, `bedrock.bedrockGuardrailNoPiiDetection` |
| AGENTSEC01.BP03 (Hallucination propagation) | `bedrock.bedrockGuardrailNoGroundingFilter` |
| AGENTSEC02.BP01 (Tool permission boundaries) | `bedrock.bedrockAgentIamRoleOverprivileged`, `iam.InlinePolicyFullAdminAccess` |
| AGENTSEC02.BP02 (Least-privilege tool access) | `iam.InlinePolicyFullAccessOneServ`, `iam.FullAdminAccess`, `lambda.lambdaRoleTooPermissive` |
| AGENTSEC02.BP03 (Tool encryption & data protection) | `bedrock.bedrockAgentNoEncryptionKey`, `bedrock.bedrockGuardrailNoEncryption`, `bedrock.bedrockKBNoEncryption` |
| AGENTSEC03.BP01 (Agent identity & access) | `iam.missingPermissionsBoundaries`, `bedrock.bedrockAgentIamRoleOverprivileged` |
| AGENTSEC03.BP02 (KB & tool role least privilege) | `bedrock.bedrockKBRoleOverprivileged` |
| AGENTSEC04.BP01 (Guardrails & alignment) | `bedrock.bedrockAgentGuardrailAttached`, `bedrock.bedrockGuardrailContentFilterDisabled`, `bedrock.bedrockGuardrailNoDeniedTopics`, `bedrock.bedrockNoGuardrailsExist` |
| AGENTSEC04.BP02 (Output filtering & response safety) | `bedrock.bedrockGuardrailOutputFilterDisabled`, `bedrock.bedrockGuardrailContentFilterWeak` |
| AGENTSEC05.BP01 (Comprehensive logging) | `bedrock.bedrockModelInvocationLoggingDisabled`, `cloudtrail.trailEnabled`, `cloudtrail.trailMultiRegion` |
| AGENTSEC05.BP02 (Long-term log archival) | `bedrock.bedrockModelInvocationNoS3` |
| AGENTSEC08.BP01 (Input validation & prompt injection) | `bedrock.bedrockGuardrailNoPromptAttackFilter`, `bedrock.bedrockGuardrailNoPiiDetection` |
| AGENTSEC08.BP02 (Word filter & profanity defense) | `bedrock.bedrockGuardrailNoWordFilter` |
| AGENTSEC09.BP01 (Vulnerability scanning) | `iam.enableGuardDuty`, `guardduty.$length` |

#### Reliability (AGENTREL)

| Lens BP | Mapped Checks |
|---|---|
| AGENTREL01.BP01 (Resilient messaging layer) | `sqs.DeadLetterQueue`, `sqs.EncryptionAtRest` |
| AGENTREL02.BP01 (Predictable execution) | `lambda.lambdaTimeoutNotOptimized`, `lambda.lambdaDeadLetterQueueDisabled` |
| AGENTREL05.BP03 (Ground cognition in real info) | `bedrock.bedrockKBNoDataSources`, `bedrock.bedrockKBDataSourceSyncStale` |
| AGENTREL07.BP02 (Auto recovery) | `sqs.DeadLetterQueue`, `lambda.lambdaDeadLetterQueueDisabled` |
| AGENTREL08.BP01 (Capacity planning & scaling) | `bedrock.bedrockServiceLimitAgents`, `bedrock.bedrockServiceLimitTPM` |

#### Performance Efficiency (AGENTPERF)

| Lens BP | Mapped Checks |
|---|---|
| AGENTPERF01.BP02 (Comprehensive telemetry) | `bedrock.bedrockModelInvocationLoggingDisabled`, `bedrock.bedrockModelInvocationNoCloudWatch` |
| AGENTPERF03.BP01 (Tiered memory management) | `bedrock.bedrockAgentMemoryDisabled`, `elasticache.encryptionInTransit` |
| AGENTPERF06.BP01 (Tool integration strategies) | `lambda.lambdaTimeoutNotOptimized`, `lambda.lambdaReservedConcurrencyDisabled` |
| AGENTPERF07.BP01 (Multitenant performance isolation) | `bedrock.bedrockServiceLimitTPM`, `bedrock.bedrockServiceLimitAgents` |

#### Cost Optimization (AGENTCOST)

| Lens BP | Mapped Checks |
|---|---|
| AGENTCOST01.BP01 (Reasoning cost governance) | `bedrock.bedrockModelInvocationLoggingDisabled` |
| AGENTCOST03.BP01 (Memory cost management) | `bedrock.bedrockAgentIdleSessionTimeout` |
| AGENTCOST04.BP01 (Tool invocation cost) | `lambda.lambdaReservedConcurrencyDisabled` |
| AGENTCOST06.BP02 (Versioning & deployment) | `bedrock.bedrockAgentExcessiveVersions` |
| AGENTCOST07.BP01 (Cost governance & quota management) | `bedrock.bedrockServiceLimitAgents`, `bedrock.bedrockServiceLimitKnowledgeBases`, `bedrock.bedrockServiceLimitGuardrails` |

#### Sustainability (AGENTSUS)

| Lens BP | Mapped Checks |
|---|---|
| AGENTSUS01.BP01 (Specialized agents with resource boundaries) | `bedrock.bedrockAgentIamRoleOverprivileged`, `bedrock.bedrockAgentNoInstruction` |
| AGENTSUS02.BP04 (Environmental footprint) | `cloudwatch.missingBillingAlarms` |

---

## Phase 3: Extend Existing Services — ALREADY DONE

| Proposed Check | Already Exists | Existing Name |
|---|---|---|
| Lambda DLQ | YES | `lambdaDeadLetterQueueDisabled` |
| Lambda concurrency | YES | `lambdaReservedConcurrencyDisabled` |
| Lambda timeout | YES | `lambdaTimeoutNotOptimized` |
| IAM permissions boundaries | YES | `missingPermissionsBoundaries` |
| DynamoDB PITR | YES | `disabledPointInTimeRecovery` |
| DynamoDB encryption | YES | `encryptionAtRest` |
| SQS DLQ | YES | `DeadLetterQueue` |
| SQS max receive count | YES | `MaxReceiveCountDetection` |
| SQS encryption | YES | `EncryptionAtRest` |
| IAM session policy (new) | NO | _(only new check needed)_ |

**Conclusion: Phase 3 is 90% done.** Only `iamRoleSessionPolicyMissing` is genuinely new, and it's low priority.

---

## Execution Plan

| Step | Action | Deliverable |
|---|---|---|
| 1 | Setup venv | Working dev environment |
| 2 | `python3 scripts/CreateService.py -s bedrock` | `services/bedrock/` scaffold |
| 3 | Write `bedrock.reporter.json` (30 checks) | Check definitions |
| 4 | Implement `Bedrock.py` + 4 drivers | Service code |
| 5 | Create `frameworks/AAIL/` (map.json + classes) | Framework mapping |
| 6 | Register service in Config | Bedrock scannable |
| 7 | Test: `python3 main.py --regions us-east-1 --services bedrock` | Verify findings |
| 8 | Test: `python3 main.py --regions us-east-1 --frameworks AAIL` | Framework report |
| 9 | Create simulation tests | Validation scripts |

### Quick Start

```bash
cd /Users/kuettai/Documents/project/ss-genai/service-screener-v2
python3 -m venv .
source bin/activate
pip install -r requirements.txt

# Scaffold
python3 scripts/CreateService.py -s bedrock

# Run after implementation
python3 main.py --regions us-east-1 --services bedrock --beta 1 --sequential 1

# Run full agentic AI assessment
python3 main.py --regions us-east-1 --services bedrock,iam,lambda,sqs,cloudwatch,dynamodb,guardduty,elasticache --frameworks AAIL --beta 1 --sequential 1
```

### Estimated Effort

| Phase | Effort | Priority |
|---|---|---|
| Phase 1 (30 Bedrock checks) | 4–6 days | P0 |
| Phase 2 (AAIL framework) | 1–2 days | P0 |
| Phase 3 (already done) | 0 days | Done |
| Testing & polish | 2–3 days | P1 |
| **Total** | **7–11 days** | |

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Bedrock APIs not available in all regions | Default to `us-east-1`; handle `EndpointConnectionError` gracefully |
| AgentCore APIs too new for current boto3 | Skip AgentCore-specific checks; focus on stable `bedrock`/`bedrock-agent` APIs |
| Some lens BPs are purely procedural | Leave as `[]` in map.json → shows "Manual review required" in report |
| High API call volume for large agent fleets | Implement concurrency limits; paginate with small batch sizes |
| botocore may lack latest Bedrock models | Run `pip install --upgrade boto3` in setup; check botocore data dir for bedrock-agent |

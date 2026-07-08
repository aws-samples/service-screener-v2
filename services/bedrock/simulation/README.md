# Bedrock Simulation Testing

Scripts that create intentionally-insecure Amazon Bedrock resources so
Service Screener's bedrock checks can be validated end-to-end. Uses AWS CLI
only (no boto3/Python), consistent with the SageMaker simulation.

## Purpose

Running Service Screener against a clean account produces mostly passing
results — you can't confirm that the FAIL path of each check actually fires.
These scripts stand up bad configurations that should each trigger a `-1`
finding in the report, then let you tear it all down when you're done.

## Resources Created

All resources are prefixed with `ss-test-` for easy identification.

| Resource | Configuration | Directly Validates |
|---|---|---|
| IAM role `ss-test-bedrock-role-*` | Trust: `bedrock.amazonaws.com`; inline policy `Action:*, Resource:*` | #2, #25, #39 |
| Bedrock Agent `ss-test-agent-broken-*` | Empty (whitespace) instruction; idleSessionTTL=3601; no memory; no CMK; no guardrail; no collaboration; **not prepared** | #1, #3, #4, #5, #6, #7, #10, #30 |
| Guardrail A `ss-test-gr-minimal-*` | Only a trivial word policy (`test-blocked-word`); no content/PII/topic/grounding policy; no CMK | #11, #13, #14, #15, #17, #18 |
| Guardrail B `ss-test-gr-weak-*` | Single VIOLENCE filter with `inputStrength=LOW`, `outputEnabled=false` | #12, #20 |
| Model invocation logging | **Deleted** at the account/region level (previous config backed up) | #26, #27, #28 |
| AgentCore Memory `ss_test_ac_memory_*` *(if service available)* | No CMK, no strategies | #44, #45 |
| AgentCore API-key provider `ss-test-ac-apikey-*` *(if service available)* | Test API key value | #48 |

The account also gets these findings for free — no explicit resource needed:

| Check | Why it fires naturally |
|---|---|
| #30 `bedrockAgentWithoutGuardrail` | Same broken agent as #1 |
| #46 `bedrockACNoPolicyEngine` | Only fires if AgentCore resources exist — the Memory/APIKey created above are sufficient to activate the check, and no policy engines are created |
| #47 `bedrockACNoIdentityProvider` | Fires the moment the API-key provider is deleted or if no OAuth is set up (default state after cleanup) — during the test run it will PASS because the API-key provider exists |

## Coverage vs. Spec

| Category | Checks in spec | Directly simulated | Not simulatable (API validation) | Documented as manual |
|---|---:|---:|---:|---:|
| Agent (easy) | 8 | 8 | 0 | 0 |
| Agent (effort) | 1 (#8 versions) | 0 | 0 | 1 |
| Agent action group | 1 (#9 no-schema) | 0 | 1 | 0 |
| Guardrail | 9 | 9 | 0 | 0 |
| Knowledge Base | 4 | 0 | 0 | 4 |
| Account-level | 4 | 4 | 0 | 0 |
| AgentCore (easy) | 6 | 4 (Memory, API-key) | 0 | 2 (Gateway) |
| AgentCore (effort) | 2 | 0 | 0 | 2 |
| **Total** | **35** | **25** | **1** | **9** |

### Not Simulatable (#9 `bedrockAgentActionGroupNoSchema`)

The Bedrock CreateAgentActionGroup API rejects any action group that lacks
both `apiSchema` and `functionSchema` (validation error). The driver's check
is still correct — it will detect schemaless action groups created by other
means (SDK bugs, direct API abuse, or older console versions) — but the
misconfiguration cannot be produced through the CLI. Do not include #9 in
your expected-FAIL list when validating this simulation.

## Manual Setup Required

The following checks are NOT wired into the automation because they need
resources that are either expensive (KB → OpenSearch Serverless) or need
extra infrastructure the script can't stand up unattended (Gateway → JWT
authorizer):

### Knowledge Base (#21–#25)

A Bedrock Knowledge Base requires an external vector store. The cheapest
supported option is an OpenSearch Serverless collection, which has a
**minimum-billed capacity of 2 OCUs (~$0.24/hour ≈ $175/month)** even for
tiny KBs. That's above the "small change" cost profile of this simulation,
so KB checks are left as manual.

To simulate manually:

```bash
# 1. Create a vector store (OpenSearch Serverless collection) — outside script scope
#
# 2. Create KB WITHOUT encryption / without data source — triggers #21, #23:
aws bedrock-agent create-knowledge-base \
    --name ss-test-kb-broken \
    --role-arn "$OVERPRIVILEGED_ROLE_ARN" \
    --knowledge-base-configuration '{"type":"VECTOR","vectorKnowledgeBaseConfiguration":{"embeddingModelArn":"arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v1"}}' \
    --storage-configuration '{"type":"OPENSEARCH_SERVERLESS","opensearchServerlessConfiguration":{"collectionArn":"<COLLECTION_ARN>","vectorIndexName":"my-idx","fieldMapping":{"vectorField":"vec","textField":"text","metadataField":"meta"}}}' \
    --region us-east-1

# 3. To trigger #24 (sync stale), add a data source but never run start-ingestion-job:
aws bedrock-agent create-data-source ...

# 4. #22 (KB FAILED) — force a failure by pointing the KB at a non-existent
#    collection ARN. Not a normal state; usually only encountered accidentally.
```

Overprivileged role reuse triggers #25 automatically once the KB is attached.

### Agent Excessive Versions (#8)

Requires a *valid* (prepared) agent + 11 aliases without `routingConfiguration`.
The broken agent produced by this script cannot be prepared (empty instruction),
so #8 is left as manual:

```bash
# With a properly-configured, prepared agent:
for i in $(seq 1 11); do
    aws bedrock-agent create-agent-alias \
        --agent-id "$AGENT_ID" \
        --agent-alias-name "v${i}" \
        --region us-east-1
    sleep 5
done
```

### AgentCore Gateway (#40, #41, #42, #43)

`CreateGateway` requires a JWT authorizer configuration (typically a Cognito
user pool). The script emits the commented-out CLI commands for reference —
see Step 6 in `create_test_resources.sh`. To exercise these checks manually,
create a Cognito user pool with a domain, then run the printed `create-gateway`
command (omit `--policy-engine-configuration` to trigger #41; skip
`create-gateway-target` to trigger #42; use `create-gateway-target` with no
`credentialProviderConfigurations` to trigger #43).

## Cost

| Resource | Cost while running |
|---|---|
| IAM role, guardrails, agent (not prepared), API-key provider | $0 |
| Model invocation logging (deleted state) | $0 |
| AgentCore Memory | ≤ $0.01 per test run (event-level charges, none exercised) |
| **Total per test cycle** | **~$0** if cleaned up within a few hours |

Notable exclusions: any KB resources you set up manually will incur
OpenSearch Serverless charges (~$175/month minimum). Delete them yourself
when done — the cleanup script does not touch KBs it did not create.

## Usage

### Create

```bash
cd services/bedrock/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region us-east-1
```

Options:
- `--region <region>` — default `us-east-1`
- `--skip-agentcore` — don't attempt AgentCore resources even if available
- `--help` — show help header

The script writes a resource manifest to `created_resources_<TIMESTAMP>.txt`
in the current directory. That file is the input for cleanup.

### Run Service Screener

```bash
cd ../../..                   # back to repo root
# Allow ~60s for IAM propagation before scanning
sleep 60
python3 main.py --regions us-east-1 --services bedrock --beta 1 --sequential 1
```

Open `adminlte/aws/<ACCOUNT_ID>/bedrock.html` to see the findings. Expect
`-1` (FAIL) status on the checks listed in the coverage table above.

### Cleanup

```bash
cd services/bedrock/simulation
./cleanup_test_resources.sh created_resources_<TIMESTAMP>.txt --region us-east-1
```

If you omit the manifest argument, the script auto-detects the most recent
`created_resources_*.txt` in the current directory. Use `--force` to skip
the confirmation prompt.

The cleanup script:
1. Deletes any Bedrock agents (with `--skip-resource-in-use-check`)
2. Deletes both guardrails
3. Deletes AgentCore memory and API-key provider (if any)
4. Restores the prior model invocation logging configuration (if a backup
   was saved during creation)
5. Detaches policies + deletes the IAM role

All deletion steps are error-tolerant — resources that are already gone are
skipped silently.

## Troubleshooting

**`Action group without schema rejected`** — This is the expected outcome
and #9 has been dropped from the coverage list. The Bedrock CreateAgentActionGroup
API rejects action groups that lack both `apiSchema` and `functionSchema`, so the
misconfiguration can't be produced through the CLI. The check itself is still
correct (it will detect schemaless action groups created via other means).

**`AgentCore not available in region`** — The `bedrock-agentcore-control`
API is not published in every region. When the preflight probe fails, all
AgentCore-related resources are skipped and the corresponding checks will
report `INFO` (no resources to evaluate) rather than `FAIL`.

**Cleanup says "already deleted"** — Bedrock deletion is eventually
consistent. If you interrupt the create script mid-flight, some resources
may not be in the manifest but were still created. Search the console for
resources named `ss-test-*` in the region and delete them manually.

**`invalid instruction length`** — The bedrock CreateAgent API requires
`instruction` to be at least 40 characters if provided. The script sends 45
whitespace characters so the driver's `.strip()` classifies it as empty
while still passing API validation.

**Prior logging config lost** — The create script backs up the previous
`get-model-invocation-logging-configuration` response to
`logging_config_backup_<TIMESTAMP>.json` before deleting. The cleanup script
attempts to restore it. If the backup references resources you've since
deleted (e.g., an old S3 bucket), the restore will fail — reconfigure
logging manually via the Bedrock console.

## IAM Permissions Required

To run both scripts you need permission to:
- `iam:CreateRole`, `iam:DeleteRole`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:DetachRolePolicy`
- `bedrock:CreateGuardrail`, `bedrock:DeleteGuardrail`,
  `bedrock:GetModelInvocationLoggingConfiguration`,
  `bedrock:DeleteModelInvocationLoggingConfiguration`,
  `bedrock:PutModelInvocationLoggingConfiguration`
- `bedrock:CreateAgent`, `bedrock:DeleteAgent`, `bedrock:CreateAgentActionGroup`
- (optional) `bedrock-agentcore:CreateMemory`, `bedrock-agentcore:DeleteMemory`,
  `bedrock-agentcore:CreateApiKeyCredentialProvider`,
  `bedrock-agentcore:DeleteApiKeyCredentialProvider`,
  `bedrock-agentcore:ListMemories`
- `sts:GetCallerIdentity`

The overprivileged inline policy on the created role also requires
`iam:PassRole` for `bedrock.amazonaws.com` from the caller — usually granted
by `AmazonBedrockFullAccess` or equivalent.

## Notes

- All resources are prefixed with `ss-test-` for easy identification and
  filtering in the AWS console.
- Bedrock resources themselves have no standing charges — the agent doesn't
  invoke any model, the guardrails aren't attached to anything, and the
  action group has no Lambda.
- If you run the scan while cleanup is in progress, you may see transient
  `ResourceNotFoundException` messages logged by the driver — the drivers
  swallow these and continue.

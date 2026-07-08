# Bedrock Simulation Test Spec

Create `services/bedrock/simulation/` with:
- `create_test_resources.sh` — creates insecure Bedrock resources that trigger FAIL on the listed checks
- `cleanup_test_resources.sh` — deletes everything created
- `README.md` — documents what's created, which checks are validated, costs

Use AWS CLI (not boto3 scripts) — consistent with existing simulations in `services/sagemaker/simulation/`.

All resources should use prefix `ss-test-` for easy identification.
Region: us-east-1
Wait 15s after IAM role creation before using roles.

## Checks to Simulate (37 total)

### Agent Checks (Easy)
1. `bedrockAgentGuardrailAttached` — create agent WITHOUT guardrail
2. `bedrockAgentIamRoleOverprivileged` — create IAM role with Action:*,Resource:* then attach to agent
3. `bedrockAgentNoInstruction` — create agent with empty instruction ("")
4. `bedrockAgentIdleSessionTimeout` — create agent with idleSessionTTLInSeconds=3601
5. `bedrockAgentMemoryDisabled` — create agent without memoryConfiguration
6. `bedrockAgentNoEncryptionKey` — create agent without customerEncryptionKeyArn
7. `bedrockAgentNotPrepared` — create agent, do NOT call prepare-agent
9. `bedrockAgentActionGroupNoSchema` — create action group without apiSchema (use RETURN_CONTROL type)
10. `bedrockAgentCollaborationDisabled` — create agent without agentCollaboration setting

### Agent (More Effort)
8. `bedrockAgentExcessiveVersions` — create agent, prepare it, then create 11 versions via create-agent-alias (loop)

### Guardrail Checks (Easy)
11. `bedrockGuardrailContentFilterDisabled` — create guardrail with NO contentPolicyConfig
12. `bedrockGuardrailContentFilterWeak` — create guardrail with inputStrength=LOW on all categories
13. `bedrockGuardrailNoPromptAttackFilter` — create guardrail with content filters but NO PROMPT_ATTACK type
14. `bedrockGuardrailNoPiiDetection` — create guardrail without sensitiveInformationPolicyConfig
15. `bedrockGuardrailNoDeniedTopics` — create guardrail without topicPolicyConfig
16. `bedrockGuardrailNoWordFilter` — create guardrail without wordPolicyConfig
17. `bedrockGuardrailNoGroundingFilter` — create guardrail without contextualGroundingPolicyConfig
18. `bedrockGuardrailNoEncryption` — create guardrail without kmsKeyArn
20. `bedrockGuardrailOutputFilterDisabled` — create guardrail with content filters where input is enabled but output is disabled

### Knowledge Base Checks (Easy)
21. `bedrockKBNoEncryption` — create KB without serverSideEncryptionConfiguration
23. `bedrockKBNoDataSources` — create KB with no data sources added
24. `bedrockKBDataSourceSyncStale` — create KB + data source but never run ingestion
25. `bedrockKBRoleOverprivileged` — create KB with overprivileged role (Action:*,Resource:*)

NOTE: KB creation requires a vector store (OpenSearch Serverless collection or similar). Use the simplest option — if too expensive, use a managed KB type that doesn't need external infra. If KB creation is too complex/expensive via CLI, document it in README as "manual setup required" and skip those 4.

### Account-Level Checks (Easy)
26. `bedrockModelInvocationLoggingDisabled` — call delete-model-invocation-logging-configuration
27. `bedrockModelInvocationNoCloudWatch` — put logging config with S3 only (no CW)
28. `bedrockModelInvocationNoS3` — put logging config with CW only (no S3)
30. `bedrockAgentWithoutGuardrail` — same as #1 (already covered)

### AgentCore Checks (Easy — if service available)
41. `bedrockACGatewayNoPolicy` — create-gateway without policy engine
42. `bedrockACGatewayNoTargets` — create-gateway then don't add targets
44. `bedrockACMemoryNoEncryption` — create-memory without encryptionKeyArn
45. `bedrockACMemoryNoNamespace` — create-memory without namespace config
46. `bedrockACNoPolicyEngine` — account-level, just verify none exist
47. `bedrockACNoIdentityProvider` — account-level, just verify none exist

### AgentCore (More Effort)
43. `bedrockACGatewayTargetNoAuth` — create gateway + target without credentialProviderConfigurations
48. `bedrockACApiKeyProviderUsed` — create-api-key-credential-provider

## Important Notes

- For AgentCore checks: wrap in `if aws bedrock-agentcore-control list-gateways ... 2>/dev/null; then ... fi` — skip if service not available in region
- The IAM role for bedrock agent needs trust policy for `bedrock.amazonaws.com`
- The IAM role for KB needs trust policy for `bedrock.amazonaws.com`
- Include cost estimate in README (most resources are free except KB vector store)
- cleanup script should handle "resource not found" errors gracefully (resource may already be deleted)
- Add `set -e` only where appropriate — some commands are expected to fail during cleanup

## Expected Test Flow

```bash
# Create
cd services/bedrock/simulation
./create_test_resources.sh

# Wait 60s for IAM propagation + resource readiness
sleep 60

# Scan
cd ../../..
python3 main.py --regions us-east-1 --services bedrock --beta 1 --sequential 1

# Verify findings (should show FAIL for all simulated checks)

# Cleanup
cd services/bedrock/simulation
./cleanup_test_resources.sh
```

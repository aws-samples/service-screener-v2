#!/bin/bash

################################################################################
# Bedrock Service Screener - Test Resource Creation Script
#
# Creates intentionally-insecure Bedrock resources to trigger FAIL findings
# on service-screener bedrock checks. Uses AWS CLI only (no boto3/Python).
#
# Resources created (all prefixed with ss-test-):
#   - IAM role (overprivileged: Action:*, Resource:*)
#   - Bedrock agent (broken: empty instruction, no guardrail, no memory,
#                    no CMK, high idle TTL, not prepared, no collaboration)
#   - Guardrail A (minimal: no filters at all)
#   - Guardrail B (weak: content filter at LOW strength, output disabled,
#                  no PROMPT_ATTACK, no PII/topic/word/grounding, no CMK)
#   - Model invocation logging: DELETED (triggers logging-disabled checks)
#   - AgentCore Memory (no CMK, no namespace) — if service available
#   - AgentCore API-key credential provider — if service available
#
# Checks NOT directly simulated by this script (documented in README):
#   #8  bedrockAgentExcessiveVersions       (needs valid prepared agent + 11 aliases)
#   #9  bedrockAgentActionGroupNoSchema     (Bedrock API rejects schemaless action groups)
#   #21-25 bedrockKB*                        (KB requires OpenSearch Serverless — expensive)
#   #40 bedrockACRuntimeNoGateway            (requires a Runtime + Gateway wiring)
#   #43 bedrockACGatewayTargetNoAuth         (Gateway creation needs custom JWT authorizer)
#
# Usage:
#   ./create_test_resources.sh [OPTIONS]
#
# Options:
#   --region REGION      AWS region (default: us-east-1)
#   --skip-agentcore     Skip AgentCore resources even if service is available
#   --help               Show this help message
#
################################################################################

# NOTE: 'set -e' is intentionally NOT set — several commands are permitted to
# fail (e.g., action group without schema is often rejected by the API), and
# we still want the rest of the script to run.
set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SKIP_AGENTCORE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region)         REGION="$2"; shift 2 ;;
        --skip-agentcore) SKIP_AGENTCORE=true; shift ;;
        --help)           grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)                echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

# ------------------------------------------------------------------ #
# Preflight
# ------------------------------------------------------------------ #
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
if [ -z "${ACCOUNT_ID:-}" ]; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"
    exit 1
fi

ROLE_NAME="${PREFIX}-bedrock-role-${TIMESTAMP}"
AGENT_NAME="${PREFIX}-agent-broken-${TIMESTAMP}"
GR_MIN_NAME="${PREFIX}-gr-minimal-${TIMESTAMP}"
GR_WEAK_NAME="${PREFIX}-gr-weak-${TIMESTAMP}"
AC_MEMORY_NAME="ssTestMemory_${TIMESTAMP//-/_}"          # regex [a-zA-Z][a-zA-Z0-9_]{0,47} - no dashes
AC_APIKEY_NAME="${PREFIX}-ac-apikey-${TIMESTAMP}"

OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Bedrock Test Resource Creation ===${NC}"
echo "Region:      $REGION"
echo "Account:     $ACCOUNT_ID"
echo "Timestamp:   $TIMESTAMP"
echo "Output file: $OUTPUT_FILE"
echo ""
echo -e "${YELLOW}All resources prefixed with '${PREFIX}-' for easy identification.${NC}"
echo -e "${YELLOW}Bedrock resources themselves are free — logging and AgentCore memory${NC}"
echo -e "${YELLOW}may incur small charges. Run cleanup promptly.${NC}"
echo ""

################################################################################
# Step 1: Overprivileged IAM Role
#   Triggers: #2 bedrockAgentIamRoleOverprivileged
#             #25 bedrockKBRoleOverprivileged (if a KB is ever attached)
#             #39 bedrockACRuntimeWildcardRole (if a Runtime is ever attached)
################################################################################

echo -e "${GREEN}=== Step 1: IAM role (overprivileged) ===${NC}"

cat > /tmp/${PREFIX}-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "bedrock.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

cat > /tmp/${PREFIX}-inline-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF

aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document file:///tmp/${PREFIX}-trust-policy.json \
    --description "Service Screener bedrock simulation - intentionally overprivileged" \
    > /dev/null

aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "${PREFIX}-wildcard" \
    --policy-document file:///tmp/${PREFIX}-inline-policy.json

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
log_resource "IAM_ROLE:${ROLE_NAME}"
echo -e "${GREEN}✓ IAM role: ${ROLE_NAME}${NC}"

# Wait for IAM role propagation (spec requires 15s minimum)
echo -e "${YELLOW}Sleeping 15s for IAM role propagation...${NC}"
sleep 15

################################################################################
# Step 2: Broken Bedrock Agent
#   Triggers: #1  bedrockAgentGuardrailAttached      (no guardrail)
#             #3  bedrockAgentNoInstruction          (empty instruction)
#             #4  bedrockAgentIdleSessionTimeout     (TTL > 3600s)
#             #5  bedrockAgentMemoryDisabled         (no memoryConfiguration)
#             #6  bedrockAgentNoEncryptionKey        (no CMK)
#             #7  bedrockAgentNotPrepared            (never call PrepareAgent)
#             #10 bedrockAgentCollaborationDisabled  (default DISABLED)
#             #30 bedrockAgentWithoutGuardrail       (account-level, same cause as #1)
################################################################################

echo -e "\n${GREEN}=== Step 2: Broken Bedrock agent ===${NC}"

# Note: bedrock CreateAgent requires 'instruction' to have length >= 40 chars
# when it IS provided. We simulate "empty instruction" by supplying a whitespace-
# only string of sufficient length that the driver's .strip() will treat as empty.
INSTRUCTION_WHITESPACE=$(printf ' %.0s' {1..45})

AGENT_JSON=$(aws bedrock-agent create-agent \
    --agent-name "$AGENT_NAME" \
    --agent-resource-role-arn "$ROLE_ARN" \
    --foundation-model "anthropic.claude-3-haiku-20240307-v1:0" \
    --instruction "$INSTRUCTION_WHITESPACE" \
    --idle-session-ttl-in-seconds 3601 \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Agent creation failed${NC}"
        echo "$AGENT_JSON" | head -5
        AGENT_JSON=""
    }

if [ -n "$AGENT_JSON" ]; then
    AGENT_ID=$(echo "$AGENT_JSON" | grep -o '"agentId": *"[^"]*"' | head -1 | sed 's/.*"agentId": *"\([^"]*\)".*/\1/')
    if [ -n "${AGENT_ID:-}" ]; then
        log_resource "AGENT:${AGENT_ID}"
        echo -e "${GREEN}✓ Agent: ${AGENT_NAME} (id=${AGENT_ID})${NC}"

        # NOTE: #9 bedrockAgentActionGroupNoSchema is NOT simulated here —
        # Bedrock's CreateAgentActionGroup API rejects action groups that
        # lack both apiSchema and functionSchema, so the misconfiguration
        # cannot be produced through the CLI. The driver-side check is
        # still correct for action groups created by other means.
    else
        echo -e "${YELLOW}⚠ Could not parse agent ID${NC}"
    fi
fi

################################################################################
# Step 3: Guardrail A — only a trivial word policy (no content/PII/topic/grounding)
#   Bedrock now requires at least one policy per guardrail, so we attach a
#   minimal wordPolicyConfig containing a single throwaway word. Everything
#   else is omitted so these checks still fire:
#   Triggers: #11 bedrockGuardrailContentFilterDisabled  (no contentPolicy)
#             #13 bedrockGuardrailNoPromptAttackFilter    (no PROMPT_ATTACK)
#             #14 bedrockGuardrailNoPiiDetection          (no sensitive info)
#             #15 bedrockGuardrailNoDeniedTopics          (no topics)
#             #17 bedrockGuardrailNoGroundingFilter       (no grounding)
#             #18 bedrockGuardrailNoEncryption            (no CMK)
################################################################################

echo -e "\n${GREEN}=== Step 3: Guardrail A (word-only policy) ===${NC}"

cat > /tmp/${PREFIX}-gr-min.json <<EOF
{
  "name": "${GR_MIN_NAME}",
  "description": "SS simulation: only a trivial word policy; all other policies absent",
  "blockedInputMessaging": "blocked",
  "blockedOutputsMessaging": "blocked",
  "wordPolicyConfig": {
    "wordsConfig": [
      { "text": "test-blocked-word" }
    ]
  }
}
EOF

GR_A_JSON=$(aws bedrock create-guardrail \
    --cli-input-json file:///tmp/${PREFIX}-gr-min.json \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Guardrail A creation failed${NC}"
        echo "$GR_A_JSON" | head -5
        GR_A_JSON=""
    }

if [ -n "$GR_A_JSON" ]; then
    GR_A_ID=$(echo "$GR_A_JSON" | grep -o '"guardrailId": *"[^"]*"' | head -1 | sed 's/.*"guardrailId": *"\([^"]*\)".*/\1/')
    if [ -n "${GR_A_ID:-}" ]; then
        log_resource "GUARDRAIL:${GR_A_ID}"
        echo -e "${GREEN}✓ Guardrail A: ${GR_MIN_NAME} (id=${GR_A_ID})${NC}"
    fi
fi

################################################################################
# Step 4: Guardrail B — Weak filters, output-disabled
#   Triggers: #12 bedrockGuardrailContentFilterWeak       (inputStrength=LOW)
#             #13 bedrockGuardrailNoPromptAttackFilter    (only VIOLENCE, no PROMPT_ATTACK)
#             #20 bedrockGuardrailOutputFilterDisabled    (outputEnabled=false)
#             plus #14/#15/#16/#17/#18 (still missing all other configs)
################################################################################

echo -e "\n${GREEN}=== Step 4: Guardrail B (weak filters) ===${NC}"

cat > /tmp/${PREFIX}-gr-weak.json <<EOF
{
  "name": "${GR_WEAK_NAME}",
  "description": "SS simulation: weak content filter, output disabled",
  "blockedInputMessaging": "blocked",
  "blockedOutputsMessaging": "blocked",
  "contentPolicyConfig": {
    "filtersConfig": [
      {
        "type": "VIOLENCE",
        "inputStrength": "LOW",
        "outputStrength": "NONE",
        "inputEnabled": true,
        "outputEnabled": false
      }
    ]
  }
}
EOF

GR_B_JSON=$(aws bedrock create-guardrail \
    --cli-input-json file:///tmp/${PREFIX}-gr-weak.json \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Guardrail B creation failed${NC}"
        echo "$GR_B_JSON" | head -5
        GR_B_JSON=""
    }

if [ -n "$GR_B_JSON" ]; then
    GR_B_ID=$(echo "$GR_B_JSON" | grep -o '"guardrailId": *"[^"]*"' | head -1 | sed 's/.*"guardrailId": *"\([^"]*\)".*/\1/')
    if [ -n "${GR_B_ID:-}" ]; then
        log_resource "GUARDRAIL:${GR_B_ID}"
        echo -e "${GREEN}✓ Guardrail B: ${GR_WEAK_NAME} (id=${GR_B_ID})${NC}"
    fi
fi

################################################################################
# Step 5: Delete Model Invocation Logging Configuration
#   Triggers: #26 bedrockModelInvocationLoggingDisabled  (fully disabled)
#             #27 bedrockModelInvocationNoCloudWatch     (falls through: no CW)
#             #28 bedrockModelInvocationNoS3             (falls through: no S3)
################################################################################

echo -e "\n${GREEN}=== Step 5: Disable model invocation logging ===${NC}"

# Save current config so cleanup can restore it if needed
CURRENT_LOG_CFG=$(aws bedrock get-model-invocation-logging-configuration \
    --region "$REGION" --output json 2>/dev/null || echo '{}')

if [ "$CURRENT_LOG_CFG" != "{}" ] && ! echo "$CURRENT_LOG_CFG" | grep -q '"loggingConfig": *null'; then
    echo "$CURRENT_LOG_CFG" > "logging_config_backup_${TIMESTAMP}.json"
    log_resource "LOGGING_BACKUP:logging_config_backup_${TIMESTAMP}.json"
    echo "Backed up previous logging config to logging_config_backup_${TIMESTAMP}.json"
fi

aws bedrock delete-model-invocation-logging-configuration \
    --region "$REGION" 2>/dev/null \
    && echo -e "${GREEN}✓ Model invocation logging disabled${NC}" \
    || echo -e "${YELLOW}⚠ Logging config was already absent or delete failed${NC}"
log_resource "LOGGING_DELETED:1"

################################################################################
# Step 6: AgentCore resources (best-effort — service may not be available)
#   Triggers: #44 bedrockACMemoryNoEncryption   (no CMK)
#             #45 bedrockACMemoryNoNamespace    (no strategies)
#             #48 bedrockACApiKeyProviderUsed   (API key provider exists)
################################################################################

if [ "$SKIP_AGENTCORE" = true ]; then
    echo -e "\n${YELLOW}=== Step 6: AgentCore skipped (--skip-agentcore) ===${NC}"
elif aws bedrock-agentcore-control list-memories --region "$REGION" > /dev/null 2>&1; then
    echo -e "\n${GREEN}=== Step 6: AgentCore resources ===${NC}"

    # ---- Memory (no CMK, no strategies) -----------------------------
    MEM_JSON=$(aws bedrock-agentcore-control create-memory \
        --name "$AC_MEMORY_NAME" \
        --description "SS simulation: no CMK, no namespace" \
        --event-expiry-duration 30 \
        --region "$REGION" \
        --output json 2>&1) || {
            echo -e "${YELLOW}⚠ Memory creation failed: $(echo "$MEM_JSON" | head -2)${NC}"
            MEM_JSON=""
        }
    if [ -n "$MEM_JSON" ]; then
        MEM_ID=$(echo "$MEM_JSON" | grep -o '"id": *"[^"]*"' | head -1 | sed 's/.*"id": *"\([^"]*\)".*/\1/')
        if [ -n "${MEM_ID:-}" ]; then
            log_resource "AC_MEMORY:${MEM_ID}"
            echo -e "${GREEN}✓ AgentCore Memory: ${AC_MEMORY_NAME} (id=${MEM_ID})${NC}"
        fi
    fi

    # ---- API-key credential provider --------------------------------
    APIKEY_JSON=$(aws bedrock-agentcore-control create-api-key-credential-provider \
        --name "$AC_APIKEY_NAME" \
        --api-key "ss-test-fake-api-key-do-not-use-$(date +%s)" \
        --region "$REGION" \
        --output json 2>&1) || {
            echo -e "${YELLOW}⚠ API-key provider creation failed: $(echo "$APIKEY_JSON" | head -2)${NC}"
            APIKEY_JSON=""
        }
    if [ -n "$APIKEY_JSON" ]; then
        log_resource "AC_APIKEY:${AC_APIKEY_NAME}"
        echo -e "${GREEN}✓ AgentCore API-key credential provider: ${AC_APIKEY_NAME}${NC}"
    fi

    # ---- Gateway (COMMENTED OUT — needs custom JWT authorizer) ------
    # To simulate #41 bedrockACGatewayNoPolicy and #42 bedrockACGatewayNoTargets
    # manually, set up a JWT authorizer (e.g., Cognito user pool with domain
    # 'https://cognito-idp.<region>.amazonaws.com/<pool-id>') and run:
    #
    # aws bedrock-agentcore-control create-gateway \
    #     --name "${PREFIX}-gw-nopolicy-${TIMESTAMP}" \
    #     --role-arn "${ROLE_ARN}" \
    #     --authorizer-type CUSTOM_JWT \
    #     --authorizer-configuration '{"customJWTAuthorizer":{"discoveryUrl":"https://cognito-idp.us-east-1.amazonaws.com/<POOL_ID>/.well-known/openid-configuration","allowedClients":["<CLIENT_ID>"]}}' \
    #     --protocol-type MCP \
    #     --region "$REGION"
    #
    # (Do NOT set --policy-engine-configuration → triggers #41)
    # (Do NOT run create-gateway-target → triggers #42)

    echo -e "${CYAN}NOTE: AgentCore Gateway not created — requires a JWT authorizer${NC}"
    echo -e "${CYAN}(Cognito user pool). See commented-out commands in the script.${NC}"
else
    echo -e "\n${YELLOW}=== Step 6: AgentCore not available in $REGION — skipping ===${NC}"
fi

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}=== All Resources Created ===${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "Resource file: $OUTPUT_FILE"
echo ""
cat "$OUTPUT_FILE" | sed 's/^/  /'
echo ""
echo "Next steps:"
echo "  1. Wait 60s for IAM propagation:  sleep 60"
echo "  2. Run screener from repo root:"
echo "       python3 main.py --regions $REGION --services bedrock --beta 1 --sequential 1"
echo "  3. Verify FAIL findings in the report"
echo "  4. Cleanup:"
echo "       ./cleanup_test_resources.sh $OUTPUT_FILE --region $REGION"
echo ""
echo -e "${YELLOW}Cost impact: negligible for Bedrock resources themselves; AgentCore Memory${NC}"
echo -e "${YELLOW}stores incur a small per-event charge. Clean up promptly.${NC}"

# Cleanup temp files
rm -f /tmp/${PREFIX}-trust-policy.json /tmp/${PREFIX}-inline-policy.json /tmp/${PREFIX}-gr-min.json /tmp/${PREFIX}-gr-weak.json

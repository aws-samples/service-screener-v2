#!/bin/bash

################################################################################
# Bedrock Service Screener - Test Resource Cleanup Script
#
# Deletes resources created by create_test_resources.sh. Reads the resource
# file emitted by the creation script and processes each line.
#
# Cleanup order:
#   1. Bedrock agents (must delete before role can be deleted)
#   2. Bedrock guardrails
#   3. AgentCore memory
#   4. AgentCore API-key credential providers
#   5. IAM role (detach policies, delete inline policies, delete role)
#   6. Restore model invocation logging config if a backup exists
#
# Errors are tolerated throughout — resources may already be gone.
#
# Usage:
#   ./cleanup_test_resources.sh <RESOURCE_FILE> [OPTIONS]
#
# Options:
#   --region REGION    AWS region (default: us-east-1)
#   --force            Skip confirmation prompt
#   --help             Show this help message
#
################################################################################

# NOTE: no 'set -e' — cleanup must proceed even when individual deletes fail.
set -u

REGION="${AWS_REGION:-us-east-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --force)  FORCE=true; shift ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then
                RESOURCE_FILE="$1"; shift
            else
                echo -e "${RED}Error: Unknown option $1${NC}"; exit 1
            fi
            ;;
    esac
done

# Auto-detect the most recent resource file if none provided
if [ -z "$RESOURCE_FILE" ]; then
    RESOURCE_FILE=$(ls -1t created_resources_*.txt 2>/dev/null | head -1)
    if [ -z "$RESOURCE_FILE" ]; then
        echo -e "${RED}Error: no resource file specified and none found in CWD${NC}"
        echo "Usage: $0 <resource_file> [--region REGION] [--force]"
        exit 1
    fi
    echo -e "${YELLOW}Auto-detected resource file: $RESOURCE_FILE${NC}"
fi

if [ ! -f "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: resource file not found: $RESOURCE_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}=== Bedrock Test Resource Cleanup ===${NC}"
echo "Region:        $REGION"
echo "Resource file: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    [ -n "$line" ] && RESOURCES+=("$line")
done < "$RESOURCE_FILE"

echo "Resources to delete:"
for r in "${RESOURCES[@]}"; do
    echo "  - $r"
done
echo ""

if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}WARNING: This will permanently delete these resources.${NC}"
    read -p "Continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Cleanup cancelled."
        exit 0
    fi
fi

# Helper: extract IDs by type
by_type() {
    local type="$1"
    for r in "${RESOURCES[@]}"; do
        [[ "$r" == ${type}:* ]] && echo "${r#${type}:}"
    done
}

################################################################################
# Step 1: Delete Bedrock Agents
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting Bedrock agents ===${NC}"
for AGENT_ID in $(by_type AGENT); do
    echo "Deleting agent: $AGENT_ID"
    aws bedrock-agent delete-agent \
        --agent-id "$AGENT_ID" \
        --skip-resource-in-use-check \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓ deleted${NC}" \
        || echo -e "${YELLOW}  ⚠ already deleted or not found${NC}"
done

################################################################################
# Step 2: Delete Bedrock Guardrails
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting Bedrock guardrails ===${NC}"
for GR_ID in $(by_type GUARDRAIL); do
    echo "Deleting guardrail: $GR_ID"
    aws bedrock delete-guardrail \
        --guardrail-identifier "$GR_ID" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓ deleted${NC}" \
        || echo -e "${YELLOW}  ⚠ already deleted or not found${NC}"
done

################################################################################
# Step 3: Delete AgentCore Memory
################################################################################

echo -e "\n${GREEN}=== Step 3: Deleting AgentCore memory ===${NC}"
ac_mem_ids=$(by_type AC_MEMORY)
if [ -z "$ac_mem_ids" ]; then
    echo "  (none created)"
else
    for MEM_ID in $ac_mem_ids; do
        echo "Deleting AgentCore memory: $MEM_ID"
        aws bedrock-agentcore-control delete-memory \
            --memory-id "$MEM_ID" \
            --region "$REGION" > /dev/null 2>&1 \
            && echo -e "${GREEN}  ✓ deleted${NC}" \
            || echo -e "${YELLOW}  ⚠ already deleted or service unavailable${NC}"
    done
fi

################################################################################
# Step 4: Delete AgentCore API-key credential providers
################################################################################

echo -e "\n${GREEN}=== Step 4: Deleting AgentCore API-key credential providers ===${NC}"
ac_apikey_names=$(by_type AC_APIKEY)
if [ -z "$ac_apikey_names" ]; then
    echo "  (none created)"
else
    for APIKEY_NAME in $ac_apikey_names; do
        echo "Deleting API-key provider: $APIKEY_NAME"
        aws bedrock-agentcore-control delete-api-key-credential-provider \
            --name "$APIKEY_NAME" \
            --region "$REGION" > /dev/null 2>&1 \
            && echo -e "${GREEN}  ✓ deleted${NC}" \
            || echo -e "${YELLOW}  ⚠ already deleted or service unavailable${NC}"
    done
fi

################################################################################
# Step 5: Restore prior model invocation logging config, if a backup exists
################################################################################

echo -e "\n${GREEN}=== Step 5: Restore model invocation logging (if backed up) ===${NC}"
backup_file=""
for r in "${RESOURCES[@]}"; do
    if [[ "$r" == LOGGING_BACKUP:* ]]; then
        backup_file="${r#LOGGING_BACKUP:}"
    fi
done

if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
    # The backup is the full response of get-model-invocation-logging-configuration
    # which nests the useful config under .loggingConfig — extract and reapply.
    LOG_CFG_JSON=$(python3 - "$backup_file" <<'PY' 2>/dev/null || true
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    cfg = data.get('loggingConfig')
    if cfg:
        print(json.dumps(cfg))
except Exception:
    pass
PY
)
    if [ -n "$LOG_CFG_JSON" ]; then
        echo "Restoring prior logging configuration from $backup_file"
        echo "$LOG_CFG_JSON" > /tmp/ss-test-logging-restore.json
        aws bedrock put-model-invocation-logging-configuration \
            --logging-config file:///tmp/ss-test-logging-restore.json \
            --region "$REGION" > /dev/null 2>&1 \
            && echo -e "${GREEN}  ✓ restored${NC}" \
            || echo -e "${YELLOW}  ⚠ restore failed (previous config may reference deleted resources)${NC}"
        rm -f /tmp/ss-test-logging-restore.json
    else
        echo "  (backup file present but contained no loggingConfig — nothing to restore)"
    fi
else
    echo "  (no backup — leaving logging disabled)"
fi

################################################################################
# Step 6: Delete IAM role
################################################################################

echo -e "\n${GREEN}=== Step 6: Deleting IAM role ===${NC}"
for ROLE_NAME in $(by_type IAM_ROLE); do
    echo "Deleting IAM role: $ROLE_NAME"

    # Detach any attached managed policies
    attached=$(aws iam list-attached-role-policies \
        --role-name "$ROLE_NAME" \
        --query 'AttachedPolicies[].PolicyArn' \
        --output text 2>/dev/null || true)
    for arn in $attached; do
        aws iam detach-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-arn "$arn" 2>/dev/null || true
    done

    # Delete all inline policies
    inline=$(aws iam list-role-policies \
        --role-name "$ROLE_NAME" \
        --query 'PolicyNames' \
        --output text 2>/dev/null || true)
    for pname in $inline; do
        aws iam delete-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-name "$pname" 2>/dev/null || true
    done

    aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null \
        && echo -e "${GREEN}  ✓ deleted${NC}" \
        || echo -e "${YELLOW}  ⚠ already deleted or not found${NC}"
done

################################################################################
# Done
################################################################################

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}You may now delete the resource file:${NC} rm $RESOURCE_FILE"

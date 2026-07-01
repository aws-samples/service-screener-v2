#!/bin/bash

################################################################################
# Step Functions Service Screener - Test Resource Creation Script
#
# Creates two intentionally-insecure state machines:
#   1. STANDARD workflow with no logging, no tracing, no encryption CMK,
#      no Retry/Catch/Timeout in definition, overprivileged role, no tags
#   2. EXPRESS workflow with logging disabled (triggers the express-specific
#      check that STANDARD workflows can't)
#
# Checks triggered (11 of 12 — sfnStatusNotActive can't be forced):
#   #1  sfnEncryptionAtRest           — no CMK
#   #2  sfnRoleOverprivileged         — Action:*/Resource:* role
#   #3  sfnLoggingDisabled            — level=OFF
#   #4  sfnLoggingLevelWeak           — (fires via #3's fallthrough is skipped)
#   #5  sfnTracingDisabled            — tracingConfiguration.enabled=false
#   #6  sfnNoRetryPolicy              — Task states without Retry
#   #7  sfnNoCatchHandler             — Task states without Catch
#   #8  sfnNoTimeout                  — no top-level TimeoutSeconds
#   #9  sfnExpressWorkflowNoLogging   — EXPRESS + logging off
#  #11  sfnUnusedStateMachine         — freshly created, never invoked (age 0 → PASS not FAIL)
#  #12  sfnResourcesWithoutTags       — no tags
#
# Not simulated (documented in README):
#   #10 sfnStatusNotActive  — status only leaves ACTIVE during API-driven delete
#   #11 sfnUnusedStateMachine — cannot be aged-out; a brand new SM is < 90 days
#
# Usage:
#   ./create_test_resources.sh [OPTIONS]
#
# Options:
#   --region REGION    AWS region (default: us-east-1)
#   --help             Show this help
#
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)        echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
if [ -z "${ACCOUNT_ID:-}" ]; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"; exit 1
fi

ROLE_NAME="${PREFIX}-sfn-role-${TIMESTAMP}"
SM_STD_NAME="${PREFIX}-sfn-standard-${TIMESTAMP}"
SM_EXP_NAME="${PREFIX}-sfn-express-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Step Functions Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}All resources prefixed with '${PREFIX}-'. State machines with no${NC}"
echo -e "${YELLOW}executions are effectively free. Clean up when done.${NC}"
echo ""

################################################################################
# Step 1: Overprivileged IAM role
################################################################################

echo -e "${GREEN}=== Step 1: IAM role (overprivileged) ===${NC}"

cat > /tmp/${PREFIX}-sfn-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "states.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

cat > /tmp/${PREFIX}-sfn-wild.json <<'EOF'
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
    --assume-role-policy-document file:///tmp/${PREFIX}-sfn-trust.json \
    --description "SS simulation - intentionally overprivileged" \
    > /dev/null

aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "${PREFIX}-wildcard" \
    --policy-document file:///tmp/${PREFIX}-sfn-wild.json

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
log "IAM_ROLE:${ROLE_NAME}"
echo -e "${GREEN}✓ IAM role: ${ROLE_NAME}${NC}"

echo -e "${YELLOW}Sleeping 15s for IAM role propagation...${NC}"
sleep 15

################################################################################
# Step 2: Definitions with no Retry/Catch/TimeoutSeconds
################################################################################

echo -e "\n${GREEN}=== Step 2: State-machine definitions ===${NC}"

# A minimal STANDARD workflow with:
#   - No top-level TimeoutSeconds
#   - Two Task states with NEITHER Retry NOR Catch
# Uses SNS:Publish inline so we don't need a Lambda; SNS topic doesn't have
# to exist for validation to pass at create time — the machine is never run.
cat > /tmp/${PREFIX}-sfn-std-def.json <<EOF
{
  "Comment": "SS simulation: no timeout, no retry, no catch",
  "StartAt": "PublishOne",
  "States": {
    "PublishOne": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "arn:aws:sns:${REGION}:${ACCOUNT_ID}:ss-test-sim-topic-does-not-exist",
        "Message": "hello"
      },
      "Next": "PublishTwo"
    },
    "PublishTwo": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "arn:aws:sns:${REGION}:${ACCOUNT_ID}:ss-test-sim-topic-does-not-exist",
        "Message": "world"
      },
      "End": true
    }
  }
}
EOF

# EXPRESS workflow — identical shape, logging left off.
cp /tmp/${PREFIX}-sfn-std-def.json /tmp/${PREFIX}-sfn-exp-def.json

################################################################################
# Step 3: Create STANDARD state machine (11 FAILs)
################################################################################

echo -e "\n${GREEN}=== Step 3: STANDARD state machine (no logging/tracing/CMK/retry/catch/timeout/tags) ===${NC}"

STD_JSON=$(aws stepfunctions create-state-machine \
    --name "$SM_STD_NAME" \
    --definition file:///tmp/${PREFIX}-sfn-std-def.json \
    --role-arn "$ROLE_ARN" \
    --type STANDARD \
    --logging-configuration '{"level":"OFF","includeExecutionData":false,"destinations":[]}' \
    --tracing-configuration '{"enabled":false}' \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ STANDARD state machine creation failed${NC}"
        echo "$STD_JSON" | head -3
        STD_JSON=""
    }
if [ -n "$STD_JSON" ]; then
    STD_ARN=$(echo "$STD_JSON" | grep -o '"stateMachineArn": *"[^"]*"' | head -1 | sed 's/.*"stateMachineArn": *"\([^"]*\)".*/\1/')
    if [ -n "${STD_ARN:-}" ]; then
        log "STATE_MACHINE:${STD_ARN}"
        echo -e "${GREEN}✓ STANDARD SM: ${SM_STD_NAME}${NC}"
    fi
fi

################################################################################
# Step 4: Create EXPRESS state machine (triggers sfnExpressWorkflowNoLogging)
################################################################################

echo -e "\n${GREEN}=== Step 4: EXPRESS state machine (logging OFF) ===${NC}"

EXP_JSON=$(aws stepfunctions create-state-machine \
    --name "$SM_EXP_NAME" \
    --definition file:///tmp/${PREFIX}-sfn-exp-def.json \
    --role-arn "$ROLE_ARN" \
    --type EXPRESS \
    --logging-configuration '{"level":"OFF","includeExecutionData":false,"destinations":[]}' \
    --tracing-configuration '{"enabled":false}' \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ EXPRESS state machine creation failed${NC}"
        echo "$EXP_JSON" | head -3
        EXP_JSON=""
    }
if [ -n "$EXP_JSON" ]; then
    EXP_ARN=$(echo "$EXP_JSON" | grep -o '"stateMachineArn": *"[^"]*"' | head -1 | sed 's/.*"stateMachineArn": *"\([^"]*\)".*/\1/')
    if [ -n "${EXP_ARN:-}" ]; then
        log "STATE_MACHINE:${EXP_ARN}"
        echo -e "${GREEN}✓ EXPRESS SM: ${SM_EXP_NAME}${NC}"
    fi
fi

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}=== Resources Created ===${NC}"
echo -e "${GREEN}=========================================${NC}"
cat "$OUTPUT_FILE" | sed 's/^/  /'
echo ""
echo "Next:"
echo "  1. sleep 60   # IAM propagation"
echo "  2. cd ../../.. && python3 main.py --regions $REGION --services stepfunctions --beta 1 --sequential 1"
echo "  3. cd services/stepfunctions/simulation && ./cleanup_test_resources.sh"

rm -f /tmp/${PREFIX}-sfn-trust.json /tmp/${PREFIX}-sfn-wild.json /tmp/${PREFIX}-sfn-std-def.json /tmp/${PREFIX}-sfn-exp-def.json

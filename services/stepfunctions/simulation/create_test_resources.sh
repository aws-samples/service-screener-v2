#!/bin/bash

################################################################################
# Step Functions Service Screener - Test Resource Creation Script
#
# Creates FOUR intentionally-insecure state machines that exercise every
# `sfn*` service-screener check that can be forced through the AWS API:
#
#   SM #1 (STANDARD, "std")   — Phase 1 baseline: no logging/tracing/CMK, no
#                               Retry/Catch/Timeout, no tags, overprivileged
#                               role. Fires Phase 1 checks 13-22, 24 plus
#                               Phase 2 checks 25, 26.
#   SM #2 (EXPRESS, "exp")    — Phase 1 EXPRESS baseline: logging OFF.
#                               Fires Phase 1 check 21 (sfnExpressWorkflowNoLogging).
#   SM #3 (STANDARD, "logged")— Phase 2 addition: logging.level=ALL with
#                               includeExecutionData=true and default
#                               (AWS_OWNED_KEY) encryption. Fires Phase 2
#                               check 27 (sfnLoggingWithoutEncryption).
#   SM #4 (STANDARD, "http")  — Phase 2 addition: single Task state using
#                               `arn:aws:states:::http:invoke` with a
#                               *dynamic* `ApiEndpoint.$` reference (Step
#                               Functions rejects a static `http://` scheme
#                               at CreateStateMachine time via
#                               SCHEMA_VALIDATION_FAILED, so the FAIL branch
#                               of check 28 cannot be forced through the
#                               API — see README). Exercises the INFO branch
#                               of Phase 2 check 28 (sfnHttpTaskNoTLS).
#
# Supporting resources:
#   - 1 IAM role (wildcard Action:*/Resource:*) shared by all four SMs
#     (also fires Phase 2 check 25 sfnIAMRoleAllowsPassRole because
#      Action:* implicitly includes iam:PassRole with Resource:*).
#   - 1 CloudWatch log group for SM #3.
#   - 1 EventBridge connection for SM #4 (Step Functions validates the
#     ConnectionArn at create-state-machine time).
#
# Phase 2 checks covered (13-28):
#   All 4 SMs → check 26 (sfnNoCloudWatchAlarm) because we create no alarms.
#   SM #1 role → check 25 (sfnIAMRoleAllowsPassRole).
#   SM #3 → check 27 (sfnLoggingWithoutEncryption).
#   SM #4 → check 28 (sfnHttpTaskNoTLS) INFO branch (dynamic endpoint).
#
# Not simulated (documented in README):
#   Phase 1 #10 sfnStatusNotActive — transient state only during delete.
#   Phase 1 #11 sfnUnusedStateMachine — cannot fast-forward creation date.
#   Phase 1 #4  sfnLoggingLevelWeak — SM #1 uses level=OFF (falls to #3);
#               SM #3 uses level=ALL (PASS). Add a 5th SM with level=ERROR
#               if you want to force this check.
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
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
SM_LOG_NAME="${PREFIX}-sfn-logged-${TIMESTAMP}"
SM_HTTP_NAME="${PREFIX}-sfn-http-${TIMESTAMP}"
LOG_GROUP_NAME="/aws/vendedlogs/states/${SM_LOG_NAME}"
CONN_NAME="${PREFIX}-sfn-conn-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Step Functions Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}All resources prefixed with '${PREFIX}-'. State machines with no${NC}"
echo -e "${YELLOW}executions are effectively free. Clean up when done.${NC}"
echo ""

################################################################################
# Step 1: Overprivileged IAM role (shared by all four state machines)
################################################################################

echo -e "${GREEN}=== Step 1: IAM role (overprivileged — Action:*/Resource:*) ===${NC}"

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
echo -e "  Fires: Phase 1 #14 (sfnRoleOverprivileged), Phase 2 #25 (sfnIAMRoleAllowsPassRole via Action:*)"

echo -e "${YELLOW}Sleeping 15s for IAM role propagation...${NC}"
sleep 15

################################################################################
# Step 2: CloudWatch log group + EventBridge connection (Phase 2 support)
################################################################################

echo -e "\n${GREEN}=== Step 2: Log group + EventBridge connection ===${NC}"

# Log group for SM #3 (logging.level=ALL destination).
aws logs create-log-group \
    --log-group-name "$LOG_GROUP_NAME" \
    --region "$REGION" 2>&1 | head -3 || true
log "LOG_GROUP:${LOG_GROUP_NAME}"
echo -e "${GREEN}✓ Log group: ${LOG_GROUP_NAME}${NC}"

# EventBridge connection for SM #4 (http:invoke Authentication.ConnectionArn).
# Auth params are dummy; the state machine is never executed.
CONN_JSON=$(aws events create-connection \
    --name "$CONN_NAME" \
    --authorization-type API_KEY \
    --auth-parameters '{"ApiKeyAuthParameters":{"ApiKeyName":"x-ss-test","ApiKeyValue":"dummy-value-do-not-use"}}' \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ EventBridge connection create failed${NC}"
        echo "$CONN_JSON" | head -3
        CONN_JSON=""
    }
if [ -n "$CONN_JSON" ]; then
    CONN_ARN=$(echo "$CONN_JSON" | grep -o '"ConnectionArn": *"[^"]*"' | head -1 | sed 's/.*"ConnectionArn": *"\([^"]*\)".*/\1/')
    if [ -n "${CONN_ARN:-}" ]; then
        log "CONNECTION:${CONN_ARN}"
        echo -e "${GREEN}✓ Connection: ${CONN_NAME}${NC}"
    fi
else
    CONN_ARN=""
fi

################################################################################
# Step 3: STANDARD state-machine definition (Phase 1 baseline)
################################################################################

echo -e "\n${GREEN}=== Step 3: STANDARD state-machine definitions ===${NC}"

# Standard/Express Phase 1 workflow: no TimeoutSeconds, no Retry/Catch on Tasks.
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

cp /tmp/${PREFIX}-sfn-std-def.json /tmp/${PREFIX}-sfn-exp-def.json
cp /tmp/${PREFIX}-sfn-std-def.json /tmp/${PREFIX}-sfn-log-def.json

################################################################################
# Step 4: STANDARD state machine (Phase 1 baseline — 11 FAILs)
################################################################################

echo -e "\n${GREEN}=== Step 4: STANDARD SM (Phase 1 baseline) ===${NC}"

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
# Step 5: EXPRESS state machine (Phase 1 sfnExpressWorkflowNoLogging)
################################################################################

echo -e "\n${GREEN}=== Step 5: EXPRESS SM (logging OFF) ===${NC}"

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
# Step 6: LOGGED STANDARD state machine (Phase 2 check 27)
################################################################################

echo -e "\n${GREEN}=== Step 6: LOGGED SM (logging.level=ALL + includeExecutionData=true) ===${NC}"

LOG_GROUP_ARN="arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_NAME}:*"
LOGGING_CFG=$(cat <<EOF
{
  "level": "ALL",
  "includeExecutionData": true,
  "destinations": [{"cloudWatchLogsLogGroup":{"logGroupArn":"${LOG_GROUP_ARN}"}}]
}
EOF
)

LOG_JSON=$(aws stepfunctions create-state-machine \
    --name "$SM_LOG_NAME" \
    --definition file:///tmp/${PREFIX}-sfn-log-def.json \
    --role-arn "$ROLE_ARN" \
    --type STANDARD \
    --logging-configuration "$LOGGING_CFG" \
    --tracing-configuration '{"enabled":false}' \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ LOGGED state machine creation failed${NC}"
        echo "$LOG_JSON" | head -3
        LOG_JSON=""
    }
if [ -n "$LOG_JSON" ]; then
    LOG_ARN=$(echo "$LOG_JSON" | grep -o '"stateMachineArn": *"[^"]*"' | head -1 | sed 's/.*"stateMachineArn": *"\([^"]*\)".*/\1/')
    if [ -n "${LOG_ARN:-}" ]; then
        log "STATE_MACHINE:${LOG_ARN}"
        echo -e "${GREEN}✓ LOGGED SM: ${SM_LOG_NAME}${NC}"
        echo -e "  Fires: Phase 2 #27 (sfnLoggingWithoutEncryption)"
    fi
fi

################################################################################
# Step 7: HTTP-TASK STANDARD state machine (Phase 2 check 28)
################################################################################

echo -e "\n${GREEN}=== Step 7: HTTP-TASK SM (http:invoke over plain HTTP) ===${NC}"

if [ -z "${CONN_ARN:-}" ]; then
    echo -e "${YELLOW}⚠ Skipping HTTP SM — EventBridge connection was not created${NC}"
else
    cat > /tmp/${PREFIX}-sfn-http-def.json <<EOF
{
  "Comment": "SS simulation: http:invoke Task with dynamic ApiEndpoint.$ (INFO branch of check 28). Static http:// is rejected by SFN schema validation at create time.",
  "StartAt": "HttpCall",
  "States": {
    "HttpCall": {
      "Type": "Task",
      "Resource": "arn:aws:states:::http:invoke",
      "Parameters": {
        "ApiEndpoint.\$": "\$.endpoint",
        "Method": "GET",
        "Authentication": {
          "ConnectionArn": "${CONN_ARN}"
        }
      },
      "End": true
    }
  }
}
EOF

    HTTP_JSON=$(aws stepfunctions create-state-machine \
        --name "$SM_HTTP_NAME" \
        --definition file:///tmp/${PREFIX}-sfn-http-def.json \
        --role-arn "$ROLE_ARN" \
        --type STANDARD \
        --logging-configuration '{"level":"OFF","includeExecutionData":false,"destinations":[]}' \
        --tracing-configuration '{"enabled":false}' \
        --region "$REGION" \
        --output json 2>&1) || {
            echo -e "${RED}✗ HTTP-TASK state machine creation failed${NC}"
            echo "$HTTP_JSON" | head -3
            HTTP_JSON=""
        }
    if [ -n "$HTTP_JSON" ]; then
        HTTP_ARN=$(echo "$HTTP_JSON" | grep -o '"stateMachineArn": *"[^"]*"' | head -1 | sed 's/.*"stateMachineArn": *"\([^"]*\)".*/\1/')
        if [ -n "${HTTP_ARN:-}" ]; then
            log "STATE_MACHINE:${HTTP_ARN}"
            echo -e "${GREEN}✓ HTTP-TASK SM: ${SM_HTTP_NAME}${NC}"
            echo -e "  Fires: Phase 2 #28 (sfnHttpTaskNoTLS, INFO — dynamic endpoint; static http:// is rejected by SFN schema validation)"
        fi
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

rm -f /tmp/${PREFIX}-sfn-trust.json /tmp/${PREFIX}-sfn-wild.json \
      /tmp/${PREFIX}-sfn-std-def.json /tmp/${PREFIX}-sfn-exp-def.json \
      /tmp/${PREFIX}-sfn-log-def.json /tmp/${PREFIX}-sfn-http-def.json

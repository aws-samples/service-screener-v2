#!/bin/bash

################################################################################
# SNS Service Screener - Test Resource Creation Script
#
# Creates ONE intentionally-insecure SNS topic that triggers 9+ of the 12
# checks:
#   - No KmsMasterKeyId          (#1 snsEncryptionAtRest)
#   - Policy Principal:* no Cond (#3 snsPublicAccess)
#   - Policy without SecureTrans (#4 snsNoHttpsEnforcement)
#   - HTTP subscription          (#5 snsInsecureSubscription)
#   - SignatureVersion=1         (#6 snsSignatureVersionOld — default)
#   - SQS sub without RedrivePol (#7 snsSubscriptionNoDlq)
#   - No feedback role           (#9 snsDeliveryStatusLoggingDisabled)
#   - TracingConfig!=Active      (#10 snsTracingDisabled — default)
#   - No tags                    (#12 snsResourcesWithoutTags)
#
# NOT simulated:
#   #2  snsEncryptionNotCMK    — mutually exclusive with #1 (would need CMK)
#   #8  snsPendingSubscription — protocol=email creates a pending sub, but SNS
#                                 sends confirmation to a real inbox; skip.
#   #11 snsUnusedTopic          — we attach an HTTP subscription (unconfirmed
#                                 URL) which STILL keeps SubscriptionsConfirmed=0,
#                                 so this actually DOES fire (bonus).
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
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

TOPIC_NAME="${PREFIX}-sns-topic-${TIMESTAMP}"
QUEUE_NAME="${PREFIX}-sns-dlq-source-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== SNS Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Create SNS topic with default (insecure) config
################################################################################

echo -e "${GREEN}=== Step 1: Create SNS topic (no encryption, no tags, no tracing) ===${NC}"

TOPIC_JSON=$(aws sns create-topic \
    --name "$TOPIC_NAME" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Topic create failed${NC}"; echo "$TOPIC_JSON" | head -3; exit 1;
    }

TOPIC_ARN=$(echo "$TOPIC_JSON" | grep -o '"TopicArn": *"[^"]*"' | head -1 | sed 's/.*"TopicArn": *"\([^"]*\)".*/\1/')
log "TOPIC:${TOPIC_ARN}"
echo -e "${GREEN}✓ Topic: ${TOPIC_NAME}${NC}"

################################################################################
# Step 2: Set a public wildcard-principal policy (no Condition, no SecureTransport)
################################################################################

echo -e "\n${GREEN}=== Step 2: Set overly permissive access policy ===${NC}"

cat > /tmp/${PREFIX}-sns-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicPublishNoCondition",
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": ["SNS:Publish", "SNS:Subscribe"],
      "Resource": "${TOPIC_ARN}"
    }
  ]
}
EOF

aws sns set-topic-attributes \
    --topic-arn "$TOPIC_ARN" \
    --attribute-name Policy \
    --attribute-value "$(cat /tmp/${PREFIX}-sns-policy.json | tr -d '\n')" \
    --region "$REGION"
echo -e "${GREEN}✓ Public policy applied${NC}"

################################################################################
# Step 3: Force SignatureVersion=1 explicitly (the deprecated SHA-1 default)
################################################################################

aws sns set-topic-attributes \
    --topic-arn "$TOPIC_ARN" \
    --attribute-name SignatureVersion \
    --attribute-value 1 \
    --region "$REGION" > /dev/null 2>&1 \
    && echo -e "${GREEN}✓ SignatureVersion=1 forced${NC}" \
    || echo -e "${YELLOW}⚠ SignatureVersion=1 already default (that's the whole point)${NC}"

################################################################################
# Step 4: Add an HTTP subscription (protocol=http) — insecure
################################################################################

echo -e "\n${GREEN}=== Step 4: Add HTTP subscription ===${NC}"

# NOTE: SNS will attempt to confirm the subscription by POSTing to this URL.
# example.com will 200 the POST but doesn't call ConfirmSubscription, so it
# stays in PendingConfirmation. That's OK — the check inspects Protocol only.
SUB_HTTP=$(aws sns subscribe \
    --topic-arn "$TOPIC_ARN" \
    --protocol http \
    --notification-endpoint "http://example.com/ss-test-sns" \
    --region "$REGION" \
    --output json 2>&1) || echo -e "${YELLOW}⚠ HTTP subscription creation returned error (may still be logged as pending)${NC}"

HTTP_SUB_ARN=$(echo "$SUB_HTTP" | grep -o '"SubscriptionArn": *"[^"]*"' | head -1 | sed 's/.*"SubscriptionArn": *"\([^"]*\)".*/\1/')
if [ -n "${HTTP_SUB_ARN:-}" ] && [ "$HTTP_SUB_ARN" != "PendingConfirmation" ]; then
    log "SUBSCRIPTION:${HTTP_SUB_ARN}"
fi
echo -e "${GREEN}✓ HTTP subscription created (state: ${HTTP_SUB_ARN})${NC}"

################################################################################
# Step 5: Create SQS queue + subscribe it WITHOUT RedrivePolicy → triggers #7
################################################################################

echo -e "\n${GREEN}=== Step 5: Create SQS subscriber without DLQ ===${NC}"

QUEUE_URL=$(aws sqs create-queue \
    --queue-name "$QUEUE_NAME" \
    --region "$REGION" \
    --query 'QueueUrl' --output text 2>/dev/null || true)

if [ -n "$QUEUE_URL" ]; then
    QUEUE_ARN=$(aws sqs get-queue-attributes \
        --queue-url "$QUEUE_URL" \
        --attribute-names QueueArn \
        --query 'Attributes.QueueArn' --output text --region "$REGION")
    log "SQS_QUEUE:${QUEUE_URL}"
    echo -e "${GREEN}✓ SQS queue: ${QUEUE_NAME}${NC}"

    # Allow SNS to publish to the queue
    cat > /tmp/${PREFIX}-sqs-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "sns.amazonaws.com"},
    "Action": "sqs:SendMessage",
    "Resource": "${QUEUE_ARN}",
    "Condition": {"ArnEquals": {"aws:SourceArn": "${TOPIC_ARN}"}}
  }]
}
EOF
    aws sqs set-queue-attributes \
        --queue-url "$QUEUE_URL" \
        --attributes "{\"Policy\":\"$(cat /tmp/${PREFIX}-sqs-policy.json | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' | tr -d '"')\"}" \
        --region "$REGION" > /dev/null 2>&1 || true

    # Subscribe (no RedrivePolicy → triggers #7 snsSubscriptionNoDlq)
    SUB_SQS=$(aws sns subscribe \
        --topic-arn "$TOPIC_ARN" \
        --protocol sqs \
        --notification-endpoint "$QUEUE_ARN" \
        --region "$REGION" \
        --output json 2>&1)
    SQS_SUB_ARN=$(echo "$SUB_SQS" | grep -o '"SubscriptionArn": *"[^"]*"' | head -1 | sed 's/.*"SubscriptionArn": *"\([^"]*\)".*/\1/')
    if [ -n "${SQS_SUB_ARN:-}" ] && [ "$SQS_SUB_ARN" != "PendingConfirmation" ]; then
        log "SUBSCRIPTION:${SQS_SUB_ARN}"
    fi
    echo -e "${GREEN}✓ SQS subscription (no DLQ)${NC}"
else
    echo -e "${YELLOW}⚠ SQS queue creation failed — #7 will not fire${NC}"
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
echo "  1. cd ../../.. && python3 main.py --regions $REGION --services sns --beta 1 --sequential 1"
echo "  2. cd services/sns/simulation && ./cleanup_test_resources.sh"

rm -f /tmp/${PREFIX}-sns-policy.json /tmp/${PREFIX}-sqs-policy.json

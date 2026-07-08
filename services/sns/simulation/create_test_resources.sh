#!/bin/bash

################################################################################
# SNS Service Screener - Test Resource Creation Script
#
# Creates two intentionally-insecure SNS topics that exercise every `sns*`
# service-screener check that can be forced through the AWS API. Covers
# Phase 1 (checks 13-19) plus Phase 2 (checks 20-23).
#
#   Topic #1 (STANDARD, non-FIFO)  — Phase 1 baseline:
#     - no KmsMasterKeyId              → Phase 1 #13 snsEncryptionAtRest
#     - Policy Principal:* no Cond     → Phase 1 #15 snsPublicAccess
#     - Policy without SecureTransport → Phase 1 #16 snsNoHttpsEnforcement
#     - HTTP subscription              → Phase 1 #17 snsInsecureSubscription
#     - SignatureVersion=1             → Phase 1 #18 snsSignatureVersionOld
#     - SQS sub without RedrivePolicy  → Phase 1 #19 snsSubscriptionNoDlq
#     - No feedback role               → Phase 1 (delivery status logging)
#     - TracingConfig=default          → Phase 1 (tracing disabled)
#     - no tags                        → Phase 1 (untagged)
#     - Policy Version="2008-10-17"    → Phase 2 #22 snsPolicyVersionOutdated
#     - SMS subscription (placeholder) → Phase 2 #21 snsSmsNoSpendLimit
#                                        (fires only if account has no
#                                        MonthlySpendLimit set for SMS)
#
#   Topic #2 (FIFO, .fifo suffix)  — Phase 2 additions:
#     - ContentBasedDeduplication=false → Phase 2 #20
#     - no ArchivePolicy                → Phase 2 #23
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Placeholder E.164 phone number for the SMS subscription. This is a
# "555" (fictional-use) US number pattern; SNS accepts any well-formed
# E.164 value. No SMS is ever published to it by this script.
SMS_PLACEHOLDER="+15005550100"

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
FIFO_TOPIC_NAME="${PREFIX}-sns-fifo-${TIMESTAMP}.fifo"
QUEUE_NAME="${PREFIX}-sns-dlq-source-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== SNS Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Create standard (non-FIFO) SNS topic with default (insecure) config
################################################################################

echo -e "${GREEN}=== Step 1: Create standard SNS topic (no encryption, no tags, no tracing) ===${NC}"

TOPIC_JSON=$(aws sns create-topic \
    --name "$TOPIC_NAME" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Topic create failed${NC}"; echo "$TOPIC_JSON" | head -3; exit 1;
    }

TOPIC_ARN=$(echo "$TOPIC_JSON" | grep -o '"TopicArn": *"[^"]*"' | head -1 | sed 's/.*"TopicArn": *"\([^"]*\)".*/\1/')
log "TOPIC:${TOPIC_ARN}"
echo -e "${GREEN}✓ Standard topic: ${TOPIC_NAME}${NC}"

################################################################################
# Step 2: Set a public wildcard-principal policy using outdated Version=2008-10-17
################################################################################

echo -e "\n${GREEN}=== Step 2: Set overly permissive access policy (Version=2008-10-17) ===${NC}"

# The deprecated 2008-10-17 policy version fires Phase 2 #22 while the
# wildcard Principal + no SecureTransport fires Phase 1 #15/#16.
cat > /tmp/${PREFIX}-sns-policy.json <<EOF
{
  "Version": "2008-10-17",
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
echo -e "${GREEN}✓ Public policy applied (Version=2008-10-17 → fires Phase 2 #22)${NC}"

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

SUB_HTTP=$(aws sns subscribe \
    --topic-arn "$TOPIC_ARN" \
    --protocol http \
    --notification-endpoint "http://example.com/ss-test-sns" \
    --region "$REGION" \
    --output json 2>&1) || echo -e "${YELLOW}⚠ HTTP subscription creation returned error${NC}"

HTTP_SUB_ARN=$(echo "$SUB_HTTP" | grep -o '"SubscriptionArn": *"[^"]*"' | head -1 | sed 's/.*"SubscriptionArn": *"\([^"]*\)".*/\1/')
# Only log confirmed subscriptions — pending ones have no useful ARN and would
# create malformed manifest entries.
case "${HTTP_SUB_ARN:-}" in
    arn:aws:*) log "SUBSCRIPTION:${HTTP_SUB_ARN}" ;;
esac
echo -e "${GREEN}✓ HTTP subscription created (state: ${HTTP_SUB_ARN})${NC}"

################################################################################
# Step 5: Create SQS queue + subscribe it WITHOUT RedrivePolicy → Phase 1 #19
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

    # Subscribe (no RedrivePolicy → Phase 1 #19)
    SUB_SQS=$(aws sns subscribe \
        --topic-arn "$TOPIC_ARN" \
        --protocol sqs \
        --notification-endpoint "$QUEUE_ARN" \
        --region "$REGION" \
        --output json 2>&1)
    SQS_SUB_ARN=$(echo "$SUB_SQS" | grep -o '"SubscriptionArn": *"[^"]*"' | head -1 | sed 's/.*"SubscriptionArn": *"\([^"]*\)".*/\1/')
    case "${SQS_SUB_ARN:-}" in
        arn:aws:*) log "SUBSCRIPTION:${SQS_SUB_ARN}" ;;
    esac
    echo -e "${GREEN}✓ SQS subscription (no DLQ)${NC}"
else
    echo -e "${YELLOW}⚠ SQS queue creation failed — Phase 1 #19 will not fire${NC}"
fi

################################################################################
# Step 6: SMS subscription with placeholder E.164 number → Phase 2 #21
################################################################################

echo -e "\n${GREEN}=== Step 6: Add SMS subscription (Phase 2 #21 support) ===${NC}"

# The SMS subscription tests Phase 2 #21 snsSmsNoSpendLimit. The check
# fires only when (a) the topic has at least one SMS subscription and
# (b) the account-level MonthlySpendLimit is unset (or >= $1000). We
# never Publish, so no SMS is ever sent.
SUB_SMS=$(aws sns subscribe \
    --topic-arn "$TOPIC_ARN" \
    --protocol sms \
    --notification-endpoint "$SMS_PLACEHOLDER" \
    --region "$REGION" \
    --output json 2>&1) || echo -e "${YELLOW}⚠ SMS subscribe returned error (may be region without SMS)${NC}"

SMS_SUB_ARN=$(echo "$SUB_SMS" | grep -o '"SubscriptionArn": *"[^"]*"' | head -1 | sed 's/.*"SubscriptionArn": *"\([^"]*\)".*/\1/')
case "${SMS_SUB_ARN:-}" in
    arn:aws:*) log "SUBSCRIPTION:${SMS_SUB_ARN}" ;;
esac
echo -e "${GREEN}✓ SMS subscription created (state: ${SMS_SUB_ARN:-none}, endpoint: ${SMS_PLACEHOLDER})${NC}"

################################################################################
# Step 7: FIFO topic (no ContentBasedDeduplication, no ArchivePolicy)
################################################################################

echo -e "\n${GREEN}=== Step 7: Create FIFO topic (Phase 2 #20 + #23) ===${NC}"

# Attributes: FifoTopic=true, ContentBasedDeduplication=false (default),
# no ArchivePolicy.
FIFO_JSON=$(aws sns create-topic \
    --name "$FIFO_TOPIC_NAME" \
    --attributes '{"FifoTopic":"true","ContentBasedDeduplication":"false"}' \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${YELLOW}⚠ FIFO topic create failed${NC}"; echo "$FIFO_JSON" | head -3;
        FIFO_JSON=""
    }

if [ -n "$FIFO_JSON" ]; then
    FIFO_ARN=$(echo "$FIFO_JSON" | grep -o '"TopicArn": *"[^"]*"' | head -1 | sed 's/.*"TopicArn": *"\([^"]*\)".*/\1/')
    if [ -n "${FIFO_ARN:-}" ]; then
        log "TOPIC:${FIFO_ARN}"
        echo -e "${GREEN}✓ FIFO topic: ${FIFO_TOPIC_NAME}${NC}"
        echo -e "  Fires: Phase 2 #20 (ContentBasedDeduplication=false), #23 (no ArchivePolicy)"
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
echo "  1. cd ../../.. && python3 main.py --regions $REGION --services sns --beta 1 --sequential 1"
echo "  2. cd services/sns/simulation && ./cleanup_test_resources.sh"

rm -f /tmp/${PREFIX}-sns-policy.json /tmp/${PREFIX}-sqs-policy.json

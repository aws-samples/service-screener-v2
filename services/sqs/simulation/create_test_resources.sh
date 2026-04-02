#!/bin/bash

# SQS Test Resources Creation Script
# Creates test SQS queues to validate the 3 new checks:
# 1. LongPollingConfiguration
# 2. WildcardPrincipalDetection
# 3. MaxReceiveCountDetection

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test-sqs"
TIMESTAMP=$(date +%s)

echo -e "${GREEN}Creating SQS test resources in region: ${REGION}${NC}"
echo "Prefix: ${PREFIX}"
echo "Timestamp: ${TIMESTAMP}"
echo ""

# Get AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Account ID: ${ACCOUNT_ID}"
echo ""

# Function to create queue and return URL
create_queue() {
    local queue_name=$1
    local attributes=$2
    
    echo -e "${YELLOW}Creating queue: ${queue_name}${NC}" >&2
    
    if [ -n "$attributes" ]; then
        QUEUE_URL=$(aws sqs create-queue \
            --queue-name "${queue_name}" \
            --attributes "$attributes" \
            --region "${REGION}" \
            --query 'QueueUrl' \
            --output text)
    else
        QUEUE_URL=$(aws sqs create-queue \
            --queue-name "${queue_name}" \
            --region "${REGION}" \
            --query 'QueueUrl' \
            --output text)
    fi
    
    echo "Created: ${QUEUE_URL}" >&2
    echo "$QUEUE_URL"
}

# Function to set queue policy
set_queue_policy() {
    local queue_url=$1
    local policy=$2
    
    echo -e "${YELLOW}Setting policy for queue${NC}"
    local escaped_policy=$(echo "$policy" | sed 's/"/\\"/g')
    aws sqs set-queue-attributes \
        --queue-url "${queue_url}" \
        --attributes "{\"Policy\":\"${escaped_policy}\"}" \
        --region "${REGION}"
    echo "Policy set successfully"
}

echo "=== Creating Dead Letter Queues ==="
echo ""

# Create DLQ for maxReceiveCount tests
DLQ_URL=$(create_queue "${PREFIX}-dlq-${TIMESTAMP}" "")
echo ""

echo "=== Test 1: LongPollingConfiguration ==="
echo ""

# 1.1 Short polling (FAIL - ReceiveMessageWaitTimeSeconds = 0)
create_queue "${PREFIX}-short-polling-${TIMESTAMP}" '{"ReceiveMessageWaitTimeSeconds":"0"}'
echo ""

# 1.2 Suboptimal polling (WARNING - ReceiveMessageWaitTimeSeconds = 3)
create_queue "${PREFIX}-suboptimal-polling-${TIMESTAMP}" '{"ReceiveMessageWaitTimeSeconds":"3"}'
echo ""

# 1.3 Long polling (PASS - ReceiveMessageWaitTimeSeconds = 10)
create_queue "${PREFIX}-long-polling-${TIMESTAMP}" '{"ReceiveMessageWaitTimeSeconds":"10"}'
echo ""

echo "=== Test 2: WildcardPrincipalDetection ==="
echo ""

# 2.1 No policy (PASS)
QUEUE_NO_POLICY=$(create_queue "${PREFIX}-no-policy-${TIMESTAMP}" "")
echo ""

# 2.2 Wildcard principal (FAIL)
QUEUE_WILDCARD=$(create_queue "${PREFIX}-wildcard-principal-${TIMESTAMP}" "")
WILDCARD_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "sqs:SendMessage",
    "Resource": "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:${PREFIX}-wildcard-principal-${TIMESTAMP}"
  }]
}
EOF
)
set_queue_policy "${QUEUE_WILDCARD}" "$(echo $WILDCARD_POLICY | jq -c .)"
echo ""

# 2.3 Wildcard with conditions (WARNING)
QUEUE_WILDCARD_COND=$(create_queue "${PREFIX}-wildcard-with-conditions-${TIMESTAMP}" "")
WILDCARD_COND_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "sqs:SendMessage",
    "Resource": "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:${PREFIX}-wildcard-with-conditions-${TIMESTAMP}",
    "Condition": {
      "StringEquals": {
        "aws:SourceAccount": "${ACCOUNT_ID}"
      }
    }
  }]
}
EOF
)
set_queue_policy "${QUEUE_WILDCARD_COND}" "$(echo $WILDCARD_COND_POLICY | jq -c .)"
echo ""

# 2.4 Specific principal (PASS)
QUEUE_SPECIFIC=$(create_queue "${PREFIX}-specific-principal-${TIMESTAMP}" "")
SPECIFIC_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
    },
    "Action": "sqs:SendMessage",
    "Resource": "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:${PREFIX}-specific-principal-${TIMESTAMP}"
  }]
}
EOF
)
set_queue_policy "${QUEUE_SPECIFIC}" "$(echo $SPECIFIC_POLICY | jq -c .)"
echo ""

echo "=== Test 3: MaxReceiveCountDetection ==="
echo ""

# Get DLQ ARN
DLQ_ARN=$(aws sqs get-queue-attributes \
    --queue-url "${DLQ_URL}" \
    --attribute-names QueueArn \
    --region "${REGION}" \
    --query 'Attributes.QueueArn' \
    --output text)

# 3.1 maxReceiveCount = 1 (FAIL - anti-pattern)
REDRIVE_POLICY_1="{\\\"deadLetterTargetArn\\\":\\\"${DLQ_ARN}\\\",\\\"maxReceiveCount\\\":1}"
create_queue "${PREFIX}-max-receive-1-${TIMESTAMP}" "{\"RedrivePolicy\":\"${REDRIVE_POLICY_1}\"}"
echo ""

# 3.2 maxReceiveCount = 2 (WARNING)
REDRIVE_POLICY_2="{\\\"deadLetterTargetArn\\\":\\\"${DLQ_ARN}\\\",\\\"maxReceiveCount\\\":2}"
create_queue "${PREFIX}-max-receive-2-${TIMESTAMP}" "{\"RedrivePolicy\":\"${REDRIVE_POLICY_2}\"}"
echo ""

# 3.3 maxReceiveCount = 3 (PASS)
REDRIVE_POLICY_3="{\\\"deadLetterTargetArn\\\":\\\"${DLQ_ARN}\\\",\\\"maxReceiveCount\\\":3}"
create_queue "${PREFIX}-max-receive-3-${TIMESTAMP}" "{\"RedrivePolicy\":\"${REDRIVE_POLICY_3}\"}"
echo ""

# 3.4 maxReceiveCount = 5 (PASS)
REDRIVE_POLICY_5="{\\\"deadLetterTargetArn\\\":\\\"${DLQ_ARN}\\\",\\\"maxReceiveCount\\\":5}"
create_queue "${PREFIX}-max-receive-5-${TIMESTAMP}" "{\"RedrivePolicy\":\"${REDRIVE_POLICY_5}\"}"
echo ""

echo -e "${GREEN}=== Test Resources Created Successfully ===${NC}"
echo ""
echo "Summary:"
echo "- 1 Dead Letter Queue"
echo "- 3 Long Polling test queues"
echo "- 4 Wildcard Principal test queues"
echo "- 4 MaxReceiveCount test queues"
echo ""
echo "Total: 12 queues created"
echo ""
echo -e "${YELLOW}To clean up these resources, run: ./cleanup_test_resources.sh${NC}"
echo ""
echo "Queue prefix: ${PREFIX}"
echo "Timestamp: ${TIMESTAMP}"
echo ""
echo "Save this timestamp for cleanup: ${TIMESTAMP}"
echo "${TIMESTAMP}" > .last_test_timestamp

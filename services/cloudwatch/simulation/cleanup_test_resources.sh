#!/bin/bash

# CloudWatch Service Screener Simulation - Cleanup Test Resources
# This script deletes all test resources created by create_test_resources.sh
# Safe to run multiple times (idempotent)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGION="${AWS_REGION:-us-east-1}"
SNS_TOPIC_NAME="service-screener-test-topic"
ALARM_WITH_SNS="test-alarm-with-sns"
ALARM_WITHOUT_SNS="test-alarm-without-sns"
BILLING_ALARM="test-billing-alarm"

echo -e "${GREEN}=== CloudWatch Service Screener Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo ""

# Check AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed${NC}"
    exit 1
fi

# Check AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials are not configured${NC}"
    exit 1
fi

# Function to delete alarm if it exists
delete_alarm() {
    local alarm_name=$1
    local region=$2
    
    if aws cloudwatch describe-alarms --alarm-names "$alarm_name" --region "$region" --output text 2>/dev/null | grep -q "$alarm_name"; then
        aws cloudwatch delete-alarms --alarm-names "$alarm_name" --region "$region" 2>/dev/null
        echo -e "${GREEN}✓ Deleted alarm: $alarm_name${NC}"
    else
        echo -e "${YELLOW}  Alarm not found (already deleted): $alarm_name${NC}"
    fi
}

echo -e "${YELLOW}Step 1: Deleting CloudWatch Alarms${NC}"
delete_alarm "$ALARM_WITH_SNS" "$REGION"
delete_alarm "$ALARM_WITHOUT_SNS" "$REGION"

if [ "$REGION" = "us-east-1" ]; then
    delete_alarm "$BILLING_ALARM" "us-east-1"
fi

echo ""
echo -e "${YELLOW}Step 2: Deleting SNS Topic${NC}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
SNS_TOPIC_ARN="arn:aws:sns:${REGION}:${ACCOUNT_ID}:${SNS_TOPIC_NAME}"

if aws sns get-topic-attributes --topic-arn "$SNS_TOPIC_ARN" --region "$REGION" &> /dev/null; then
    aws sns delete-topic --topic-arn "$SNS_TOPIC_ARN" --region "$REGION" 2>/dev/null
    echo -e "${GREEN}✓ Deleted SNS topic: $SNS_TOPIC_ARN${NC}"
else
    echo -e "${YELLOW}  SNS topic not found (already deleted): $SNS_TOPIC_NAME${NC}"
fi

echo ""
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "Deleted resources:"
echo "  - Alarm: $ALARM_WITH_SNS"
echo "  - Alarm: $ALARM_WITHOUT_SNS"
if [ "$REGION" = "us-east-1" ]; then
    echo "  - Alarm: $BILLING_ALARM"
fi
echo "  - SNS Topic: $SNS_TOPIC_NAME"
echo ""

# ============================================================================
# Tier 2 and Tier 3 Checks - Cleanup
# ============================================================================

echo ""
echo -e "${YELLOW}Step 3: Deleting Tier 2 & Tier 3 Test Resources${NC}"

# Delete Tier 2 & 3 alarms
TIER23_ALARMS=(
  "test-tier2-no-service-quota-alarm"
  "test-tier2-untagged-alarm"
  "test-tier3-ec2-no-autoscaling"
  "test-tier3-no-metric-math"
)

for ALARM in "${TIER23_ALARMS[@]}"; do
  delete_alarm "$ALARM" "$REGION"
done

# Delete Tier 2 log groups
echo ""
echo -e "${YELLOW}Deleting Tier 2 log groups...${NC}"
TIER2_LOG_GROUPS=(
  "/test/tier2/untagged-log-group"
  "/test/tier2/no-insights-usage"
)

for LOG_GROUP in "${TIER2_LOG_GROUPS[@]}"; do
  if aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" --region "$REGION" --output text 2>/dev/null | grep -q "$LOG_GROUP"; then
    aws logs delete-log-group --region "$REGION" --log-group-name "$LOG_GROUP" 2>/dev/null
    echo -e "${GREEN}✓ Deleted log group: $LOG_GROUP${NC}"
  else
    echo -e "${YELLOW}  Log group not found (already deleted): $LOG_GROUP${NC}"
  fi
done

# Delete Tier 2 dashboard
echo ""
echo -e "${YELLOW}Deleting Tier 2 dashboard...${NC}"
if aws cloudwatch list-dashboards --region "$REGION" --output text 2>/dev/null | grep -q "test-tier2-single-account-dashboard"; then
  aws cloudwatch delete-dashboards --region "$REGION" --dashboard-names "test-tier2-single-account-dashboard" 2>/dev/null
  echo -e "${GREEN}✓ Deleted dashboard: test-tier2-single-account-dashboard${NC}"
else
  echo -e "${YELLOW}  Dashboard not found (already deleted): test-tier2-single-account-dashboard${NC}"
fi

echo ""
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "Deleted resources:"
echo "  Tier 1 (Original):"
echo "    - Alarm: $ALARM_WITH_SNS"
echo "    - Alarm: $ALARM_WITHOUT_SNS"
if [ "$REGION" = "us-east-1" ]; then
    echo "    - Alarm: $BILLING_ALARM"
fi
echo "    - SNS Topic: $SNS_TOPIC_NAME"
echo ""
echo "  Tier 2 & 3 (New):"
echo "    - 4 CloudWatch alarms"
echo "    - 2 Log groups"
echo "    - 1 Dashboard"
echo ""

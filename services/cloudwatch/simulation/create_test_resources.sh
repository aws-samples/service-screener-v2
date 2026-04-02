#!/bin/bash

# CloudWatch Service Screener Simulation - Create Test Resources
# This script creates test AWS resources to validate CloudWatch checks:
# - alarmsWithoutSNS: CloudWatch alarms with and without SNS notifications
# - missingBillingAlarms: Billing alarms in us-east-1

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

echo -e "${GREEN}=== CloudWatch Service Screener Test Resource Creation ===${NC}"
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

echo -e "${YELLOW}Step 1: Creating SNS Topic${NC}"
SNS_TOPIC_ARN=$(aws sns create-topic \
    --name "$SNS_TOPIC_NAME" \
    --region "$REGION" \
    --output text \
    --query 'TopicArn' 2>/dev/null || true)

if [ -z "$SNS_TOPIC_ARN" ]; then
    # Topic might already exist, try to get ARN
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    SNS_TOPIC_ARN="arn:aws:sns:${REGION}:${ACCOUNT_ID}:${SNS_TOPIC_NAME}"
    echo -e "${YELLOW}SNS topic already exists: $SNS_TOPIC_ARN${NC}"
else
    echo -e "${GREEN}✓ Created SNS topic: $SNS_TOPIC_ARN${NC}"
fi

echo ""
echo -e "${YELLOW}Step 2: Creating CloudWatch Alarm WITH SNS Notification${NC}"
aws cloudwatch put-metric-alarm \
    --alarm-name "$ALARM_WITH_SNS" \
    --alarm-description "Test alarm with SNS notification for Service Screener validation" \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --statistic Average \
    --period 300 \
    --evaluation-periods 1 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --alarm-actions "$SNS_TOPIC_ARN" \
    --region "$REGION" \
    > /dev/null

echo -e "${GREEN}✓ Created alarm with SNS: $ALARM_WITH_SNS${NC}"

echo ""
echo -e "${YELLOW}Step 3: Creating CloudWatch Alarm WITHOUT SNS Notification${NC}"
aws cloudwatch put-metric-alarm \
    --alarm-name "$ALARM_WITHOUT_SNS" \
    --alarm-description "Test alarm without SNS notification for Service Screener validation" \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --statistic Average \
    --period 300 \
    --evaluation-periods 1 \
    --threshold 90 \
    --comparison-operator GreaterThanThreshold \
    --region "$REGION" \
    > /dev/null

echo -e "${GREEN}✓ Created alarm without SNS: $ALARM_WITHOUT_SNS${NC}"

echo ""
if [ "$REGION" = "us-east-1" ]; then
    echo -e "${YELLOW}Step 4: Creating Billing Alarm (us-east-1 only)${NC}"
    aws cloudwatch put-metric-alarm \
        --alarm-name "$BILLING_ALARM" \
        --alarm-description "Test billing alarm for Service Screener validation" \
        --metric-name EstimatedCharges \
        --namespace AWS/Billing \
        --statistic Maximum \
        --period 21600 \
        --evaluation-periods 1 \
        --threshold 100 \
        --comparison-operator GreaterThanThreshold \
        --alarm-actions "$SNS_TOPIC_ARN" \
        --dimensions Name=Currency,Value=USD \
        --region us-east-1 \
        > /dev/null
    
    echo -e "${GREEN}✓ Created billing alarm: $BILLING_ALARM${NC}"
else
    echo -e "${YELLOW}Step 4: Skipping billing alarm (only available in us-east-1)${NC}"
fi

echo ""
echo -e "${GREEN}=== Test Resources Created Successfully ===${NC}"
echo ""
echo "Created resources:"
echo "  - SNS Topic: $SNS_TOPIC_ARN"
echo "  - Alarm with SNS: $ALARM_WITH_SNS"
echo "  - Alarm without SNS: $ALARM_WITHOUT_SNS"
if [ "$REGION" = "us-east-1" ]; then
    echo "  - Billing alarm: $BILLING_ALARM"
fi
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Run Service Screener: python screener.py --regions $REGION --services cloudwatch"
echo "  2. Verify results:"
echo "     - alarmsWithoutSNS check should flag: $ALARM_WITHOUT_SNS"
echo "     - alarmsWithoutSNS check should pass: $ALARM_WITH_SNS"
if [ "$REGION" = "us-east-1" ]; then
    echo "     - missingBillingAlarms check should pass (billing alarm exists)"
else
    echo "     - missingBillingAlarms check is skipped (not in us-east-1)"
fi
echo "  3. Clean up: ./cleanup_test_resources.sh"
echo ""

# ============================================================================
# Tier 2 and Tier 3 Checks - Test Resources
# ============================================================================

echo ""
echo -e "${GREEN}=== Creating Tier 2 & Tier 3 Test Resources ===${NC}"

# Tier 2: missingServiceQuotaAlarms - Create alarm WITHOUT service quota monitoring
echo -e "${YELLOW}Creating alarm without service quota monitoring...${NC}"
aws cloudwatch put-metric-alarm \
  --region $REGION \
  --alarm-name "test-tier2-no-service-quota-alarm" \
  --alarm-description "Test alarm monitoring AWS/Usage but not a critical service quota" \
  --metric-name ResourceCount \
  --namespace AWS/Usage \
  --dimensions Name=Service,Value=CloudFormation Name=Type,Value=Resource Name=Resource,Value=AWS::CloudFormation::Stack \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  > /dev/null

echo -e "${GREEN}✓ Created alarm without service quota monitoring${NC}"

# Tier 2: cloudwatchResourcesWithoutTags - Create log group without required tags
echo -e "${YELLOW}Creating log group without required tags...${NC}"
aws logs create-log-group \
  --region $REGION \
  --log-group-name "/test/tier2/untagged-log-group" 2>/dev/null || echo -e "${YELLOW}  Log group already exists${NC}"

echo -e "${GREEN}✓ Created untagged log group${NC}"

# Tier 2: cloudwatchResourcesWithoutTags - Create alarm without required tags
echo -e "${YELLOW}Creating alarm without required tags...${NC}"
aws cloudwatch put-metric-alarm \
  --region $REGION \
  --alarm-name "test-tier2-untagged-alarm" \
  --alarm-description "Test alarm without required tags" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  > /dev/null

echo -e "${GREEN}✓ Created untagged alarm${NC}"

# Tier 2: logGroupsWithoutLogInsightsUsage - Log group exists but no queries run
echo -e "${YELLOW}Creating log group without Log Insights usage...${NC}"
aws logs create-log-group \
  --region $REGION \
  --log-group-name "/test/tier2/no-insights-usage" 2>/dev/null || echo -e "${YELLOW}  Log group already exists${NC}"

echo -e "${GREEN}✓ Created log group without insights usage${NC}"

# Tier 2: missingCrossAccountDashboards - Create dashboard without cross-account metrics
echo -e "${YELLOW}Creating dashboard without cross-account metrics...${NC}"
DASHBOARD_BODY='{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/EC2", "CPUUtilization"]
        ],
        "period": 300,
        "stat": "Average",
        "region": "'$REGION'",
        "title": "EC2 CPU"
      }
    }
  ]
}'

aws cloudwatch put-dashboard \
  --region $REGION \
  --dashboard-name "test-tier2-single-account-dashboard" \
  --dashboard-body "$DASHBOARD_BODY" \
  > /dev/null

echo -e "${GREEN}✓ Created single-account dashboard${NC}"

# Tier 3: alarmsWithoutAutoScalingActions - Create EC2 alarm without Auto Scaling action
echo -e "${YELLOW}Creating EC2 alarm without Auto Scaling actions...${NC}"
aws cloudwatch put-metric-alarm \
  --region $REGION \
  --alarm-name "test-tier3-ec2-no-autoscaling" \
  --alarm-description "Test EC2 alarm without Auto Scaling actions" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  > /dev/null

echo -e "${GREEN}✓ Created alarm without Auto Scaling actions${NC}"

# Tier 3: alarmsWithoutMetricMath - Create alarm without metric math
echo -e "${YELLOW}Creating alarm without metric math...${NC}"
aws cloudwatch put-metric-alarm \
  --region $REGION \
  --alarm-name "test-tier3-no-metric-math" \
  --alarm-description "Test alarm without metric math expressions" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  > /dev/null

echo -e "${GREEN}✓ Created alarm without metric math${NC}"

echo ""
echo -e "${GREEN}=== All Test Resources Created Successfully ===${NC}"
echo ""
echo "Created resources:"
echo "  Tier 1 (Original):"
echo "    - SNS Topic: $SNS_TOPIC_ARN"
echo "    - Alarm with SNS: $ALARM_WITH_SNS"
echo "    - Alarm without SNS: $ALARM_WITHOUT_SNS"
if [ "$REGION" = "us-east-1" ]; then
    echo "    - Billing alarm: $BILLING_ALARM"
fi
echo ""
echo "  Tier 2 & 3 (New):"
echo "    - 4 CloudWatch alarms (service quota, untagged, autoscaling, metric math)"
echo "    - 2 Log groups (untagged, no insights usage)"
echo "    - 1 Dashboard (single-account, non-vended)"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Run Service Screener: python screener.py --regions $REGION --services cloudwatch"
echo "  2. Verify Tier 1 results:"
echo "     - alarmsWithoutSNS check should flag: $ALARM_WITHOUT_SNS"
echo "     - alarmsWithoutSNS check should pass: $ALARM_WITH_SNS"
if [ "$REGION" = "us-east-1" ]; then
    echo "     - missingBillingAlarms check should pass (billing alarm exists)"
fi
echo "  3. Verify Tier 2 & 3 results:"
echo "     - missingServiceQuotaAlarms: test-tier2-no-service-quota-alarm"
echo "     - cloudwatchResourcesWithoutTags: test-tier2-untagged-alarm, /test/tier2/untagged-log-group"
echo "     - logGroupsWithoutLogInsightsUsage: /test/tier2/no-insights-usage"
echo "     - missingCrossAccountDashboards: test-tier2-single-account-dashboard"
echo "     - alarmsWithoutAutoScalingActions: test-tier3-ec2-no-autoscaling"
echo "     - alarmsWithoutMetricMath: test-tier3-no-metric-math"
echo "     - missingVendedDashboards: test-tier2-single-account-dashboard"
echo "  4. Clean up: ./cleanup_test_resources.sh"
echo ""

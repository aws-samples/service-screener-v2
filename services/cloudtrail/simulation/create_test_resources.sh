#!/bin/bash

# CloudTrail Test Resources Creation Script
# Creates test resources to validate the 6 new Tier 1 checks:
# 1. GuardDutyIntegration
# 2. SecurityHubIntegration
# 3. IAMFullAccessRestriction
# 4. KMSPolicySourceArn
# 5. OrganizationTrailEnabled
# 6. CloudWatchAlarmsConfigured

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test-cloudtrail"
TIMESTAMP=$(date +%s)

echo -e "${GREEN}Creating CloudTrail test resources in region: ${REGION}${NC}"
echo "Prefix: ${PREFIX}"
echo "Timestamp: ${TIMESTAMP}"
echo ""

# Get AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Account ID: ${ACCOUNT_ID}"
echo ""

echo "=== IMPORTANT NOTES ===${NC}"
echo ""
echo -e "${YELLOW}This script creates test resources for CloudTrail checks validation.${NC}"
echo -e "${YELLOW}Some checks (GuardDuty, Security Hub, Organizations) require manual setup.${NC}"
echo ""
echo "What this script creates:"
echo "  ✓ Test CloudTrail trail with S3 bucket"
echo "  ✓ KMS key with policy (with/without SourceArn)"
echo "  ✓ IAM test user with CloudTrail full access"
echo "  ✓ CloudWatch Logs integration"
echo "  ✓ Metric filters and alarms"
echo ""
echo "What requires manual setup:"
echo "  ⚠ GuardDuty detector (enable via Console or CLI)"
echo "  ⚠ Security Hub (enable via Console or CLI)"
echo "  ⚠ AWS Organizations (if testing organization trails)"
echo ""
echo -e "${YELLOW}Press Enter to continue or Ctrl+C to cancel...${NC}"
read

# Function to create S3 bucket
create_s3_bucket() {
    local bucket_name=$1
    
    echo -e "${YELLOW}Creating S3 bucket: ${bucket_name}${NC}"
    
    if [ "${REGION}" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "${bucket_name}" \
            --region "${REGION}" 2>/dev/null || echo "Bucket may already exist"
    else
        aws s3api create-bucket \
            --bucket "${bucket_name}" \
            --region "${REGION}" \
            --create-bucket-configuration LocationConstraint="${REGION}" 2>/dev/null || echo "Bucket may already exist"
    fi
    
    # Set bucket policy for CloudTrail
    local bucket_policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${bucket_name}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${bucket_name}/AWSLogs/${ACCOUNT_ID}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
EOF
)
    
    aws s3api put-bucket-policy \
        --bucket "${bucket_name}" \
        --policy "${bucket_policy}"
    
    echo "Created: ${bucket_name}"
}

# Function to create KMS key
create_kms_key() {
    local description=$1
    local with_source_arn=$2
    
    echo -e "${YELLOW}Creating KMS key: ${description}${NC}" >&2
    
    local key_policy
    if [ "${with_source_arn}" = "true" ]; then
        key_policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudTrail to encrypt logs",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": [
        "kms:GenerateDataKey*",
        "kms:Decrypt"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:SourceArn": "arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/${PREFIX}-with-source-arn-${TIMESTAMP}"
        }
      }
    },
    {
      "Sid": "Allow CloudTrail to describe key",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:DescribeKey",
      "Resource": "*"
    }
  ]
}
EOF
)
    else
        key_policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudTrail to encrypt logs",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": [
        "kms:GenerateDataKey*",
        "kms:Decrypt"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudTrail to describe key",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:DescribeKey",
      "Resource": "*"
    }
  ]
}
EOF
)
    fi
    
    KEY_ID=$(aws kms create-key \
        --description "${description}" \
        --policy "${key_policy}" \
        --region "${REGION}" \
        --query 'KeyMetadata.KeyId' \
        --output text)
    
    aws kms create-alias \
        --alias-name "alias/${PREFIX}-${TIMESTAMP}-$(echo ${description} | tr ' ' '-' | tr '[:upper:]' '[:lower:]')" \
        --target-key-id "${KEY_ID}" \
        --region "${REGION}"
    
    echo "Created KMS key: ${KEY_ID}" >&2
    echo "${KEY_ID}"
}

echo "=== Test 1: S3 Bucket for CloudTrail ===${NC}"
echo ""

BUCKET_NAME="${PREFIX}-logs-${TIMESTAMP}"
create_s3_bucket "${BUCKET_NAME}"
echo ""

echo "=== Test 2: KMS Keys ===${NC}"
echo ""

# KMS key without SourceArn (FAIL)
KMS_KEY_NO_SOURCE=$(create_kms_key "CloudTrail No SourceArn" "false")
echo ""

# KMS key with SourceArn (PASS)
KMS_KEY_WITH_SOURCE=$(create_kms_key "CloudTrail With SourceArn" "true")
echo ""

echo "=== Test 3: CloudWatch Logs ===${NC}"
echo ""

# Create CloudWatch Logs log group
LOG_GROUP_NAME="/aws/cloudtrail/${PREFIX}-${TIMESTAMP}"
echo -e "${YELLOW}Creating CloudWatch Logs log group: ${LOG_GROUP_NAME}${NC}"
aws logs create-log-group \
    --log-group-name "${LOG_GROUP_NAME}" \
    --region "${REGION}" 2>/dev/null || echo "Log group may already exist"
echo "Created: ${LOG_GROUP_NAME}"
echo ""

# Create IAM role for CloudTrail to CloudWatch Logs
ROLE_NAME="${PREFIX}-cloudwatch-role-${TIMESTAMP}"
echo -e "${YELLOW}Creating IAM role: ${ROLE_NAME}${NC}"

TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
)

aws iam create-role \
    --role-name "${ROLE_NAME}" \
    --assume-role-policy-document "${TRUST_POLICY}" \
    --description "CloudTrail CloudWatch Logs role for testing" 2>/dev/null || echo "Role may already exist"

ROLE_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_NAME}:*"
    }
  ]
}
EOF
)

aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "CloudTrailCloudWatchLogsPolicy" \
    --policy-document "${ROLE_POLICY}"

echo "Created role: ${ROLE_NAME}"
echo ""

# Wait for role to be available
echo "Waiting 10 seconds for IAM role to propagate..."
sleep 10
echo ""

echo "=== Test 4: CloudTrail Trails ===${NC}"
echo ""

# Trail without KMS (basic)
TRAIL_NO_KMS="${PREFIX}-no-kms-${TIMESTAMP}"
echo -e "${YELLOW}Creating trail without KMS: ${TRAIL_NO_KMS}${NC}"
aws cloudtrail create-trail \
    --name "${TRAIL_NO_KMS}" \
    --s3-bucket-name "${BUCKET_NAME}" \
    --is-multi-region-trail \
    --region "${REGION}"
aws cloudtrail start-logging --name "${TRAIL_NO_KMS}" --region "${REGION}"
echo "Created: ${TRAIL_NO_KMS}"
echo ""

# Trail with KMS but no SourceArn (FAIL)
TRAIL_NO_SOURCE="${PREFIX}-no-source-arn-${TIMESTAMP}"
echo -e "${YELLOW}Creating trail with KMS but no SourceArn: ${TRAIL_NO_SOURCE}${NC}"
aws cloudtrail create-trail \
    --name "${TRAIL_NO_SOURCE}" \
    --s3-bucket-name "${BUCKET_NAME}" \
    --kms-key-id "${KMS_KEY_NO_SOURCE}" \
    --is-multi-region-trail \
    --region "${REGION}"
aws cloudtrail start-logging --name "${TRAIL_NO_SOURCE}" --region "${REGION}"
echo "Created: ${TRAIL_NO_SOURCE}"
echo ""

# Trail with KMS and SourceArn (PASS)
TRAIL_WITH_SOURCE="${PREFIX}-with-source-arn-${TIMESTAMP}"
echo -e "${YELLOW}Creating trail with KMS and SourceArn: ${TRAIL_WITH_SOURCE}${NC}"
aws cloudtrail create-trail \
    --name "${TRAIL_WITH_SOURCE}" \
    --s3-bucket-name "${BUCKET_NAME}" \
    --kms-key-id "${KMS_KEY_WITH_SOURCE}" \
    --is-multi-region-trail \
    --cloud-watch-logs-log-group-arn "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP_NAME}:*" \
    --cloud-watch-logs-role-arn "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}" \
    --region "${REGION}"
aws cloudtrail start-logging --name "${TRAIL_WITH_SOURCE}" --region "${REGION}"
echo "Created: ${TRAIL_WITH_SOURCE}"
echo ""

echo "=== Test 5: CloudWatch Metric Filters and Alarms ===${NC}"
echo ""

# Create metric filter for unauthorized API calls
FILTER_NAME="${PREFIX}-unauthorized-api-calls-${TIMESTAMP}"
echo -e "${YELLOW}Creating metric filter: ${FILTER_NAME}${NC}"
aws logs put-metric-filter \
    --log-group-name "${LOG_GROUP_NAME}" \
    --filter-name "${FILTER_NAME}" \
    --filter-pattern '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }' \
    --metric-transformations \
        metricName=UnauthorizedAPICalls,metricNamespace=CloudTrailMetrics,metricValue=1 \
    --region "${REGION}"
echo "Created: ${FILTER_NAME}"
echo ""

# Create CloudWatch alarm
ALARM_NAME="${PREFIX}-unauthorized-api-alarm-${TIMESTAMP}"
echo -e "${YELLOW}Creating CloudWatch alarm: ${ALARM_NAME}${NC}"
aws cloudwatch put-metric-alarm \
    --alarm-name "${ALARM_NAME}" \
    --alarm-description "Alarm for unauthorized API calls" \
    --metric-name UnauthorizedAPICalls \
    --namespace CloudTrailMetrics \
    --statistic Sum \
    --period 300 \
    --evaluation-periods 1 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --region "${REGION}"
echo "Created: ${ALARM_NAME}"
echo ""

echo "=== Test 6: IAM Test User ===${NC}"
echo ""

# Create IAM test user with CloudTrail full access
TEST_USER="${PREFIX}-test-user-${TIMESTAMP}"
echo -e "${YELLOW}Creating IAM test user: ${TEST_USER}${NC}"
aws iam create-user \
    --user-name "${TEST_USER}" \
    --tags Key=Purpose,Value=ServiceScreenerTest Key=Timestamp,Value="${TIMESTAMP}"

aws iam attach-user-policy \
    --user-name "${TEST_USER}" \
    --policy-arn "arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess"

echo "Created: ${TEST_USER}"
echo ""

echo -e "${GREEN}=== Test Resources Created Successfully ===${NC}"
echo ""
echo "Summary:"
echo "- 1 S3 bucket: ${BUCKET_NAME}"
echo "- 2 KMS keys (with/without SourceArn)"
echo "- 3 CloudTrail trails (no KMS, KMS no SourceArn, KMS with SourceArn)"
echo "- 1 CloudWatch Logs log group: ${LOG_GROUP_NAME}"
echo "- 1 IAM role for CloudWatch Logs: ${ROLE_NAME}"
echo "- 1 Metric filter and alarm"
echo "- 1 IAM test user: ${TEST_USER}"
echo ""
echo -e "${YELLOW}=== Manual Setup Required ===${NC}"
echo ""
echo "To fully test all checks, you need to manually enable:"
echo ""
echo "1. GuardDuty:"
echo "   aws guardduty create-detector --enable --region ${REGION}"
echo ""
echo "2. Security Hub:"
echo "   aws securityhub enable-security-hub --region ${REGION}"
echo "   aws securityhub batch-enable-standards --standards-subscription-requests StandardsArn=arn:aws:securityhub:${REGION}::standards/aws-foundational-security-best-practices/v/1.0.0 --region ${REGION}"
echo ""
echo "3. Organization Trail (if in AWS Organizations management account):"
echo "   aws cloudtrail create-trail --name org-trail --s3-bucket-name ${BUCKET_NAME} --is-organization-trail --is-multi-region-trail --region ${REGION}"
echo ""
echo -e "${YELLOW}To clean up these resources, run: ./cleanup_test_resources.sh${NC}"
echo ""
echo "Timestamp: ${TIMESTAMP}"
echo "${TIMESTAMP}" > .last_test_timestamp

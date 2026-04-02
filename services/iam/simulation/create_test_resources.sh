#!/bin/bash

# IAM Service Review - Create Test Resources
# Creates IAM resources to test new checks

set -e

echo "=========================================="
echo "IAM Service Screener - Create Test Resources"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed${NC}"
    exit 1
fi

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials are not configured${NC}"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}Using AWS Account: ${ACCOUNT_ID}${NC}"
echo ""

# File to store created resource identifiers
RESOURCE_FILE="test_resources.txt"
> "$RESOURCE_FILE"

echo "Creating test resources..."
echo ""

# 1. Create unused customer managed policy
echo -e "${YELLOW}[1/5] Creating unused customer managed policy...${NC}"
UNUSED_POLICY_DOC='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}'

UNUSED_POLICY_ARN=$(aws iam create-policy \
    --policy-name ss-test-unused-policy \
    --policy-document "$UNUSED_POLICY_DOC" \
    --description "Test policy for unusedCustomerManagedPolicy check" \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || echo "EXISTS")

if [ "$UNUSED_POLICY_ARN" != "EXISTS" ]; then
    echo -e "${GREEN}✓ Created: ${UNUSED_POLICY_ARN}${NC}"
    echo "POLICY:ss-test-unused-policy:$UNUSED_POLICY_ARN" >> "$RESOURCE_FILE"
else
    echo -e "${YELLOW}⚠ Policy already exists${NC}"
fi
echo ""

# 2. Create policy with S3 wildcard actions
echo -e "${YELLOW}[2/5] Creating policy with S3 wildcard actions...${NC}"
S3_WILDCARD_DOC='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}'

S3_WILDCARD_ARN=$(aws iam create-policy \
    --policy-name ss-test-s3-wildcard-policy \
    --policy-document "$S3_WILDCARD_DOC" \
    --description "Test policy for wildcardActionsDetection check" \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || echo "EXISTS")

if [ "$S3_WILDCARD_ARN" != "EXISTS" ]; then
    echo -e "${GREEN}✓ Created: ${S3_WILDCARD_ARN}${NC}"
    echo "POLICY:ss-test-s3-wildcard-policy:$S3_WILDCARD_ARN" >> "$RESOURCE_FILE"
else
    echo -e "${YELLOW}⚠ Policy already exists${NC}"
fi
echo ""

# 3. Create policy with EC2 wildcard actions
echo -e "${YELLOW}[3/5] Creating policy with EC2 wildcard actions...${NC}"
EC2_WILDCARD_DOC='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*"
    }
  ]
}'

EC2_WILDCARD_ARN=$(aws iam create-policy \
    --policy-name ss-test-ec2-wildcard-policy \
    --policy-document "$EC2_WILDCARD_DOC" \
    --description "Test policy for wildcardActionsDetection check" \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || echo "EXISTS")

if [ "$EC2_WILDCARD_ARN" != "EXISTS" ]; then
    echo -e "${GREEN}✓ Created: ${EC2_WILDCARD_ARN}${NC}"
    echo "POLICY:ss-test-ec2-wildcard-policy:$EC2_WILDCARD_ARN" >> "$RESOURCE_FILE"
else
    echo -e "${YELLOW}⚠ Policy already exists${NC}"
fi
echo ""

# 4. Create custom policy that duplicates AWS managed policy
echo -e "${YELLOW}[4/5] Creating custom policy that duplicates AWS managed policy...${NC}"
CUSTOM_READONLY_DOC='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:List*",
        "ec2:Describe*"
      ],
      "Resource": "*"
    }
  ]
}'

CUSTOM_READONLY_ARN=$(aws iam create-policy \
    --policy-name ss-test-ReadOnlyAccess-Custom \
    --policy-document "$CUSTOM_READONLY_DOC" \
    --description "Test policy for unnecessaryCustomPolicies check" \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || echo "EXISTS")

if [ "$CUSTOM_READONLY_ARN" != "EXISTS" ]; then
    echo -e "${GREEN}✓ Created: ${CUSTOM_READONLY_ARN}${NC}"
    echo "POLICY:ss-test-ReadOnlyAccess-Custom:$CUSTOM_READONLY_ARN" >> "$RESOURCE_FILE"
else
    echo -e "${YELLOW}⚠ Policy already exists${NC}"
fi
echo ""

# 5. Create IAM user with access keys (for federation check)
echo -e "${YELLOW}[5/8] Creating IAM user with access keys...${NC}"
aws iam create-user \
    --user-name ss-test-user-with-keys \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    &>/dev/null || echo -e "${YELLOW}⚠ User already exists${NC}"

# Create access key for the user
ACCESS_KEY_ID=$(aws iam create-access-key \
    --user-name ss-test-user-with-keys \
    --query 'AccessKey.AccessKeyId' \
    --output text 2>/dev/null || echo "EXISTS")

if [ "$ACCESS_KEY_ID" != "EXISTS" ]; then
    echo -e "${GREEN}✓ Created user: ss-test-user-with-keys${NC}"
    echo -e "${GREEN}✓ Created access key: ${ACCESS_KEY_ID}${NC}"
    echo "USER:ss-test-user-with-keys:$ACCESS_KEY_ID" >> "$RESOURCE_FILE"
else
    echo -e "${YELLOW}⚠ User or access key already exists${NC}"
fi
echo ""

# === TIER 2 CHECKS ===

# 6. Create policy with sensitive actions but no security conditions (Tier 2)
echo -e "${YELLOW}[6/8] Creating policy with sensitive actions missing conditions...${NC}"
NO_CONDITIONS_DOC='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey"
      ],
      "Resource": "*"
    }
  ]
}'

NO_CONDITIONS_ARN=$(aws iam create-policy \
    --policy-name ss-test-no-conditions-policy \
    --policy-document "$NO_CONDITIONS_DOC" \
    --description "Test policy for missingPolicyConditions check (Tier 2)" \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || echo "EXISTS")

if [ "$NO_CONDITIONS_ARN" != "EXISTS" ]; then
    echo -e "${GREEN}✓ Created: ${NO_CONDITIONS_ARN}${NC}"
    echo "POLICY:ss-test-no-conditions-policy:$NO_CONDITIONS_ARN" >> "$RESOURCE_FILE"
else
    echo -e "${YELLOW}⚠ Policy already exists${NC}"
fi
echo ""

# 7. Create delegated admin role without permissions boundary (Tier 2)
echo -e "${YELLOW}[7/8] Creating delegated admin role without permissions boundary...${NC}"
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}'

aws iam create-role \
    --role-name ss-test-delegated-admin-role \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "Test role for missingPermissionsBoundaries check (Tier 2)" \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    &>/dev/null || echo -e "${YELLOW}⚠ Role already exists${NC}"

# Attach IAM management policy to make it a delegated admin
ADMIN_POLICY_DOC='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:AttachUserPolicy"
      ],
      "Resource": "*"
    }
  ]
}'

ADMIN_POLICY_ARN=$(aws iam create-policy \
    --policy-name ss-test-delegated-admin-policy \
    --policy-document "$ADMIN_POLICY_DOC" \
    --description "Admin policy for delegated admin role test" \
    --tags Key=Purpose,Value=ServiceScreenerTest \
    --query 'Policy.Arn' \
    --output text 2>/dev/null || echo "arn:aws:iam::${ACCOUNT_ID}:policy/ss-test-delegated-admin-policy")

aws iam attach-role-policy \
    --role-name ss-test-delegated-admin-role \
    --policy-arn "$ADMIN_POLICY_ARN" \
    &>/dev/null || true

echo -e "${GREEN}✓ Created role: ss-test-delegated-admin-role (without permissions boundary)${NC}"
echo "ROLE:ss-test-delegated-admin-role:$ADMIN_POLICY_ARN" >> "$RESOURCE_FILE"
echo ""

# 8. Note about SCP check (Tier 2)
echo -e "${YELLOW}[8/8] Note about SCP best practices check...${NC}"
echo -e "${YELLOW}The scpBestPractices check requires AWS Organizations to be enabled.${NC}"
echo -e "${YELLOW}If Organizations is enabled, review your SCPs manually for:${NC}"
echo -e "${YELLOW}  - Root user action denials${NC}"
echo -e "${YELLOW}  - Region restrictions${NC}"
echo -e "${YELLOW}  - Privilege escalation prevention${NC}"
echo ""

echo "=========================================="
echo -e "${GREEN}Test resources created successfully!${NC}"
echo "=========================================="
echo ""
echo "Resource identifiers saved to: $RESOURCE_FILE"
echo ""
echo "Next steps:"
echo "1. Run Service Screener: python screener.py --services iam --regions us-east-1"
echo "2. Verify the following checks detect issues:"
echo ""
echo "   TIER 1 CHECKS:"
echo "   - unusedCustomerManagedPolicy"
echo "   - iamUsersWithFederationAvailable (if federation configured)"
echo "   - wildcardActionsDetection"
echo "   - unnecessaryCustomPolicies"
echo ""
echo "   TIER 2 CHECKS:"
echo "   - missingPolicyConditions"
echo "   - missingPermissionsBoundaries"
echo "   - scpBestPractices (if Organizations enabled)"
echo ""
echo "3. Clean up: ./cleanup_test_resources.sh"
echo ""

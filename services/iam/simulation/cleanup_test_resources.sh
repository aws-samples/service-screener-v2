#!/bin/bash

# IAM Service Review - Cleanup Test Resources
# Removes all test resources created by create_test_resources.sh

set -e

echo "=========================================="
echo "IAM Service Screener - Cleanup Test Resources"
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

# Confirmation prompt
echo -e "${YELLOW}This will delete all IAM resources with 'ss-test-' prefix.${NC}"
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo ""
echo "Cleaning up test resources..."
echo ""

# 1. Delete IAM user and access keys
echo -e "${YELLOW}[1/5] Deleting IAM user and access keys...${NC}"
USER_NAME="ss-test-user-with-keys"

# List and delete access keys
ACCESS_KEYS=$(aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null || echo "")

if [ -n "$ACCESS_KEYS" ]; then
    for KEY_ID in $ACCESS_KEYS; do
        aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$KEY_ID" 2>/dev/null || true
        echo -e "${GREEN}✓ Deleted access key: ${KEY_ID}${NC}"
    done
fi

# Delete user
aws iam delete-user --user-name "$USER_NAME" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted user: ${USER_NAME}${NC}" || \
    echo -e "${YELLOW}⚠ User not found or already deleted${NC}"
echo ""

# 2. Delete unused policy
echo -e "${YELLOW}[2/5] Deleting unused policy...${NC}"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/ss-test-unused-policy"
aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted: ${POLICY_ARN}${NC}" || \
    echo -e "${YELLOW}⚠ Policy not found or already deleted${NC}"
echo ""

# 3. Delete S3 wildcard policy
echo -e "${YELLOW}[3/5] Deleting S3 wildcard policy...${NC}"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/ss-test-s3-wildcard-policy"
aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted: ${POLICY_ARN}${NC}" || \
    echo -e "${YELLOW}⚠ Policy not found or already deleted${NC}"
echo ""

# 4. Delete EC2 wildcard policy
echo -e "${YELLOW}[4/5] Deleting EC2 wildcard policy...${NC}"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/ss-test-ec2-wildcard-policy"
aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted: ${POLICY_ARN}${NC}" || \
    echo -e "${YELLOW}⚠ Policy not found or already deleted${NC}"
echo ""

# 5. Delete custom ReadOnly policy
echo -e "${YELLOW}[5/8] Deleting custom ReadOnly policy...${NC}"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/ss-test-ReadOnlyAccess-Custom"
aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted: ${POLICY_ARN}${NC}" || \
    echo -e "${YELLOW}⚠ Policy not found or already deleted${NC}"
echo ""

# === TIER 2 CLEANUP ===

# 6. Delete policy with no conditions (Tier 2)
echo -e "${YELLOW}[6/8] Deleting policy with no conditions...${NC}"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/ss-test-no-conditions-policy"
aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted: ${POLICY_ARN}${NC}" || \
    echo -e "${YELLOW}⚠ Policy not found or already deleted${NC}"
echo ""

# 7. Delete delegated admin role and policy (Tier 2)
echo -e "${YELLOW}[7/8] Deleting delegated admin role...${NC}"
ROLE_NAME="ss-test-delegated-admin-role"
ADMIN_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/ss-test-delegated-admin-policy"

# Detach policy from role
aws iam detach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$ADMIN_POLICY_ARN" 2>/dev/null || true

# Delete role
aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted role: ${ROLE_NAME}${NC}" || \
    echo -e "${YELLOW}⚠ Role not found or already deleted${NC}"

# Delete admin policy
aws iam delete-policy --policy-arn "$ADMIN_POLICY_ARN" 2>/dev/null && \
    echo -e "${GREEN}✓ Deleted: ${ADMIN_POLICY_ARN}${NC}" || \
    echo -e "${YELLOW}⚠ Policy not found or already deleted${NC}"
echo ""

# 8. Note about SCP cleanup
echo -e "${YELLOW}[8/8] Note about SCP resources...${NC}"
echo -e "${YELLOW}No SCP resources were created (requires Organizations).${NC}"
echo ""

# Clean up resource file
RESOURCE_FILE="test_resources.txt"
if [ -f "$RESOURCE_FILE" ]; then
    rm "$RESOURCE_FILE"
    echo -e "${GREEN}✓ Removed resource file: ${RESOURCE_FILE}${NC}"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}Cleanup completed successfully!${NC}"
echo "=========================================="
echo ""
echo "All test resources have been removed."
echo ""

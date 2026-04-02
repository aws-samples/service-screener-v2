#!/bin/bash

################################################################################
# SageMaker Service Review - Test Resource Creation Script
#
# Creates a notebook instance with intentionally weak config to trigger checks.
# Notebook is the cheapest SageMaker resource (~$0.058/hour for ml.t3.medium).
#
# Checks triggered (Notebook - 5):
#   EncryptionEnabled, RootAccessDisabled, NotebookVpcSettings,
#   DirectInternetAccess, NotebookLifecycleConfigAttached
#
# Usage:
#   ./create_test_resources.sh [OPTIONS]
#
# Options:
#   --region REGION    AWS region (default: ap-southeast-1)
#   --help             Show this help message
#
################################################################################

set -e
set -u

REGION="${AWS_REGION:-ap-southeast-1}"
PREFIX="sm-sim"
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

ROLE_NAME="${PREFIX}-role-${TIMESTAMP}"
NOTEBOOK_NAME="${PREFIX}-nb-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

echo -e "${GREEN}=== SageMaker Test Resource Creation ===${NC}"
echo "Region: $REGION | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}WARNING: ml.t3.medium costs ~\$0.058/hour. Clean up promptly!${NC}"
echo ""

################################################################################
# Step 1: Create IAM Role
################################################################################

echo -e "${GREEN}=== Step 1: Creating IAM Role ===${NC}"

cat > /tmp/sm-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "sagemaker.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document file:///tmp/sm-trust-policy.json > /dev/null

aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/AmazonSageMakerFullAccess

log_resource "IAM_ROLE:$ROLE_NAME"
echo -e "${GREEN}✓ IAM role created: $ROLE_NAME${NC}"

sleep 10

################################################################################
# Step 2: Create Notebook Instance (intentionally insecure)
# - No KMS encryption (triggers EncryptionEnabled)
# - Root access enabled (triggers RootAccessDisabled)
# - No VPC (triggers NotebookVpcSettings)
# - Direct internet enabled (triggers DirectInternetAccess)
# - No lifecycle config (triggers NotebookLifecycleConfigAttached)
################################################################################

echo -e "\n${GREEN}=== Step 2: Creating Notebook Instance ===${NC}"
echo "This will take 3-5 minutes..."

aws sagemaker create-notebook-instance \
    --notebook-instance-name "$NOTEBOOK_NAME" \
    --instance-type ml.t3.medium \
    --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}" \
    --root-access Enabled \
    --direct-internet-access Enabled \
    --region "$REGION" > /dev/null

log_resource "NOTEBOOK:$NOTEBOOK_NAME"
echo -e "${GREEN}✓ Notebook creation initiated: $NOTEBOOK_NAME${NC}"

echo -e "${YELLOW}Waiting for notebook to become InService...${NC}"
aws sagemaker wait notebook-instance-in-service \
    --notebook-instance-name "$NOTEBOOK_NAME" \
    --region "$REGION"
echo -e "${GREEN}✓ Notebook is InService${NC}"

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}=== All Resources Created ===${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Resources saved to: $OUTPUT_FILE"
echo ""
echo "Created:"
echo "  ✓ IAM Role:   $ROLE_NAME"
echo "  ✓ Notebook:   $NOTEBOOK_NAME"
echo ""
echo "Next steps:"
echo "  1. Run screener:"
echo "     cd /Users/kuettai/Documents/project/ssvsprowler/service-screener-v2"
echo "     python main.py --services sagemaker --regions $REGION --sequential 1 --beta 1"
echo ""
echo "  2. Cleanup when done:"
echo "     ./cleanup_test_resources.sh $OUTPUT_FILE --region $REGION"
echo ""
echo -e "${RED}IMPORTANT: ~\$0.058/hour while running. Clean up promptly!${NC}"

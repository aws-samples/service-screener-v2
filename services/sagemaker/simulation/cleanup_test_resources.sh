#!/bin/bash

################################################################################
# SageMaker Service Review - Test Resource Cleanup Script
#
# Deletion order:
#   1. Stop + Delete Notebook Instances
#   2. Delete IAM Roles
#
# Usage:
#   ./cleanup_test_resources.sh [RESOURCE_FILE] [OPTIONS]
#
# Options:
#   --region REGION    AWS region (default: ap-southeast-1)
#   --force            Skip confirmation prompts
#   --help             Show this help message
#
################################################################################

set -e
set -u

REGION="${AWS_REGION:-ap-southeast-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --force)  FORCE=true; shift ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then
                RESOURCE_FILE="$1"; shift
            else
                echo -e "${RED}Error: Unknown option $1${NC}"; exit 1
            fi
            ;;
    esac
done

if [ -z "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file required${NC}"
    echo "Usage: $0 <resource_file> [OPTIONS]"
    exit 1
fi

if [ ! -f "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file not found: $RESOURCE_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}=== SageMaker Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo "Resource file: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    RESOURCES+=("$line")
done < "$RESOURCE_FILE"

if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}WARNING: This will permanently delete all resources.${NC}"
    read -p "Continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Cleanup cancelled."
        exit 0
    fi
fi

################################################################################
# Step 1: Stop + Delete Notebooks
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting Notebooks ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == NOTEBOOK:* ]]; then
        NAME="${resource#NOTEBOOK:}"
        echo "Stopping notebook: $NAME"
        aws sagemaker stop-notebook-instance \
            --notebook-instance-name "$NAME" \
            --region "$REGION" 2>/dev/null || true

        echo -e "${YELLOW}Waiting for notebook to stop...${NC}"
        aws sagemaker wait notebook-instance-stopped \
            --notebook-instance-name "$NAME" \
            --region "$REGION" 2>/dev/null || true

        echo "Deleting notebook: $NAME"
        aws sagemaker delete-notebook-instance \
            --notebook-instance-name "$NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
        echo -e "${GREEN}✓ $NAME deleted${NC}"
    fi
done

################################################################################
# Step 2: Delete IAM Roles
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting IAM Roles ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == IAM_ROLE:* ]]; then
        ROLE_NAME="${resource#IAM_ROLE:}"
        echo "Deleting IAM role: $ROLE_NAME"

        POLICIES=$(aws iam list-attached-role-policies \
            --role-name "$ROLE_NAME" \
            --query 'AttachedPolicies[].PolicyArn' \
            --output text 2>/dev/null || true)

        for policy in $POLICIES; do
            aws iam detach-role-policy \
                --role-name "$ROLE_NAME" \
                --policy-arn "$policy" 2>/dev/null || true
        done

        aws iam delete-role \
            --role-name "$ROLE_NAME" 2>/dev/null || echo "  (already deleted or not found)"
        echo -e "${GREEN}✓ $ROLE_NAME deleted${NC}"
    fi
done

echo -e "\n${GREEN}=== Cleanup Complete ===${NC}"
echo -e "${YELLOW}You can now delete the resource file: $RESOURCE_FILE${NC}"
echo -e "${GREEN}Cleanup successful!${NC}"

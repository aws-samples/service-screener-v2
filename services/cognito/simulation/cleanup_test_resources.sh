#!/bin/bash

################################################################################
# Cognito Service Screener - Test Resource Cleanup Script
#
# Deletes user pools + Lambda + IAM roles created by create_test_resources.sh.
# App clients and groups are deleted implicitly when the pool is deleted.
#
# Usage:
#   ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --force)  FORCE=true; shift ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then RESOURCE_FILE="$1"; shift
            else echo -e "${RED}Unknown: $1${NC}"; exit 1; fi
            ;;
    esac
done

if [ -z "$RESOURCE_FILE" ]; then
    RESOURCE_FILE=$(ls -1t created_resources_*.txt 2>/dev/null | head -1)
    [ -z "$RESOURCE_FILE" ] && { echo -e "${RED}No manifest found${NC}"; exit 1; }
    echo -e "${YELLOW}Auto-detected: $RESOURCE_FILE${NC}"
fi

[ ! -f "$RESOURCE_FILE" ] && { echo -e "${RED}Not found: $RESOURCE_FILE${NC}"; exit 1; }

echo -e "${GREEN}=== Cognito Test Resource Cleanup ===${NC}"
echo "Region: $REGION | File: $RESOURCE_FILE"

RESOURCES=()
while IFS= read -r line; do
    [ -n "$line" ] && RESOURCES+=("$line")
done < "$RESOURCE_FILE"

echo ""
echo "Resources to delete:"
for r in "${RESOURCES[@]}"; do echo "  - $r"; done
echo ""

if [ "$FORCE" = false ]; then
    read -p "Continue? (yes/no): " C
    [ "$C" != "yes" ] && { echo "Cancelled."; exit 0; }
fi

by_type() {
    local t="$1"
    for r in "${RESOURCES[@]}"; do
        [[ "$r" == ${t}:* ]] && echo "${r#${t}:}"
    done
}

################################################################################
# Step 1: Delete app clients (safety; also removed with pool)
################################################################################

echo -e "\n${GREEN}=== Step 1: Delete app clients ===${NC}"
for ENTRY in $(by_type APP_CLIENT); do
    POOL_ID="${ENTRY%%:*}"
    CLIENT_ID="${ENTRY##*:}"
    echo "Deleting app client ${CLIENT_ID} in pool ${POOL_ID}"
    aws cognito-idp delete-user-pool-client \
        --user-pool-id "$POOL_ID" \
        --client-id "$CLIENT_ID" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

################################################################################
# Step 2: Delete user pools
################################################################################

echo -e "\n${GREEN}=== Step 2: Delete user pools ===${NC}"
for POOL_ID in $(by_type USER_POOL); do
    # If deletion protection got flipped to ACTIVE, disable it first
    aws cognito-idp update-user-pool \
        --user-pool-id "$POOL_ID" \
        --deletion-protection INACTIVE \
        --region "$REGION" > /dev/null 2>&1 || true

    echo "Deleting user pool: $POOL_ID"
    aws cognito-idp delete-user-pool \
        --user-pool-id "$POOL_ID" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

################################################################################
# Step 3: Delete Lambda function
################################################################################

echo -e "\n${GREEN}=== Step 3: Delete Lambda function ===${NC}"
for FN in $(by_type LAMBDA); do
    echo "Deleting Lambda: $FN"
    aws lambda delete-function \
        --function-name "$FN" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

################################################################################
# Step 4: Delete IAM roles (Lambda exec role + Cognito group role)
################################################################################

echo -e "\n${GREEN}=== Step 4: Delete IAM roles ===${NC}"
for ROLE_NAME in $(by_type IAM_ROLE); do
    echo "Deleting: $ROLE_NAME"

    attached=$(aws iam list-attached-role-policies \
        --role-name "$ROLE_NAME" \
        --query 'AttachedPolicies[].PolicyArn' \
        --output text 2>/dev/null || true)
    for arn in $attached; do
        aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$arn" 2>/dev/null || true
    done

    inline=$(aws iam list-role-policies \
        --role-name "$ROLE_NAME" \
        --query 'PolicyNames' \
        --output text 2>/dev/null || true)
    for pname in $inline; do
        aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$pname" 2>/dev/null || true
    done

    aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null \
        && echo -e "${GREEN}  ✓ deleted${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or still referenced${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."

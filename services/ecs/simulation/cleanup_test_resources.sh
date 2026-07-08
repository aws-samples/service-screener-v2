#!/bin/bash

################################################################################
# ECS Service Screener - Test Resource Cleanup Script
#
# Deletes, in order:
#   1. ECS service   (must be scaled to 0 before delete; --force works too)
#   2. ECS cluster   (must be empty of services)
#   3. Task definition(s)   (deregister — only ACTIVE revisions can be deregistered)
#   4. CloudWatch log group
#   5. IAM role     (detach + delete inline policies + delete role)
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
            if [ -z "$RESOURCE_FILE" ]; then
                RESOURCE_FILE="$1"; shift
            else
                echo -e "${RED}Error: Unknown option $1${NC}"; exit 1
            fi
            ;;
    esac
done

if [ -z "$RESOURCE_FILE" ]; then
    RESOURCE_FILE=$(ls -1t created_resources_*.txt 2>/dev/null | head -1)
    if [ -z "$RESOURCE_FILE" ]; then
        echo -e "${RED}Error: no resource file specified and none found in CWD${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Auto-detected resource file: $RESOURCE_FILE${NC}"
fi

if [ ! -f "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: resource file not found: $RESOURCE_FILE${NC}"; exit 1
fi

echo -e "${GREEN}=== ECS Test Resource Cleanup ===${NC}"
echo "Region: $REGION | File: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    [ -n "$line" ] && RESOURCES+=("$line")
done < "$RESOURCE_FILE"

echo "Resources to delete:"
for r in "${RESOURCES[@]}"; do echo "  - $r"; done
echo ""

if [ "$FORCE" = false ]; then
    read -p "Continue? (yes/no): " CONFIRM
    [ "$CONFIRM" != "yes" ] && { echo "Cancelled."; exit 0; }
fi

by_type() {
    local t="$1"
    for r in "${RESOURCES[@]}"; do
        [[ "$r" == ${t}:* ]] && echo "${r#${t}:}"
    done
}

################################################################################
# Step 1: Delete services (with --force to skip scale-to-0 requirement)
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting ECS services ===${NC}"
for ENTRY in $(by_type SERVICE); do
    CLUSTER="${ENTRY%%:*}"
    SVC="${ENTRY##*:}"
    echo "Deleting service: ${SVC} (cluster ${CLUSTER})"
    aws ecs delete-service \
        --cluster "$CLUSTER" \
        --service "$SVC" \
        --force \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓ delete requested${NC}" \
        || echo -e "${YELLOW}  ⚠ already deleted or not found${NC}"
done

# ECS service deletion is asynchronous; wait for it to drain before removing cluster
sleep 15

################################################################################
# Step 2: Deregister task definitions
################################################################################

echo -e "\n${GREEN}=== Step 2: Deregistering task definitions ===${NC}"
for ARN in $(by_type TASK_DEF); do
    echo "Deregistering: $ARN"
    aws ecs deregister-task-definition \
        --task-definition "$ARN" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already deregistered${NC}"
done

################################################################################
# Step 3: Delete clusters
################################################################################

echo -e "\n${GREEN}=== Step 3: Deleting ECS clusters ===${NC}"
for CLUSTER in $(by_type CLUSTER); do
    echo "Deleting cluster: $CLUSTER"
    aws ecs delete-cluster \
        --cluster "$CLUSTER" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ still has services or already deleted (retry after services fully drain)${NC}"
done

################################################################################
# Step 4: Delete CloudWatch log groups
################################################################################

echo -e "\n${GREEN}=== Step 4: Deleting CloudWatch log groups ===${NC}"
for LG in $(by_type LOG_GROUP); do
    echo "Deleting: $LG"
    aws logs delete-log-group \
        --log-group-name "$LG" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

################################################################################
# Step 5: Delete IAM role
################################################################################

echo -e "\n${GREEN}=== Step 5: Deleting IAM role ===${NC}"
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
        || echo -e "${YELLOW}  ⚠ role still referenced (retry after task definitions/services fully drain)${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}You may now remove the resource file:${NC} rm $RESOURCE_FILE"

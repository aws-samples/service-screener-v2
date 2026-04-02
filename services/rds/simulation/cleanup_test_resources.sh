#!/bin/bash

################################################################################
# RDS Service Review - Comprehensive Test Resource Cleanup Script
#
# Purpose: Clean up all RDS test resources created by create_test_resources.sh
#
# Deletion order (respects dependencies):
#   1. RDS Event Subscriptions (if any)
#   2. RDS Instances (skip final snapshot, wait for deletion)
#   3. DB Subnet Groups
#   4. DB Parameter Groups
#   5. Security Groups
#   6. SNS Topics
#
# Usage:
#   ./cleanup_test_resources.sh [RESOURCE_FILE] [OPTIONS]
#
# Options:
#   --region REGION          AWS region (default: us-east-1)
#   --force                  Skip confirmation prompts
#   --help                   Show this help message
#
################################################################################

set -e
set -u

REGION="us-east-1"
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

echo -e "${GREEN}=== RDS Comprehensive Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo "Resource file: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    RESOURCES+=("$line")
done < "$RESOURCE_FILE"

# Count resources
count_type() { grep -c "^$1:" "$RESOURCE_FILE" 2>/dev/null || echo 0; }

INSTANCE_COUNT=$(count_type "RDS_INSTANCE")
PARAM_GROUP_COUNT=$(count_type "DB_PARAM_GROUP")
SUBNET_GROUP_COUNT=$(count_type "DB_SUBNET_GROUP")
SG_COUNT=$(count_type "SECURITY_GROUP")
TOPIC_COUNT=$(count_type "SNS_TOPIC")
EVENT_SUB_COUNT=$(count_type "RDS_EVENT_SUB")

echo "Resources to delete:"
echo "  - RDS Instances:        $INSTANCE_COUNT"
echo "  - DB Parameter Groups:  $PARAM_GROUP_COUNT"
echo "  - DB Subnet Groups:     $SUBNET_GROUP_COUNT"
echo "  - Security Groups:      $SG_COUNT"
echo "  - SNS Topics:           $TOPIC_COUNT"
echo "  - Event Subscriptions:  $EVENT_SUB_COUNT"
echo ""

if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}WARNING: This will permanently delete all resources listed above.${NC}"
    read -p "Continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Cleanup cancelled."
        exit 0
    fi
fi

################################################################################
# Step 1: Delete RDS Event Subscriptions
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting Event Subscriptions ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == RDS_EVENT_SUB:* ]]; then
        NAME="${resource#RDS_EVENT_SUB:}"
        echo "Deleting event subscription: $NAME"
        aws rds delete-event-subscription \
            --subscription-name "$NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ Event subscriptions cleanup complete${NC}"

################################################################################
# Step 2: Delete RDS Instances
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting RDS Instances ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == RDS_INSTANCE:* ]]; then
        ID="${resource#RDS_INSTANCE:}"
        echo "Deleting RDS instance: $ID (skip final snapshot)"

        # Disable deletion protection first (in case it was enabled manually)
        aws rds modify-db-instance \
            --db-instance-identifier "$ID" \
            --no-deletion-protection \
            --apply-immediately \
            --region "$REGION" 2>/dev/null || true

        aws rds delete-db-instance \
            --db-instance-identifier "$ID" \
            --skip-final-snapshot \
            --delete-automated-backups \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done

# Wait for all instances to be deleted
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == RDS_INSTANCE:* ]]; then
        ID="${resource#RDS_INSTANCE:}"
        echo -e "${YELLOW}Waiting for $ID to be deleted (may take several minutes)...${NC}"
        aws rds wait db-instance-deleted \
            --db-instance-identifier "$ID" \
            --region "$REGION" 2>/dev/null || echo "  (wait completed or instance already gone)"
        echo -e "${GREEN}✓ $ID deleted${NC}"
    fi
done

################################################################################
# Step 3: Delete DB Subnet Groups
################################################################################

echo -e "\n${GREEN}=== Step 3: Deleting DB Subnet Groups ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == DB_SUBNET_GROUP:* ]]; then
        NAME="${resource#DB_SUBNET_GROUP:}"
        echo "Deleting DB subnet group: $NAME"
        aws rds delete-db-subnet-group \
            --db-subnet-group-name "$NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ DB subnet groups cleanup complete${NC}"

################################################################################
# Step 4: Delete DB Parameter Groups
################################################################################

echo -e "\n${GREEN}=== Step 4: Deleting DB Parameter Groups ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == DB_PARAM_GROUP:* ]]; then
        NAME="${resource#DB_PARAM_GROUP:}"
        echo "Deleting DB parameter group: $NAME"
        aws rds delete-db-parameter-group \
            --db-parameter-group-name "$NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ DB parameter groups cleanup complete${NC}"

################################################################################
# Step 5: Delete Security Groups
################################################################################

echo -e "\n${GREEN}=== Step 5: Deleting Security Groups ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == SECURITY_GROUP:* ]]; then
        SG_ID="${resource#SECURITY_GROUP:}"
        echo "Deleting security group: $SG_ID"
        aws ec2 delete-security-group \
            --group-id "$SG_ID" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ Security groups cleanup complete${NC}"

################################################################################
# Step 6: Delete SNS Topics
################################################################################

echo -e "\n${GREEN}=== Step 6: Deleting SNS Topics ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == SNS_TOPIC:* ]]; then
        ARN="${resource#SNS_TOPIC:}"
        echo "Deleting SNS topic: $ARN"
        aws sns delete-topic \
            --topic-arn "$ARN" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ SNS topics cleanup complete${NC}"

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Deleted:"
echo "  ✓ $INSTANCE_COUNT RDS instance(s)"
echo "  ✓ $PARAM_GROUP_COUNT DB parameter group(s)"
echo "  ✓ $SUBNET_GROUP_COUNT DB subnet group(s)"
echo "  ✓ $SG_COUNT security group(s)"
echo "  ✓ $TOPIC_COUNT SNS topic(s)"
echo "  ✓ $EVENT_SUB_COUNT event subscription(s)"
echo ""
echo -e "${YELLOW}You can now delete the resource file: $RESOURCE_FILE${NC}"
echo -e "${GREEN}Cleanup successful!${NC}"

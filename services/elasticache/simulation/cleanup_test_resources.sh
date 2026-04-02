#!/bin/bash

################################################################################
# ElastiCache Service Review - Test Resource Cleanup Script
#
# Deletion order:
#   1. Replication Groups (wait for deletion)
#   2. Cache Subnet Groups
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

echo -e "${GREEN}=== ElastiCache Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo "Resource file: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    RESOURCES+=("$line")
done < "$RESOURCE_FILE"

count_type() { grep -c "^$1:" "$RESOURCE_FILE" 2>/dev/null || echo 0; }

RG_COUNT=$(count_type "REPLICATION_GROUP")
SUBNET_COUNT=$(count_type "SUBNET_GROUP")

echo "Resources to delete:"
echo "  - Replication Groups:   $RG_COUNT"
echo "  - Subnet Groups:        $SUBNET_COUNT"
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
# Step 1: Delete Replication Groups
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting Replication Groups ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == REPLICATION_GROUP:* ]]; then
        ID="${resource#REPLICATION_GROUP:}"
        echo "Deleting replication group: $ID (no final snapshot)"
        aws elasticache delete-replication-group \
            --replication-group-id "$ID" \
            --no-retain-primary-cluster \
            --region "$REGION" > /dev/null 2>&1 || echo "  (already deleted or not found)"
    fi
done

for resource in "${RESOURCES[@]}"; do
    if [[ $resource == REPLICATION_GROUP:* ]]; then
        ID="${resource#REPLICATION_GROUP:}"
        echo -e "${YELLOW}Waiting for $ID to be deleted (may take 5-10 minutes)...${NC}"
        aws elasticache wait replication-group-deleted \
            --replication-group-id "$ID" \
            --region "$REGION" 2>/dev/null || echo "  (wait completed or already gone)"
        echo -e "${GREEN}✓ $ID deleted${NC}"
    fi
done

################################################################################
# Step 2: Delete Cache Subnet Groups
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting Subnet Groups ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == SUBNET_GROUP:* ]]; then
        NAME="${resource#SUBNET_GROUP:}"
        echo "Deleting subnet group: $NAME"
        aws elasticache delete-cache-subnet-group \
            --cache-subnet-group-name "$NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ Subnet groups cleanup complete${NC}"

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Deleted:"
echo "  ✓ $RG_COUNT replication group(s)"
echo "  ✓ $SUBNET_COUNT subnet group(s)"
echo ""
echo -e "${YELLOW}You can now delete the resource file: $RESOURCE_FILE${NC}"
echo -e "${GREEN}Cleanup successful!${NC}"

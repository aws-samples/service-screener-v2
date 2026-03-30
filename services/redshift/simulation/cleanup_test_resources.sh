#!/bin/bash

################################################################################
# Redshift Service Review - Test Resource Cleanup Script
#
# Deletion order (respects dependencies):
#   1. Redshift Cluster (skip final snapshot, wait for deletion)
#   2. Cluster Subnet Groups
#   3. SNS Topics
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

echo -e "${GREEN}=== Redshift Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo "Resource file: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    RESOURCES+=("$line")
done < "$RESOURCE_FILE"

count_type() { grep -c "^$1:" "$RESOURCE_FILE" 2>/dev/null || echo 0; }

CLUSTER_COUNT=$(count_type "CLUSTER")
SUBNET_GROUP_COUNT=$(count_type "SUBNET_GROUP")
TOPIC_COUNT=$(count_type "SNS_TOPIC")

echo "Resources to delete:"
echo "  - Redshift Clusters:    $CLUSTER_COUNT"
echo "  - Subnet Groups:        $SUBNET_GROUP_COUNT"
echo "  - SNS Topics:           $TOPIC_COUNT"
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
# Step 1: Delete Redshift Clusters
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting Redshift Clusters ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == CLUSTER:* ]]; then
        ID="${resource#CLUSTER:}"
        echo "Deleting cluster: $ID (skip final snapshot)"
        aws redshift delete-cluster \
            --cluster-identifier "$ID" \
            --skip-final-cluster-snapshot \
            --region "$REGION" > /dev/null 2>&1 || echo "  (already deleted or not found)"
    fi
done

for resource in "${RESOURCES[@]}"; do
    if [[ $resource == CLUSTER:* ]]; then
        ID="${resource#CLUSTER:}"
        echo -e "${YELLOW}Waiting for $ID to be deleted (may take 5-10 minutes)...${NC}"
        aws redshift wait cluster-deleted \
            --cluster-identifier "$ID" \
            --region "$REGION" 2>/dev/null || echo "  (wait completed or cluster already gone)"
        echo -e "${GREEN}✓ $ID deleted${NC}"
    fi
done

################################################################################
# Step 2: Delete Cluster Subnet Groups
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting Subnet Groups ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == SUBNET_GROUP:* ]]; then
        NAME="${resource#SUBNET_GROUP:}"
        echo "Deleting subnet group: $NAME"
        aws redshift delete-cluster-subnet-group \
            --cluster-subnet-group-name "$NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ Subnet groups cleanup complete${NC}"

################################################################################
# Step 3: Delete SNS Topics
################################################################################

echo -e "\n${GREEN}=== Step 3: Deleting SNS Topics ===${NC}"
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
echo "  ✓ $CLUSTER_COUNT cluster(s)"
echo "  ✓ $SUBNET_GROUP_COUNT subnet group(s)"
echo "  ✓ $TOPIC_COUNT SNS topic(s)"
echo ""
echo -e "${YELLOW}You can now delete the resource file: $RESOURCE_FILE${NC}"
echo -e "${GREEN}Cleanup successful!${NC}"

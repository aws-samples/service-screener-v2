#!/bin/bash

################################################################################
# ElastiCache Service Review - Test Resource Creation Script
#
# Creates a single minimal Redis replication group with intentionally weak
# config to trigger as many checks as possible.
#
# Resources Created:
#   1. Cache Subnet Group
#   2. Redis Replication Group (single node, no cluster mode, no backups)
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
PREFIX="ec-sim"
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

SUBNET_GROUP="${PREFIX}-subnet-${TIMESTAMP}"
RG_ID="${PREFIX}-rg-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== ElastiCache Test Resource Creation ===${NC}"
echo "Region: $REGION | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}WARNING: cache.t3.micro costs ~\$0.017/hour. Clean up promptly!${NC}"
echo ""

################################################################################
# Step 0: Detect VPC and Subnets
################################################################################

echo -e "${CYAN}--- Detecting VPC and subnets ---${NC}"

VPC_ID=$(aws ec2 describe-vpcs \
    --filters Name=isDefault,Values=true \
    --query 'Vpcs[0].VpcId' --output text \
    --region "$REGION")

if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
    echo -e "${RED}Error: No default VPC found.${NC}"
    exit 1
fi

SUBNET_ID=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=default-for-az,Values=true" \
    --query 'Subnets[0].SubnetId' --output text \
    --region "$REGION")

echo "VPC: $VPC_ID | Subnet: $SUBNET_ID"

################################################################################
# Step 1: Create Cache Subnet Group
################################################################################

echo -e "\n${GREEN}=== Step 1: Creating Cache Subnet Group ===${NC}"

aws elasticache create-cache-subnet-group \
    --cache-subnet-group-name "$SUBNET_GROUP" \
    --cache-subnet-group-description "ElastiCache simulation subnet group" \
    --subnet-ids "$SUBNET_ID" \
    --tags Key=Purpose,Value=ElastiCacheSimulation \
    --region "$REGION" > /dev/null

log_resource "SUBNET_GROUP:$SUBNET_GROUP"
echo -e "${GREEN}✓ Subnet group created: $SUBNET_GROUP${NC}"

################################################################################
# Step 2: Create Redis Replication Group (intentionally weak config)
# Triggers (ReplicationGroup driver):
#   EnableReadReplica (no replicas), EnableSlowLog (no logs),
#   ClusterModeEnabled (disabled), MultiAZEnabled (disabled),
#   BackupEnabled (retention 0)
# Triggers (Common driver via cluster nodes):
#   EncInTransitAndRest (no encryption), DefaultParamGroup (default params),
#   RInstanceType (t3 not r), EnableNotification (no SNS)
################################################################################

echo -e "\n${GREEN}=== Step 2: Creating Redis Replication Group ===${NC}"
echo "This will take 5-10 minutes..."

aws elasticache create-replication-group \
    --replication-group-id "$RG_ID" \
    --replication-group-description "ElastiCache simulation - weak config" \
    --engine redis \
    --cache-node-type cache.t3.micro \
    --num-cache-clusters 1 \
    --cache-subnet-group-name "$SUBNET_GROUP" \
    --snapshot-retention-limit 0 \
    --region "$REGION" > /dev/null

log_resource "REPLICATION_GROUP:$RG_ID"
echo -e "${GREEN}✓ Replication group creation initiated: $RG_ID${NC}"

################################################################################
# Wait for replication group
################################################################################

echo -e "\n${YELLOW}=== Waiting for replication group to become available ===${NC}"

aws elasticache wait replication-group-available \
    --replication-group-id "$RG_ID" \
    --region "$REGION"

echo -e "${GREEN}✓ Replication group is available${NC}"

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
echo "  ✓ Subnet Group:        $SUBNET_GROUP"
echo "  ✓ Replication Group:   $RG_ID"
echo ""
echo "Next steps:"
echo "  1. Run screener:"
echo "     cd /Users/kuettai/Documents/project/ssvsprowler/service-screener-v2"
echo "     python main.py --services elasticache --regions $REGION --sequential 1 --beta 1"
echo ""
echo "  2. Cleanup when done:"
echo "     ./cleanup_test_resources.sh $OUTPUT_FILE --region $REGION"
echo ""
echo -e "${RED}IMPORTANT: ~\$0.017/hour while running. Clean up promptly!${NC}"

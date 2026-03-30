#!/bin/bash

################################################################################
# Redshift Service Review - Test Resource Creation Script
#
# Creates a single-node Redshift cluster with intentionally weak config
# to trigger as many checks as possible from RedshiftCluster.py.
#
# Resources Created:
#   1. Cluster Subnet Group (for VPC deployment)
#   2. Redshift Cluster (dc2.large single-node, insecure config)
#   3. SNS Topic (but NO event subscription → triggers EventNotifications)
#
# Checks expected to FAIL:
#   PubliclyAccessible, AutomaticSnapshots, CrossRegionSnapshots,
#   EnhancedVpcRouting, DefaultDatabaseName, EncryptedAtRest,
#   EncryptedWithKMS, AZRelocation, EncryptedInTransit, AuditLogging,
#   IAMRoles, EventNotifications, QueryMonitoringRules
#
# Checks expected to PASS:
#   VpcDeployment, SecurityGroups, AutomaticUpgrades, MaintenanceWindow,
#   DefaultAdminUsername
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
PREFIX="rs-sim"
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

SUBNET_GROUP_NAME="${PREFIX}-subnet-${TIMESTAMP}"
CLUSTER_ID="${PREFIX}-cluster-${TIMESTAMP}"
SNS_TOPIC_NAME="${PREFIX}-events-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Redshift Test Resource Creation ===${NC}"
echo "Region: $REGION | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}WARNING: Redshift dc2.large costs ~\$0.25/hour. Clean up promptly!${NC}"
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
    echo -e "${RED}Error: No default VPC found. Create one with: aws ec2 create-default-vpc${NC}"
    exit 1
fi

SUBNET_ID=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=default-for-az,Values=true" \
    --query 'Subnets[0].SubnetId' --output text \
    --region "$REGION")

echo "VPC: $VPC_ID | Subnet: $SUBNET_ID"

################################################################################
# Step 1: Create Cluster Subnet Group
################################################################################

echo -e "\n${GREEN}=== Step 1: Creating Cluster Subnet Group ===${NC}"

aws redshift create-cluster-subnet-group \
    --cluster-subnet-group-name "$SUBNET_GROUP_NAME" \
    --description "Redshift simulation subnet group" \
    --subnet-ids "$SUBNET_ID" \
    --tags Key=Purpose,Value=RedshiftSimulation \
    --region "$REGION" > /dev/null

log_resource "SUBNET_GROUP:$SUBNET_GROUP_NAME"
echo -e "${GREEN}✓ Subnet group created: $SUBNET_GROUP_NAME${NC}"

################################################################################
# Step 2: Create Redshift Cluster (intentionally insecure)
# Triggers: PubliclyAccessible, AutomaticSnapshots, CrossRegionSnapshots,
#           EnhancedVpcRouting, DefaultDatabaseName, EncryptedAtRest,
#           EncryptedWithKMS, AZRelocation, EncryptedInTransit, AuditLogging,
#           IAMRoles, QueryMonitoringRules
# Passes:  VpcDeployment, SecurityGroups, AutomaticUpgrades, MaintenanceWindow,
#           DefaultAdminUsername
################################################################################

echo -e "\n${GREEN}=== Step 2: Creating Redshift Cluster ===${NC}"
echo "This will take 5-10 minutes..."

aws redshift create-cluster \
    --cluster-identifier "$CLUSTER_ID" \
    --node-type ra3.large \
    --cluster-type single-node \
    --master-username testadmin \
    --master-user-password "SimTest1234!" \
    --cluster-subnet-group-name "$SUBNET_GROUP_NAME" \
    --publicly-accessible \
    --automated-snapshot-retention-period 1 \
    --encrypted \
    --region "$REGION" > /dev/null

log_resource "CLUSTER:$CLUSTER_ID"
echo -e "${GREEN}✓ Cluster creation initiated: $CLUSTER_ID${NC}"

################################################################################
# Step 3: Create SNS Topic (no event subscription)
# Triggers: EventNotifications (by NOT creating a subscription)
################################################################################

echo -e "\n${GREEN}=== Step 3: Creating SNS Topic (no event subscription) ===${NC}"

SNS_TOPIC_ARN=$(aws sns create-topic \
    --name "$SNS_TOPIC_NAME" \
    --tags Key=Purpose,Value=RedshiftSimulation \
    --query 'TopicArn' --output text \
    --region "$REGION")

log_resource "SNS_TOPIC:$SNS_TOPIC_ARN"
echo -e "${GREEN}✓ SNS Topic created: $SNS_TOPIC_ARN${NC}"
echo -e "${YELLOW}  (No event subscription created — triggers EventNotifications)${NC}"

################################################################################
# Wait for cluster
################################################################################

echo -e "\n${YELLOW}=== Waiting for cluster to become available ===${NC}"

aws redshift wait cluster-available \
    --cluster-identifier "$CLUSTER_ID" \
    --region "$REGION"

echo -e "${GREEN}✓ Cluster is available${NC}"

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
echo "  ✓ Subnet Group:  $SUBNET_GROUP_NAME"
echo "  ✓ Cluster:       $CLUSTER_ID"
echo "  ✓ SNS Topic:     $SNS_TOPIC_ARN"
echo ""
echo "Next steps:"
echo "  1. Run screener:"
echo "     cd /Users/kuettai/Documents/project/ssvsprowler/service-screener-v2"
echo "     python main.py --services redshift --regions $REGION --sequential 1 --beta 1"
echo ""
echo "  2. Cleanup when done:"
echo "     ./cleanup_test_resources.sh $OUTPUT_FILE --region $REGION"
echo ""
echo -e "${RED}IMPORTANT: ~\$0.25/hour while running. Clean up promptly!${NC}"

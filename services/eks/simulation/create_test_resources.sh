#!/bin/bash

################################################################################
# EKS Service Review - Test Resource Creation Script
#
# Creates a single EKS cluster with intentionally weak config to trigger
# as many checks as possible from EksCommon.py.
#
# Single cluster triggers:
#   eksClusterLogging, eksClusterLoggingIncomplete, eksSecretsEncryption,
#   eksSecretsEncryptionNoKMS, eksEndpointPublicAccess, eksNoKarpenter,
#   eksNoSpotInstances, eksNoAutoscaling, eksNoManagedStorageDrivers,
#   eksAutoModeNotEnabled
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
PREFIX="eks-sim"
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

CLUSTER_NAME="${PREFIX}-${TIMESTAMP}"
ROLE_NAME="${PREFIX}-role-${TIMESTAMP}"
NG_ROLE_NAME="${PREFIX}-ng-role-${TIMESTAMP}"
NG_NAME="${PREFIX}-ng-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== EKS Test Resource Creation ===${NC}"
echo "Region: $REGION | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}WARNING: EKS control plane costs \$0.10/hour + node costs. Clean up promptly!${NC}"
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

# Get 2 subnets in different AZs
ALL_SUBNETS=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=default-for-az,Values=true" \
    --query 'Subnets[*].[SubnetId,AvailabilityZone]' --output text \
    --region "$REGION")

SUBNET_1=$(echo "$ALL_SUBNETS" | head -1 | awk '{print $1}')
AZ_1=$(echo "$ALL_SUBNETS" | head -1 | awk '{print $2}')
SUBNET_2=$(echo "$ALL_SUBNETS" | awk -v az="$AZ_1" '$2 != az {print $1; exit}')

echo "VPC: $VPC_ID | Subnets: $SUBNET_1, $SUBNET_2"

################################################################################
# Step 1: Create IAM Roles
################################################################################

echo -e "\n${GREEN}=== Step 1: Creating IAM Roles ===${NC}"

# Cluster role
cat > /tmp/eks-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "eks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document file:///tmp/eks-trust-policy.json > /dev/null

aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy

ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)
log_resource "IAM_ROLE:$ROLE_NAME"
echo -e "${GREEN}✓ Cluster role: $ROLE_NAME${NC}"

# Node group role
cat > /tmp/eks-ng-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
    --role-name "$NG_ROLE_NAME" \
    --assume-role-policy-document file:///tmp/eks-ng-trust-policy.json > /dev/null

for POLICY in AmazonEKSWorkerNodePolicy AmazonEKS_CNI_Policy AmazonEC2ContainerRegistryReadOnly; do
    aws iam attach-role-policy \
        --role-name "$NG_ROLE_NAME" \
        --policy-arn "arn:aws:iam::aws:policy/$POLICY"
done

NG_ROLE_ARN=$(aws iam get-role --role-name "$NG_ROLE_NAME" --query 'Role.Arn' --output text)
log_resource "IAM_ROLE:$NG_ROLE_NAME"
echo -e "${GREEN}✓ Node group role: $NG_ROLE_NAME${NC}"

# Brief pause for IAM propagation
sleep 10

################################################################################
# Step 2: Create EKS Cluster (intentionally weak config)
# - No logging (triggers eksClusterLogging, eksClusterLoggingIncomplete)
# - No encryption (triggers eksSecretsEncryption, eksSecretsEncryptionNoKMS)
# - Public endpoint (triggers eksEndpointPublicAccess)
# - No add-ons (triggers eksNoKarpenter, eksNoManagedStorageDrivers)
################################################################################

echo -e "\n${GREEN}=== Step 2: Creating EKS Cluster ===${NC}"
echo "This will take 10-15 minutes..."

aws eks create-cluster \
    --name "$CLUSTER_NAME" \
    --role-arn "$ROLE_ARN" \
    --resources-vpc-config "subnetIds=$SUBNET_1,$SUBNET_2,endpointPublicAccess=true,endpointPrivateAccess=false" \
    --tags Purpose=EksSimulation \
    --region "$REGION" > /dev/null

log_resource "EKS_CLUSTER:$CLUSTER_NAME"
echo -e "${GREEN}✓ Cluster creation initiated: $CLUSTER_NAME${NC}"

echo -e "${YELLOW}Waiting for cluster to become ACTIVE...${NC}"
aws eks wait cluster-active \
    --name "$CLUSTER_NAME" \
    --region "$REGION"
echo -e "${GREEN}✓ Cluster is ACTIVE${NC}"

################################################################################
# Step 3: Create Node Group (single AZ, ON_DEMAND, no autoscaling)
# Triggers: eksNodeGroupSingleAZ, eksNoSpotInstances, eksNoAutoscaling
################################################################################

echo -e "\n${GREEN}=== Step 3: Creating Node Group (single AZ, on-demand) ===${NC}"

aws eks create-nodegroup \
    --cluster-name "$CLUSTER_NAME" \
    --nodegroup-name "$NG_NAME" \
    --subnets "$SUBNET_1" \
    --node-role "$NG_ROLE_ARN" \
    --capacity-type ON_DEMAND \
    --scaling-config minSize=1,maxSize=1,desiredSize=1 \
    --instance-types t3.medium \
    --tags Purpose=EksSimulation \
    --region "$REGION" > /dev/null

log_resource "EKS_NODEGROUP:$CLUSTER_NAME:$NG_NAME"
echo -e "${GREEN}✓ Node group creation initiated: $NG_NAME${NC}"

echo -e "${YELLOW}Waiting for node group to become ACTIVE...${NC}"
aws eks wait nodegroup-active \
    --cluster-name "$CLUSTER_NAME" \
    --nodegroup-name "$NG_NAME" \
    --region "$REGION"
echo -e "${GREEN}✓ Node group is ACTIVE${NC}"

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
echo "  ✓ Cluster Role:    $ROLE_NAME"
echo "  ✓ NG Role:         $NG_ROLE_NAME"
echo "  ✓ Cluster:         $CLUSTER_NAME"
echo "  ✓ Node Group:      $NG_NAME (single AZ, ON_DEMAND)"
echo ""
echo "Next steps:"
echo "  1. Run screener:"
echo "     cd /Users/kuettai/Documents/project/ssvsprowler/service-screener-v2"
echo "     python main.py --services eks --regions $REGION --sequential 1 --beta 1"
echo ""
echo "  2. Cleanup when done:"
echo "     ./cleanup_test_resources.sh $OUTPUT_FILE --region $REGION"
echo ""
echo -e "${RED}IMPORTANT: ~\$0.10/hour (control plane) + node costs. Clean up promptly!${NC}"

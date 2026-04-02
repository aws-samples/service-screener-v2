#!/bin/bash

################################################################################
# EKS Service Review - Test Resource Cleanup Script
#
# Purpose: Clean up EKS test resources created by create_test_resources.sh
#
# Prerequisites:
#   - AWS CLI installed and configured
#   - IAM permissions for EKS, EC2, IAM
#   - Resource list file from create_test_resources.sh
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

set -e  # Exit on error
set -u  # Exit on undefined variable

# Default values
REGION="us-east-1"
FORCE=false
RESOURCE_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region)
            REGION="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'
            exit 0
            ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then
                RESOURCE_FILE="$1"
                shift
            else
                echo -e "${RED}Error: Unknown option $1${NC}"
                echo "Use --help for usage information"
                exit 1
            fi
            ;;
    esac
done

# Validate resource file
if [ -z "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file required${NC}"
    echo "Usage: $0 <resource_file> [OPTIONS]"
    echo "Use --help for usage information"
    exit 1
fi

if [ ! -f "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file not found: $RESOURCE_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}=== EKS Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo "Resource file: $RESOURCE_FILE"
echo ""

# Read resources from file
RESOURCES=()
while IFS= read -r line; do
    RESOURCES+=("$line")
done < "$RESOURCE_FILE"

# Count resources
CLUSTER_COUNT=$(grep -c "^EKS_CLUSTER:" "$RESOURCE_FILE" || true)
NODEGROUP_COUNT=$(grep -c "^EKS_NODEGROUP:" "$RESOURCE_FILE" || true)
ROLE_COUNT=$(grep -c "^IAM_ROLE:" "$RESOURCE_FILE" || true)

echo "Resources to delete:"
echo "  - EKS Clusters: $CLUSTER_COUNT"
echo "  - EKS Node Groups: $NODEGROUP_COUNT"
echo "  - IAM Roles: $ROLE_COUNT"
echo ""

# Confirmation prompt
if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}WARNING: This will delete all resources listed above.${NC}"
    read -p "Are you sure you want to continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Cleanup cancelled."
        exit 0
    fi
fi

# Function to wait for node group deletion
wait_for_nodegroup_deletion() {
    local cluster_name="$1"
    local nodegroup_name="$2"
    
    echo -e "${YELLOW}Waiting for node group ${nodegroup_name} to be deleted...${NC}"
    
    while true; do
        STATUS=$(aws eks describe-nodegroup \
            --cluster-name "${cluster_name}" \
            --nodegroup-name "${nodegroup_name}" \
            --region "$REGION" \
            --query 'nodegroup.status' \
            --output text 2>/dev/null || echo "DELETED")
        
        if [ "$STATUS" = "DELETED" ]; then
            echo -e "${GREEN}Node group ${nodegroup_name} deleted${NC}"
            break
        fi
        
        echo "Status: $STATUS - waiting..."
        sleep 15
    done
}

# Function to wait for cluster deletion
wait_for_cluster_deletion() {
    local cluster_name="$1"
    
    echo -e "${YELLOW}Waiting for cluster ${cluster_name} to be deleted...${NC}"
    
    while true; do
        STATUS=$(aws eks describe-cluster \
            --name "${cluster_name}" \
            --region "$REGION" \
            --query 'cluster.status' \
            --output text 2>/dev/null || echo "DELETED")
        
        if [ "$STATUS" = "DELETED" ]; then
            echo -e "${GREEN}Cluster ${cluster_name} deleted${NC}"
            break
        fi
        
        echo "Status: $STATUS - waiting..."
        sleep 15
    done
}

################################################################################
# Step 1: Delete Node Groups
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting Node Groups ===${NC}"

for resource in "${RESOURCES[@]}"; do
    if [[ $resource == EKS_NODEGROUP:* ]]; then
        # Parse: EKS_NODEGROUP:cluster-name:nodegroup-name
        IFS=':' read -ra PARTS <<< "$resource"
        CLUSTER_NAME="${PARTS[1]}"
        NODEGROUP_NAME="${PARTS[2]}"
        
        echo "Deleting node group: $NODEGROUP_NAME in cluster: $CLUSTER_NAME"
        
        aws eks delete-nodegroup \
            --cluster-name "$CLUSTER_NAME" \
            --nodegroup-name "$NODEGROUP_NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
        
        # Wait for deletion to complete
        wait_for_nodegroup_deletion "$CLUSTER_NAME" "$NODEGROUP_NAME"
    fi
done

echo -e "${GREEN}✓ All node groups deleted${NC}"

################################################################################
# Step 2: Delete EKS Clusters
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting EKS Clusters ===${NC}"

for resource in "${RESOURCES[@]}"; do
    if [[ $resource == EKS_CLUSTER:* ]]; then
        # Parse: EKS_CLUSTER:cluster-name
        CLUSTER_NAME="${resource#EKS_CLUSTER:}"
        
        echo "Deleting cluster: $CLUSTER_NAME"
        
        aws eks delete-cluster \
            --name "$CLUSTER_NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
        
        # Wait for deletion to complete
        wait_for_cluster_deletion "$CLUSTER_NAME"
    fi
done

echo -e "${GREEN}✓ All clusters deleted${NC}"

################################################################################
# Step 3: Delete IAM Roles
################################################################################

echo -e "\n${GREEN}=== Step 3: Deleting IAM Roles ===${NC}"

for resource in "${RESOURCES[@]}"; do
    if [[ $resource == IAM_ROLE:* ]]; then
        # Parse: IAM_ROLE:role-name
        ROLE_NAME="${resource#IAM_ROLE:}"
        
        echo "Deleting IAM role: $ROLE_NAME"
        
        # Detach all policies first
        POLICIES=$(aws iam list-attached-role-policies \
            --role-name "$ROLE_NAME" \
            --region "$REGION" \
            --query 'AttachedPolicies[].PolicyArn' \
            --output text 2>/dev/null || true)
        
        for policy in $POLICIES; do
            echo "  Detaching policy: $policy"
            aws iam detach-role-policy \
                --role-name "$ROLE_NAME" \
                --policy-arn "$policy" \
                --region "$REGION" 2>/dev/null || true
        done
        
        # Delete the role
        aws iam delete-role \
            --role-name "$ROLE_NAME" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done

echo -e "${GREEN}✓ All IAM roles deleted${NC}"

################################################################################
# Step 4: Clean up temporary files
################################################################################

echo -e "\n${GREEN}=== Step 4: Cleaning up temporary files ===${NC}"

rm -f /tmp/eks-trust-policy.json
rm -f /tmp/ng-trust-policy.json

echo -e "${GREEN}✓ Temporary files cleaned up${NC}"

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "All test resources have been deleted:"
echo "  ✓ $NODEGROUP_COUNT node groups"
echo "  ✓ $CLUSTER_COUNT clusters"
echo "  ✓ $ROLE_COUNT IAM roles"
echo ""
echo -e "${YELLOW}Note: You can now delete the resource file: $RESOURCE_FILE${NC}"
echo ""
echo -e "${GREEN}Cleanup successful!${NC}"

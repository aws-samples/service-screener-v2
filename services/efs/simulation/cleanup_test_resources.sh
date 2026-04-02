#!/bin/bash

# EFS Test Resources Cleanup Script
# This script removes all test resources created by create_test_resources.sh
#
# Usage:
#   1. Source the test_resources.env file: source test_resources.env
#   2. Run this script: ./cleanup_test_resources.sh
#
# Or provide resource IDs as environment variables

set -e

REGION="${AWS_REGION:-${REGION:-us-east-1}}"

echo "=========================================="
echo "EFS Service Screener - Test Resource Cleanup"
echo "Region: $REGION"
echo "=========================================="

# Check if resource IDs are provided
if [ -z "$FS1_ID" ] && [ -z "$FS2_ID" ] && [ -z "$FS3_ID" ]; then
    echo "Error: No file system IDs provided"
    echo ""
    echo "Please either:"
    echo "  1. Source test_resources.env: source test_resources.env"
    echo "  2. Set environment variables manually"
    echo ""
    exit 1
fi

# Function to delete resource with error handling
delete_resource() {
    local resource_type=$1
    local resource_id=$2
    local delete_command=$3
    
    if [ -z "$resource_id" ]; then
        return
    fi
    
    echo "Deleting $resource_type: $resource_id"
    if eval "$delete_command" 2>/dev/null; then
        echo "  ✓ Deleted successfully"
    else
        echo "  ⚠ Failed to delete (may not exist or already deleted)"
    fi
}

# Function to wait for resource deletion
wait_for_deletion() {
    local check_command=$1
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if ! eval "$check_command" 2>/dev/null; then
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    return 1
}

# ========================================
# Delete File System 1 Resources
# ========================================
if [ -n "$FS1_ID" ]; then
    echo ""
    echo "Cleaning up File System 1: $FS1_ID"
    echo "----------------------------------------"
    
    # Delete replication configuration
    echo "1. Deleting replication configuration..."
    aws efs delete-replication-configuration \
        --source-file-system-id $FS1_ID \
        --region $REGION 2>/dev/null || echo "  ⚠ No replication to delete"
    
    # Delete access point
    if [ -n "$AP1_ID" ]; then
        delete_resource "Access Point" "$AP1_ID" \
            "aws efs delete-access-point --access-point-id $AP1_ID --region $REGION"
    fi
    
    # Delete file system policy
    echo "2. Deleting file system policy..."
    aws efs delete-file-system-policy \
        --file-system-id $FS1_ID \
        --region $REGION 2>/dev/null || echo "  ⚠ No policy to delete"
    
    # Delete mount target
    if [ -n "$MT1_ID" ]; then
        delete_resource "Mount Target" "$MT1_ID" \
            "aws efs delete-mount-target --mount-target-id $MT1_ID --region $REGION"
        echo "  Waiting for mount target deletion..."
        wait_for_deletion "aws efs describe-mount-targets --mount-target-id $MT1_ID --region $REGION"
    fi
    
    # Delete file system
    delete_resource "File System" "$FS1_ID" \
        "aws efs delete-file-system --file-system-id $FS1_ID --region $REGION"
fi

# ========================================
# Delete File System 2 Resources
# ========================================
if [ -n "$FS2_ID" ]; then
    echo ""
    echo "Cleaning up File System 2: $FS2_ID"
    echo "----------------------------------------"
    
    # Delete mount target
    if [ -n "$MT2_ID" ]; then
        delete_resource "Mount Target" "$MT2_ID" \
            "aws efs delete-mount-target --mount-target-id $MT2_ID --region $REGION"
        echo "  Waiting for mount target deletion..."
        wait_for_deletion "aws efs describe-mount-targets --mount-target-id $MT2_ID --region $REGION"
    fi
    
    # Delete file system
    delete_resource "File System" "$FS2_ID" \
        "aws efs delete-file-system --file-system-id $FS2_ID --region $REGION"
fi

# ========================================
# Delete File System 3 Resources
# ========================================
if [ -n "$FS3_ID" ]; then
    echo ""
    echo "Cleaning up File System 3: $FS3_ID"
    echo "----------------------------------------"
    
    # Delete file system policy
    echo "1. Deleting file system policy..."
    aws efs delete-file-system-policy \
        --file-system-id $FS3_ID \
        --region $REGION 2>/dev/null || echo "  ⚠ No policy to delete"
    
    # Delete mount target
    if [ -n "$MT3_ID" ]; then
        delete_resource "Mount Target" "$MT3_ID" \
            "aws efs delete-mount-target --mount-target-id $MT3_ID --region $REGION"
        echo "  Waiting for mount target deletion..."
        wait_for_deletion "aws efs describe-mount-targets --mount-target-id $MT3_ID --region $REGION"
    fi
    
    # Delete file system
    delete_resource "File System" "$FS3_ID" \
        "aws efs delete-file-system --file-system-id $FS3_ID --region $REGION"
fi

# Wait for all file systems to be deleted
echo ""
echo "Waiting for file systems to be fully deleted..."
sleep 10

# ========================================
# Delete VPC Resources
# ========================================
echo ""
echo "Cleaning up VPC Resources"
echo "----------------------------------------"

# Delete security group
if [ -n "$SG_ID" ]; then
    delete_resource "Security Group" "$SG_ID" \
        "aws ec2 delete-security-group --group-id $SG_ID --region $REGION"
fi

# Delete subnet
if [ -n "$SUBNET_ID" ]; then
    delete_resource "Subnet" "$SUBNET_ID" \
        "aws ec2 delete-subnet --subnet-id $SUBNET_ID --region $REGION"
fi

# Delete VPC
if [ -n "$VPC_ID" ]; then
    delete_resource "VPC" "$VPC_ID" \
        "aws ec2 delete-vpc --vpc-id $VPC_ID --region $REGION"
fi

# ========================================
# Summary
# ========================================
echo ""
echo "=========================================="
echo "✅ Cleanup Complete"
echo "=========================================="
echo ""
echo "All test resources have been deleted."
echo ""
echo "If you saved resource IDs in test_resources.env, you can delete that file:"
echo "  rm test_resources.env"
echo ""

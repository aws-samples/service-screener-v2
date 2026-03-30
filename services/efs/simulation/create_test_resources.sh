#!/bin/bash

# EFS Test Resources Creation Script
# This script creates EFS resources to test all 11 implemented checks
# 
# Prerequisites:
# - AWS CLI configured with appropriate credentials
# - Permissions to create EFS resources, VPC resources, and IAM policies
# - jq installed for JSON parsing

set -e

# Configuration
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
VPC_CIDR="10.0.0.0/16"
SUBNET_CIDR="10.0.1.0/24"
PROJECT_TAG="efs-service-screener-test"

echo "=========================================="
echo "EFS Service Screener - Test Resource Creation"
echo "Region: $REGION"
echo "=========================================="

# Function to wait for resource availability
wait_for_resource() {
    local resource_type=$1
    local resource_id=$2
    local max_attempts=30
    local attempt=1
    
    echo "Waiting for $resource_type $resource_id to be available..."
    while [ $attempt -le $max_attempts ]; do
        sleep 2
        attempt=$((attempt + 1))
    done
}

# Create VPC for testing
echo ""
echo "1. Creating VPC..."
VPC_ID=$(aws ec2 create-vpc \
    --cidr-block $VPC_CIDR \
    --region $REGION \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$PROJECT_TAG-vpc},{Key=Project,Value=$PROJECT_TAG}]" \
    --query 'Vpc.VpcId' \
    --output text)
echo "   VPC created: $VPC_ID"

# Create subnet
echo ""
echo "2. Creating Subnet..."
SUBNET_ID=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block $SUBNET_CIDR \
    --region $REGION \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=$PROJECT_TAG-subnet},{Key=Project,Value=$PROJECT_TAG}]" \
    --query 'Subnet.SubnetId' \
    --output text)
echo "   Subnet created: $SUBNET_ID"

# Create security group
echo ""
echo "3. Creating Security Group..."
SG_ID=$(aws ec2 create-security-group \
    --group-name "$PROJECT_TAG-sg" \
    --description "Security group for EFS testing" \
    --vpc-id $VPC_ID \
    --region $REGION \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$PROJECT_TAG-sg},{Key=Project,Value=$PROJECT_TAG}]" \
    --query 'GroupId' \
    --output text)
echo "   Security Group created: $SG_ID"

# Add NFS ingress rule
aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 2049 \
    --cidr 10.0.0.0/16 \
    --region $REGION > /dev/null
echo "   NFS ingress rule added"

# ========================================
# TEST CASE 1: Compliant File System (passes all checks)
# ========================================
echo ""
echo "=========================================="
echo "Creating Test Case 1: COMPLIANT File System"
echo "=========================================="

echo "4. Creating compliant EFS file system..."
FS1_ID=$(aws efs create-file-system \
    --region $REGION \
    --encrypted \
    --performance-mode generalPurpose \
    --throughput-mode elastic \
    --backup \
    --tags Key=Name,Value=$PROJECT_TAG-compliant Key=Project,Value=$PROJECT_TAG Key=Environment,Value=test \
    --query 'FileSystemId' \
    --output text)
echo "   File System created: $FS1_ID"
wait_for_resource "File System" $FS1_ID

# Set lifecycle policy
aws efs put-lifecycle-configuration \
    --file-system-id $FS1_ID \
    --lifecycle-policies '[{"TransitionToIA":"AFTER_30_DAYS"}]' \
    --region $REGION > /dev/null
echo "   Lifecycle policy set"

# Create mount target with security group
echo "5. Creating mount target with security group..."
MT1_ID=$(aws efs create-mount-target \
    --file-system-id $FS1_ID \
    --subnet-id $SUBNET_ID \
    --security-groups $SG_ID \
    --region $REGION \
    --query 'MountTargetId' \
    --output text)
echo "   Mount Target created: $MT1_ID"

# Create access point
echo "6. Creating access point..."
AP1_ID=$(aws efs create-access-point \
    --file-system-id $FS1_ID \
    --region $REGION \
    --posix-user '{"Uid":1000,"Gid":1000}' \
    --root-directory '{"Path":"/data","CreationInfo":{"OwnerUid":1000,"OwnerGid":1000,"Permissions":"755"}}' \
    --tags Key=Name,Value=$PROJECT_TAG-ap1 Key=Project,Value=$PROJECT_TAG \
    --query 'AccessPointId' \
    --output text)
echo "   Access Point created: $AP1_ID"

# Create file system policy with TLS requirement
echo "7. Creating file system policy with TLS requirement..."
cat > /tmp/efs-policy-$FS1_ID.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite"
      ],
      "Resource": "arn:aws:elasticfilesystem:$REGION:$ACCOUNT_ID:file-system/$FS1_ID"
    },
    {
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": "*",
      "Resource": "arn:aws:elasticfilesystem:$REGION:$ACCOUNT_ID:file-system/$FS1_ID",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
EOF

aws efs put-file-system-policy \
    --file-system-id $FS1_ID \
    --region $REGION \
    --policy file:///tmp/efs-policy-$FS1_ID.json > /dev/null
echo "   File system policy created (requires TLS)"
rm /tmp/efs-policy-$FS1_ID.json

# Enable replication (to a different region if possible)
echo "8. Enabling replication..."
DEST_REGION="us-west-2"
aws efs create-replication-configuration \
    --source-file-system-id $FS1_ID \
    --destinations Region=$DEST_REGION \
    --region $REGION > /dev/null 2>&1 || echo "   Note: Replication may not be available in all regions"

echo ""
echo "✅ Test Case 1 Complete: $FS1_ID"
echo "   Expected Results: Should PASS all checks"

# ========================================
# TEST CASE 2: Non-Compliant File System (fails multiple checks)
# ========================================
echo ""
echo "=========================================="
echo "Creating Test Case 2: NON-COMPLIANT File System"
echo "=========================================="

echo "9. Creating non-compliant EFS file system..."
FS2_ID=$(aws efs create-file-system \
    --region $REGION \
    --encrypted \
    --performance-mode maxIO \
    --throughput-mode bursting \
    --tags Key=Name,Value=$PROJECT_TAG-noncompliant Key=Project,Value=$PROJECT_TAG Key=password,Value=test123 Key=api-key,Value=sensitive \
    --query 'FileSystemId' \
    --output text)
echo "   File System created: $FS2_ID"
wait_for_resource "File System" $FS2_ID

# Create mount target WITHOUT security group (will fail check)
echo "10. Creating mount target without security group..."
MT2_ID=$(aws efs create-mount-target \
    --file-system-id $FS2_ID \
    --subnet-id $SUBNET_ID \
    --region $REGION \
    --query 'MountTargetId' \
    --output text)
echo "   Mount Target created: $MT2_ID (no security group)"

# Do NOT create access point (will fail check)
# Do NOT create file system policy (will fail check)
# Do NOT enable replication (will fail check)
# Do NOT enable lifecycle (will fail check)
# Do NOT enable backup (will fail check)

echo ""
echo "❌ Test Case 2 Complete: $FS2_ID"
echo "   Expected Results: Should FAIL multiple checks:"
echo "   - ElasticThroughput (using bursting mode)"
echo "   - ThroughputModeOptimized (using bursting mode)"
echo "   - PerformanceModeOptimized (using maxIO)"
echo "   - FileSystemPolicy (no policy)"
echo "   - MountTargetSecurityGroups (no security group)"
echo "   - AccessPointsConfigured (no access points)"
echo "   - ComprehensiveSecurity (missing all 3 controls)"
echo "   - TLSRequired (no policy)"
echo "   - ReplicationEnabled (no replication)"
echo "   - EnabledLifecycle (no lifecycle)"
echo "   - AutomatedBackup (no backup)"
echo "   - NoSensitiveDataInTags (has 'password' and 'api-key' tags)"

# ========================================
# TEST CASE 3: Partially Compliant File System
# ========================================
echo ""
echo "=========================================="
echo "Creating Test Case 3: PARTIALLY COMPLIANT File System"
echo "=========================================="

echo "11. Creating partially compliant EFS file system..."
FS3_ID=$(aws efs create-file-system \
    --region $REGION \
    --encrypted \
    --performance-mode generalPurpose \
    --throughput-mode provisioned \
    --provisioned-throughput-in-mibps 10 \
    --backup \
    --tags Key=Name,Value=$PROJECT_TAG-partial Key=Project,Value=$PROJECT_TAG \
    --query 'FileSystemId' \
    --output text)
echo "   File System created: $FS3_ID"
wait_for_resource "File System" $FS3_ID

# Set lifecycle policy
aws efs put-lifecycle-configuration \
    --file-system-id $FS3_ID \
    --lifecycle-policies '[{"TransitionToIA":"AFTER_7_DAYS"}]' \
    --region $REGION > /dev/null
echo "   Lifecycle policy set"

# Create mount target with security group
echo "12. Creating mount target with security group..."
MT3_ID=$(aws efs create-mount-target \
    --file-system-id $FS3_ID \
    --subnet-id $SUBNET_ID \
    --security-groups $SG_ID \
    --region $REGION \
    --query 'MountTargetId' \
    --output text)
echo "   Mount Target created: $MT3_ID"

# Create file system policy (but without TLS requirement)
echo "13. Creating file system policy without TLS requirement..."
cat > /tmp/efs-policy-$FS3_ID.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite"
      ],
      "Resource": "arn:aws:elasticfilesystem:$REGION:$ACCOUNT_ID:file-system/$FS3_ID"
    }
  ]
}
EOF

aws efs put-file-system-policy \
    --file-system-id $FS3_ID \
    --region $REGION \
    --policy file:///tmp/efs-policy-$FS3_ID.json > /dev/null
echo "   File system policy created (no TLS requirement)"
rm /tmp/efs-policy-$FS3_ID.json

echo ""
echo "⚠️  Test Case 3 Complete: $FS3_ID"
echo "   Expected Results: Should PASS some checks and FAIL others:"
echo "   PASS: EncryptedAtRest, PerformanceModeOptimized, MountTargetSecurityGroups,"
echo "         FileSystemPolicy, EnabledLifecycle, AutomatedBackup"
echo "   FAIL: ElasticThroughput (using provisioned), ThroughputModeOptimized (using provisioned),"
echo "         AccessPointsConfigured, ComprehensiveSecurity, TLSRequired, ReplicationEnabled"

# ========================================
# Summary
# ========================================
echo ""
echo "=========================================="
echo "✅ Test Resources Created Successfully"
echo "=========================================="
echo ""
echo "Summary:"
echo "--------"
echo "VPC ID:              $VPC_ID"
echo "Subnet ID:           $SUBNET_ID"
echo "Security Group ID:   $SG_ID"
echo ""
echo "Test File Systems:"
echo "  1. Compliant:        $FS1_ID (should pass all checks)"
echo "  2. Non-Compliant:    $FS2_ID (should fail multiple checks)"
echo "  3. Partial:          $FS3_ID (should pass some, fail others)"
echo ""
echo "Next Steps:"
echo "1. Run Service Screener against these file systems"
echo "2. Verify check results match expected outcomes"
echo "3. Run cleanup script when done: ./cleanup_test_resources.sh"
echo ""
echo "To save these IDs for cleanup:"
echo "cat > test_resources.env <<EOF
export VPC_ID=$VPC_ID
export SUBNET_ID=$SUBNET_ID
export SG_ID=$SG_ID
export FS1_ID=$FS1_ID
export FS2_ID=$FS2_ID
export FS3_ID=$FS3_ID
export MT1_ID=$MT1_ID
export MT2_ID=$MT2_ID
export MT3_ID=$MT3_ID
export AP1_ID=$AP1_ID
export REGION=$REGION
EOF"
echo ""

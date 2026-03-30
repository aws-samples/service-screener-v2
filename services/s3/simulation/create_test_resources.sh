#!/bin/bash

# S3 Test Resources Creation Script
# This script creates test S3 resources to validate the new Tier 1, 2, and 3 checks
# 
# Prerequisites:
# - AWS CLI configured with appropriate credentials
# - Permissions to create S3 buckets, policies, and S3Control configurations
# - jq installed for JSON parsing

set -e

# Configuration
REGION="${AWS_REGION:-us-east-1}"
BUCKET_PREFIX="ss-test-s3"
TIMESTAMP=$(date +%s)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}S3 Test Resources Creation${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Region: $REGION"
echo "Timestamp: $TIMESTAMP"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Get AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
print_status "AWS Account ID: $ACCOUNT_ID"

# Save and temporarily disable account-level S3 Block Public Access
# (needed for test cases that require public bucket policies)
ORIG_PUBLIC_BLOCK=$(aws s3control get-public-access-block --account-id "$ACCOUNT_ID" --region "$REGION" 2>/dev/null || echo "NONE")
if [ "$ORIG_PUBLIC_BLOCK" != "NONE" ]; then
    print_warning "Temporarily disabling account-level S3 Block Public Access for testing"
    aws s3control put-public-access-block \
        --account-id "$ACCOUNT_ID" \
        --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" \
        --region "$REGION"
fi

# Store created resource IDs
RESOURCE_IDS_FILE="simulation/test_resources_${TIMESTAMP}.json"

# Initialize JSON file
echo "{" > "$RESOURCE_IDS_FILE"
echo "  \"timestamp\": \"$TIMESTAMP\"," >> "$RESOURCE_IDS_FILE"
echo "  \"region\": \"$REGION\"," >> "$RESOURCE_IDS_FILE"
echo "  \"account_id\": \"$ACCOUNT_ID\"," >> "$RESOURCE_IDS_FILE"
echo "  \"resources\": {" >> "$RESOURCE_IDS_FILE"

# ========================================
# SECURITY CHECKS
# ========================================

# ========================================
# Test Case 1: Bucket with SSE Encryption (PASS)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 1: Bucket with SSE Encryption (PASS)${NC}"

BUCKET1="${BUCKET_PREFIX}-sse-enabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET1" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET1" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET1"

# Enable SSE-S3
aws s3api put-bucket-encryption \
    --bucket "$BUCKET1" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
    --region "$REGION"

print_status "Enabled SSE-S3 on $BUCKET1"
echo "    \"bucket_sse_enabled\": \"$BUCKET1\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 2: Bucket without SSE Encryption (FAIL)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 2: Bucket without SSE Encryption (FAIL)${NC}"

BUCKET2="${BUCKET_PREFIX}-sse-disabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET2" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET2" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET2 (no encryption)"
echo "    \"bucket_sse_disabled\": \"$BUCKET2\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 3: Bucket with SSE-KMS (PASS)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 3: Bucket with SSE-KMS (PASS)${NC}"

BUCKET3="${BUCKET_PREFIX}-kms-enabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET3" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET3" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET3"

# Enable SSE-KMS (using default aws/s3 key)
aws s3api put-bucket-encryption \
    --bucket "$BUCKET3" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}' \
    --region "$REGION"

print_status "Enabled SSE-KMS on $BUCKET3"
echo "    \"bucket_kms_enabled\": \"$BUCKET3\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 4: Bucket with ACLs (FAIL)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 4: Bucket with ACLs (FAIL)${NC}"

BUCKET4="${BUCKET_PREFIX}-with-acls-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET4" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET4" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET4 (with ACLs enabled)"
echo "    \"bucket_with_acls\": \"$BUCKET4\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 5: Bucket with ACL Enforcement (PASS)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 5: Bucket with ACL Enforcement (PASS)${NC}"

BUCKET1="${BUCKET_PREFIX}-acl-enforced-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET1" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET1" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET1"

# Set bucket owner enforced
aws s3api put-bucket-ownership-controls \
    --bucket "$BUCKET1" \
    --ownership-controls Rules='[{ObjectOwnership=BucketOwnerEnforced}]' \
    --region "$REGION"

print_status "Set BucketOwnerEnforced on $BUCKET1"
echo "    \"bucket_acl_enforced\": \"$BUCKET1\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 2: Bucket without ACL Enforcement (FAIL)
# ========================================
echo -e "\n${YELLOW}[TIER 1] Creating Test Case 2: Bucket without ACL Enforcement (FAIL)${NC}"

BUCKET2="${BUCKET_PREFIX}-acl-not-enforced-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET2" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET2" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET2 (no ownership controls)"
echo "    \"bucket_acl_not_enforced\": \"$BUCKET2\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 3: Bucket with Transfer Acceleration (PASS)
# ========================================
echo -e "\n${YELLOW}[TIER 1] Creating Test Case 3: Bucket with Transfer Acceleration (PASS)${NC}"

BUCKET3="${BUCKET_PREFIX}-acceleration-enabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET3" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET3" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET3"

# Enable transfer acceleration
aws s3api put-bucket-accelerate-configuration \
    --bucket "$BUCKET3" \
    --accelerate-configuration Status=Enabled \
    --region "$REGION"

print_status "Enabled transfer acceleration on $BUCKET3"
echo "    \"bucket_acceleration_enabled\": \"$BUCKET3\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 4: Bucket without Transfer Acceleration (FAIL)
# ========================================
echo -e "\n${YELLOW}[TIER 1] Creating Test Case 4: Bucket without Transfer Acceleration (FAIL)${NC}"

BUCKET4="${BUCKET_PREFIX}-acceleration-disabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET4" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET4" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET4 (no acceleration)"
echo "    \"bucket_acceleration_disabled\": \"$BUCKET4\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 5: Bucket with CloudWatch Metrics (PASS)
# ========================================
echo -e "\n${YELLOW}[TIER 1] Creating Test Case 5: Bucket with CloudWatch Metrics (PASS)${NC}"

BUCKET5="${BUCKET_PREFIX}-metrics-enabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET5" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET5" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET5"

# Configure CloudWatch metrics
aws s3api put-bucket-metrics-configuration \
    --bucket "$BUCKET5" \
    --id EntireBucket \
    --metrics-configuration '{"Id":"EntireBucket"}' \
    --region "$REGION"

print_status "Configured CloudWatch metrics on $BUCKET5"
echo "    \"bucket_metrics_enabled\": \"$BUCKET5\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 6: Bucket without CloudWatch Metrics (FAIL)
# ========================================
echo -e "\n${YELLOW}[TIER 1] Creating Test Case 6: Bucket without CloudWatch Metrics (FAIL)${NC}"

BUCKET6="${BUCKET_PREFIX}-metrics-disabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET6" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET6" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET6 (no metrics)"
echo "    \"bucket_metrics_disabled\": \"$BUCKET6\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# TIER 2 CHECKS
# ========================================

# ========================================
# Test Case 7: Bucket with Safe Policy (PASS)
# ========================================
echo -e "\n${YELLOW}[TIER 2] Creating Test Case 7: Bucket with Safe Policy (PASS)${NC}"

BUCKET7="${BUCKET_PREFIX}-safe-policy-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET7" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET7" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET7"

# Add safe policy with specific principal
SAFE_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SpecificPrincipalAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET7}/*"
    }
  ]
}
EOF
)

aws s3api put-bucket-policy \
    --bucket "$BUCKET7" \
    --policy "$SAFE_POLICY" \
    --region "$REGION"

print_status "Added safe policy to $BUCKET7"
echo "    \"bucket_safe_policy\": \"$BUCKET7\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 8: Bucket with Wildcard Policy (FAIL)
# ========================================
echo -e "\n${YELLOW}[TIER 2] Creating Test Case 8: Bucket with Wildcard Policy (FAIL)${NC}"

BUCKET8="${BUCKET_PREFIX}-wildcard-policy-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET8" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET8" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET8"

# Disable public access block to allow wildcard policy
aws s3api delete-public-access-block \
    --bucket "$BUCKET8" \
    --region "$REGION" 2>/dev/null

# Add wildcard policy
WILDCARD_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WildcardPrincipal",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::${BUCKET8}/*"
    }
  ]
}
EOF
)

aws s3api put-bucket-policy \
    --bucket "$BUCKET8" \
    --policy "$WILDCARD_POLICY" \
    --region "$REGION"

print_status "Added wildcard policy to $BUCKET8"
echo "    \"bucket_wildcard_policy\": \"$BUCKET8\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 9: Bucket Blocking SSE-C (PASS)
# ========================================
echo -e "\n${YELLOW}[TIER 2] Creating Test Case 9: Bucket Blocking SSE-C (PASS)${NC}"

BUCKET9="${BUCKET_PREFIX}-ssec-blocked-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET9" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET9" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET9"

# Add policy blocking SSE-C
SSEC_BLOCK_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySSEC",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET9}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption-customer-algorithm": "AES256"
        }
      }
    }
  ]
}
EOF
)

aws s3api put-bucket-policy \
    --bucket "$BUCKET9" \
    --policy "$SSEC_BLOCK_POLICY" \
    --region "$REGION"

# Set default encryption to SSE-S3
aws s3api put-bucket-encryption \
    --bucket "$BUCKET9" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
    --region "$REGION"

print_status "Configured SSE-C blocking on $BUCKET9"
echo "    \"bucket_ssec_blocked\": \"$BUCKET9\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 10: Bucket Allowing SSE-C (FAIL)
# ========================================
echo -e "\n${YELLOW}[TIER 2] Creating Test Case 10: Bucket Allowing SSE-C (FAIL)${NC}"

BUCKET10="${BUCKET_PREFIX}-ssec-allowed-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET10" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET10" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET10 (no SSE-C blocking)"
echo "    \"bucket_ssec_allowed\": \"$BUCKET10\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 11: Storage Lens Configuration (PASS)
# ========================================
echo -e "\n${YELLOW}[TIER 2] Creating Test Case 11: Storage Lens Configuration (PASS)${NC}"

STORAGE_LENS_ID="ss-test-storage-lens-${TIMESTAMP}"

STORAGE_LENS_CONFIG=$(cat <<EOF
{
  "Id": "${STORAGE_LENS_ID}",
  "AccountLevel": {
    "ActivityMetrics": {
      "IsEnabled": true
    },
    "BucketLevel": {}
  },
  "IsEnabled": true
}
EOF
)

if aws s3control put-storage-lens-configuration \
    --account-id "$ACCOUNT_ID" \
    --config-id "$STORAGE_LENS_ID" \
    --storage-lens-configuration "$STORAGE_LENS_CONFIG" \
    --region "$REGION" 2>/dev/null; then
    print_status "Created Storage Lens configuration: $STORAGE_LENS_ID"
else
    print_warning "Storage Lens creation failed (may require specific account settings). Skipping."
fi
echo "    \"storage_lens_config\": \"$STORAGE_LENS_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 12: Public Bucket with Approval Tags (PASS)
# ========================================
echo -e "\n${YELLOW}[TIER 2] Creating Test Case 12: Public Bucket with Approval Tags (PASS)${NC}"

BUCKET12="${BUCKET_PREFIX}-public-approved-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET12" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET12" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET12"

# Disable public access block to make it public
aws s3api delete-public-access-block \
    --bucket "$BUCKET12" \
    --region "$REGION"

# Add public policy
PUBLIC_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET12}/*"
    }
  ]
}
EOF
)

aws s3api put-bucket-policy \
    --bucket "$BUCKET12" \
    --policy "$PUBLIC_POLICY" \
    --region "$REGION"

# Add approval tags
aws s3api put-bucket-tagging \
    --bucket "$BUCKET12" \
    --tagging "TagSet=[{Key=PublicAccessApproved,Value=true},{Key=ApprovalDate,Value=$(date +%Y-%m-%d)},{Key=ApprovalTicket,Value=TICKET-12345}]" \
    --region "$REGION"

print_status "Configured public bucket with approval tags: $BUCKET12"
echo "    \"bucket_public_approved\": \"$BUCKET12\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 13: Public Bucket without Approval Tags (FAIL)
# ========================================
echo -e "\n${YELLOW}[TIER 2] Creating Test Case 13: Public Bucket without Approval Tags (FAIL)${NC}"

BUCKET13="${BUCKET_PREFIX}-public-not-approved-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET13" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET13" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket: $BUCKET13"

# Disable public access block
aws s3api delete-public-access-block \
    --bucket "$BUCKET13" \
    --region "$REGION"

# Add public policy
PUBLIC_POLICY2=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET13}/*"
    }
  ]
}
EOF
)

aws s3api put-bucket-policy \
    --bucket "$BUCKET13" \
    --policy "$PUBLIC_POLICY2" \
    --region "$REGION"

print_status "Configured public bucket without approval tags: $BUCKET13"
echo "    \"bucket_public_not_approved\": \"$BUCKET13\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# TIER 3 CHECKS
# ========================================

# ========================================
# Test Case 14: Bucket with Unpredictable Name (PASS)
# ========================================
echo -e "\n${YELLOW}[TIER 3] Creating Test Case 14: Bucket with Unpredictable Name (PASS)${NC}"

# Generate random UUID-like name
RANDOM_UUID=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-z0-9' | fold -w 32 | head -n 1)
BUCKET14="${BUCKET_PREFIX}-${RANDOM_UUID}"
aws s3api create-bucket \
    --bucket "$BUCKET14" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET14" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket with unpredictable name: $BUCKET14"
echo "    \"bucket_unpredictable_name\": \"$BUCKET14\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 15: Bucket with Predictable Name (FAIL)
# ========================================
echo -e "\n${YELLOW}[TIER 3] Creating Test Case 15: Bucket with Predictable Name (FAIL)${NC}"

BUCKET15="${BUCKET_PREFIX}-bucket-001-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET15" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET15" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket with predictable name: $BUCKET15"
echo "    \"bucket_predictable_name\": \"$BUCKET15\"" >> "$RESOURCE_IDS_FILE"

# Close JSON file
echo "  }" >> "$RESOURCE_IDS_FILE"
echo "}" >> "$RESOURCE_IDS_FILE"

# ========================================
# Summary
# ========================================
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Resource Creation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Created resources saved to: $RESOURCE_IDS_FILE"
echo ""
echo -e "${YELLOW}TIER 1 Test Cases:${NC}"
echo "  1. Bucket with ACL Enforcement (PASS) - $BUCKET1"
echo "  2. Bucket without ACL Enforcement (FAIL) - $BUCKET2"
echo "  3. Bucket with Transfer Acceleration (PASS) - $BUCKET3"
echo "  4. Bucket without Transfer Acceleration (FAIL) - $BUCKET4"
echo "  5. Bucket with CloudWatch Metrics (PASS) - $BUCKET5"
echo "  6. Bucket without CloudWatch Metrics (FAIL) - $BUCKET6"
echo ""
echo -e "${YELLOW}TIER 2 Test Cases:${NC}"
echo "  7. Bucket with Safe Policy (PASS) - $BUCKET7"
echo "  8. Bucket with Wildcard Policy (FAIL) - $BUCKET8"
echo "  9. Bucket Blocking SSE-C (PASS) - $BUCKET9"
echo "  10. Bucket Allowing SSE-C (FAIL) - $BUCKET10"
echo "  11. Storage Lens Configuration (PASS) - $STORAGE_LENS_ID"
echo "  12. Public Bucket with Approval Tags (PASS) - $BUCKET12"
echo "  13. Public Bucket without Approval Tags (FAIL) - $BUCKET13"
echo ""
echo -e "${YELLOW}TIER 3 Test Cases:${NC}"
echo "  14. Bucket with Unpredictable Name (PASS) - $BUCKET14"
echo "  15. Bucket with Predictable Name (FAIL) - $BUCKET15"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Run Service Screener against these buckets"
echo "  2. Verify expected check results"
echo "  3. Run cleanup script when done: ./cleanup_test_resources.sh $TIMESTAMP"
echo ""

# ========================================
# ADDITIONAL SECURITY CHECKS
# ========================================

# ========================================
# Test Case 16: Bucket with TLS Enforced (PASS)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 16: Bucket with TLS Enforced (PASS)${NC}"

BUCKET16="${BUCKET_PREFIX}-tls-enforced-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET16" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET16" \
    --region "$REGION" 2>/dev/null

TLS_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET16}",
        "arn:aws:s3:::${BUCKET16}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
EOF
)

aws s3api put-bucket-policy \
    --bucket "$BUCKET16" \
    --policy "$TLS_POLICY" \
    --region "$REGION"

print_status "Created bucket with TLS enforced: $BUCKET16"
echo "    \"bucket_tls_enforced\": \"$BUCKET16\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 17: Bucket without TLS Enforcement (FAIL)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 17: Bucket without TLS Enforcement (FAIL)${NC}"

BUCKET17="${BUCKET_PREFIX}-no-tls-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET17" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET17" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket without TLS enforcement: $BUCKET17"
echo "    \"bucket_no_tls\": \"$BUCKET17\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 18: Bucket with Logging (PASS)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 18: Bucket with Logging (PASS)${NC}"

# Create target bucket for logs first
BUCKET18_LOGS="${BUCKET_PREFIX}-logs-target-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET18_LOGS" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET18_LOGS" \
    --region "$REGION" 2>/dev/null

# Grant log delivery permissions via bucket policy (ACLs disabled by default on new buckets)
aws s3api put-bucket-policy \
    --bucket "$BUCKET18_LOGS" \
    --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"S3ServerAccessLogsPolicy\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"logging.s3.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::${BUCKET18_LOGS}/logs/*\",\"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"${ACCOUNT_ID}\"}}}]}" \
    --region "$REGION"

BUCKET18="${BUCKET_PREFIX}-with-logging-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET18" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET18" \
    --region "$REGION" 2>/dev/null

aws s3api put-bucket-logging \
    --bucket "$BUCKET18" \
    --bucket-logging-status "{\"LoggingEnabled\":{\"TargetBucket\":\"${BUCKET18_LOGS}\",\"TargetPrefix\":\"logs/\"}}" \
    --region "$REGION"

print_status "Created bucket with logging: $BUCKET18"
echo "    \"bucket_with_logging\": \"$BUCKET18\"," >> "$RESOURCE_IDS_FILE"
echo "    \"bucket_logs_target\": \"$BUCKET18_LOGS\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 19: Bucket without Logging (FAIL)
# ========================================
echo -e "\n${YELLOW}[SECURITY] Creating Test Case 19: Bucket without Logging (FAIL)${NC}"

BUCKET19="${BUCKET_PREFIX}-no-logging-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET19" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET19" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket without logging: $BUCKET19"
echo "    \"bucket_no_logging\": \"$BUCKET19\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# RELIABILITY & RESILIENCE CHECKS
# ========================================

# ========================================
# Test Case 20: Bucket with Versioning (PASS)
# ========================================
echo -e "\n${YELLOW}[RELIABILITY] Creating Test Case 20: Bucket with Versioning (PASS)${NC}"

BUCKET20="${BUCKET_PREFIX}-versioning-enabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET20" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET20" \
    --region "$REGION" 2>/dev/null

aws s3api put-bucket-versioning \
    --bucket "$BUCKET20" \
    --versioning-configuration Status=Enabled \
    --region "$REGION"

print_status "Created bucket with versioning: $BUCKET20"
echo "    \"bucket_versioning_enabled\": \"$BUCKET20\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 21: Bucket without Versioning (FAIL)
# ========================================
echo -e "\n${YELLOW}[RELIABILITY] Creating Test Case 21: Bucket without Versioning (FAIL)${NC}"

BUCKET21="${BUCKET_PREFIX}-no-versioning-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET21" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET21" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket without versioning: $BUCKET21"
echo "    \"bucket_no_versioning\": \"$BUCKET21\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# COST OPTIMIZATION CHECKS
# ========================================

# ========================================
# Test Case 22: Bucket with Lifecycle Policy (PASS)
# ========================================
echo -e "\n${YELLOW}[COST] Creating Test Case 22: Bucket with Lifecycle Policy (PASS)${NC}"

BUCKET22="${BUCKET_PREFIX}-lifecycle-enabled-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET22" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET22" \
    --region "$REGION" 2>/dev/null

LIFECYCLE_CONFIG=$(cat <<EOF
{
  "Rules": [
    {
      "ID": "MoveToIA",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        }
      ]
    }
  ]
}
EOF
)

aws s3api put-bucket-lifecycle-configuration \
    --bucket "$BUCKET22" \
    --lifecycle-configuration "$LIFECYCLE_CONFIG" \
    --region "$REGION"

print_status "Created bucket with lifecycle policy: $BUCKET22"
echo "    \"bucket_lifecycle_enabled\": \"$BUCKET22\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 23: Bucket without Lifecycle Policy (FAIL)
# ========================================
echo -e "\n${YELLOW}[COST] Creating Test Case 23: Bucket without Lifecycle Policy (FAIL)${NC}"

BUCKET23="${BUCKET_PREFIX}-no-lifecycle-${TIMESTAMP}"
aws s3api create-bucket \
    --bucket "$BUCKET23" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || \
aws s3api create-bucket \
    --bucket "$BUCKET23" \
    --region "$REGION" 2>/dev/null

print_status "Created bucket without lifecycle policy: $BUCKET23"
echo "    \"bucket_no_lifecycle\": \"$BUCKET23\"" >> "$RESOURCE_IDS_FILE"

# Close JSON file (update the previous line to add comma)
sed -i '' 's/"bucket_predictable_name": ".*"$/"bucket_predictable_name": "'"$BUCKET15"'",/' "$RESOURCE_IDS_FILE" 2>/dev/null || \
sed -i 's/"bucket_predictable_name": ".*"$/"bucket_predictable_name": "'"$BUCKET15"'",/' "$RESOURCE_IDS_FILE"

# ========================================
# OPERATIONAL EXCELLENCE CHECKS
# ========================================
echo -e "\n${YELLOW}[OPERATIONAL] Note: Event Notification Check${NC}"
print_warning "Event notifications require SNS/SQS/Lambda setup. Skipping for basic simulation."

echo -e "\n${YELLOW}[SECURITY] Note: Object Lock Check${NC}"
print_warning "Object Lock must be enabled at bucket creation. Skipping for basic simulation."

# Update summary
echo ""
echo -e "${YELLOW}ADDITIONAL SECURITY Test Cases:${NC}"
echo "  16. Bucket with TLS Enforced (PASS) - $BUCKET16"
echo "  17. Bucket without TLS (FAIL) - $BUCKET17"
echo "  18. Bucket with Logging (PASS) - $BUCKET18"
echo "  19. Bucket without Logging (FAIL) - $BUCKET19"
echo ""
echo -e "${YELLOW}RELIABILITY Test Cases:${NC}"
echo "  20. Bucket with Versioning (PASS) - $BUCKET20"
echo "  21. Bucket without Versioning (FAIL) - $BUCKET21"
echo ""
echo -e "${YELLOW}COST OPTIMIZATION Test Cases:${NC}"
echo "  22. Bucket with Lifecycle (PASS) - $BUCKET22"
echo "  23. Bucket without Lifecycle (FAIL) - $BUCKET23"
echo ""
echo -e "${GREEN}Total: 26 test scenarios created covering all S3 checks${NC}"

# Restore account-level S3 Block Public Access
if [ "$ORIG_PUBLIC_BLOCK" != "NONE" ]; then
    print_warning "Restoring account-level S3 Block Public Access"
    aws s3control put-public-access-block \
        --account-id "$ACCOUNT_ID" \
        --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
        --region "$REGION"
    print_status "Account-level S3 Block Public Access restored"
fi

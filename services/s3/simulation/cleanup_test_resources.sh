#!/bin/bash

# S3 Test Resources Cleanup Script
# This script deletes test S3 resources created by create_test_resources.sh
#
# Usage: ./cleanup_test_resources.sh [TIMESTAMP]
#   TIMESTAMP: Optional timestamp from resource creation (reads from JSON file)

set -e

# Configuration
REGION="${AWS_REGION:-us-east-1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}S3 Test Resources Cleanup${NC}"
echo -e "${GREEN}========================================${NC}"
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

# Check if timestamp provided
TIMESTAMP=$1

if [ -z "$TIMESTAMP" ]; then
    # Find most recent resource file
    RESOURCE_FILE=$(ls -t simulation/test_resources_*.json 2>/dev/null | head -1)
    
    if [ -z "$RESOURCE_FILE" ]; then
        print_error "No resource files found and no timestamp provided"
        echo "Usage: $0 [TIMESTAMP]"
        echo ""
        echo "Available resource files:"
        ls -1 simulation/test_resources_*.json 2>/dev/null || echo "  None found"
        exit 1
    fi
    
    print_warning "No timestamp provided, using most recent: $RESOURCE_FILE"
else
    RESOURCE_FILE="simulation/test_resources_${TIMESTAMP}.json"
    
    if [ ! -f "$RESOURCE_FILE" ]; then
        print_error "Resource file not found: $RESOURCE_FILE"
        exit 1
    fi
fi

echo "Resource file: $RESOURCE_FILE"
echo "Region: $REGION"
echo ""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    print_error "jq is required but not installed. Please install jq."
    exit 1
fi

# Parse resource IDs from JSON
ACCOUNT_ID=$(jq -r '.account_id // empty' "$RESOURCE_FILE")

# Original buckets (Tier 1-3)
BUCKET_SSE_ENABLED=$(jq -r '.resources.bucket_sse_enabled // empty' "$RESOURCE_FILE")
BUCKET_SSE_DISABLED=$(jq -r '.resources.bucket_sse_disabled // empty' "$RESOURCE_FILE")
BUCKET_KMS_ENABLED=$(jq -r '.resources.bucket_kms_enabled // empty' "$RESOURCE_FILE")
BUCKET_WITH_ACLS=$(jq -r '.resources.bucket_with_acls // empty' "$RESOURCE_FILE")
BUCKET_ACL_ENFORCED=$(jq -r '.resources.bucket_acl_enforced // empty' "$RESOURCE_FILE")
BUCKET_ACL_NOT_ENFORCED=$(jq -r '.resources.bucket_acl_not_enforced // empty' "$RESOURCE_FILE")
BUCKET_ACCELERATION_ENABLED=$(jq -r '.resources.bucket_acceleration_enabled // empty' "$RESOURCE_FILE")
BUCKET_ACCELERATION_DISABLED=$(jq -r '.resources.bucket_acceleration_disabled // empty' "$RESOURCE_FILE")
BUCKET_METRICS_ENABLED=$(jq -r '.resources.bucket_metrics_enabled // empty' "$RESOURCE_FILE")
BUCKET_METRICS_DISABLED=$(jq -r '.resources.bucket_metrics_disabled // empty' "$RESOURCE_FILE")
BUCKET_SAFE_POLICY=$(jq -r '.resources.bucket_safe_policy // empty' "$RESOURCE_FILE")
BUCKET_WILDCARD_POLICY=$(jq -r '.resources.bucket_wildcard_policy // empty' "$RESOURCE_FILE")
BUCKET_SSEC_BLOCKED=$(jq -r '.resources.bucket_ssec_blocked // empty' "$RESOURCE_FILE")
BUCKET_SSEC_ALLOWED=$(jq -r '.resources.bucket_ssec_allowed // empty' "$RESOURCE_FILE")
STORAGE_LENS_CONFIG=$(jq -r '.resources.storage_lens_config // empty' "$RESOURCE_FILE")
BUCKET_PUBLIC_APPROVED=$(jq -r '.resources.bucket_public_approved // empty' "$RESOURCE_FILE")
BUCKET_PUBLIC_NOT_APPROVED=$(jq -r '.resources.bucket_public_not_approved // empty' "$RESOURCE_FILE")
BUCKET_UNPREDICTABLE_NAME=$(jq -r '.resources.bucket_unpredictable_name // empty' "$RESOURCE_FILE")
BUCKET_PREDICTABLE_NAME=$(jq -r '.resources.bucket_predictable_name // empty' "$RESOURCE_FILE")

# Additional buckets
BUCKET_TLS_ENFORCED=$(jq -r '.resources.bucket_tls_enforced // empty' "$RESOURCE_FILE")
BUCKET_NO_TLS=$(jq -r '.resources.bucket_no_tls // empty' "$RESOURCE_FILE")
BUCKET_WITH_LOGGING=$(jq -r '.resources.bucket_with_logging // empty' "$RESOURCE_FILE")
BUCKET_LOGS_TARGET=$(jq -r '.resources.bucket_logs_target // empty' "$RESOURCE_FILE")
BUCKET_NO_LOGGING=$(jq -r '.resources.bucket_no_logging // empty' "$RESOURCE_FILE")
BUCKET_VERSIONING_ENABLED=$(jq -r '.resources.bucket_versioning_enabled // empty' "$RESOURCE_FILE")
BUCKET_NO_VERSIONING=$(jq -r '.resources.bucket_no_versioning // empty' "$RESOURCE_FILE")
BUCKET_LIFECYCLE_ENABLED=$(jq -r '.resources.bucket_lifecycle_enabled // empty' "$RESOURCE_FILE")
BUCKET_NO_LIFECYCLE=$(jq -r '.resources.bucket_no_lifecycle // empty' "$RESOURCE_FILE")

# Function to delete bucket
delete_bucket() {
    local BUCKET_NAME=$1
    local BUCKET_DESC=$2
    
    if [ -z "$BUCKET_NAME" ]; then
        return
    fi
    
    echo -e "\n${YELLOW}Deleting $BUCKET_DESC (Bucket: $BUCKET_NAME)${NC}"
    
    # First, try to empty the bucket (in case it has objects)
    if aws s3 rm "s3://${BUCKET_NAME}" --recursive --region "$REGION" 2>/dev/null; then
        print_status "Emptied bucket: $BUCKET_NAME"
    fi
    
    # Delete the bucket
    if aws s3api delete-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" 2>/dev/null; then
        print_status "Deleted bucket: $BUCKET_NAME"
    else
        print_error "Failed to delete bucket: $BUCKET_NAME (may already be deleted)"
    fi
}

# Function to delete Storage Lens configuration
delete_storage_lens() {
    local CONFIG_ID=$1
    
    if [ -z "$CONFIG_ID" ] || [ -z "$ACCOUNT_ID" ]; then
        return
    fi
    
    echo -e "\n${YELLOW}Deleting Storage Lens Configuration (ID: $CONFIG_ID)${NC}"
    
    if aws s3control delete-storage-lens-configuration \
        --account-id "$ACCOUNT_ID" \
        --config-id "$CONFIG_ID" \
        --region "$REGION" 2>/dev/null; then
        print_status "Deleted Storage Lens configuration: $CONFIG_ID"
    else
        print_error "Failed to delete Storage Lens configuration: $CONFIG_ID (may already be deleted)"
    fi
}

# ========================================
# Delete Storage Lens Configuration First
# ========================================
echo -e "\n${YELLOW}Deleting Storage Lens Configuration...${NC}"
delete_storage_lens "$STORAGE_LENS_CONFIG"

# ========================================
# Delete Buckets
# ========================================
echo -e "\n${YELLOW}Deleting Buckets...${NC}"

# Security buckets
delete_bucket "$BUCKET_SSE_ENABLED" "Bucket with SSE-S3"
delete_bucket "$BUCKET_SSE_DISABLED" "Bucket without SSE"
delete_bucket "$BUCKET_KMS_ENABLED" "Bucket with SSE-KMS"
delete_bucket "$BUCKET_WITH_ACLS" "Bucket with ACLs"
delete_bucket "$BUCKET_ACL_ENFORCED" "Bucket with ACL Enforcement"
delete_bucket "$BUCKET_ACL_NOT_ENFORCED" "Bucket without ACL Enforcement"
delete_bucket "$BUCKET_TLS_ENFORCED" "Bucket with TLS Enforced"
delete_bucket "$BUCKET_NO_TLS" "Bucket without TLS"
delete_bucket "$BUCKET_WITH_LOGGING" "Bucket with Logging"
delete_bucket "$BUCKET_LOGS_TARGET" "Logs Target Bucket"
delete_bucket "$BUCKET_NO_LOGGING" "Bucket without Logging"

# Performance buckets
delete_bucket "$BUCKET_ACCELERATION_ENABLED" "Bucket with Transfer Acceleration"
delete_bucket "$BUCKET_ACCELERATION_DISABLED" "Bucket without Transfer Acceleration"

# Operational buckets
delete_bucket "$BUCKET_METRICS_ENABLED" "Bucket with CloudWatch Metrics"
delete_bucket "$BUCKET_METRICS_DISABLED" "Bucket without CloudWatch Metrics"

# Policy buckets
delete_bucket "$BUCKET_SAFE_POLICY" "Bucket with Safe Policy"
delete_bucket "$BUCKET_WILDCARD_POLICY" "Bucket with Wildcard Policy"
delete_bucket "$BUCKET_SSEC_BLOCKED" "Bucket Blocking SSE-C"
delete_bucket "$BUCKET_SSEC_ALLOWED" "Bucket Allowing SSE-C"
delete_bucket "$BUCKET_PUBLIC_APPROVED" "Public Bucket with Approval Tags"
delete_bucket "$BUCKET_PUBLIC_NOT_APPROVED" "Public Bucket without Approval Tags"

# Naming buckets
delete_bucket "$BUCKET_UNPREDICTABLE_NAME" "Bucket with Unpredictable Name"
delete_bucket "$BUCKET_PREDICTABLE_NAME" "Bucket with Predictable Name"

# Reliability buckets
delete_bucket "$BUCKET_VERSIONING_ENABLED" "Bucket with Versioning"
delete_bucket "$BUCKET_NO_VERSIONING" "Bucket without Versioning"

# Cost optimization buckets
delete_bucket "$BUCKET_LIFECYCLE_ENABLED" "Bucket with Lifecycle"
delete_bucket "$BUCKET_NO_LIFECYCLE" "Bucket without Lifecycle"

# ========================================
# Cleanup resource file
# ========================================
echo -e "\n${YELLOW}Cleaning up resource file...${NC}"

if [ -f "$RESOURCE_FILE" ]; then
    # Move to archive instead of deleting
    ARCHIVE_DIR="simulation/archive"
    mkdir -p "$ARCHIVE_DIR"
    mv "$RESOURCE_FILE" "$ARCHIVE_DIR/"
    print_status "Archived resource file to: $ARCHIVE_DIR/$(basename $RESOURCE_FILE)"
fi

# ========================================
# Summary
# ========================================
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Cleanup Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "All test resources have been deleted."
echo ""
echo -e "${YELLOW}Note:${NC} If any buckets contained objects, they were emptied before deletion."
echo ""

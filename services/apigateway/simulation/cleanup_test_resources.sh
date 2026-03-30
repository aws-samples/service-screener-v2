#!/bin/bash

# API Gateway Test Resources Cleanup Script
# This script deletes test API Gateway resources created by create_test_resources.sh
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
echo -e "${GREEN}API Gateway Test Resources Cleanup${NC}"
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
API_WITH_POLICY=$(jq -r '.resources.api_with_policy // empty' "$RESOURCE_FILE")
API_WITHOUT_POLICY=$(jq -r '.resources.api_without_policy // empty' "$RESOURCE_FILE")
API_WITH_IAM_AUTH=$(jq -r '.resources.api_with_iam_auth // empty' "$RESOURCE_FILE")
API_WITHOUT_AUTH=$(jq -r '.resources.api_without_auth // empty' "$RESOURCE_FILE")
API_WITH_THROTTLING=$(jq -r '.resources.api_with_throttling // empty' "$RESOURCE_FILE")
API_WITHOUT_THROTTLING=$(jq -r '.resources.api_without_throttling // empty' "$RESOURCE_FILE")
USAGE_PLAN_WITH_LIMITS=$(jq -r '.resources.usage_plan_with_limits // empty' "$RESOURCE_FILE")
USAGE_PLAN_WITHOUT_LIMITS=$(jq -r '.resources.usage_plan_without_limits // empty' "$RESOURCE_FILE")

# Function to delete API
delete_api() {
    local API_ID=$1
    local API_NAME=$2
    
    if [ -z "$API_ID" ]; then
        return
    fi
    
    echo -e "\n${YELLOW}Deleting $API_NAME (ID: $API_ID)${NC}"
    
    if aws apigateway delete-rest-api \
        --rest-api-id "$API_ID" \
        --region "$REGION" 2>/dev/null; then
        print_status "Deleted API: $API_ID"
    else
        print_error "Failed to delete API: $API_ID (may already be deleted)"
    fi
}

# Function to delete usage plan
delete_usage_plan() {
    local PLAN_ID=$1
    local PLAN_NAME=$2
    
    if [ -z "$PLAN_ID" ]; then
        return
    fi
    
    echo -e "\n${YELLOW}Deleting $PLAN_NAME (ID: $PLAN_ID)${NC}"
    
    if aws apigateway delete-usage-plan \
        --usage-plan-id "$PLAN_ID" \
        --region "$REGION" 2>/dev/null; then
        print_status "Deleted usage plan: $PLAN_ID"
    else
        print_error "Failed to delete usage plan: $PLAN_ID (may already be deleted)"
    fi
}

# ========================================
# Delete Usage Plans First
# ========================================
echo -e "\n${YELLOW}Deleting Usage Plans...${NC}"

delete_usage_plan "$USAGE_PLAN_WITH_LIMITS" "Usage Plan with Limits"
delete_usage_plan "$USAGE_PLAN_WITHOUT_LIMITS" "Usage Plan without Limits"

# ========================================
# Delete APIs
# ========================================
echo -e "\n${YELLOW}Deleting APIs...${NC}"

delete_api "$API_WITH_POLICY" "API with Resource Policy"
delete_api "$API_WITHOUT_POLICY" "API without Resource Policy"
delete_api "$API_WITH_IAM_AUTH" "API with IAM Authentication"
delete_api "$API_WITHOUT_AUTH" "API with NONE Authentication"
delete_api "$API_WITH_THROTTLING" "API with Throttling"
delete_api "$API_WITHOUT_THROTTLING" "API without Throttling"

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
echo -e "${YELLOW}Note:${NC} If you created custom domains or VPC endpoints manually,"
echo "      please delete them separately."
echo ""

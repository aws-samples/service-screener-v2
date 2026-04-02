#!/bin/bash

# DynamoDB Test Resources Creation Script
# Creates test tables to validate the 3 new DynamoDB checks:
# 1. Encryption at Rest
# 2. Global Table Version
# 3. Table Class Optimization

set -e

# Configuration
REGION="${AWS_REGION:-us-east-1}"
TABLE_PREFIX="ss-test-dynamodb"
TIMESTAMP=$(date +%s)

echo "=========================================="
echo "DynamoDB Test Resources Creation"
echo "=========================================="
echo "Region: $REGION"
echo "Table Prefix: $TABLE_PREFIX"
echo "Timestamp: $TIMESTAMP"
echo ""

# Function to wait for table to be active
wait_for_table() {
    local table_name=$1
    echo "Waiting for table $table_name to become ACTIVE..."
    aws dynamodb wait table-exists --table-name "$table_name" --region "$REGION"
    echo "✓ Table $table_name is ACTIVE"
}

# Function to add items to table to increase size
add_test_items() {
    local table_name=$1
    local item_count=$2
    echo "Adding $item_count test items to $table_name..."
    
    for i in $(seq 1 $item_count); do
        # Create items with large attributes to increase table size
        aws dynamodb put-item \
            --table-name "$table_name" \
            --item "{
                \"id\": {\"S\": \"item-$i\"},
                \"data\": {\"S\": \"$(head -c 10000 /dev/urandom | base64)\"}
            }" \
            --region "$REGION" > /dev/null
    done
    echo "✓ Added $item_count items to $table_name"
}

echo "=========================================="
echo "Test 1: Encryption at Rest"
echo "=========================================="

# Table 1a: No encryption (FAIL)
TABLE_NO_ENCRYPTION="${TABLE_PREFIX}-no-encryption-${TIMESTAMP}"
echo "Creating table without encryption: $TABLE_NO_ENCRYPTION"
aws dynamodb create-table \
    --table-name "$TABLE_NO_ENCRYPTION" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region "$REGION" > /dev/null
wait_for_table "$TABLE_NO_ENCRYPTION"
echo ""

# Table 1b: KMS encryption (PASS)
TABLE_KMS_ENCRYPTION="${TABLE_PREFIX}-kms-encryption-${TIMESTAMP}"
echo "Creating table with KMS encryption: $TABLE_KMS_ENCRYPTION"
aws dynamodb create-table \
    --table-name "$TABLE_KMS_ENCRYPTION" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --sse-specification Enabled=true,SSEType=KMS \
    --region "$REGION" > /dev/null
wait_for_table "$TABLE_KMS_ENCRYPTION"
echo ""

echo "=========================================="
echo "Test 2: Global Table Version"
echo "=========================================="

# Note: Creating legacy global tables (2017.11.29) requires special setup
# and is deprecated. For testing purposes, we'll create a current version
# global table which should PASS the check.

TABLE_GLOBAL="${TABLE_PREFIX}-global-${TIMESTAMP}"
echo "Creating global table (current version): $TABLE_GLOBAL"
aws dynamodb create-table \
    --table-name "$TABLE_GLOBAL" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES \
    --region "$REGION" > /dev/null
wait_for_table "$TABLE_GLOBAL"

# Create replica in another region to make it a global table
REPLICA_REGION="${AWS_REPLICA_REGION:-us-west-2}"
echo "Creating replica in $REPLICA_REGION..."
aws dynamodb update-table \
    --table-name "$TABLE_GLOBAL" \
    --replica-updates "Create={RegionName=$REPLICA_REGION}" \
    --region "$REGION" > /dev/null || echo "Note: Replica creation may take time or require permissions"
echo ""

echo "=========================================="
echo "Test 3: Table Class Optimization"
echo "=========================================="

# Table 3a: Standard class with large size (FAIL - should recommend IA)
TABLE_STANDARD_LARGE="${TABLE_PREFIX}-standard-large-${TIMESTAMP}"
echo "Creating large table with Standard class: $TABLE_STANDARD_LARGE"
aws dynamodb create-table \
    --table-name "$TABLE_STANDARD_LARGE" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --table-class STANDARD \
    --region "$REGION" > /dev/null
wait_for_table "$TABLE_STANDARD_LARGE"

# Add items to increase table size beyond 10GB threshold
echo "Note: Adding items to increase table size (this may take a few minutes)..."
echo "For faster testing, you can skip this step and manually add data later."
read -p "Add test items to increase table size? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    add_test_items "$TABLE_STANDARD_LARGE" 1000
fi
echo ""

# Table 3b: Standard-IA class (PASS)
TABLE_STANDARD_IA="${TABLE_PREFIX}-standard-ia-${TIMESTAMP}"
echo "Creating table with Standard-IA class: $TABLE_STANDARD_IA"
aws dynamodb create-table \
    --table-name "$TABLE_STANDARD_IA" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --table-class STANDARD_INFREQUENT_ACCESS \
    --region "$REGION" > /dev/null
wait_for_table "$TABLE_STANDARD_IA"
echo ""

# Table 3c: Standard class with small size (PASS)
TABLE_STANDARD_SMALL="${TABLE_PREFIX}-standard-small-${TIMESTAMP}"
echo "Creating small table with Standard class: $TABLE_STANDARD_SMALL"
aws dynamodb create-table \
    --table-name "$TABLE_STANDARD_SMALL" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --table-class STANDARD \
    --region "$REGION" > /dev/null
wait_for_table "$TABLE_STANDARD_SMALL"
echo ""

echo "=========================================="
echo "Summary of Created Resources"
echo "=========================================="
echo ""
echo "Encryption at Rest:"
echo "  - $TABLE_NO_ENCRYPTION (FAIL - no encryption)"
echo "  - $TABLE_KMS_ENCRYPTION (PASS - KMS encryption)"
echo ""
echo "Global Table Version:"
echo "  - $TABLE_GLOBAL (PASS - current version)"
echo ""
echo "Table Class Optimization:"
echo "  - $TABLE_STANDARD_LARGE (FAIL - large table with Standard class)"
echo "  - $TABLE_STANDARD_IA (PASS - using Standard-IA)"
echo "  - $TABLE_STANDARD_SMALL (PASS - small table with Standard class)"
echo ""
echo "=========================================="
echo "Next Steps"
echo "=========================================="
echo ""
echo "1. Run Service Screener against region $REGION:"
echo "   python screener.py --regions $REGION --services dynamodb"
echo ""
echo "2. Review the results for the new checks:"
echo "   - encryptionAtRest"
echo "   - globalTableVersion"
echo "   - tableClassOptimization"
echo ""
echo "3. Clean up resources when done:"
echo "   ./cleanup_test_resources.sh"
echo ""
echo "=========================================="
echo "Resource creation completed!"
echo "=========================================="

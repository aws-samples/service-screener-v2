#!/bin/bash

# DynamoDB Test Resources Cleanup Script
# Deletes all test tables created by create_test_resources.sh

set -e

# Configuration
REGION="${AWS_REGION:-us-east-1}"
TABLE_PREFIX="ss-test-dynamodb"

echo "=========================================="
echo "DynamoDB Test Resources Cleanup"
echo "=========================================="
echo "Region: $REGION"
echo "Table Prefix: $TABLE_PREFIX"
echo ""

# Function to delete table
delete_table() {
    local table_name=$1
    echo "Deleting table: $table_name"
    
    # Check if table exists
    if aws dynamodb describe-table --table-name "$table_name" --region "$REGION" &> /dev/null; then
        # Remove deletion protection if enabled
        aws dynamodb update-table \
            --table-name "$table_name" \
            --no-deletion-protection-enabled \
            --region "$REGION" &> /dev/null || true
        
        # Delete the table
        aws dynamodb delete-table \
            --table-name "$table_name" \
            --region "$REGION" > /dev/null
        echo "✓ Deleted $table_name"
    else
        echo "⊘ Table $table_name not found (may have been deleted already)"
    fi
}

# Function to delete global table replicas
delete_global_table_replicas() {
    local table_name=$1
    local replica_region="${AWS_REPLICA_REGION:-us-west-2}"
    
    echo "Checking for global table replicas: $table_name"
    
    # Check if table exists and has replicas
    if aws dynamodb describe-table --table-name "$table_name" --region "$REGION" &> /dev/null; then
        local replicas=$(aws dynamodb describe-table \
            --table-name "$table_name" \
            --region "$REGION" \
            --query 'Table.Replicas[].RegionName' \
            --output text 2>/dev/null || echo "")
        
        if [ -n "$replicas" ]; then
            echo "Removing replicas from $table_name..."
            for region in $replicas; do
                if [ "$region" != "$REGION" ]; then
                    echo "  Removing replica in $region..."
                    aws dynamodb update-table \
                        --table-name "$table_name" \
                        --replica-updates "Delete={RegionName=$region}" \
                        --region "$REGION" > /dev/null || echo "  Note: Could not remove replica in $region"
                fi
            done
            echo "Waiting for replica removal to complete..."
            sleep 10
        fi
    fi
}

echo "=========================================="
echo "Finding test tables..."
echo "=========================================="
echo ""

# List all tables with the test prefix
TABLES=$(aws dynamodb list-tables \
    --region "$REGION" \
    --query "TableNames[?starts_with(@, '$TABLE_PREFIX')]" \
    --output text)

if [ -z "$TABLES" ]; then
    echo "No test tables found with prefix: $TABLE_PREFIX"
    echo ""
    echo "=========================================="
    echo "Cleanup completed (nothing to delete)"
    echo "=========================================="
    exit 0
fi

echo "Found the following test tables:"
for table in $TABLES; do
    echo "  - $table"
done
echo ""

# Confirm deletion
read -p "Delete all these tables? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo ""
echo "=========================================="
echo "Deleting tables..."
echo "=========================================="
echo ""

# Delete each table
for table in $TABLES; do
    # Check if it's a global table and remove replicas first
    if [[ $table == *"global"* ]]; then
        delete_global_table_replicas "$table"
    fi
    
    delete_table "$table"
    echo ""
done

echo "=========================================="
echo "Cleanup Summary"
echo "=========================================="
echo ""
echo "Deleted tables:"
for table in $TABLES; do
    echo "  ✓ $table"
done
echo ""
echo "=========================================="
echo "Cleanup completed successfully!"
echo "=========================================="
echo ""
echo "Note: It may take a few minutes for tables to be fully deleted."
echo "You can verify with: aws dynamodb list-tables --region $REGION"
echo ""

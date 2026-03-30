#!/bin/bash

# SQS Test Resources Cleanup Script
# Deletes all test SQS queues created by create_test_resources.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test-sqs"

echo -e "${GREEN}Cleaning up SQS test resources in region: ${REGION}${NC}"
echo "Prefix: ${PREFIX}"
echo ""

# Check if timestamp file exists
if [ -f .last_test_timestamp ]; then
    TIMESTAMP=$(cat .last_test_timestamp)
    echo "Found timestamp from last run: ${TIMESTAMP}"
    echo ""
else
    echo -e "${YELLOW}No timestamp file found. Will search for all queues with prefix: ${PREFIX}${NC}"
    echo ""
fi

# Function to delete queue
delete_queue() {
    local queue_url=$1
    local queue_name=$(basename "$queue_url")
    
    echo -e "${YELLOW}Deleting queue: ${queue_name}${NC}"
    aws sqs delete-queue \
        --queue-url "${queue_url}" \
        --region "${REGION}"
    echo "Deleted: ${queue_url}"
}

# Get all queues with the prefix
echo "Searching for queues with prefix: ${PREFIX}"
QUEUE_URLS=$(aws sqs list-queues \
    --queue-name-prefix "${PREFIX}" \
    --region "${REGION}" \
    --query 'QueueUrls[]' \
    --output text 2>/dev/null || echo "")

if [ -z "$QUEUE_URLS" ]; then
    echo -e "${GREEN}No test queues found. Nothing to clean up.${NC}"
    exit 0
fi

# Count queues
QUEUE_COUNT=$(echo "$QUEUE_URLS" | wc -w | tr -d ' ')
echo "Found ${QUEUE_COUNT} queue(s) to delete"
echo ""

# Delete all non-DLQ queues first (to avoid dependency issues)
echo "=== Deleting source queues first ==="
echo ""
for queue_url in $QUEUE_URLS; do
    queue_name=$(basename "$queue_url")
    if [[ ! "$queue_name" =~ -dlq- ]]; then
        delete_queue "$queue_url"
        echo ""
    fi
done

# Wait a bit for AWS to process deletions
echo "Waiting 5 seconds for AWS to process deletions..."
sleep 5
echo ""

# Delete DLQ queues
echo "=== Deleting dead letter queues ==="
echo ""
for queue_url in $QUEUE_URLS; do
    queue_name=$(basename "$queue_url")
    if [[ "$queue_name" =~ -dlq- ]]; then
        delete_queue "$queue_url"
        echo ""
    fi
done

# Clean up timestamp file
if [ -f .last_test_timestamp ]; then
    rm .last_test_timestamp
    echo "Removed timestamp file"
fi

echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "All test queues with prefix '${PREFIX}' have been deleted."
echo ""

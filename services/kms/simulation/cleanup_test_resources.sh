#!/bin/bash

# KMS Test Resources Cleanup Script
# This script removes KMS keys created by create_test_resources.sh

set -e

REGION="${AWS_REGION:-us-east-1}"
TAG_KEY="ServiceScreenerTest"

if [ -z "$1" ]; then
    echo "Usage: $0 <tag-value>"
    echo ""
    echo "Example: $0 kms-test-20240101-120000"
    echo ""
    echo "To find tag values, run:"
    echo "  aws kms list-keys --region $REGION --query 'Keys[*].KeyId' --output text | \\"
    echo "    xargs -I {} aws kms list-resource-tags --region $REGION --key-id {} --query 'Tags[?TagKey==\`$TAG_KEY\`].TagValue' --output text"
    exit 1
fi

TAG_VALUE=$1

echo "=========================================="
echo "KMS Test Resources Cleanup"
echo "=========================================="
echo "Region: $REGION"
echo "Tag: $TAG_KEY=$TAG_VALUE"
echo "=========================================="

# Find all keys with the specified tag
echo ""
echo "Finding keys with tag $TAG_KEY=$TAG_VALUE..."

KEY_IDS=$(aws kms list-keys --region $REGION --query 'Keys[*].KeyId' --output text)

KEYS_TO_DELETE=()

for KEY_ID in $KEY_IDS; do
    # Check if key has the tag
    TAG_CHECK=$(aws kms list-resource-tags \
        --region $REGION \
        --key-id "$KEY_ID" \
        --query "Tags[?TagKey=='$TAG_KEY' && TagValue=='$TAG_VALUE'].TagValue" \
        --output text 2>/dev/null || echo "")
    
    if [ "$TAG_CHECK" == "$TAG_VALUE" ]; then
        KEYS_TO_DELETE+=("$KEY_ID")
        echo "Found key to delete: $KEY_ID"
    fi
done

if [ ${#KEYS_TO_DELETE[@]} -eq 0 ]; then
    echo ""
    echo "No keys found with tag $TAG_KEY=$TAG_VALUE"
    exit 0
fi

echo ""
echo "Found ${#KEYS_TO_DELETE[@]} key(s) to delete"
echo ""

# Delete aliases first
echo "Deleting aliases..."
for KEY_ID in "${KEYS_TO_DELETE[@]}"; do
    ALIASES=$(aws kms list-aliases \
        --region $REGION \
        --key-id "$KEY_ID" \
        --query 'Aliases[*].AliasName' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$ALIASES" ]; then
        for ALIAS in $ALIASES; do
            echo "Deleting alias: $ALIAS"
            aws kms delete-alias --region $REGION --alias-name "$ALIAS" 2>/dev/null || true
        done
    fi
done

echo ""
echo "Retiring grants..."
for KEY_ID in "${KEYS_TO_DELETE[@]}"; do
    GRANTS=$(aws kms list-grants \
        --region $REGION \
        --key-id "$KEY_ID" \
        --query 'Grants[*].GrantId' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$GRANTS" ]; then
        for GRANT_ID in $GRANTS; do
            echo "Retiring grant: $GRANT_ID"
            aws kms retire-grant --region $REGION --grant-id "$GRANT_ID" 2>/dev/null || true
        done
    fi
done

echo ""
echo "Scheduling keys for deletion (7-day waiting period)..."
for KEY_ID in "${KEYS_TO_DELETE[@]}"; do
    echo "Scheduling deletion for key: $KEY_ID"
    
    # Check if key is already pending deletion
    KEY_STATE=$(aws kms describe-key \
        --region $REGION \
        --key-id "$KEY_ID" \
        --query 'KeyMetadata.KeyState' \
        --output text 2>/dev/null || echo "")
    
    if [ "$KEY_STATE" == "PendingDeletion" ]; then
        echo "  Key is already pending deletion"
        continue
    fi
    
    # Schedule deletion with minimum waiting period (7 days)
    aws kms schedule-key-deletion \
        --region $REGION \
        --key-id "$KEY_ID" \
        --pending-window-in-days 7 \
        --output text 2>/dev/null || echo "  Failed to schedule deletion (may already be scheduled)"
    
    echo "  Scheduled for deletion in 7 days"
done

echo ""
echo "=========================================="
echo "Cleanup Complete"
echo "=========================================="
echo ""
echo "Deleted ${#KEYS_TO_DELETE[@]} key(s)"
echo ""
echo "Note: KMS keys have a mandatory 7-30 day waiting period before deletion."
echo "Keys are now in 'PendingDeletion' state and will be automatically deleted after 7 days."
echo ""
echo "To cancel deletion of a key:"
echo "  aws kms cancel-key-deletion --region $REGION --key-id <KEY_ID>"
echo ""

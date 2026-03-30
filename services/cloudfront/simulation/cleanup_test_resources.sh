#!/bin/bash

################################################################################
# CloudFront Service Review - Test Resource Cleanup Script
#
# Deletion order (respects dependencies):
#   1. CloudFront Distribution (disable → wait → delete)
#   2. S3 Bucket (empty → delete)
#
# Usage:
#   ./cleanup_test_resources.sh <resource_file> [OPTIONS]
#
# Options:
#   --force    Skip confirmation prompt
#   --help     Show this help message
#
################################################################################

set -e
set -u

REGION="${AWS_REGION:-us-east-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --force) FORCE=true; shift ;;
        --help)  grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then
                RESOURCE_FILE="$1"; shift
            else
                echo -e "${RED}Error: Unknown option $1${NC}"; exit 1
            fi
            ;;
    esac
done

if [ -z "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file required${NC}"
    echo "Usage: $0 <resource_file> [OPTIONS]"
    exit 1
fi

if [ ! -f "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file not found: $RESOURCE_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}=== CloudFront Test Resource Cleanup ===${NC}"
echo "Resource file: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    RESOURCES+=("$line")
done < "$RESOURCE_FILE"

count_type() { grep -c "^$1:" "$RESOURCE_FILE" 2>/dev/null || echo 0; }

DIST_COUNT=$(count_type "DISTRIBUTION")
BUCKET_COUNT=$(count_type "S3_BUCKET")

echo "Resources to delete:"
echo "  - Distributions:  $DIST_COUNT"
echo "  - S3 Buckets:     $BUCKET_COUNT"
echo ""

if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}WARNING: This will permanently delete all resources listed above.${NC}"
    read -p "Continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Cleanup cancelled."
        exit 0
    fi
fi

################################################################################
# Step 1: Disable and Delete CloudFront Distributions
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting CloudFront Distributions ===${NC}"

for resource in "${RESOURCES[@]}"; do
    if [[ $resource == DISTRIBUTION:* ]]; then
        ID="${resource#DISTRIBUTION:}"
        echo "Processing distribution: $ID"

        # Get current config
        ETAG=$(aws cloudfront get-distribution-config --id "$ID" \
            --query 'ETag' --output text 2>/dev/null || echo "")

        if [ -z "$ETAG" ] || [ "$ETAG" = "None" ]; then
            echo "  (already deleted or not found)"
            continue
        fi

        IS_ENABLED=$(aws cloudfront get-distribution-config --id "$ID" \
            --query 'DistributionConfig.Enabled' --output text)

        if [ "$IS_ENABLED" = "True" ]; then
            echo "  Disabling distribution..."
            # Get full config, flip Enabled to false, update
            DIST_CONFIG=$(aws cloudfront get-distribution-config --id "$ID")
            ETAG=$(echo "$DIST_CONFIG" | python3 -c "import sys,json; print(json.load(sys.stdin)['ETag'])")
            echo "$DIST_CONFIG" | python3 -c "
import sys, json
d = json.load(sys.stdin)
c = d['DistributionConfig']
c['Enabled'] = False
json.dump(c, open('/tmp/cf-sim-disable.json','w'))
"
            NEW_ETAG=$(aws cloudfront update-distribution \
                --id "$ID" \
                --distribution-config file:///tmp/cf-sim-disable.json \
                --if-match "$ETAG" \
                --query 'ETag' --output text)
            rm -f /tmp/cf-sim-disable.json
            echo -e "${GREEN}  ✓ Disabled${NC}"
        fi

        echo -e "${YELLOW}  Waiting for distribution to deploy disabled state...${NC}"
        aws cloudfront wait distribution-deployed --id "$ID"

        # Get fresh ETag for deletion
        FRESH_ETAG=$(aws cloudfront get-distribution-config --id "$ID" \
            --query 'ETag' --output text)

        aws cloudfront delete-distribution --id "$ID" --if-match "$FRESH_ETAG"
        echo -e "${GREEN}  ✓ Deleted: $ID${NC}"
    fi
done

################################################################################
# Step 2: Delete S3 Buckets
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting S3 Buckets ===${NC}"

for resource in "${RESOURCES[@]}"; do
    if [[ $resource == S3_BUCKET:* ]]; then
        BUCKET="${resource#S3_BUCKET:}"
        echo "Deleting bucket: $BUCKET"
        aws s3 rm "s3://${BUCKET}" --recursive > /dev/null 2>&1 || true
        aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null \
            || echo "  (already deleted or not found)"
        echo -e "${GREEN}  ✓ Deleted${NC}"
    fi
done

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Deleted:"
echo "  ✓ $DIST_COUNT distribution(s)"
echo "  ✓ $BUCKET_COUNT bucket(s)"
echo ""
echo -e "${YELLOW}You can now delete the resource file: $RESOURCE_FILE${NC}"

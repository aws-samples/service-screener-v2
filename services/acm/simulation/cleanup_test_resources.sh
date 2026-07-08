#!/bin/bash

# ACM Test Resources Cleanup Script
#
# Deletes all ACM certificates tagged with ServiceScreenerTest=<tag-value>
# plus any untagged certificate ARN recorded in .acm-untagged-arn.
#
# Usage:
#   ./cleanup_test_resources.sh <tag-value>
# Example:
#   ./cleanup_test_resources.sh acm-test-20260702-152500

set -e

REGION="${AWS_REGION:-ap-southeast-1}"
TAG_KEY="ServiceScreenerTest"

if [ -z "$1" ]; then
    echo "Usage: $0 <tag-value>"
    echo ""
    echo "To list all ServiceScreenerTest-tagged ACM certificates:"
    echo "  aws acm list-certificates --region $REGION \\"
    echo "    --includes keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1 \\"
    echo "    --query 'CertificateSummaryList[].CertificateArn' --output text"
    exit 1
fi

TAG_VALUE=$1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "ACM Test Resources Cleanup"
echo "=========================================="
echo "Region: $REGION"
echo "Tag:    $TAG_KEY=$TAG_VALUE"
echo "=========================================="

# ------------------------------------------------------------------
# 1. Discover certificates that have our tag
# ------------------------------------------------------------------
ARNS=$(aws acm list-certificates \
    --region "$REGION" \
    --includes keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1 \
    --query 'CertificateSummaryList[].CertificateArn' \
    --output text)

MATCHING=()
for ARN in $ARNS; do
    TAG_MATCH=$(aws acm list-tags-for-certificate \
        --region "$REGION" \
        --certificate-arn "$ARN" \
        --query "Tags[?Key=='$TAG_KEY' && Value=='$TAG_VALUE'].Value" \
        --output text 2>/dev/null || echo "")
    if [ "$TAG_MATCH" == "$TAG_VALUE" ]; then
        MATCHING+=("$ARN")
    fi
done

# ------------------------------------------------------------------
# 2. Add the untagged ARN recorded during create (if the file exists)
# ------------------------------------------------------------------
UNTAGGED_FILE="$SCRIPT_DIR/.acm-untagged-arn"
if [ -f "$UNTAGGED_FILE" ]; then
    UNTAGGED_ARN=$(cat "$UNTAGGED_FILE")
    if [ -n "$UNTAGGED_ARN" ]; then
        echo "Including untagged ARN from .acm-untagged-arn:"
        echo "  $UNTAGGED_ARN"
        MATCHING+=("$UNTAGGED_ARN")
    fi
fi

if [ ${#MATCHING[@]} -eq 0 ]; then
    echo ""
    echo "No certificates found with tag $TAG_KEY=$TAG_VALUE"
    exit 0
fi

echo ""
echo "Deleting ${#MATCHING[@]} certificate(s):"
for ARN in "${MATCHING[@]}"; do
    echo "  $ARN"
done
echo ""

# ------------------------------------------------------------------
# 3. Delete
# ------------------------------------------------------------------
FAILED=0
for ARN in "${MATCHING[@]}"; do
    if aws acm delete-certificate --region "$REGION" --certificate-arn "$ARN" 2>/dev/null; then
        echo "  ✓ deleted $ARN"
    else
        # Most common failure: cert is InUseBy an ALB/CloudFront/etc.
        echo "  ✗ failed to delete $ARN (may be in use by another resource)"
        FAILED=$((FAILED+1))
    fi
done

# Remove the untagged-arn marker if we processed it
[ -f "$UNTAGGED_FILE" ] && rm -f "$UNTAGGED_FILE"

echo ""
echo "=========================================="
echo "Cleanup Complete"
echo "=========================================="
echo "Deleted: $(( ${#MATCHING[@]} - FAILED )) / ${#MATCHING[@]}"
[ "$FAILED" -gt 0 ] && echo "Failures: $FAILED (check InUseBy attachments)"

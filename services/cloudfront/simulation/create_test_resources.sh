#!/bin/bash

################################################################################
# CloudFront Service Review - Test Resource Creation Script
#
# Creates a single CloudFront distribution with intentionally weak config
# to trigger all 16 checks from cloudfrontDist.py.
#
# Resources Created:
#   1. S3 Bucket (origin)
#   2. CloudFront Distribution (insecure config)
#
# Checks expected to FAIL (15):
#   accessLogging, WAFAssociation, defaultRootObject,
#   compressObjectsAutomatically, DeprecatedSSLProtocol, originFailover,
#   fieldLevelEncryption, viewerPolicyHttps, S3OriginAccessControl,
#   OriginTrafficEncryption, CustomSSLCertificate, OriginShieldEnabled,
#   GeoRestrictionsConfigured, PriceClassOptimization, S3OriginBucketExists(PASS)
#
# Checks expected to PASS:
#   S3OriginBucketExists (bucket exists)
#
# Not simulated:
#   SNIConfiguration (requires custom SSL certificate with dedicated IP)
#
# Usage:
#   AWS_REGION=ap-southeast-1 ./create_test_resources.sh
#
################################################################################

set -e
set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="cf-sim"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="${PREFIX}-origin-${ACCOUNT_ID}-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== CloudFront Test Resource Creation ===${NC}" >&2
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP" >&2
echo "" >&2

################################################################################
# Step 1: Create S3 Bucket (origin)
################################################################################

echo -e "${CYAN}--- Step 1: Creating S3 bucket for origin ---${NC}" >&2

if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" > /dev/null
else
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" \
        --create-bucket-configuration LocationConstraint="$REGION" > /dev/null
fi

log_resource "S3_BUCKET:$BUCKET_NAME"
echo -e "${GREEN}✓ S3 bucket created: $BUCKET_NAME${NC}" >&2

# Upload test content
echo "<html><body><h1>Test</h1></body></html>" > /tmp/cf-sim-index.html
aws s3 cp /tmp/cf-sim-index.html "s3://${BUCKET_NAME}/index.html" --region "$REGION" > /dev/null
rm -f /tmp/cf-sim-index.html
echo -e "${GREEN}✓ Test content uploaded${NC}" >&2

################################################################################
# Step 2: Create CloudFront Distribution
#
# Triggers FAIL:
#   accessLogging (Logging.Enabled=false)
#   WAFAssociation (WebACLId="")
#   defaultRootObject (DefaultRootObject="")
#   compressObjectsAutomatically (Compress=false)
#   DeprecatedSSLProtocol (SSLv3 in custom origin with match-viewer)
#   originFailover (OriginGroups.Quantity=0)
#   fieldLevelEncryption (FieldLevelEncryptionId="")
#   viewerPolicyHttps (ViewerProtocolPolicy=allow-all)
#   S3OriginAccessControl (no OAC/OAI on S3 origin)
#   OriginTrafficEncryption (match-viewer custom origin + allow-all viewer)
#   CustomSSLCertificate (CloudFrontDefaultCertificate=true)
#   OriginShieldEnabled (no OriginShield)
#   GeoRestrictionsConfigured (RestrictionType=none)
#   PriceClassOptimization (PriceClass_All)
#
# Triggers PASS:
#   S3OriginBucketExists (bucket exists)
#
# Not triggered:
#   SNIConfiguration (only fires when custom cert uses dedicated IP)
################################################################################

echo -e "\n${CYAN}--- Step 2: Creating CloudFront distribution ---${NC}" >&2

cat > /tmp/cf-sim-config.json <<EOF
{
  "CallerReference": "${PREFIX}-${TIMESTAMP}",
  "Comment": "cf-sim test distribution",
  "Enabled": true,
  "Origins": {
    "Quantity": 2,
    "Items": [
      {
        "Id": "S3-no-OAC",
        "DomainName": "${BUCKET_NAME}.s3.${REGION}.amazonaws.com",
        "S3OriginConfig": {
          "OriginAccessIdentity": ""
        }
      },
      {
        "Id": "Custom-HTTP",
        "DomainName": "example.com",
        "CustomOriginConfig": {
          "HTTPPort": 80,
          "HTTPSPort": 443,
          "OriginProtocolPolicy": "match-viewer",
          "OriginSslProtocols": {
            "Quantity": 3,
            "Items": ["SSLv3", "TLSv1", "TLSv1.1"]
          },
          "OriginReadTimeout": 30,
          "OriginKeepaliveTimeout": 5
        }
      }
    ]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "S3-no-OAC",
    "ViewerProtocolPolicy": "allow-all",
    "AllowedMethods": {
      "Quantity": 2,
      "Items": ["GET", "HEAD"],
      "CachedMethods": {
        "Quantity": 2,
        "Items": ["GET", "HEAD"]
      }
    },
    "Compress": false,
    "ForwardedValues": {
      "QueryString": false,
      "Cookies": { "Forward": "none" }
    },
    "MinTTL": 0,
    "DefaultTTL": 86400,
    "MaxTTL": 31536000,
    "TrustedSigners": { "Enabled": false, "Quantity": 0 },
    "FieldLevelEncryptionId": ""
  },
  "CacheBehaviors": { "Quantity": 0 },
  "CustomErrorResponses": { "Quantity": 0 },
  "Logging": {
    "Enabled": false,
    "IncludeCookies": false,
    "Bucket": "",
    "Prefix": ""
  },
  "PriceClass": "PriceClass_All",
  "ViewerCertificate": {
    "CloudFrontDefaultCertificate": true,
    "MinimumProtocolVersion": "TLSv1",
    "CertificateSource": "cloudfront"
  },
  "Restrictions": {
    "GeoRestriction": {
      "RestrictionType": "none",
      "Quantity": 0
    }
  },
  "WebACLId": "",
  "HttpVersion": "http2",
  "IsIPV6Enabled": true,
  "OriginGroups": { "Quantity": 0 }
}
EOF

DISTRIBUTION_ID=$(aws cloudfront create-distribution \
    --distribution-config file:///tmp/cf-sim-config.json \
    --query 'Distribution.Id' --output text)

rm -f /tmp/cf-sim-config.json
log_resource "DISTRIBUTION:$DISTRIBUTION_ID"
echo -e "${GREEN}✓ Distribution created: $DISTRIBUTION_ID${NC}" >&2

################################################################################
# Wait for deployment
################################################################################

echo -e "\n${YELLOW}=== Waiting for distribution to deploy (15-25 min) ===${NC}" >&2

aws cloudfront wait distribution-deployed --id "$DISTRIBUTION_ID"

echo -e "${GREEN}✓ Distribution deployed${NC}" >&2

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}========================================${NC}" >&2
echo -e "${GREEN}=== All Resources Created ===${NC}" >&2
echo -e "${GREEN}========================================${NC}" >&2
echo "" >&2
echo "Resources saved to: $OUTPUT_FILE" >&2
echo "" >&2
echo "Created:" >&2
echo "  ✓ S3 Bucket:      $BUCKET_NAME" >&2
echo "  ✓ Distribution:   $DISTRIBUTION_ID" >&2
echo "" >&2
echo "Next steps:" >&2
echo "  1. Run screener:" >&2
echo "     cd /Users/kuettai/Documents/project/ssvsprowler/service-screener-v2" >&2
echo "     python main.py --services cloudfront --regions $REGION --sequential 1 --beta 1" >&2
echo "" >&2
echo "  2. Cleanup when done:" >&2
echo "     ./cleanup_test_resources.sh $OUTPUT_FILE" >&2

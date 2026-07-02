#!/bin/bash

################################################################################
# Firehose Service Screener - Test Resource Creation Script
#
# Creates an intentionally-insecure Amazon Data Firehose delivery stream plus
# its required S3 bucket + IAM role, so every `firehose*` service-screener
# check that can be forced through the AWS API is validated end-to-end.
#
#   Delivery stream `ss-test-firehose-*`:
#     - DirectPut source (no Kinesis stream needed)
#     - DeliveryStreamEncryption: DISABLED    → #1 firehoseSSEDisabled
#     - S3 destination NoEncryption            → #3 firehoseS3DestinationNoEncryption
#     - CloudWatchLoggingOptions.Enabled=false → #4 firehoseLoggingDisabled
#     - BufferingHints: 60s / 1MB (both below default thresholds when we
#       apply 59s / 0.5 - but AWS floors size at 1MB, so we set 59s + we
#       set no processing so backup check reports N/A)
#       Actual: IntervalInSeconds=59 (fires #6 firehoseBufferingSuboptimal)
#     - No user-defined tags                   → #7 firehoseNoTags
#
# Checks that CANNOT be reliably forced through the AWS API in a script:
#     - #2 firehoseSSEDefaultKey        (requires ENABLED SSE, mutually
#       exclusive with #1 in this simulation)
#     - #5 firehoseS3BackupDisabled     (requires Lambda processor +
#       explicit backup=Disabled — kept out for cost / IAM scope reasons)
#     - #8 firehoseStreamNotActive      (CREATING_FAILED requires a
#       destination misconfig strong enough that the create call itself
#       succeeds but the stream lands in FAILED — hard to induce reliably.
#       Advisory only.)
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)        echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

STREAM_NAME="${PREFIX}-firehose-${TIMESTAMP}"
BUCKET_NAME="${PREFIX}-firehose-${ACCOUNT_ID}-${TIMESTAMP}"
ROLE_NAME="${PREFIX}-firehose-role-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Firehose Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Create destination S3 bucket
################################################################################

echo -e "${GREEN}=== Step 1: Create destination S3 bucket ===${NC}"

if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" > /dev/null 2>&1
else
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$REGION" \
        --create-bucket-configuration "LocationConstraint=$REGION" > /dev/null 2>&1
fi

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ S3 bucket create failed${NC}"
    exit 1
fi

log "S3_BUCKET:${BUCKET_NAME}"
echo -e "${GREEN}✓ S3 bucket: ${BUCKET_NAME}${NC}"

################################################################################
# Step 2: Create IAM role that Firehose can assume
################################################################################

echo -e "\n${GREEN}=== Step 2: Create Firehose service role ===${NC}"

cat > /tmp/${PREFIX}-firehose-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "firehose.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "${ACCOUNT_ID}"}}
  }]
}
EOF

ROLE_JSON=$(aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file:///tmp/${PREFIX}-firehose-trust.json" \
    --output json 2>&1) || {
        echo -e "${RED}✗ IAM role create failed${NC}"; echo "$ROLE_JSON" | head -3; exit 1;
    }
ROLE_ARN=$(echo "$ROLE_JSON" | grep -o '"Arn": *"[^"]*"' | head -1 | sed 's/.*"Arn": *"\([^"]*\)".*/\1/')
log "IAM_ROLE:${ROLE_NAME}"
echo -e "${GREEN}✓ IAM role: ${ROLE_ARN}${NC}"

# Minimum IAM permissions the role needs to write to the bucket
cat > /tmp/${PREFIX}-firehose-inline.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject"
    ],
    "Resource": [
      "arn:aws:s3:::${BUCKET_NAME}",
      "arn:aws:s3:::${BUCKET_NAME}/*"
    ]
  }]
}
EOF

aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "${PREFIX}-firehose-s3-write" \
    --policy-document "file:///tmp/${PREFIX}-firehose-inline.json" > /dev/null 2>&1

echo -e "${GREEN}✓ Inline S3 policy attached${NC}"
echo -e "${YELLOW}⚠ Waiting 15s for IAM role to propagate...${NC}"
sleep 15

################################################################################
# Step 3: Create delivery stream (insecure configuration)
################################################################################

echo -e "\n${GREEN}=== Step 3: Create insecure Firehose delivery stream ===${NC}"

# ExtendedS3DestinationConfiguration deliberately sets:
#   - EncryptionConfiguration.NoEncryptionConfig=NoEncryption
#   - CloudWatchLoggingOptions.Enabled=false
#   - BufferingHints.IntervalInSeconds=59  (below the 60s threshold)
#   - BufferingHints.SizeInMBs=1           (minimum allowed by AWS)
#
# CompressionFormat=UNCOMPRESSED is default; kept explicit.
cat > /tmp/${PREFIX}-firehose-config.json <<EOF
{
  "DeliveryStreamName": "${STREAM_NAME}",
  "DeliveryStreamType": "DirectPut",
  "ExtendedS3DestinationConfiguration": {
    "RoleARN": "${ROLE_ARN}",
    "BucketARN": "arn:aws:s3:::${BUCKET_NAME}",
    "Prefix": "ss-test/",
    "ErrorOutputPrefix": "ss-test-errors/",
    "BufferingHints": {
      "SizeInMBs": 1,
      "IntervalInSeconds": 59
    },
    "CompressionFormat": "UNCOMPRESSED",
    "EncryptionConfiguration": {
      "NoEncryptionConfig": "NoEncryption"
    },
    "CloudWatchLoggingOptions": {
      "Enabled": false
    },
    "S3BackupMode": "Disabled"
  }
}
EOF

STREAM_JSON=$(aws firehose create-delivery-stream \
    --cli-input-json "file:///tmp/${PREFIX}-firehose-config.json" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Delivery stream create failed${NC}"; echo "$STREAM_JSON" | head -10; exit 1;
    }

STREAM_ARN=$(echo "$STREAM_JSON" | grep -o '"DeliveryStreamARN": *"[^"]*"' | head -1 | sed 's/.*"DeliveryStreamARN": *"\([^"]*\)".*/\1/')
log "DELIVERY_STREAM:${STREAM_NAME}"
echo -e "${GREEN}✓ Delivery stream: ${STREAM_NAME}${NC}"
echo -e "  ARN: ${STREAM_ARN}"

echo -e "\n${YELLOW}⚠ Firehose takes ~30-60s to reach ACTIVE state.${NC}"
echo -e "${YELLOW}  You can run the scanner immediately — CREATING is a valid state.${NC}"

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}=== Resources Created ===${NC}"
echo -e "${GREEN}=========================================${NC}"
cat "$OUTPUT_FILE" | sed 's/^/  /'
echo ""
echo "Expected findings (once stream reaches ACTIVE):"
echo "  ✗ firehoseSSEDisabled              (no server-side encryption)"
echo "  ✗ firehoseS3DestinationNoEncryption (NoEncryptionConfig on S3 dest)"
echo "  ✗ firehoseLoggingDisabled          (CloudWatchLoggingOptions.Enabled=false)"
echo "  ✗ firehoseBufferingSuboptimal      (IntervalInSeconds=59 < 60)"
echo "  ✗ firehoseNoTags                   (no user tags)"
echo "  ○ firehoseSSEDefaultKey            (N/A — encryption is off)"
echo "  ○ firehoseS3BackupDisabled         (N/A — no data transformation)"
echo "  ✓ firehoseStreamNotActive          (should PASS once ACTIVE)"
echo ""
echo "Next:"
echo "  1. cd ../../.. && python3 main.py --regions $REGION --services firehose --beta 1 --sequential 1"
echo "  2. cd services/firehose/simulation && ./cleanup_test_resources.sh"

rm -f /tmp/${PREFIX}-firehose-trust.json \
      /tmp/${PREFIX}-firehose-inline.json \
      /tmp/${PREFIX}-firehose-config.json

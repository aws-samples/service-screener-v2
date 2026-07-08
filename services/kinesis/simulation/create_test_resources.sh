#!/bin/bash

################################################################################
# Kinesis Data Streams - Service Screener Simulation Setup
#
# Creates two intentionally-suboptimal Kinesis Data Streams that exercise
# every `kinesis*` service-screener check that can be forced through the
# AWS API without waiting > 7 days or exceeding the account shard quota.
#
#   Stream A  ss-test-kinesis-basic-*     (ON_DEMAND, unencrypted)
#     - EncryptionType=NONE               → kinesisSSEDisabled              [FAIL]
#     - RetentionPeriodHours=24 (default) → kinesisRetentionPeriodMinimum   [FAIL]
#     - No user tags                      → kinesisNoTags                   [FAIL]
#     - No shard-level metrics            → kinesisEnhancedMonitoringDisabled [FAIL]
#     - No CloudWatch alarms              → kinesisNoCloudWatchAlarms       [FAIL]
#     - StreamMode=ON_DEMAND (<30 days)   → kinesisOnDemandPredictableWorkload [PASS - too young]
#     - ConsumerCount=0 (<7 days)         → kinesisNoConsumers              [PASS - too young]
#
#   Stream B  ss-test-kinesis-provisioned-*  (PROVISIONED, AWS-managed key,
#                                             partial shard metrics)
#     - EncryptionType=KMS, KeyId=alias/aws/kinesis
#                                         → kinesisSSEDefaultKey            [FAIL]
#     - StreamMode=PROVISIONED, 1 shard   → kinesisProvisionedModeNoAutoScaling [FAIL]
#     - Only IncomingBytes metric enabled → kinesisEnhancedMonitoringPartial [FAIL]
#     - No user tags                      → kinesisNoTags                   [FAIL]
#     - RetentionPeriodHours=24 (default) → kinesisRetentionPeriodMinimum   [FAIL]
#     - No CloudWatch alarms              → kinesisNoCloudWatchAlarms       [FAIL]
#
# Cost: ~$0.01 for a few minutes of provisioned shard-hours plus the
#       negligible per-stream monthly baseline. No PutRecord traffic.
#
# Usage:
#   ./create_test_resources.sh [--region REGION]
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

BASIC_STREAM="${PREFIX}-kinesis-basic-${TIMESTAMP}"
PROV_STREAM="${PREFIX}-kinesis-provisioned-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Kinesis Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Stream A: ON_DEMAND, unencrypted, no tags, default retention, no metrics
################################################################################

echo -e "${GREEN}=== Step 1: Create baseline stream (ON_DEMAND, unencrypted) ===${NC}"

if aws kinesis create-stream \
    --stream-name "$BASIC_STREAM" \
    --stream-mode-details 'StreamMode=ON_DEMAND' \
    --region "$REGION" 2>&1; then
    log "STREAM:${BASIC_STREAM}"
    echo -e "${GREEN}✓ Baseline stream created: ${BASIC_STREAM}${NC}"
    echo "  Fires: kinesisSSEDisabled, kinesisRetentionPeriodMinimum, kinesisNoTags,"
    echo "         kinesisEnhancedMonitoringDisabled, kinesisNoCloudWatchAlarms"
else
    echo -e "${RED}✗ Baseline stream creation failed${NC}"
    exit 1
fi

################################################################################
# Stream B: PROVISIONED, AWS-managed KMS, partial shard-level metrics
################################################################################

echo -e "\n${GREEN}=== Step 2: Create provisioned stream (AWS-managed KMS, partial metrics) ===${NC}"

if aws kinesis create-stream \
    --stream-name "$PROV_STREAM" \
    --stream-mode-details 'StreamMode=PROVISIONED' \
    --shard-count 1 \
    --region "$REGION" 2>&1; then
    log "STREAM:${PROV_STREAM}"
    echo -e "${GREEN}✓ Provisioned stream created: ${PROV_STREAM}${NC}"
else
    echo -e "${YELLOW}⚠ Provisioned stream creation failed — skipping enrichment${NC}"
    PROV_STREAM=""
fi

if [ -n "$PROV_STREAM" ]; then
    echo -e "\n${GREEN}=== Step 3: Wait for provisioned stream to reach ACTIVE ===${NC}"
    # Both streams need to be ACTIVE before enabling encryption / monitoring
    aws kinesis wait stream-exists \
        --stream-name "$PROV_STREAM" \
        --region "$REGION" 2>&1 || \
        echo -e "${YELLOW}⚠ wait failed; will retry operations directly${NC}"

    echo -e "\n${GREEN}=== Step 4: Enable AWS-managed KMS encryption on provisioned stream ===${NC}"
    aws kinesis start-stream-encryption \
        --stream-name "$PROV_STREAM" \
        --encryption-type KMS \
        --key-id "alias/aws/kinesis" \
        --region "$REGION" 2>&1 \
        && echo -e "${GREEN}✓ AWS-managed KMS encryption enabled → fires kinesisSSEDefaultKey${NC}" \
        || echo -e "${YELLOW}⚠ start-stream-encryption returned an error (may be transient — stream still UPDATING)${NC}"

    echo -e "\n${GREEN}=== Step 5: Enable ONLY IncomingBytes shard-level metric ===${NC}"
    # Enable a single non-critical metric to fire kinesisEnhancedMonitoringPartial.
    # Critical metrics per the driver:
    #   IteratorAgeMilliseconds, WriteProvisionedThroughputExceeded,
    #   ReadProvisionedThroughputExceeded
    #
    # StartStreamEncryption puts the stream into UPDATING for ~30-60s;
    # retry until it's ACTIVE (max ~90s).
    for i in 1 2 3 4 5 6; do
        STATUS=$(aws kinesis describe-stream-summary \
            --stream-name "$PROV_STREAM" \
            --region "$REGION" \
            --query 'StreamDescriptionSummary.StreamStatus' \
            --output text 2>/dev/null || echo "UNKNOWN")
        if [ "$STATUS" = "ACTIVE" ]; then
            break
        fi
        echo "  Waiting for stream to reach ACTIVE (currently: $STATUS)... [attempt $i/6]"
        sleep 15
    done

    aws kinesis enable-enhanced-monitoring \
        --stream-name "$PROV_STREAM" \
        --shard-level-metrics IncomingBytes \
        --region "$REGION" 2>&1 > /dev/null \
        && echo -e "${GREEN}✓ Partial shard-level metrics enabled → fires kinesisEnhancedMonitoringPartial${NC}" \
        || echo -e "${YELLOW}⚠ enable-enhanced-monitoring returned an error (stream may still be UPDATING)${NC}"
fi

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}=== Resources Created ===${NC}"
echo -e "${GREEN}=========================================${NC}"
cat "$OUTPUT_FILE" | sed 's/^/  /'
echo ""
echo -e "${CYAN}Wait ~30s for the stream to fully settle if you enabled encryption,${NC}"
echo -e "${CYAN}then run the screener:${NC}"
echo ""
echo "  cd ../../.."
echo "  python3 main.py --regions $REGION --services kinesis --beta 1 --sequential 1"
echo ""
echo "After testing:"
echo "  cd services/kinesis/simulation && ./cleanup_test_resources.sh"

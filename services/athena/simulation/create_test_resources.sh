#!/bin/bash
################################################################################
# Athena Service Screener - Test Resource Creation Script
#
# Creates an intentionally-misconfigured Athena workgroup, plus one workgroup
# that uses managed query results.
#
#   Workgroup #1:
#     - no ResultConfiguration encryption      -> athenaWorkgroupNotEncrypted
#     - EnforceWorkGroupConfiguration false    -> athenaWorkgroupNoEnforcement
#     - EnableMinimumEncryptionConfiguration
#       false                                  -> athenaMinimumEncryptionDisabled
#     - PublishCloudWatchMetricsEnabled false  -> athenaPublishMetricsDisabled
#     - no BytesScannedCutoffPerQuery          -> athenaBytesScannedNoLimit
#     - output location at bucket ROOT         -> athenaWorkgroupS3OutputNoPrefix
#     - no tags                                -> athenaNoTags
#
#   Workgroup #2 (managed query results, AWS owned key):
#     - athenaWorkgroupNotEncrypted            -> PASS (always encrypted)
#     - athenaMinimumEncryptionDisabled,
#       athenaWorkgroupS3OutputNoPrefix,
#       athenaS3OutputNotEncrypted             -> INFO (not applicable)
#
# Checks NOT simulated:
#   athenaWorkgroupDisabled -- would require creating then disabling; the account's
#     existing workgroups already exercise the ENABLED (PASS) branch.
#   athenaEngineVersionOutdated -- AWS no longer allows selecting an engine older
#     than 3, so the FAIL branch is unreachable on a current account.
#   athenaS3OutputNotEncrypted -- depends on the bucket's own encryption; the
#     bucket created here has S3 default encryption (AWS enables SSE-S3 on all new
#     buckets), so this exercises the PASS branch.
#
# Usage: ./create_test_resources.sh [--region REGION] [--help]
################################################################################
set -u
REGION="${AWS_REGION:-ap-southeast-1}"; PREFIX="ss-test"; TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
while [[ $# -gt 0 ]]; do case $1 in
    --region) REGION="$2"; shift 2 ;;
    --help) grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
    *) echo -e "${RED}Unknown: $1${NC}"; exit 1 ;; esac; done
export AWS_PAGER=""
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }
WG="${PREFIX}-athena-wg-${TIMESTAMP}"
WG_MANAGED="${PREFIX}-athena-wg-managed-${TIMESTAMP}"
BUCKET="${PREFIX}-athena-${ACCOUNT_ID}-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"; > "$OUTPUT_FILE"
log() { echo "$1" >> "$OUTPUT_FILE"; }
echo -e "${GREEN}=== Athena Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID"; echo ""

if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" > /dev/null 2>&1
else
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
        --create-bucket-configuration "LocationConstraint=$REGION" > /dev/null 2>&1
fi
[ $? -eq 0 ] && { log "BUCKET:${BUCKET}"; echo -e "${GREEN}✓ s3://${BUCKET}${NC}"; } \
             || { echo -e "${RED}✗ bucket create failed${NC}"; exit 1; }

# OutputLocation points at the bucket ROOT (no prefix) on purpose.
aws athena create-work-group --name "$WG" \
    --configuration "ResultConfiguration={OutputLocation=s3://${BUCKET}/},EnforceWorkGroupConfiguration=false,PublishCloudWatchMetricsEnabled=false" \
    --region "$REGION" > /dev/null 2>&1 \
    && { log "WORKGROUP:${WG}"; echo -e "${GREEN}✓ ${WG}${NC}";
         echo -e "  ${CYAN}-> athenaWorkgroupNotEncrypted, athenaWorkgroupNoEnforcement,${NC}";
         echo -e "  ${CYAN}   athenaMinimumEncryptionDisabled, athenaPublishMetricsDisabled,${NC}";
         echo -e "  ${CYAN}   athenaBytesScannedNoLimit, athenaWorkgroupS3OutputNoPrefix,${NC}";
         echo -e "  ${CYAN}   athenaNoTags${NC}"; } \
    || echo -e "${YELLOW}⚠ create-work-group failed${NC}"

# Managed query results: Athena stores and encrypts the results itself, so the
# workgroup has no ResultConfiguration.
aws athena create-work-group --name "$WG_MANAGED" \
    --configuration "ManagedQueryResultsConfiguration={Enabled=true}" \
    --region "$REGION" > /dev/null 2>&1 \
    && { log "WORKGROUP:${WG_MANAGED}"; echo -e "${GREEN}✓ ${WG_MANAGED}${NC}";
         echo -e "  ${CYAN}-> athenaWorkgroupNotEncrypted PASS; athenaMinimumEncryptionDisabled,${NC}";
         echo -e "  ${CYAN}   athenaWorkgroupS3OutputNoPrefix, athenaS3OutputNotEncrypted INFO${NC}"; } \
    || echo -e "${YELLOW}⚠ create-work-group (managed query results) failed${NC}"

echo ""; echo -e "${GREEN}=== Creation Complete ===${NC}"
echo "  cd ../../.. && python3 main.py --regions $REGION --services athena --beta 1 --sequential 1"
echo -e "${YELLOW}No queries are ever run, so no Athena scan charges are incurred.${NC}"

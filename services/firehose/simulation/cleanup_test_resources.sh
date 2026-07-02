#!/bin/bash

################################################################################
# Firehose Service Screener - Test Resource Cleanup Script
#
# Deletes Firehose delivery stream + IAM role + S3 bucket (and its objects).
# Usage: ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --force)  FORCE=true; shift ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then RESOURCE_FILE="$1"; shift
            else echo -e "${RED}Unknown: $1${NC}"; exit 1; fi
            ;;
    esac
done

if [ -z "$RESOURCE_FILE" ]; then
    RESOURCE_FILE=$(ls -1t created_resources_*.txt 2>/dev/null | head -1)
    [ -z "$RESOURCE_FILE" ] && { echo -e "${RED}No manifest found${NC}"; exit 1; }
    echo -e "${YELLOW}Auto-detected: $RESOURCE_FILE${NC}"
fi

[ ! -f "$RESOURCE_FILE" ] && { echo -e "${RED}Not found: $RESOURCE_FILE${NC}"; exit 1; }

echo -e "${GREEN}=== Firehose Test Resource Cleanup ===${NC}"
echo "Region: $REGION | File: $RESOURCE_FILE"

RESOURCES=()
while IFS= read -r line; do
    [ -n "$line" ] && RESOURCES+=("$line")
done < "$RESOURCE_FILE"

echo ""
echo "Resources:"
for r in "${RESOURCES[@]}"; do echo "  - $r"; done
echo ""

if [ "$FORCE" = false ]; then
    read -p "Continue? (yes/no): " C
    [ "$C" != "yes" ] && { echo "Cancelled."; exit 0; }
fi

by_type() {
    local t="$1"
    for r in "${RESOURCES[@]}"; do
        [[ "$r" == ${t}:* ]] && echo "${r#${t}:}"
    done
}

################################################################################
# Step 1: Delete Firehose delivery stream
################################################################################

echo -e "\n${GREEN}=== Step 1: Delete Firehose delivery stream ===${NC}"
for STREAM in $(by_type DELIVERY_STREAM); do
    echo "Deleting: $STREAM"
    aws firehose delete-delivery-stream \
        --delivery-stream-name "$STREAM" \
        --allow-force-delete \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓ requested (delete is asynchronous)${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

# Delivery stream deletion is async but the IAM role can be detached
# even while it's still deleting.

################################################################################
# Step 2: Delete IAM role (inline policies first)
################################################################################

echo -e "\n${GREEN}=== Step 2: Delete IAM role ===${NC}"
for ROLE in $(by_type IAM_ROLE); do
    echo "Deleting: $ROLE"
    # Detach inline policies (only one attached in this script)
    for POL in $(aws iam list-role-policies --role-name "$ROLE" \
                    --query 'PolicyNames' --output text 2>/dev/null); do
        aws iam delete-role-policy --role-name "$ROLE" --policy-name "$POL" 2>/dev/null || true
    done
    aws iam delete-role --role-name "$ROLE" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or role still in use${NC}"
done

################################################################################
# Step 3: Empty + delete S3 bucket
################################################################################

echo -e "\n${GREEN}=== Step 3: Empty + delete S3 bucket ===${NC}"
for BUCKET in $(by_type S3_BUCKET); do
    echo "Emptying: $BUCKET"
    aws s3 rm "s3://${BUCKET}" --recursive --region "$REGION" 2>/dev/null || true
    aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or non-empty${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."
echo ""
echo -e "${YELLOW}Note: Firehose deletion is asynchronous. If you re-run the${NC}"
echo -e "${YELLOW}scanner within ~1-2 minutes, the stream may still appear${NC}"
echo -e "${YELLOW}in DELETING state.${NC}"

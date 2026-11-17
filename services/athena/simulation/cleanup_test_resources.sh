#!/bin/bash
################################################################################
# Athena Service Screener - Test Resource Cleanup Script
# Deletes only the workgroups/buckets recorded in a manifest (this includes
# the managed-query-results workgroup, which create_test_resources.sh records
# as a WORKGROUP: line like the other one).
# Usage: ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
################################################################################
set -u
REGION="${AWS_REGION:-ap-southeast-1}"; FORCE=false; RESOURCE_FILE=""
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
while [[ $# -gt 0 ]]; do case $1 in
    --region) REGION="$2"; shift 2 ;; --force) FORCE=true; shift ;;
    --help) grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
    *) if [ -z "$RESOURCE_FILE" ]; then RESOURCE_FILE="$1"; shift; else shift; fi ;;
esac; done
export AWS_PAGER=""
[ -z "$RESOURCE_FILE" ] && RESOURCE_FILE=$(ls -1t created_resources_*.txt 2>/dev/null | head -1)
[ -z "$RESOURCE_FILE" ] || [ ! -f "$RESOURCE_FILE" ] && { echo -e "${RED}No manifest${NC}"; exit 1; }
echo -e "${GREEN}=== Athena Cleanup ===${NC} ($RESOURCE_FILE)"
if [ "$FORCE" = false ]; then read -p "Continue? (yes/no): " C; [ "$C" != "yes" ] && exit 0; fi
D=0; F=0
while IFS= read -r line; do
    if [[ "$line" == WORKGROUP:* ]]; then
        W="${line#WORKGROUP:}"
        aws athena delete-work-group --work-group "$W" --recursive-delete-option \
            --region "$REGION" > /dev/null 2>&1 \
            && { echo -e "${GREEN}✓ Deleted workgroup $W${NC}"; D=$((D+1)); } \
            || { echo -e "${YELLOW}⚠ workgroup $W${NC}"; F=$((F+1)); }
    elif [[ "$line" == BUCKET:* ]]; then
        B="${line#BUCKET:}"
        aws s3 rm "s3://${B}" --recursive --region "$REGION" > /dev/null 2>&1
        aws s3api delete-bucket --bucket "$B" --region "$REGION" > /dev/null 2>&1 \
            && { echo -e "${GREEN}✓ Deleted bucket $B${NC}"; D=$((D+1)); } \
            || { echo -e "${YELLOW}⚠ bucket $B${NC}"; F=$((F+1)); }
    fi
done < "$RESOURCE_FILE"
echo ""; echo -e "${GREEN}=== Cleanup Complete: ${D} deleted, ${F} skipped ===${NC}"
[ "$F" -eq 0 ] && [ "$D" -gt 0 ] && mv "$RESOURCE_FILE" "${RESOURCE_FILE}.done"

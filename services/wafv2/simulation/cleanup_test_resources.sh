#!/bin/bash

################################################################################
# WAFv2 Service Screener - Test Resource Cleanup Script
#
# Deletes REGIONAL WebACLs created by create_test_resources.sh. Requires the
# LockToken (fetched fresh) because wafv2:DeleteWebACL uses optimistic locking.
#
# Usage: ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
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

echo -e "${GREEN}=== WAFv2 Test Resource Cleanup ===${NC}"
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

################################################################################
# Delete each WebACL
################################################################################

echo -e "\n${GREEN}=== Delete WebACLs ===${NC}"
for entry in "${RESOURCES[@]}"; do
    if [[ "$entry" != WEBACL:* ]]; then
        continue
    fi
    # Format: WEBACL:<name>|<id>|<arn>
    payload="${entry#WEBACL:}"
    NAME="${payload%%|*}"
    rest="${payload#*|}"
    ID="${rest%%|*}"
    ARN="${rest#*|}"

    # Refetch a fresh LockToken (the one in create output may be stale).
    LOCK=$(aws wafv2 get-web-acl \
        --name "$NAME" \
        --id "$ID" \
        --scope REGIONAL \
        --region "$REGION" \
        --query 'LockToken' \
        --output text 2>/dev/null || true)

    if [ -z "${LOCK:-}" ] || [ "$LOCK" = "None" ]; then
        echo -e "${YELLOW}  ⚠ ${NAME}: not found (already deleted?)${NC}"
        continue
    fi

    echo "Deleting: ${NAME}"
    aws wafv2 delete-web-acl \
        --name "$NAME" \
        --id "$ID" \
        --scope REGIONAL \
        --lock-token "$LOCK" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ delete failed (still associated? check console)${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."

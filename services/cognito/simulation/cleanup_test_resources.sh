#!/bin/bash

################################################################################
# Cognito Service Screener - Test Resource Cleanup Script
#
# Deletes the user pool created by create_test_resources.sh. App clients are
# deleted implicitly when the pool is deleted.
#
# Usage:
#   ./cleanup_test_resources.sh [RESOURCE_FILE] [--region REGION] [--force]
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

echo -e "${GREEN}=== Cognito Test Resource Cleanup ===${NC}"
echo "Region: $REGION | File: $RESOURCE_FILE"

RESOURCES=()
while IFS= read -r line; do
    [ -n "$line" ] && RESOURCES+=("$line")
done < "$RESOURCE_FILE"

echo ""
echo "Resources to delete:"
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
# Step 1: Delete app clients explicitly (also removed with pool, but be safe)
################################################################################

echo -e "\n${GREEN}=== Step 1: Delete app clients ===${NC}"
for ENTRY in $(by_type APP_CLIENT); do
    POOL_ID="${ENTRY%%:*}"
    CLIENT_ID="${ENTRY##*:}"
    echo "Deleting app client ${CLIENT_ID} in pool ${POOL_ID}"
    aws cognito-idp delete-user-pool-client \
        --user-pool-id "$POOL_ID" \
        --client-id "$CLIENT_ID" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

################################################################################
# Step 2: Turn off deletion protection (safety, in case the user enabled it),
#         then delete the user pool.
################################################################################

echo -e "\n${GREEN}=== Step 2: Delete user pool ===${NC}"
for POOL_ID in $(by_type USER_POOL); do
    # If deletion protection got flipped to ACTIVE, disable it first.
    aws cognito-idp update-user-pool \
        --user-pool-id "$POOL_ID" \
        --deletion-protection INACTIVE \
        --region "$REGION" > /dev/null 2>&1 || true

    echo "Deleting user pool: $POOL_ID"
    aws cognito-idp delete-user-pool \
        --user-pool-id "$POOL_ID" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."

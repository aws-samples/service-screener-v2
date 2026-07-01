#!/bin/bash

################################################################################
# WAFv2 Service Screener - Test Resource Cleanup Script (Phase 1 + Phase 2)
#
# Deletes every ss-test-* resource created by the extended create script.
# Order matters: WAFv2 objects that reference each other must be untangled
# before deletion, and every WAFv2 delete uses a LockToken.
#
# Deletion order:
#   1. Delete AppSync API (independent)
#   2. Delete WAFv2 LoggingConfiguration attached to partial WebACL
#   3. Delete WebACLs (both — LockToken refetched fresh)
#   4. Delete custom Rule Group (WebACL no longer references it)
#   5. Delete Regex Pattern Set
#   6. Delete IP Set
#   7. Delete CloudWatch Log Group
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

# Helper: parse a manifest entry into name|id|arn pieces.
parse_wafv2() {
    local prefix="$1"
    local entry="$2"
    local payload="${entry#${prefix}:}"
    local name="${payload%%|*}"
    local rest="${payload#*|}"
    local id="${rest%%|*}"
    rest="${rest#*|}"
    local arn="${rest%%|*}"
    echo "${name}|${id}|${arn}"
}

# LockToken helper — WAFv2 requires an up-to-date LockToken for deletes.
fresh_lock() {
    local api="$1"     # get-web-acl / get-ip-set / get-regex-pattern-set / get-rule-group
    local name="$2"
    local id="$3"
    local scope="$4"
    aws wafv2 "$api" \
        --name "$name" \
        --id "$id" \
        --scope "$scope" \
        --region "$REGION" \
        --query 'LockToken' \
        --output text 2>/dev/null || true
}

################################################################################
# Step 1: Delete AppSync APIs
################################################################################

echo -e "\n${GREEN}=== Step 1: Delete AppSync APIs ===${NC}"
for entry in "${RESOURCES[@]}"; do
    [[ "$entry" != APPSYNC:* ]] && continue
    payload="${entry#APPSYNC:}"
    API_ID="${payload%%|*}"
    echo "Deleting AppSync API: $API_ID"
    aws appsync delete-graphql-api --api-id "$API_ID" --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or delete failed${NC}"
done

################################################################################
# Step 2: Delete WAFv2 Logging Configurations
################################################################################

echo -e "\n${GREEN}=== Step 2: Delete WAF Logging Configurations ===${NC}"
found_logcfg=false
for entry in "${RESOURCES[@]}"; do
    [[ "$entry" != LOGCFG:* ]] && continue
    found_logcfg=true
    ARN="${entry#LOGCFG:}"
    echo "Deleting logging config on: $ARN"
    aws wafv2 delete-logging-configuration \
        --resource-arn "$ARN" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or never set${NC}"
done
$found_logcfg || echo "  (none)"

################################################################################
# Step 3: Delete WebACLs
################################################################################

echo -e "\n${GREEN}=== Step 3: Delete WebACLs ===${NC}"
for entry in "${RESOURCES[@]}"; do
    [[ "$entry" != WEBACL:* ]] && continue
    IFS='|' read -r NAME ID ARN < <(parse_wafv2 WEBACL "$entry")
    LOCK=$(fresh_lock get-web-acl "$NAME" "$ID" REGIONAL)
    if [ -z "${LOCK:-}" ] || [ "$LOCK" = "None" ]; then
        echo -e "${YELLOW}  ⚠ ${NAME}: not found (already deleted?)${NC}"
        continue
    fi
    echo "Deleting WebACL: $NAME"
    aws wafv2 delete-web-acl \
        --name "$NAME" \
        --id "$ID" \
        --scope REGIONAL \
        --lock-token "$LOCK" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ delete failed (still associated? check console)${NC}"
done

################################################################################
# Step 4: Delete custom Rule Groups
################################################################################

echo -e "\n${GREEN}=== Step 4: Delete custom Rule Groups ===${NC}"
found_rg=false
for entry in "${RESOURCES[@]}"; do
    [[ "$entry" != RULEGROUP:* ]] && continue
    found_rg=true
    payload="${entry#RULEGROUP:}"
    NAME="${payload%%|*}"; rest="${payload#*|}"
    ID="${rest%%|*}"; rest="${rest#*|}"
    ARN="${rest%%|*}"; rest="${rest#*|}"
    SCOPE="${rest:-REGIONAL}"
    LOCK=$(fresh_lock get-rule-group "$NAME" "$ID" "$SCOPE")
    if [ -z "${LOCK:-}" ] || [ "$LOCK" = "None" ]; then
        echo -e "${YELLOW}  ⚠ ${NAME}: not found${NC}"
        continue
    fi
    echo "Deleting Rule Group: $NAME"
    aws wafv2 delete-rule-group \
        --name "$NAME" \
        --id "$ID" \
        --scope "$SCOPE" \
        --lock-token "$LOCK" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ delete failed (still referenced?)${NC}"
done
$found_rg || echo "  (none)"

################################################################################
# Step 5: Delete Regex Pattern Sets
################################################################################

echo -e "\n${GREEN}=== Step 5: Delete Regex Pattern Sets ===${NC}"
found_rps=false
for entry in "${RESOURCES[@]}"; do
    [[ "$entry" != REGEXSET:* ]] && continue
    found_rps=true
    payload="${entry#REGEXSET:}"
    NAME="${payload%%|*}"; rest="${payload#*|}"
    ID="${rest%%|*}"; rest="${rest#*|}"
    ARN="${rest%%|*}"; rest="${rest#*|}"
    SCOPE="${rest:-REGIONAL}"
    LOCK=$(fresh_lock get-regex-pattern-set "$NAME" "$ID" "$SCOPE")
    if [ -z "${LOCK:-}" ] || [ "$LOCK" = "None" ]; then
        echo -e "${YELLOW}  ⚠ ${NAME}: not found${NC}"
        continue
    fi
    echo "Deleting Regex Pattern Set: $NAME"
    aws wafv2 delete-regex-pattern-set \
        --name "$NAME" \
        --id "$ID" \
        --scope "$SCOPE" \
        --lock-token "$LOCK" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ delete failed${NC}"
done
$found_rps || echo "  (none)"

################################################################################
# Step 6: Delete IP Sets
################################################################################

echo -e "\n${GREEN}=== Step 6: Delete IP Sets ===${NC}"
found_ipset=false
for entry in "${RESOURCES[@]}"; do
    [[ "$entry" != IPSET:* ]] && continue
    found_ipset=true
    payload="${entry#IPSET:}"
    NAME="${payload%%|*}"; rest="${payload#*|}"
    ID="${rest%%|*}"; rest="${rest#*|}"
    ARN="${rest%%|*}"; rest="${rest#*|}"
    SCOPE="${rest:-REGIONAL}"
    LOCK=$(fresh_lock get-ip-set "$NAME" "$ID" "$SCOPE")
    if [ -z "${LOCK:-}" ] || [ "$LOCK" = "None" ]; then
        echo -e "${YELLOW}  ⚠ ${NAME}: not found${NC}"
        continue
    fi
    echo "Deleting IP Set: $NAME"
    aws wafv2 delete-ip-set \
        --name "$NAME" \
        --id "$ID" \
        --scope "$SCOPE" \
        --lock-token "$LOCK" \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ delete failed${NC}"
done
$found_ipset || echo "  (none)"

################################################################################
# Step 7: Delete CloudWatch Log Groups
################################################################################

echo -e "\n${GREEN}=== Step 7: Delete CloudWatch Log Groups ===${NC}"
found_lg=false
for entry in "${RESOURCES[@]}"; do
    [[ "$entry" != LOGGROUP:* ]] && continue
    found_lg=true
    NAME="${entry#LOGGROUP:}"
    echo "Deleting log group: $NAME"
    aws logs delete-log-group --log-group-name "$NAME" --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done
$found_lg || echo "  (none)"

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."

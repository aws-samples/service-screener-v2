#!/bin/bash

################################################################################
# Route 53 Service Screener - Test Resource Cleanup Script
#
# Deletes every hosted zone and health check listed in a manifest produced
# by create_test_resources.sh. Deletes records first, then the zone.
#
# Usage:
#   ./cleanup_test_resources.sh [--force] [--manifest FILE] [--region REGION]
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
FORCE=false
MANIFEST=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region)   REGION="$2"; shift 2 ;;
        --force)    FORCE=true; shift ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --help)     grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)          echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

# If no manifest specified, use the most recent one in current dir.
if [ -z "$MANIFEST" ]; then
    MANIFEST=$(ls -t created_resources_*.txt 2>/dev/null | head -1 || true)
    if [ -z "$MANIFEST" ]; then
        echo -e "${YELLOW}No manifest file found (created_resources_*.txt).${NC}"
        echo "Nothing to clean up, or specify --manifest FILE."
        exit 0
    fi
fi

echo -e "${GREEN}=== Route 53 Cleanup ===${NC}"
echo "Manifest: $MANIFEST"
echo ""

if [ "$FORCE" != true ]; then
    echo -e "${YELLOW}This will delete every resource listed in $MANIFEST${NC}"
    read -p "Proceed? (y/N) " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

################################################################################
# Delete hosted zones (delete records first, then zone)
################################################################################
while IFS= read -r line; do
    case "$line" in
        zone:*)
            ZONE_ID="${line#zone:}"
            echo -e "${CYAN}Deleting hosted zone: $ZONE_ID${NC}"

            # Empty all non-default records first (Route 53 keeps NS + SOA at
            # deletion time — those are removed by delete-hosted-zone).
            RRSETS=$(aws route53 list-resource-record-sets \
                --hosted-zone-id "$ZONE_ID" \
                --output json 2>/dev/null || echo '{}')

            CHANGES=$(echo "$RRSETS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
changes = []
for rr in data.get('ResourceRecordSets', []):
    if rr.get('Type') in ('NS', 'SOA') and rr.get('Name', '').count('.') <= 3:
        # Skip apex NS + SOA — delete-hosted-zone removes them.
        # Heuristic: apex records have the shortest name.
        pass
    if rr.get('Type') in ('NS', 'SOA'):
        # Skip zone's own NS + SOA at the apex
        continue
    changes.append({'Action': 'DELETE', 'ResourceRecordSet': rr})
if changes:
    print(json.dumps({'Changes': changes}))
")

            if [ -n "$CHANGES" ]; then
                CHANGE_FILE=$(mktemp)
                echo "$CHANGES" > "$CHANGE_FILE"
                aws route53 change-resource-record-sets \
                    --hosted-zone-id "$ZONE_ID" \
                    --change-batch "file://$CHANGE_FILE" >/dev/null 2>&1 || \
                    echo -e "  ${YELLOW}Failed to remove records — continuing${NC}"
                rm -f "$CHANGE_FILE"
            fi

            # Delete the zone itself.
            if aws route53 delete-hosted-zone --id "$ZONE_ID" >/dev/null 2>&1; then
                echo -e "  ${GREEN}Deleted zone $ZONE_ID${NC}"
            else
                echo -e "  ${YELLOW}Failed to delete zone $ZONE_ID (may still hold records)${NC}"
            fi
            ;;
        hc:*)
            HC_ID="${line#hc:}"
            echo -e "${CYAN}Deleting health check: $HC_ID${NC}"
            if aws route53 delete-health-check --health-check-id "$HC_ID" >/dev/null 2>&1; then
                echo -e "  ${GREEN}Deleted health check $HC_ID${NC}"
            else
                echo -e "  ${YELLOW}Failed to delete health check $HC_ID${NC}"
            fi
            ;;
        "" | \#*) ;;
        *) echo -e "${YELLOW}Unknown manifest entry: $line${NC}" ;;
    esac
done < "$MANIFEST"

echo ""
echo -e "${GREEN}Cleanup complete.${NC}"

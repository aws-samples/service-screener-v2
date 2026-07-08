#!/bin/bash

################################################################################
# Kinesis Data Streams - Service Screener Simulation Cleanup
#
# Deletes the two Kinesis streams created by create_test_resources.sh.
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

echo -e "${GREEN}=== Kinesis Test Resource Cleanup ===${NC}"
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
# Delete all Kinesis streams (enforce_consumer_deletion cleans up any EFO
# consumers that may have been registered during testing)
################################################################################

echo -e "\n${GREEN}=== Delete Kinesis streams ===${NC}"
for STREAM in $(by_type STREAM); do
    echo "Deleting: $STREAM"
    aws kinesis delete-stream \
        --stream-name "$STREAM" \
        --enforce-consumer-deletion \
        --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or not deletable${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."

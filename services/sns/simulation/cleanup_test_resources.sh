#!/bin/bash

################################################################################
# SNS Service Screener - Test Resource Cleanup Script
#
# Deletes SNS topic + subscriptions + SQS subscriber queue.
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

echo -e "${GREEN}=== SNS Test Resource Cleanup ===${NC}"
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
# Step 1: Unsubscribe (confirmed subs only — pending subs die with the topic)
################################################################################

echo -e "\n${GREEN}=== Step 1: Unsubscribe confirmed subscriptions ===${NC}"
for SUB in $(by_type SUBSCRIPTION); do
    echo "Unsubscribing: $SUB"
    aws sns unsubscribe --subscription-arn "$SUB" --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or unconfirmed${NC}"
done

################################################################################
# Step 2: Delete SQS queue
################################################################################

echo -e "\n${GREEN}=== Step 2: Delete SQS queue ===${NC}"
for URL in $(by_type SQS_QUEUE); do
    echo "Deleting: $URL"
    aws sqs delete-queue --queue-url "$URL" --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

################################################################################
# Step 3: Delete SNS topic (this also removes any pending subscriptions)
################################################################################

echo -e "\n${GREEN}=== Step 3: Delete SNS topic ===${NC}"
for ARN in $(by_type TOPIC); do
    echo "Deleting: $ARN"
    aws sns delete-topic --topic-arn "$ARN" --region "$REGION" 2>/dev/null \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."

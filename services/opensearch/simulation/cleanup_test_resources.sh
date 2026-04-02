#!/bin/bash

################################################################################
# OpenSearch Service Review - Test Resource Cleanup Script
#
# Deletion order:
#   1. OpenSearch Domains (wait for deletion)
#   2. Security Groups
#
# Usage:
#   ./cleanup_test_resources.sh [RESOURCE_FILE] [OPTIONS]
#
# Options:
#   --region REGION    AWS region (default: ap-southeast-1)
#   --force            Skip confirmation prompts
#   --help             Show this help message
#
################################################################################

set -e
set -u

REGION="${AWS_REGION:-ap-southeast-1}"
FORCE=false
RESOURCE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --force)  FORCE=true; shift ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)
            if [ -z "$RESOURCE_FILE" ]; then
                RESOURCE_FILE="$1"; shift
            else
                echo -e "${RED}Error: Unknown option $1${NC}"; exit 1
            fi
            ;;
    esac
done

if [ -z "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file required${NC}"
    echo "Usage: $0 <resource_file> [OPTIONS]"
    exit 1
fi

if [ ! -f "$RESOURCE_FILE" ]; then
    echo -e "${RED}Error: Resource file not found: $RESOURCE_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}=== OpenSearch Test Resource Cleanup ===${NC}"
echo "Region: $REGION"
echo "Resource file: $RESOURCE_FILE"
echo ""

RESOURCES=()
while IFS= read -r line; do
    RESOURCES+=("$line")
done < "$RESOURCE_FILE"

count_type() { grep -c "^$1:" "$RESOURCE_FILE" 2>/dev/null || echo 0; }

DOMAIN_COUNT=$(count_type "DOMAIN")
SG_COUNT=$(count_type "SECURITY_GROUP")

echo "Resources to delete:"
echo "  - OpenSearch Domains:   $DOMAIN_COUNT"
echo "  - Security Groups:      $SG_COUNT"
echo ""

if [ "$FORCE" = false ]; then
    echo -e "${YELLOW}WARNING: This will permanently delete all resources listed above.${NC}"
    read -p "Continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Cleanup cancelled."
        exit 0
    fi
fi

################################################################################
# Step 1: Delete OpenSearch Domains
################################################################################

echo -e "\n${GREEN}=== Step 1: Deleting OpenSearch Domains ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == DOMAIN:* ]]; then
        NAME="${resource#DOMAIN:}"
        echo "Deleting domain: $NAME"
        aws opensearch delete-domain \
            --domain-name "$NAME" \
            --region "$REGION" > /dev/null 2>&1 || echo "  (already deleted or not found)"
    fi
done

# Wait for domains to be deleted
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == DOMAIN:* ]]; then
        NAME="${resource#DOMAIN:}"
        echo -e "${YELLOW}Waiting for $NAME to be deleted (may take 5-10 minutes)...${NC}"
        while true; do
            EXISTS=$(aws opensearch describe-domain \
                --domain-name "$NAME" \
                --query 'DomainStatus.Deleted' --output text \
                --region "$REGION" 2>/dev/null || echo "gone")
            if [ "$EXISTS" = "gone" ]; then
                break
            fi
            sleep 15
        done
        echo -e "${GREEN}✓ $NAME deleted${NC}"
    fi
done

################################################################################
# Step 2: Delete Security Groups
################################################################################

echo -e "\n${GREEN}=== Step 2: Deleting Security Groups ===${NC}"
for resource in "${RESOURCES[@]}"; do
    if [[ $resource == SECURITY_GROUP:* ]]; then
        SG_ID="${resource#SECURITY_GROUP:}"
        echo "Deleting security group: $SG_ID"
        aws ec2 delete-security-group \
            --group-id "$SG_ID" \
            --region "$REGION" 2>/dev/null || echo "  (already deleted or not found)"
    fi
done
echo -e "${GREEN}✓ Security groups cleanup complete${NC}"

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Deleted:"
echo "  ✓ $DOMAIN_COUNT domain(s)"
echo "  ✓ $SG_COUNT security group(s)"
echo ""
echo -e "${YELLOW}You can now delete the resource file: $RESOURCE_FILE${NC}"
echo -e "${GREEN}Cleanup successful!${NC}"

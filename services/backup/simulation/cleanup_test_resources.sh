#!/bin/bash

################################################################################
# AWS Backup Service Screener - Test Resource Cleanup Script
#
# Deletes vaults, backup plan, and IAM role created by create_test_resources.sh.
#
# NOTE: Vaults with recovery points cannot be deleted until every recovery
# point is removed first. This script does not force-delete recovery points —
# rerun after the vault has drained (recovery points typically stick to their
# lifecycle unless manually deleted).
#
# NOTE: Vaults in COMPLIANCE-mode Vault Lock (past LockDate) CANNOT be deleted
# by anyone. This script only handles GOVERNANCE-mode locks (which are
# reversible via IAM).
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

echo -e "${GREEN}=== AWS Backup Test Resource Cleanup ===${NC}"
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
# Step 1: Delete backup plans (must precede vault deletion)
################################################################################

echo -e "\n${GREEN}=== Step 1: Delete backup plans ===${NC}"
for PID in $(by_type PLAN); do
    echo "Deleting plan: $PID"
    # List and delete selections first — plans with attached selections
    # cannot be deleted directly. Our test plan has no selections but future
    # extensions may add them.
    SELECTIONS=$(aws backup list-backup-selections \
        --backup-plan-id "$PID" \
        --region "$REGION" \
        --query 'BackupSelectionsList[*].SelectionId' \
        --output text 2>/dev/null || true)
    for SID in $SELECTIONS; do
        aws backup delete-backup-selection \
            --backup-plan-id "$PID" \
            --selection-id "$SID" \
            --region "$REGION" > /dev/null 2>&1 || true
    done
    aws backup delete-backup-plan \
        --backup-plan-id "$PID" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone or has selections${NC}"
done

################################################################################
# Step 2: Delete backup vaults
################################################################################

echo -e "\n${GREEN}=== Step 2: Delete backup vaults ===${NC}"
for VAULT in $(by_type VAULT); do
    echo "Deleting vault: $VAULT"

    # Governance-mode Vault Lock can be removed via API. Compliance-mode
    # locks past LockDate are permanent — this call will simply fail.
    aws backup delete-backup-vault-lock-configuration \
        --backup-vault-name "$VAULT" \
        --region "$REGION" > /dev/null 2>&1 || true

    # Remove any access policy before vault delete.
    aws backup delete-backup-vault-access-policy \
        --backup-vault-name "$VAULT" \
        --region "$REGION" > /dev/null 2>&1 || true

    aws backup delete-backup-vault \
        --backup-vault-name "$VAULT" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ has recovery points, is locked, or already gone${NC}"
done

################################################################################
# Step 3: Delete IAM role
################################################################################

echo -e "\n${GREEN}=== Step 3: Delete IAM role ===${NC}"
for ROLE in $(by_type IAM_ROLE); do
    echo "Deleting IAM role: $ROLE"
    # Detach policies before role delete.
    ATTACHED=$(aws iam list-attached-role-policies \
        --role-name "$ROLE" \
        --query 'AttachedPolicies[*].PolicyArn' \
        --output text 2>/dev/null || true)
    for PARN in $ATTACHED; do
        aws iam detach-role-policy \
            --role-name "$ROLE" \
            --policy-arn "$PARN" > /dev/null 2>&1 || true
    done
    aws iam delete-role --role-name "$ROLE" > /dev/null 2>&1 \
        && echo -e "${GREEN}  ✓${NC}" \
        || echo -e "${YELLOW}  ⚠ already gone${NC}"
done

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
echo -e "${CYAN}rm $RESOURCE_FILE${NC} to tidy up the manifest."

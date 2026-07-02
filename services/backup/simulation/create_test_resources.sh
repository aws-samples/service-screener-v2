#!/bin/bash

################################################################################
# AWS Backup Service Screener - Test Resource Creation Script
#
# Creates an intentionally-insecure AWS Backup vault + plan + selection that
# exercises every `backup*` service-screener check that can be forced through
# the AWS API without waiting for a real backup job to complete.
#
# Resources created (all prefixed with `ss-test-backup-`):
#
#   Vault #1  (weak vault)                    → FAILs
#     - No Vault Lock                         backupVaultNoLock
#     - AWS-owned encryption key by default   backupVaultDefaultEncryption
#     - No vault access policy                backupVaultNoAccessPolicy
#     - Zero recovery points (older than 7d   backupVaultEmpty (fires only if
#       requires waiting; INFO on same-day)     script re-run 7 days later)
#
#   Vault #2  (Governance-mode lock)          → FAILs
#     - Governance-mode Vault Lock            backupVaultLockNotFinalized
#     - Otherwise passes vault checks
#
#   Backup Plan (minimal-rule plan)           → FAILs
#     - Rule with no Lifecycle.DeleteAfterDays  backupPlanNoLifecycle
#     - Rule with no CompletionWindowMinutes    backupPlanNoCompletionWindow
#     - Rule with weekly schedule (< daily)     backupPlanInfrequentSchedule
#     - Rule with no CopyActions                backupPlanNoCrossRegionCopy
#     - Rule with EnableContinuousBackup=false  backupPlanNoContinuousBackup
#     - No resource selection attached          backupPlanNotAssigned
#
# Not simulated by this script (require account/org state changes):
#   - backupNoPlanExists          (creating any plan disproves it)
#   - backupCrossAccountDisabled  (org-level setting)
#   - backupServiceOptInDisabled  (region-level setting)
#   - backupServiceManagementDisabled
#   - backupCriticalResourcesUnprotected  (fires against real EBS/RDS/DDB)
#   - backupNoLogicallyAirGappedVault  (advisory; fires whenever no
#     LOGICALLY_AIR_GAPPED_BACKUP_VAULT exists)
#   - backupPlanNoRules  (requires a plan literally with 0 rules — the
#     Backup API rejects that at CreateBackupPlan time)
#   - backupRecoveryPointNotEncrypted / NoCMK / ExpiredLifecycle
#     (requires actual backup jobs to have completed)
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test-backup"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)        echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

WEAK_VAULT="${PREFIX}-weak-${TIMESTAMP}"
LOCK_VAULT="${PREFIX}-gov-lock-${TIMESTAMP}"
PLAN_NAME="${PREFIX}-plan-${TIMESTAMP}"
IAM_ROLE_NAME="${PREFIX}-role-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== AWS Backup Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Create weak backup vault (no lock, no policy, default encryption)
################################################################################

echo -e "${GREEN}=== Step 1: Create weak backup vault (no lock/policy/CMK) ===${NC}"

# The Backup API assigns an AWS-owned key by default when EncryptionKeyArn is
# omitted. This triggers backupVaultDefaultEncryption.
aws backup create-backup-vault \
    --backup-vault-name "$WEAK_VAULT" \
    --region "$REGION" \
    --output json > /dev/null 2>&1 || {
        echo -e "${RED}✗ Vault create failed${NC}"; exit 1;
    }
log "VAULT:${WEAK_VAULT}"
echo -e "${GREEN}✓ Weak vault: ${WEAK_VAULT}${NC}"

################################################################################
# Step 2: Create a second vault + governance-mode Vault Lock
################################################################################

echo -e "\n${GREEN}=== Step 2: Create vault with GOVERNANCE-mode Vault Lock ===${NC}"

aws backup create-backup-vault \
    --backup-vault-name "$LOCK_VAULT" \
    --region "$REGION" \
    --output json > /dev/null 2>&1 || {
        echo -e "${YELLOW}⚠ Lock-vault create failed (continuing)${NC}";
    }
log "VAULT:${LOCK_VAULT}"

# Vault Lock in GOVERNANCE mode = no ChangeableForDays argument. This fires
# backupVaultLockNotFinalized (LockDate is null → lock is reversible).
aws backup put-backup-vault-lock-configuration \
    --backup-vault-name "$LOCK_VAULT" \
    --min-retention-days 1 \
    --max-retention-days 3650 \
    --region "$REGION" \
    --output json > /dev/null 2>&1 || {
        echo -e "${YELLOW}⚠ Governance-mode Vault Lock failed (may require special IAM)${NC}";
    }
echo -e "${GREEN}✓ Governance-locked vault: ${LOCK_VAULT}${NC}"

################################################################################
# Step 3: Create IAM role for AWS Backup (needed by BackupSelection)
################################################################################

echo -e "\n${GREEN}=== Step 3: Create Backup service role ===${NC}"

TRUST_POLICY=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "backup.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF
)

ROLE_ARN=$(aws iam create-role \
    --role-name "$IAM_ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --query 'Role.Arn' \
    --output text 2>/dev/null || true)

if [ -n "$ROLE_ARN" ]; then
    aws iam attach-role-policy \
        --role-name "$IAM_ROLE_NAME" \
        --policy-arn "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup" \
        > /dev/null 2>&1 || true
    log "IAM_ROLE:${IAM_ROLE_NAME}"
    echo -e "${GREEN}✓ Backup role: ${IAM_ROLE_NAME}${NC}"
    echo -e "${CYAN}  Waiting 10s for IAM role to propagate...${NC}"
    sleep 10
else
    echo -e "${YELLOW}⚠ IAM role create failed; selection creation will be skipped${NC}"
    ROLE_ARN=""
fi

################################################################################
# Step 4: Create backup plan with weak-config rule
################################################################################

echo -e "\n${GREEN}=== Step 4: Create backup plan (weak rule config) ===${NC}"

# Weak rule characteristics:
#   - Weekly cron (fires backupPlanInfrequentSchedule)
#   - No Lifecycle block (fires backupPlanNoLifecycle)
#   - No CompletionWindowMinutes (fires backupPlanNoCompletionWindow)
#   - No CopyActions (fires backupPlanNoCrossRegionCopy)
#   - EnableContinuousBackup=false (fires backupPlanNoContinuousBackup once
#     a PITR-capable resource is attached)
#
# Note: AWS Backup will accept a rule without Lifecycle but requires at least
# a schedule and TargetBackupVaultName.
PLAN_JSON=$(cat <<EOF
{
  "BackupPlanName": "${PLAN_NAME}",
  "Rules": [
    {
      "RuleName": "weekly-rule-no-lifecycle",
      "TargetBackupVaultName": "${WEAK_VAULT}",
      "ScheduleExpression": "cron(0 5 ? * 1 *)",
      "EnableContinuousBackup": false
    }
  ]
}
EOF
)

PLAN_ID=$(aws backup create-backup-plan \
    --backup-plan "$PLAN_JSON" \
    --region "$REGION" \
    --query 'BackupPlanId' \
    --output text 2>&1) || {
        echo -e "${RED}✗ Plan create failed: $PLAN_ID${NC}"; exit 1;
    }
log "PLAN:${PLAN_ID}"
echo -e "${GREEN}✓ Weak plan: ${PLAN_NAME} (${PLAN_ID})${NC}"

################################################################################
# Step 5: (Optional) Do NOT attach a selection → fires backupPlanNotAssigned
################################################################################

echo -e "\n${GREEN}=== Step 5: Leaving plan without a selection ===${NC}"
echo -e "${CYAN}  (fires backupPlanNotAssigned by design)${NC}"

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}=== Resource Creation Complete ===${NC}"
echo -e "${CYAN}Manifest: ${OUTPUT_FILE}${NC}"
echo ""
echo "Resources created:"
while IFS= read -r line; do echo "  - $line"; done < "$OUTPUT_FILE"
echo ""
echo -e "${YELLOW}Expected FAIL findings when scanning:${NC}"
echo "  Vault #1 (${WEAK_VAULT}):"
echo "    - backupVaultNoLock"
echo "    - backupVaultDefaultEncryption"
echo "    - backupVaultNoAccessPolicy"
echo "  Vault #2 (${LOCK_VAULT}):"
echo "    - backupVaultLockNotFinalized (governance mode)"
echo "  Plan (${PLAN_NAME}):"
echo "    - backupPlanNoLifecycle"
echo "    - backupPlanNoCompletionWindow"
echo "    - backupPlanInfrequentSchedule (weekly)"
echo "    - backupPlanNoCrossRegionCopy"
echo "    - backupPlanNotAssigned"
echo ""
echo -e "${CYAN}Run the scanner:${NC}"
echo "  cd ../../.."
echo "  python3 main.py --regions ${REGION} --services backup --beta 1 --sequential 1"
echo ""
echo -e "${CYAN}Clean up:${NC}"
echo "  ./cleanup_test_resources.sh --force"

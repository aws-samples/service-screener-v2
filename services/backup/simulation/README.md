# AWS Backup Simulation Testing

Scripts to create AWS Backup resources that exercise the majority of the
`backup*` service-screener checks that can be forced through the AWS API
without waiting for real backup jobs to complete.

## Resources Created

All prefixed with `ss-test-backup-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| Vault `ss-test-backup-weak-*` | No Vault Lock, no access policy, no CMK (defaults to AWS-owned key) | backupVaultNoLock, backupVaultDefaultEncryption, backupVaultNoAccessPolicy |
| Vault `ss-test-backup-gov-lock-*` | GOVERNANCE-mode Vault Lock (no LockDate) | backupVaultLockNotFinalized |
| Backup plan `ss-test-backup-plan-*` | Weekly cron, no Lifecycle, no CompletionWindow, no CopyActions, EnableContinuousBackup=false, **no selection** | backupPlanInfrequentSchedule, backupPlanNoLifecycle, backupPlanNoCompletionWindow, backupPlanNoCrossRegionCopy, backupPlanNotAssigned |
| IAM role `ss-test-backup-role-*` | Backup service role for future selection extensions | (used by backup selections) |

## Coverage

### Directly simulated (FAIL findings)

| # | Check | Simulated? |
|---:|---|---|
| 1 | backupVaultNoLock | ✓ FAIL |
| 2 | backupVaultDefaultEncryption | ✓ FAIL |
| 3 | backupVaultNoAccessPolicy | ✓ FAIL |
| 4 | backupPlanNoLifecycle | ✓ FAIL |
| 5 | backupPlanNoCrossRegionCopy | ✓ FAIL |
| 6 | backupPlanNotAssigned | ✓ FAIL |
| 7 | backupPlanInfrequentSchedule | ✓ FAIL |
| 8 | backupPlanNoCompletionWindow | ✓ FAIL |
| 9 | backupVaultLockNotFinalized | ✓ FAIL (governance mode) |

### Not scripted (require account/org state or real backup jobs)

| # | Check | Why not scripted |
|---:|---|---|
| 10 | backupNoPlanExists | Fires only when zero plans exist; creating the test plan itself contradicts it |
| 11 | backupCrossAccountDisabled | Org-level setting (Organizations mgmt account only) |
| 12 | backupServiceOptInDisabled | Region-level setting; mutating affects other tests |
| 13 | backupServiceManagementDisabled | Region-level setting |
| 14 | backupCriticalResourcesUnprotected | Fires against actual EBS/RDS/DDB in the account — no simulation needed |
| 15 | backupNoLogicallyAirGappedVault | Fires whenever no LOGICALLY_AIR_GAPPED vault exists — no simulation needed |
| 16 | backupPlanNoRules | The CreateBackupPlan API rejects zero-rule plans |
| 17 | backupPlanNoContinuousBackup | Requires the plan to protect a PITR-capable resource (needs a real selection) |
| 18 | backupRecoveryPointNotEncrypted | Requires a completed backup job on an unencrypted source |
| 19 | backupRecoveryPointNoCMK | Requires a completed backup job |
| 20 | backupRecoveryPointNeverRestored | Requires actual recovery points |
| 21 | backupRecoveryPointExpiredLifecycle | Requires backup jobs to have completed and lifecycle to have run |
| 22 | backupVaultEmpty | Fires only for vaults older than 7 days — same-day scan reports INFO |

**Directly simulated (FAIL): 9 of 22.**
**Exercised (INFO / PASS with the expected reason): 22 of 22** (every check runs; the ones above simply don't have a controllable FAIL trigger from a fresh scratch account).

## Cost

Effectively **$0**:
- Empty backup vaults are free.
- Backup plans without selections take no snapshots.
- IAM roles are free.
- No recovery points, no restore jobs — no per-GB storage or restore fees.

## Usage

```bash
cd services/backup/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1
# IAM role propagation: the script sleeps 10s automatically.

cd ../../..
python3 main.py --regions ap-southeast-1 --services backup --beta 1 --sequential 1

cd services/backup/simulation
./cleanup_test_resources.sh --force
```

## IAM Permissions Required

- `backup:CreateBackupVault`, `backup:DeleteBackupVault`
- `backup:PutBackupVaultLockConfiguration`, `backup:DeleteBackupVaultLockConfiguration`
- `backup:DeleteBackupVaultAccessPolicy`
- `backup:CreateBackupPlan`, `backup:DeleteBackupPlan`
- `backup:ListBackupSelections`, `backup:DeleteBackupSelection`
- `iam:CreateRole`, `iam:AttachRolePolicy`, `iam:DetachRolePolicy`, `iam:DeleteRole`
- `iam:ListAttachedRolePolicies`, `iam:PassRole`
- `sts:GetCallerIdentity`

## Notes

- **Governance-mode Vault Lock is reversible.** The cleanup script explicitly
  calls `delete-backup-vault-lock-configuration` before `delete-backup-vault`.
  Do **not** re-run this script with COMPLIANCE-mode locks — those cannot be
  deleted.
- **`put-backup-vault-lock-configuration` may fail** if your account lacks
  the specific IAM permission or if organisation SCPs block it. In that case
  vault #2 will simply not fire `backupVaultLockNotFinalized`.
- **`create_test_resources.sh` sleeps 10 seconds** after IAM role creation to
  allow role propagation — necessary if you later extend the script to create
  a backup selection.
- **The plan is deliberately not assigned to any resources.** This lets
  `backupPlanNotAssigned` fire without creating side-effect backups.

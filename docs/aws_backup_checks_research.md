# AWS Backup — Programmatic Security & Well-Architected Checks

## Service-Screener-v2 Research: Complete Check Enumeration

**boto3 client:** `backup`  
**Date:** 2026-07-02  
**Total Checks Identified:** 22 (across 5 resource categories)

---

## API Surface Summary

| API Call | Purpose | Pagination |
|----------|---------|------------|
| `list_backup_vaults()` | List all vaults | Yes (NextToken) |
| `describe_backup_vault(BackupVaultName)` | Vault details: encryption, lock, recovery point count | No |
| `get_backup_vault_access_policy(BackupVaultName)` | Vault resource policy (JSON) | No |
| `list_backup_plans()` | List all backup plans | Yes (NextToken) |
| `get_backup_plan(BackupPlanId)` | Plan details: rules, schedule, lifecycle, copy actions | No |
| `list_backup_selections(BackupPlanId)` | List resource assignments per plan | Yes (NextToken) |
| `get_backup_selection(BackupPlanId, SelectionId)` | Selection details: ARNs, tags, conditions | No |
| `list_protected_resources()` | All resources with at least one recovery point | Yes (NextToken) |
| `list_recovery_points_by_backup_vault(BackupVaultName)` | Recovery points with encryption, lifecycle, status | Yes (NextToken) |
| `describe_global_settings()` | Cross-account backup & MPA flags | No |
| `describe_region_settings()` | Service opt-in preferences | No |
| `list_restore_jobs()` | Restore job history (for testing verification) | Yes (NextToken) |

---

## TIER 1 — High-Value, Low-Complexity Checks (Implement First)

### 1. `backupVaultNoLock`

| Field | Value |
|-------|-------|
| **Category** | Backup Vaults |
| **API Call** | `describe_backup_vault(BackupVaultName)` |
| **Response Field** | `Locked` (boolean) |
| **FAIL Condition** | `Locked == False` (vault has no Vault Lock enabled) |
| **Severity** | HIGH |
| **Pillar** | Reliability / Security |
| **Rationale** | Without Vault Lock, recovery points can be deleted (accidentally or maliciously). Vault Lock provides WORM (Write Once Read Many) immutability for compliance (SEC 17a-4, HIPAA). |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Critical for ransomware protection and compliance |

---

### 2. `backupVaultDefaultEncryption`

| Field | Value |
|-------|-------|
| **Category** | Backup Vaults |
| **API Call** | `describe_backup_vault(BackupVaultName)` |
| **Response Fields** | `EncryptionKeyArn`, `EncryptionKeyType` |
| **FAIL Condition** | `EncryptionKeyType == 'AWS_OWNED_KMS_KEY'` OR `EncryptionKeyArn` contains `aws/backup` (service default key, not CMK) |
| **Severity** | MEDIUM |
| **Pillar** | Security |
| **Rationale** | Default AWS-owned keys don't allow key policy control, rotation customization, or cross-account access auditing. CMK enables key separation, CloudTrail logging of key usage, and granular access control. |
| **Usefulness** | ⭐⭐⭐⭐ — Important for regulated environments |

---

### 3. `backupVaultNoAccessPolicy`

| Field | Value |
|-------|-------|
| **Category** | Backup Vaults |
| **API Call** | `get_backup_vault_access_policy(BackupVaultName)` |
| **Response Field** | `Policy` (JSON string) |
| **FAIL Condition** | API returns `ResourceNotFoundException` (no policy set) OR policy contains `"Effect": "Allow"` with `"Principal": "*"` without condition keys |
| **Severity** | HIGH |
| **Pillar** | Security |
| **Rationale** | Without a vault access policy that denies `backup:DeleteRecoveryPoint` and `backup:UpdateRecoveryPointLifecycle`, any IAM principal with sufficient permissions can delete backups. An overly permissive policy (Principal: *) exposes the vault to cross-account attacks. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Essential defense-in-depth layer |

**Detection Logic:**
```python
# FAIL scenarios:
# 1. No policy at all (ResourceNotFoundException)
# 2. Policy has Statement with Effect=Allow, Principal=* without Condition
# 3. Policy does NOT deny backup:DeleteRecoveryPoint to non-admin principals
```

---

### 4. `backupNoPlanExists`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `list_backup_plans()` |
| **Response Field** | `BackupPlansList` (array) |
| **FAIL Condition** | `len(BackupPlansList) == 0` — account has no backup plans in the region |
| **Severity** | HIGH |
| **Pillar** | Reliability |
| **Rationale** | Without any backup plans, the account has no automated backup strategy. This is the most fundamental backup hygiene check. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Foundational check |

---

### 5. `backupPlanNoRules`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `get_backup_plan(BackupPlanId)` |
| **Response Field** | `BackupPlan.Rules` (array) |
| **FAIL Condition** | `len(Rules) == 0` — plan exists but has no backup rules |
| **Severity** | HIGH |
| **Pillar** | Reliability |
| **Rationale** | A plan with no rules creates zero backups. This can happen after editing/removing rules without deleting the plan. |
| **Usefulness** | ⭐⭐⭐⭐ — Catches misconfigured plans |

---

### 6. `backupPlanNoLifecycle`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `get_backup_plan(BackupPlanId)` |
| **Response Field** | `BackupPlan.Rules[*].Lifecycle` |
| **FAIL Condition** | Any rule where `Lifecycle` is `null`/missing OR `Lifecycle.DeleteAfterDays` is not set |
| **Severity** | MEDIUM |
| **Pillar** | Cost Optimization |
| **Rationale** | Recovery points without lifecycle expiration accumulate indefinitely, causing unbounded storage costs. Every rule should have a `DeleteAfterDays` value appropriate for the data classification. |
| **Usefulness** | ⭐⭐⭐⭐ — Direct cost savings |

---

### 7. `backupPlanNoCrossRegionCopy`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `get_backup_plan(BackupPlanId)` |
| **Response Field** | `BackupPlan.Rules[*].CopyActions` |
| **FAIL Condition** | ALL rules have `CopyActions` as empty array `[]` or missing |
| **Severity** | MEDIUM |
| **Pillar** | Reliability |
| **Rationale** | Without cross-region copy, a regional outage could destroy both primary data and backups. At least one rule should copy to a different region for disaster recovery. |
| **Usefulness** | ⭐⭐⭐⭐ — Critical for DR posture |

---

### 8. `backupPlanNotAssigned`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `list_backup_selections(BackupPlanId)` |
| **Response Field** | `BackupSelectionsList` (array) |
| **FAIL Condition** | `len(BackupSelectionsList) == 0` — plan has no resource assignments |
| **Severity** | HIGH |
| **Pillar** | Reliability |
| **Rationale** | A backup plan with rules but no resource selections creates zero backups. The plan exists but protects nothing. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Catches "looks good on paper" misconfigs |

---

### 9. `backupCrossAccountDisabled`

| Field | Value |
|-------|-------|
| **Category** | Account Settings |
| **API Call** | `describe_global_settings()` |
| **Response Field** | `GlobalSettings['isCrossAccountBackupEnabled']` |
| **FAIL Condition** | Value is `'false'` or key is missing |
| **Severity** | MEDIUM |
| **Pillar** | Reliability / Security |
| **Rationale** | Cross-account backup provides isolation from account compromise. If an attacker gains admin access to one account, backups in a separate account remain safe. Required for Organizations-level DR strategy. |
| **Usefulness** | ⭐⭐⭐⭐ — Important for multi-account architectures |
| **Note** | Only works if account is part of AWS Organizations. API throws `InvalidRequestException` if not in an org. |

---

### 10. `backupServiceOptInDisabled`

| Field | Value |
|-------|-------|
| **Category** | Region Settings |
| **API Call** | `describe_region_settings()` |
| **Response Fields** | `ResourceTypeOptInPreference` (dict of service→bool) |
| **FAIL Condition** | Any critical service has value `False`. Critical services: `DynamoDB`, `EBS`, `EC2`, `EFS`, `RDS`, `Aurora`, `S3`, `FSx` |
| **Severity** | MEDIUM |
| **Pillar** | Reliability |
| **Rationale** | If a service is not opted-in, AWS Backup won't protect resources of that type even if included in a backup plan selection. This is a region-level gate that can silently prevent backups. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Catches a silent failure mode |

**Response Example:**
```json
{
  "ResourceTypeOptInPreference": {
    "DynamoDB": true,
    "EBS": true,
    "EC2": true,
    "EFS": true,
    "FSx": true,
    "RDS": true,
    "Aurora": true,
    "Storage Gateway": false,
    "S3": true
  },
  "ResourceTypeManagementPreference": {
    "DynamoDB": true,
    "EFS": true
  }
}
```

---

### 11. `backupRecoveryPointNotEncrypted`

| Field | Value |
|-------|-------|
| **Category** | Recovery Points |
| **API Call** | `list_recovery_points_by_backup_vault(BackupVaultName)` |
| **Response Field** | `RecoveryPoints[*].IsEncrypted` |
| **FAIL Condition** | `IsEncrypted == False` |
| **Severity** | MEDIUM |
| **Pillar** | Security |
| **Rationale** | Maps directly to Security Hub control [Backup.1]. Unencrypted recovery points expose data at rest. |
| **Usefulness** | ⭐⭐⭐⭐ — Direct Security Hub alignment |

---

## TIER 2 — Medium-Value Checks (Second Priority)

### 12. `backupVaultEmpty`

| Field | Value |
|-------|-------|
| **Category** | Backup Vaults |
| **API Call** | `describe_backup_vault(BackupVaultName)` |
| **Response Field** | `NumberOfRecoveryPoints` |
| **FAIL Condition** | `NumberOfRecoveryPoints == 0` AND vault is not newly created (CreationDate > 7 days ago) |
| **Severity** | LOW |
| **Pillar** | Reliability |
| **Rationale** | A vault that has been around for more than a week with zero recovery points suggests either a misconfigured plan, failed jobs, or an abandoned resource. Informational but useful for cleanup. |
| **Usefulness** | ⭐⭐⭐ — Hygiene check |

---

### 13. `backupPlanInfrequentSchedule`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `get_backup_plan(BackupPlanId)` |
| **Response Field** | `BackupPlan.Rules[*].ScheduleExpression` |
| **FAIL Condition** | Schedule frequency is less than daily. Parse cron/rate expression: `rate(X hours)` where X > 24, or cron with frequency > 1 day (e.g., weekly only: `cron(0 0 ? * 1 *)`) |
| **Severity** | LOW |
| **Pillar** | Reliability |
| **Rationale** | For production workloads, backup frequency < daily (RPO > 24hr) may not meet business continuity requirements. Flag as informational — not all workloads need daily backup. |
| **Usefulness** | ⭐⭐⭐ — Context-dependent; useful as advisory |

**Detection Logic:**
```python
# Parse ScheduleExpression:
# - "cron(0 5 ? * * *)" = daily at 5am → OK
# - "cron(0 5 ? * 1 *)" = weekly Monday → FAIL (>24hr gap)
# - "rate(24 hours)" → OK
# - "rate(168 hours)" → FAIL (weekly)
```

---

### 14. `backupPlanNoCompletionWindow`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `get_backup_plan(BackupPlanId)` |
| **Response Field** | `BackupPlan.Rules[*].CompletionWindowMinutes` |
| **FAIL Condition** | `CompletionWindowMinutes` is not set (null/missing) — defaults to 7 days which is excessive |
| **Severity** | LOW |
| **Pillar** | Operational Excellence |
| **Rationale** | Without a completion window, backup jobs can run indefinitely (default 10080 minutes = 7 days). Setting an appropriate completion window ensures hung jobs are cancelled and alert-worthy, preventing resource contention and missed backup windows. |
| **Usefulness** | ⭐⭐⭐ — Operational hygiene |

---

### 15. `backupPlanNoContinuousBackup`

| Field | Value |
|-------|-------|
| **Category** | Backup Plans |
| **API Call** | `get_backup_plan(BackupPlanId)` |
| **Response Field** | `BackupPlan.Rules[*].EnableContinuousBackup` |
| **FAIL Condition** | No rule has `EnableContinuousBackup == True` AND the plan protects RDS/Aurora/S3/DynamoDB (resources that support PITR) |
| **Severity** | LOW |
| **Pillar** | Reliability |
| **Rationale** | Continuous backup enables Point-in-Time Recovery (PITR) for supported resources (RDS, Aurora, S3, DynamoDB). Without it, RPO is limited to snapshot frequency. |
| **Usefulness** | ⭐⭐⭐ — Advisory for supported resource types |
| **Note** | Requires cross-referencing with `get_backup_selection` to determine resource types in the plan |

---

### 16. `backupRecoveryPointNeverRestored`

| Field | Value |
|-------|-------|
| **Category** | Recovery Points |
| **API Call** | `list_recovery_points_by_backup_vault(BackupVaultName)` |
| **Response Field** | `RecoveryPoints[*].LastRestoreTime` |
| **FAIL Condition** | `LastRestoreTime` is `null` for ALL recovery points in the vault (no restore has ever been tested) |
| **Severity** | MEDIUM |
| **Pillar** | Reliability |
| **Rationale** | Backups that have never been restored may not be recoverable. AWS Well-Architected REL 13 recommends regular restore testing. If no recovery point in the entire vault has ever been restored, it's a strong signal that DR testing is not happening. |
| **Usefulness** | ⭐⭐⭐⭐ — WA best practice alignment |

**Alternative approach:** Use `list_restore_jobs()` to check if ANY restore job exists in the account.

---

### 17. `backupRecoveryPointExpiredLifecycle`

| Field | Value |
|-------|-------|
| **Category** | Recovery Points |
| **API Call** | `list_recovery_points_by_backup_vault(BackupVaultName)` |
| **Response Fields** | `RecoveryPoints[*].CalculatedLifecycle.DeleteAt`, `RecoveryPoints[*].Status` |
| **FAIL Condition** | `Status == 'EXPIRED'` — recovery points past their lifecycle that haven't been cleaned up |
| **Severity** | LOW |
| **Pillar** | Cost Optimization |
| **Rationale** | Expired recovery points that still exist may indicate lifecycle processing issues or vault lock preventing deletion. Could be intentional (vault lock) or a cost leak. |
| **Usefulness** | ⭐⭐⭐ — Cost hygiene |

---

### 18. `backupVaultLockNotFinalized`

| Field | Value |
|-------|-------|
| **Category** | Backup Vaults |
| **API Call** | `describe_backup_vault(BackupVaultName)` |
| **Response Fields** | `Locked == True`, `LockDate` |
| **FAIL Condition** | `Locked == True` BUT `LockDate` is null or is in the future (still in cooling-off period and can be removed) |
| **Severity** | MEDIUM |
| **Pillar** | Security |
| **Rationale** | Vault Lock in governance mode (no LockDate) can be removed by anyone with sufficient IAM permissions. Only compliance mode (with a past LockDate) provides true immutability. If LockDate is in the future, the lock can still be reverted. |
| **Usefulness** | ⭐⭐⭐⭐ — Important for compliance-critical workloads |

---

### 19. `backupServiceManagementDisabled`

| Field | Value |
|-------|-------|
| **Category** | Region Settings |
| **API Call** | `describe_region_settings()` |
| **Response Field** | `ResourceTypeManagementPreference` (dict of service→bool) |
| **FAIL Condition** | Critical services (DynamoDB, EFS) have `ResourceTypeManagementPreference` set to `False` |
| **Severity** | LOW |
| **Pillar** | Reliability |
| **Rationale** | When management preference is disabled, AWS Backup doesn't fully manage the backup lifecycle for that resource type (e.g., DynamoDB PITR must be managed separately). Enabling full management provides centralized control. |
| **Usefulness** | ⭐⭐⭐ — Centralization advisory |

---

## TIER 3 — Advanced / Cross-Resource Checks

### 20. `backupCriticalResourcesUnprotected`

| Field | Value |
|-------|-------|
| **Category** | Protected Resources |
| **API Call** | `list_protected_resources()` + cross-reference with other service APIs |
| **Response Field** | `Results[*].ResourceType`, `Results[*].ResourceArn` |
| **FAIL Condition** | Cross-reference: discover RDS instances, DynamoDB tables, EFS filesystems, EBS volumes via their respective APIs, then check if their ARNs appear in `list_protected_resources()` results |
| **Severity** | HIGH |
| **Pillar** | Reliability |
| **Rationale** | The most impactful check: identifies production resources that have ZERO backup coverage. Requires cross-service correlation. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Highest business value |

**Implementation Complexity:** HIGH — requires calling multiple service APIs:
```python
# Cross-reference approach:
# 1. Get all protected resource ARNs from list_protected_resources()
# 2. Get all RDS instances: rds.describe_db_instances()
# 3. Get all DynamoDB tables: dynamodb.list_tables()
# 4. Get all EFS filesystems: efs.describe_file_systems()
# 5. Get all EBS volumes: ec2.describe_volumes()
# 6. Compare: if resource ARN not in protected set → FAIL
```

---

### 21. `backupRecoveryPointNoCMK`

| Field | Value |
|-------|-------|
| **Category** | Recovery Points |
| **API Call** | `list_recovery_points_by_backup_vault(BackupVaultName)` |
| **Response Fields** | `RecoveryPoints[*].EncryptionKeyType`, `RecoveryPoints[*].EncryptionKeyArn` |
| **FAIL Condition** | `EncryptionKeyType == 'AWS_OWNED_KMS_KEY'` — recovery point encrypted with AWS-owned key rather than customer-managed KMS key |
| **Severity** | LOW |
| **Pillar** | Security |
| **Rationale** | Similar to vault-level check but at the recovery point level. AWS-owned keys don't allow cross-account sharing or custom rotation policies. |
| **Usefulness** | ⭐⭐⭐ — Redundant with vault check for most cases |

---

### 22. `backupNoLogicallyAirGappedVault`

| Field | Value |
|-------|-------|
| **Category** | Backup Vaults |
| **API Call** | `describe_backup_vault(BackupVaultName)` |
| **Response Field** | `VaultType` |
| **FAIL Condition** | Account has NO vault with `VaultType == 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'` |
| **Severity** | LOW |
| **Pillar** | Security |
| **Rationale** | Logically air-gapped vaults provide the highest level of backup isolation (AWS-managed second account). Advisory check for high-security environments. Not all accounts need this. |
| **Usefulness** | ⭐⭐⭐ — Advisory for high-security postures |

---

## Implementation Priority Matrix

| Priority | Check ID | Complexity | API Calls | Value |
|----------|----------|-----------|-----------|-------|
| P0 | `backupNoPlanExists` | Simple | 1 | ⭐⭐⭐⭐⭐ |
| P0 | `backupVaultNoLock` | Simple | 1 per vault | ⭐⭐⭐⭐⭐ |
| P0 | `backupVaultNoAccessPolicy` | Medium | 1 per vault | ⭐⭐⭐⭐⭐ |
| P0 | `backupPlanNotAssigned` | Simple | 1 per plan | ⭐⭐⭐⭐⭐ |
| P0 | `backupServiceOptInDisabled` | Simple | 1 | ⭐⭐⭐⭐⭐ |
| P0 | `backupCriticalResourcesUnprotected` | High | N (cross-svc) | ⭐⭐⭐⭐⭐ |
| P1 | `backupVaultDefaultEncryption` | Simple | 1 per vault | ⭐⭐⭐⭐ |
| P1 | `backupPlanNoCrossRegionCopy` | Simple | 1 per plan | ⭐⭐⭐⭐ |
| P1 | `backupCrossAccountDisabled` | Simple | 1 | ⭐⭐⭐⭐ |
| P1 | `backupRecoveryPointNeverRestored` | Medium | 1 per vault | ⭐⭐⭐⭐ |
| P1 | `backupRecoveryPointNotEncrypted` | Medium | 1 per vault | ⭐⭐⭐⭐ |
| P1 | `backupVaultLockNotFinalized` | Simple | 1 per vault | ⭐⭐⭐⭐ |
| P1 | `backupPlanNoLifecycle` | Simple | 1 per plan | ⭐⭐⭐⭐ |
| P2 | `backupPlanNoRules` | Simple | 1 per plan | ⭐⭐⭐⭐ |
| P2 | `backupPlanInfrequentSchedule` | Medium | 1 per plan | ⭐⭐⭐ |
| P2 | `backupPlanNoCompletionWindow` | Simple | 1 per plan | ⭐⭐⭐ |
| P2 | `backupPlanNoContinuousBackup` | Medium | 2 per plan | ⭐⭐⭐ |
| P2 | `backupVaultEmpty` | Simple | 1 per vault | ⭐⭐⭐ |
| P2 | `backupServiceManagementDisabled` | Simple | 1 | ⭐⭐⭐ |
| P3 | `backupRecoveryPointExpiredLifecycle` | Medium | 1 per vault | ⭐⭐⭐ |
| P3 | `backupRecoveryPointNoCMK` | Medium | 1 per vault | ⭐⭐⭐ |
| P3 | `backupNoLogicallyAirGappedVault` | Simple | N/A (derived) | ⭐⭐⭐ |

---

## API Call Optimization Strategy

For service-screener implementation efficiency:

```python
# Phase 1: Account-level (1 call each)
global_settings = client.describe_global_settings()
region_settings = client.describe_region_settings()
plans = client.list_backup_plans()  # paginate
vaults = client.list_backup_vaults()  # paginate
protected = client.list_protected_resources()  # paginate

# Phase 2: Per-vault (iterate vaults)
for vault in vaults:
    detail = client.describe_backup_vault(BackupVaultName=vault['BackupVaultName'])
    try:
        policy = client.get_backup_vault_access_policy(BackupVaultName=vault['BackupVaultName'])
    except client.exceptions.ResourceNotFoundException:
        policy = None
    # Optional (expensive for large vaults):
    recovery_points = client.list_recovery_points_by_backup_vault(
        BackupVaultName=vault['BackupVaultName'], MaxResults=100
    )

# Phase 3: Per-plan (iterate plans)
for plan in plans:
    detail = client.get_backup_plan(BackupPlanId=plan['BackupPlanId'])
    selections = client.list_backup_selections(BackupPlanId=plan['BackupPlanId'])
```

**Estimated API calls for typical account (5 vaults, 3 plans):**
- Account-level: 3 calls
- Per-vault: 5 × 3 = 15 calls
- Per-plan: 3 × 2 = 6 calls
- **Total: ~24 API calls** (very lightweight)

---

## Security Hub Control Mapping

| Security Hub Control | Service-Screener Check | Notes |
|---------------------|----------------------|-------|
| [Backup.1] Recovery points encrypted at rest | `backupRecoveryPointNotEncrypted` | Direct mapping |
| [Backup.2] Recovery points tagged | Not implemented (tagging = low value for scanning) | Skip |
| [Backup.3] Vaults tagged | Not implemented | Skip |
| [Backup.4] Report plans tagged | Not implemented | Skip |
| [Backup.5] Backup plans tagged | Not implemented | Skip |

---

## AWS Config Rule Mapping

| Config Rule | Service-Screener Check | Notes |
|-------------|----------------------|-------|
| `backup-recovery-point-encrypted` | `backupRecoveryPointNotEncrypted` | Same check |
| `backup-plan-min-frequency-and-min-retention-check` | `backupPlanInfrequentSchedule` + `backupPlanNoLifecycle` | Combined |
| `backup-recovery-point-minimum-retention-check` | `backupPlanNoLifecycle` | Partial overlap |

---

## Well-Architected Pillar Distribution

| Pillar | Checks | Count |
|--------|--------|-------|
| **Reliability** | backupNoPlanExists, backupPlanNoRules, backupPlanNoCrossRegionCopy, backupPlanNotAssigned, backupCrossAccountDisabled, backupServiceOptInDisabled, backupVaultEmpty, backupPlanInfrequentSchedule, backupPlanNoContinuousBackup, backupRecoveryPointNeverRestored, backupCriticalResourcesUnprotected, backupServiceManagementDisabled | 12 |
| **Security** | backupVaultNoLock, backupVaultDefaultEncryption, backupVaultNoAccessPolicy, backupRecoveryPointNotEncrypted, backupVaultLockNotFinalized, backupRecoveryPointNoCMK, backupNoLogicallyAirGappedVault | 7 |
| **Cost Optimization** | backupPlanNoLifecycle, backupRecoveryPointExpiredLifecycle | 2 |
| **Operational Excellence** | backupPlanNoCompletionWindow | 1 |

---

## Key Response Fields Reference

### `describe_backup_vault` Response (critical fields):
```json
{
  "BackupVaultName": "string",
  "VaultType": "BACKUP_VAULT|LOGICALLY_AIR_GAPPED_BACKUP_VAULT|RESTORE_ACCESS_BACKUP_VAULT",
  "EncryptionKeyArn": "arn:aws:kms:...",
  "EncryptionKeyType": "AWS_OWNED_KMS_KEY|CUSTOMER_MANAGED_KMS_KEY",
  "NumberOfRecoveryPoints": 123,
  "Locked": true|false,
  "MinRetentionDays": 123,
  "MaxRetentionDays": 123,
  "LockDate": "datetime"
}
```

### `get_backup_plan` → `BackupPlan.Rules[*]` (critical fields):
```json
{
  "RuleName": "string",
  "ScheduleExpression": "cron(...)|rate(...)",
  "StartWindowMinutes": 60,
  "CompletionWindowMinutes": 120,
  "Lifecycle": {
    "DeleteAfterDays": 30,
    "MoveToColdStorageAfterDays": 7,
    "OptInToArchiveForSupportedResources": false
  },
  "CopyActions": [
    {
      "DestinationBackupVaultArn": "arn:aws:backup:us-west-2:...:backup-vault:dr-vault",
      "Lifecycle": { "DeleteAfterDays": 90 }
    }
  ],
  "EnableContinuousBackup": true|false,
  "TargetBackupVaultName": "string"
}
```

### `describe_global_settings` Response:
```json
{
  "GlobalSettings": {
    "isCrossAccountBackupEnabled": "true|false",
    "isMpaEnabled": "true|false",
    "isDelegatedAdministratorEnabled": "true|false"
  }
}
```

### `list_recovery_points_by_backup_vault` → `RecoveryPoints[*]` (critical fields):
```json
{
  "RecoveryPointArn": "string",
  "ResourceType": "RDS|EBS|EC2|S3|DynamoDB|...",
  "Status": "COMPLETED|PARTIAL|DELETING|EXPIRED|AVAILABLE",
  "IsEncrypted": true|false,
  "EncryptionKeyType": "AWS_OWNED_KMS_KEY|CUSTOMER_MANAGED_KMS_KEY",
  "LastRestoreTime": "datetime|null",
  "Lifecycle": {
    "DeleteAfterDays": 30,
    "MoveToColdStorageAfterDays": 7
  },
  "CalculatedLifecycle": {
    "DeleteAt": "datetime",
    "MoveToColdStorageAt": "datetime"
  }
}
```

---

## IAM Permissions Required (Minimum)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "backup:ListBackupVaults",
      "backup:DescribeBackupVault",
      "backup:GetBackupVaultAccessPolicy",
      "backup:ListBackupPlans",
      "backup:GetBackupPlan",
      "backup:ListBackupSelections",
      "backup:GetBackupSelection",
      "backup:ListProtectedResources",
      "backup:ListRecoveryPointsByBackupVault",
      "backup:DescribeGlobalSettings",
      "backup:DescribeRegionSettings",
      "backup:ListRestoreJobs"
    ],
    "Resource": "*"
  }]
}
```

---

## Notes & Caveats

1. **`describe_global_settings`** throws `InvalidRequestException` if the account is NOT part of AWS Organizations. Handle gracefully — skip `backupCrossAccountDisabled` check in that case.

2. **`list_recovery_points_by_backup_vault`** can be expensive for vaults with thousands of recovery points. Consider sampling (MaxResults=100) rather than full enumeration for `backupRecoveryPointNotEncrypted` and `backupRecoveryPointNeverRestored`.

3. **`backupCriticalResourcesUnprotected`** requires cross-service API calls (RDS, DynamoDB, EFS, EC2). This significantly increases scan time and permissions. Consider making it opt-in or running it as a separate, deeper scan.

4. **Vault access policy parsing** requires JSON policy evaluation. Watch for:
   - Deny statements that override Allow
   - Condition keys (`aws:PrincipalOrgID`, `aws:SourceAccount`)
   - NotPrincipal patterns
   - Simple heuristic: flag if NO deny for `backup:DeleteRecoveryPoint` exists

5. **Schedule expression parsing** for frequency checks: AWS Backup uses both `cron()` and `rate()` expressions. Build a parser or use a library to determine effective frequency.

6. **Default vault (`aws/efs/automatic-backup-vault`)**: Skip built-in service vaults from certain checks (they have specific purposes and may not need CMK/lock).

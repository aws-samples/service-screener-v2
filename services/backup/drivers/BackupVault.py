import json
from datetime import datetime, timedelta, timezone

from services.Evaluator import Evaluator


class BackupVault(Evaluator):
    """
    Per-vault checks. Nine checks in total:

      - backupVaultNoLock              (S/H)   Vault Lock disabled
      - backupVaultDefaultEncryption   (S/M)   AWS-owned KMS key
      - backupVaultNoAccessPolicy      (S/H)   No policy or open policy
      - backupVaultEmpty               (R/L)   Zero recovery points > 7 days old
      - backupVaultLockNotFinalized    (S/M)   Governance mode / future LockDate
      - backupRecoveryPointNotEncrypted (S/M)  IsEncrypted=false on any point
      - backupRecoveryPointNeverRestored (R/M) LastRestoreTime null for all
      - backupRecoveryPointExpiredLifecycle (C/L) Status=EXPIRED on any point
      - backupRecoveryPointNoCMK       (S/L)   AWS_OWNED_KMS_KEY on any point

    Input:
      vault -- dict produced by Backup.py._describeVault.
      backupClient -- boto3 backup client (retained for future extension).

    Recovery-point checks operate on a sample of up to
    Backup.RECOVERY_POINT_SAMPLE_LIMIT points.
    """

    # AWS Backup's service-owned key aliases / ARN fragments.
    AWS_OWNED_KMS_ALIASES = (
        'aws/backup',    # standard service-managed alias
    )
    AWS_OWNED_KMS_TYPE = 'AWS_OWNED_KMS_KEY'

    # backupVaultEmpty grace period: newly-created vaults may legitimately be
    # empty for a few backup cycles.
    EMPTY_VAULT_GRACE_DAYS = 7

    # Default AWS-managed vaults for service integrations that are permitted
    # to lack CMK / vault-lock (AWS Backup's own defaults).
    SERVICE_DEFAULT_VAULT_PREFIXES = (
        'aws/efs/',                       # EFS automatic backups
        'aws/dynamodb/',                  # DynamoDB service-managed
    )

    def __init__(self, vault, backupClient):
        super().__init__()
        self.vault = vault
        self.backupClient = backupClient

        self._resourceName = vault.get('_name', 'unknown')
        self.recovery_points = vault.get('_recoveryPoints') or []

        self.addII('vaultArn', vault.get('_arn', 'N/A'))
        self.addII('name', self._resourceName)
        self.addII('vaultType', vault.get('_vaultType', 'BACKUP_VAULT'))
        self.addII('numberOfRecoveryPoints', vault.get('_numberOfRecoveryPoints', 0))
        self.addII('locked', str(vault.get('_locked', False)))
        self.addII('encryptionKeyArn', vault.get('_encryptionKeyArn') or 'None')

    # ------------------------------------------------------------------ #
    # 1. Vault Lock disabled
    # ------------------------------------------------------------------ #
    def _checkBackupVaultNoLock(self):
        # Skip service-owned default vaults — they are managed by AWS and
        # cannot have customer-configured Vault Lock.
        if self._isServiceDefaultVault():
            self.results['backupVaultNoLock'] = [
                0, "Service-managed default vault — Vault Lock not applicable"
            ]
            return

        if bool(self.vault.get('_locked')):
            lock_date = self.vault.get('_lockDate')
            self.results['backupVaultNoLock'] = [
                1, f"Vault Lock enabled (LockDate={lock_date or 'not set'})"
            ]
        else:
            self.results['backupVaultNoLock'] = [
                -1, "Vault Lock is not enabled"
            ]

    # ------------------------------------------------------------------ #
    # 2. Default (AWS-owned) encryption key
    # ------------------------------------------------------------------ #
    def _checkBackupVaultDefaultEncryption(self):
        if self._isServiceDefaultVault():
            self.results['backupVaultDefaultEncryption'] = [
                0, "Service-managed default vault uses AWS-managed key by design"
            ]
            return

        keyType = self.vault.get('_encryptionKeyType')
        keyArn = self.vault.get('_encryptionKeyArn') or ''

        if keyType == self.AWS_OWNED_KMS_TYPE or self._keyArnIsAwsOwned(keyArn):
            self.results['backupVaultDefaultEncryption'] = [
                -1,
                f"Encrypted with AWS-owned key ({keyArn or 'default'}); prefer a customer-managed KMS key"
            ]
        elif not keyArn:
            # AWS Backup always encrypts, but we cannot confirm the key type
            # in this response — flag as INFO rather than PASS.
            self.results['backupVaultDefaultEncryption'] = [
                0, "EncryptionKeyArn not returned by API — cannot determine"
            ]
        else:
            self.results['backupVaultDefaultEncryption'] = [
                1, f"Customer-managed KMS key: {keyArn}"
            ]

    # ------------------------------------------------------------------ #
    # 3. No / open access policy
    # ------------------------------------------------------------------ #
    def _checkBackupVaultNoAccessPolicy(self):
        if self.vault.get('_accessPolicyMissing'):
            self.results['backupVaultNoAccessPolicy'] = [
                -1, "No vault access policy attached"
            ]
            return

        raw = self.vault.get('_accessPolicy')
        if not raw:
            self.results['backupVaultNoAccessPolicy'] = [
                -1, "No vault access policy attached"
            ]
            return

        parsed = self._parsePolicy(raw)
        if parsed is None:
            self.results['backupVaultNoAccessPolicy'] = [
                0, "Vault access policy present but not parseable"
            ]
            return

        # Walk every statement; flag any Allow with Principal:* that has no
        # scoping condition. That is the classic "world-writable" misconfig
        # for Backup vaults.
        offending = []
        for i, stmt in enumerate(self._policyStatements(parsed)):
            if stmt.get('Effect') != 'Allow':
                continue
            if not self._principalIsWildcard(stmt.get('Principal')):
                continue
            if self._conditionScopes(stmt.get('Condition')):
                continue
            sid = stmt.get('Sid', f"stmt{i}")
            offending.append(sid)

        if offending:
            self.results['backupVaultNoAccessPolicy'] = [
                -1,
                f"Access policy has wildcard-principal Allow without Condition: {', '.join(offending)}"
            ]
        else:
            self.results['backupVaultNoAccessPolicy'] = [
                1, "Vault access policy present and scoped"
            ]

    # ------------------------------------------------------------------ #
    # 4. Empty vault (older than the grace window)
    # ------------------------------------------------------------------ #
    def _checkBackupVaultEmpty(self):
        count = self.vault.get('_numberOfRecoveryPoints') or 0
        if count > 0:
            self.results['backupVaultEmpty'] = [
                1, f"{count} recovery point(s) present"
            ]
            return

        creation = self.vault.get('_creationDate')
        if not creation:
            # No creation date — cannot determine grace period. Treat as INFO
            # to avoid false positives.
            self.results['backupVaultEmpty'] = [
                0, "Empty vault with no known creation date"
            ]
            return

        try:
            age_days = self._daysSince(creation)
        except (TypeError, ValueError):
            self.results['backupVaultEmpty'] = [
                0, "Empty vault; creation date unparseable"
            ]
            return

        if age_days < self.EMPTY_VAULT_GRACE_DAYS:
            self.results['backupVaultEmpty'] = [
                1, f"Empty but only {age_days} day(s) old (within grace period)"
            ]
        else:
            self.results['backupVaultEmpty'] = [
                -1, f"Empty vault, created {age_days} day(s) ago"
            ]

    # ------------------------------------------------------------------ #
    # 5. Vault Lock not finalized (governance mode or future LockDate)
    # ------------------------------------------------------------------ #
    def _checkBackupVaultLockNotFinalized(self):
        if not self.vault.get('_locked'):
            self.results['backupVaultLockNotFinalized'] = [
                0, "Vault Lock not enabled — see backupVaultNoLock"
            ]
            return

        lock_date = self.vault.get('_lockDate')
        if lock_date is None:
            # Governance mode — no LockDate, lock is reversible.
            self.results['backupVaultLockNotFinalized'] = [
                -1, "Vault Lock in GOVERNANCE mode (no LockDate) — lock is reversible"
            ]
            return

        try:
            lock_date_dt = self._asDatetime(lock_date)
        except (TypeError, ValueError):
            self.results['backupVaultLockNotFinalized'] = [
                0, f"LockDate present but unparseable: {lock_date}"
            ]
            return

        now = datetime.now(timezone.utc)
        if lock_date_dt > now:
            days_remaining = (lock_date_dt - now).days
            self.results['backupVaultLockNotFinalized'] = [
                -1,
                f"Vault Lock in cooling-off period ({days_remaining} day(s) until finalisation)"
            ]
        else:
            self.results['backupVaultLockNotFinalized'] = [
                1, "Vault Lock finalised (COMPLIANCE mode, LockDate in the past)"
            ]

    # ------------------------------------------------------------------ #
    # 6. Recovery point encryption
    # ------------------------------------------------------------------ #
    def _checkBackupRecoveryPointNotEncrypted(self):
        if not self.recovery_points:
            self.results['backupRecoveryPointNotEncrypted'] = [
                0, "No recovery points sampled in this vault"
            ]
            return

        unencrypted = [
            rp for rp in self.recovery_points if rp.get('IsEncrypted') is False
        ]
        if unencrypted:
            names = [self._rpShortId(rp) for rp in unencrypted[:5]]
            more = f" (+{len(unencrypted) - 5} more)" if len(unencrypted) > 5 else ""
            self.results['backupRecoveryPointNotEncrypted'] = [
                -1, f"Unencrypted recovery point(s): {', '.join(names)}{more}"
            ]
        else:
            self.results['backupRecoveryPointNotEncrypted'] = [
                1, f"All {len(self.recovery_points)} sampled point(s) encrypted"
            ]

    # ------------------------------------------------------------------ #
    # 7. Never-restored vault
    # ------------------------------------------------------------------ #
    def _checkBackupRecoveryPointNeverRestored(self):
        if not self.recovery_points:
            self.results['backupRecoveryPointNeverRestored'] = [
                0, "No recovery points sampled in this vault"
            ]
            return

        any_restored = any(rp.get('LastRestoreTime') for rp in self.recovery_points)
        if any_restored:
            self.results['backupRecoveryPointNeverRestored'] = [
                1, "At least one recovery point has been restored (LastRestoreTime set)"
            ]
        else:
            self.results['backupRecoveryPointNeverRestored'] = [
                -1,
                f"No recovery point in this vault has ever been restored "
                f"({len(self.recovery_points)} sampled)"
            ]

    # ------------------------------------------------------------------ #
    # 8. Expired recovery points still present
    # ------------------------------------------------------------------ #
    def _checkBackupRecoveryPointExpiredLifecycle(self):
        if not self.recovery_points:
            self.results['backupRecoveryPointExpiredLifecycle'] = [
                0, "No recovery points sampled in this vault"
            ]
            return

        expired = [
            rp for rp in self.recovery_points if str(rp.get('Status', '')).upper() == 'EXPIRED'
        ]
        if expired:
            names = [self._rpShortId(rp) for rp in expired[:5]]
            more = f" (+{len(expired) - 5} more)" if len(expired) > 5 else ""
            self.results['backupRecoveryPointExpiredLifecycle'] = [
                -1, f"Recovery point(s) in EXPIRED state: {', '.join(names)}{more}"
            ]
        else:
            self.results['backupRecoveryPointExpiredLifecycle'] = [
                1, "No expired recovery points present"
            ]

    # ------------------------------------------------------------------ #
    # 9. Recovery points using AWS-owned key
    # ------------------------------------------------------------------ #
    def _checkBackupRecoveryPointNoCMK(self):
        if not self.recovery_points:
            self.results['backupRecoveryPointNoCMK'] = [
                0, "No recovery points sampled in this vault"
            ]
            return

        aws_owned = []
        for rp in self.recovery_points:
            keyType = rp.get('EncryptionKeyType')
            keyArn = rp.get('EncryptionKeyArn') or ''
            if keyType == self.AWS_OWNED_KMS_TYPE or (
                keyArn and self._keyArnIsAwsOwned(keyArn)
            ):
                aws_owned.append(rp)

        if aws_owned:
            names = [self._rpShortId(rp) for rp in aws_owned[:5]]
            more = f" (+{len(aws_owned) - 5} more)" if len(aws_owned) > 5 else ""
            self.results['backupRecoveryPointNoCMK'] = [
                -1,
                f"Recovery point(s) encrypted with AWS-owned key: {', '.join(names)}{more}"
            ]
        else:
            self.results['backupRecoveryPointNoCMK'] = [
                1, "All sampled recovery points use a customer-managed KMS key"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _isServiceDefaultVault(self):
        """Return True for vaults that are automatically created by other
        AWS services and are not managed by the customer."""
        name = (self._resourceName or '').lower()
        for prefix in self.SERVICE_DEFAULT_VAULT_PREFIXES:
            if name.startswith(prefix):
                return True
        return False

    @classmethod
    def _keyArnIsAwsOwned(cls, keyArn):
        if not keyArn:
            return False
        lower = keyArn.lower()
        return any(alias in lower for alias in cls.AWS_OWNED_KMS_ALIASES)

    @staticmethod
    def _parsePolicy(raw):
        if not raw:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _policyStatements(policy):
        if not isinstance(policy, dict):
            return []
        stmts = policy.get('Statement', [])
        if isinstance(stmts, dict):
            return [stmts]
        return stmts if isinstance(stmts, list) else []

    @staticmethod
    def _principalIsWildcard(principal):
        if principal is None:
            return False
        if principal == '*':
            return True
        if isinstance(principal, dict):
            for v in principal.values():
                if v == '*':
                    return True
                if isinstance(v, list) and '*' in v:
                    return True
        return False

    # Conditions that legitimately scope a Principal:* Allow statement.
    SCOPING_CONDITION_KEYS = frozenset({
        'aws:SourceAccount', 'aws:SourceArn', 'aws:SourceOwner',
        'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths',
        'aws:PrincipalAccount', 'aws:PrincipalArn',
    })

    def _conditionScopes(self, condition):
        if not condition or not isinstance(condition, dict):
            return False
        for op_block in condition.values():
            if not isinstance(op_block, dict):
                continue
            for key in op_block.keys():
                if key in self.SCOPING_CONDITION_KEYS:
                    return True
        return False

    @staticmethod
    def _asDatetime(value):
        """Normalise a boto3 datetime (may be datetime, str, or int epoch)."""
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str):
            # boto rarely returns strings, but be defensive.
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                pass
        raise TypeError(f"Unparseable datetime: {value!r}")

    @classmethod
    def _daysSince(cls, value):
        dt = cls._asDatetime(value)
        return (datetime.now(timezone.utc) - dt).days

    @staticmethod
    def _rpShortId(rp):
        """Extract a short identifier from a recovery point for log lines."""
        arn = rp.get('RecoveryPointArn') or ''
        if arn:
            return arn.split(':')[-1][-24:]
        return rp.get('ResourceType', 'unknown')

from services.Evaluator import Evaluator


class BackupAccount(Evaluator):
    """
    Account/region-level checks. Six checks in total:

      - backupNoPlanExists                (R/H)  Zero plans in this region
      - backupCrossAccountDisabled        (R/M)  Org-level cross-account off
      - backupServiceOptInDisabled        (R/M)  Critical service opt-in off
      - backupServiceManagementDisabled   (R/L)  DDB/EFS mgmt preference off
      - backupCriticalResourcesUnprotected (R/H) Prod resources without backup
      - backupNoLogicallyAirGappedVault   (S/L)  No LOGICALLY_AIR_GAPPED vault

    Input:
      account -- dict produced by Backup.py._discoverAccount.
      backupClient -- boto3 backup client (retained for future extension).
    """

    LOGICALLY_AIR_GAPPED = 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'

    def __init__(self, account, backupClient):
        super().__init__()
        self.account = account
        self.backupClient = backupClient

        self._resourceName = f"Account::{account.get('_region', 'unknown')}"

        self.addII('region', account.get('_region', 'unknown'))
        self.addII('vaultCount', len(account.get('_vaults') or []))
        self.addII('planCount', len(account.get('_plans') or []))
        self.addII('protectedResourceCount', len(account.get('_protectedArns') or []))

    # ------------------------------------------------------------------ #
    # 1. No backup plan in the account
    # ------------------------------------------------------------------ #
    def _checkBackupNoPlanExists(self):
        plans = self.account.get('_plans') or []
        if plans:
            self.results['backupNoPlanExists'] = [
                1, f"{len(plans)} backup plan(s) present"
            ]
        else:
            self.results['backupNoPlanExists'] = [
                -1, "No backup plans exist in this region"
            ]

    # ------------------------------------------------------------------ #
    # 2. Cross-account backup disabled (Organizations only)
    # ------------------------------------------------------------------ #
    def _checkBackupCrossAccountDisabled(self):
        gs = self.account.get('_globalSettings') or {}
        if not gs.get('_available'):
            # Account is not part of AWS Organizations, or the caller lacks
            # organizations:DescribeGlobalSettings — either way, the check
            # is not applicable.
            reason = gs.get('_reason', 'unknown')
            self.results['backupCrossAccountDisabled'] = [
                0,
                f"describe_global_settings not applicable ({reason}) — "
                "account may not be part of an Organization"
            ]
            return

        settings = gs.get('GlobalSettings') or {}
        # The API returns string values 'true' / 'false'.
        raw = settings.get('isCrossAccountBackupEnabled', 'false')
        enabled = str(raw).strip().lower() == 'true'

        if enabled:
            self.results['backupCrossAccountDisabled'] = [
                1, "Cross-account backup is enabled at the Organizations level"
            ]
        else:
            self.results['backupCrossAccountDisabled'] = [
                -1,
                f"Cross-account backup is disabled (isCrossAccountBackupEnabled={raw})"
            ]

    # ------------------------------------------------------------------ #
    # 3. Critical services not opted-in
    # ------------------------------------------------------------------ #
    def _checkBackupServiceOptInDisabled(self):
        rs = self.account.get('_regionSettings') or {}
        if not rs.get('_available'):
            self.results['backupServiceOptInDisabled'] = [
                0,
                f"describe_region_settings not available ({rs.get('_reason', 'unknown')})"
            ]
            return

        opt_in = rs.get('ResourceTypeOptInPreference') or {}
        critical = self.account.get('_criticalServicesOptIn') or []

        disabled = []
        unknown = []
        for svc in critical:
            if svc not in opt_in:
                unknown.append(svc)
                continue
            if not bool(opt_in[svc]):
                disabled.append(svc)

        if disabled:
            self.results['backupServiceOptInDisabled'] = [
                -1,
                f"Service(s) not opted-in to AWS Backup: {', '.join(disabled)}"
            ]
        elif unknown and not opt_in:
            # region_settings returned an empty preferences map — API may not
            # be populated on brand-new accounts.
            self.results['backupServiceOptInDisabled'] = [
                0,
                "ResourceTypeOptInPreference is empty — no preferences set yet"
            ]
        else:
            self.results['backupServiceOptInDisabled'] = [
                1,
                f"All tracked services opted-in ({len(critical) - len(unknown)}/{len(critical)})"
            ]

    # ------------------------------------------------------------------ #
    # 4. DynamoDB / EFS management preference disabled
    # ------------------------------------------------------------------ #
    def _checkBackupServiceManagementDisabled(self):
        rs = self.account.get('_regionSettings') or {}
        if not rs.get('_available'):
            self.results['backupServiceManagementDisabled'] = [
                0,
                f"describe_region_settings not available ({rs.get('_reason', 'unknown')})"
            ]
            return

        mgmt = rs.get('ResourceTypeManagementPreference') or {}
        managed = self.account.get('_managedServices') or []

        disabled = []
        for svc in managed:
            if svc in mgmt and not bool(mgmt[svc]):
                disabled.append(svc)

        if not mgmt:
            self.results['backupServiceManagementDisabled'] = [
                0,
                "ResourceTypeManagementPreference is empty — not configured on this account"
            ]
            return

        if disabled:
            self.results['backupServiceManagementDisabled'] = [
                -1,
                f"AWS Backup does not fully manage: {', '.join(disabled)}"
            ]
        else:
            self.results['backupServiceManagementDisabled'] = [
                1,
                f"Full AWS Backup management enabled for tracked services"
            ]

    # ------------------------------------------------------------------ #
    # 5. Critical resources without backup coverage
    # ------------------------------------------------------------------ #
    def _checkBackupCriticalResourcesUnprotected(self):
        protected = self.account.get('_protectedArns') or set()
        candidates = self.account.get('_candidateResources') or {}

        # Flatten candidates into (service, arn) pairs.
        flat = []
        for svc, arns in candidates.items():
            for arn in arns or []:
                flat.append((svc, arn))

        if not flat:
            self.results['backupCriticalResourcesUnprotected'] = [
                0,
                "No candidate resources discovered across RDS/DynamoDB/EFS/EBS"
            ]
            return

        unprotected = []
        for svc, arn in flat:
            if arn not in protected:
                unprotected.append((svc, arn))

        if not unprotected:
            self.results['backupCriticalResourcesUnprotected'] = [
                1,
                f"All {len(flat)} candidate resource(s) are protected by AWS Backup"
            ]
            return

        # Truncate output for readability but keep the count accurate.
        preview = [f"{svc}:{arn.split('/')[-1] if '/' in arn else arn.split(':')[-1]}"
                   for svc, arn in unprotected[:5]]
        more = f" (+{len(unprotected) - 5} more)" if len(unprotected) > 5 else ""
        self.results['backupCriticalResourcesUnprotected'] = [
            -1,
            f"{len(unprotected)}/{len(flat)} candidate resource(s) unprotected: "
            f"{', '.join(preview)}{more}"
        ]

    # ------------------------------------------------------------------ #
    # 6. No logically air-gapped vault
    # ------------------------------------------------------------------ #
    def _checkBackupNoLogicallyAirGappedVault(self):
        vaults = self.account.get('_vaults') or []
        if not vaults:
            self.results['backupNoLogicallyAirGappedVault'] = [
                0, "No backup vaults exist in this region"
            ]
            return

        has_air_gapped = any(
            (v.get('_vaultType') or '').upper() == self.LOGICALLY_AIR_GAPPED
            for v in vaults
        )

        if has_air_gapped:
            self.results['backupNoLogicallyAirGappedVault'] = [
                1, "At least one logically air-gapped vault exists"
            ]
        else:
            self.results['backupNoLogicallyAirGappedVault'] = [
                -1,
                f"None of the {len(vaults)} vault(s) are LOGICALLY_AIR_GAPPED_BACKUP_VAULT"
            ]

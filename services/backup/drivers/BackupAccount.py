import json
from datetime import datetime, timedelta, timezone

import botocore

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
      - backupJobsFailing                 (R/H)  Failed/aborted/expired jobs, last 7 days
      - backupRestoreJobsFailing          (R/H)  Failed restores / validations, last 30 days
      - backupPlanNoCrossAccountCopy      (S/M)  No rule copies to another account
      - backupNoFailureAlerting           (R/M)  No notification on job failures
      - backupNoRestoreTestingPlan        (R/M)  No restore testing plan / selections
      - backupAuditFrameworkMissing       (R/L)  No Backup Audit Manager framework

    Input:
      account -- dict produced by Backup.py._discoverAccount.
      backupClient -- boto3 backup client. The job / restore-testing /
                      notification checks call read-only list/get APIs lazily
                      so they only cost API calls when they run.
      eventsClient, cloudwatchClient -- optional boto3 clients used as
                      alerting evidence by backupNoFailureAlerting.
      vaultLookup  -- optional callable(vaultArn) -> (summary|None, reason|None)
                      (Backup._lookupVault) used to resolve copy destinations
                      in other Regions of this account.
    """

    LOGICALLY_AIR_GAPPED = 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'

    # Look-back windows for job-state checks.
    JOB_LOOKBACK_DAYS = 7
    RESTORE_LOOKBACK_DAYS = 30
    FAILED_BACKUP_JOB_STATES = ('FAILED', 'ABORTED', 'EXPIRED')
    FAILED_COPY_JOB_STATES = ('FAILED',)

    # Vault notification events that fire when a backup / copy job fails.
    # BACKUP_JOB_COMPLETED is sent for every terminal state (including
    # FAILED), so it also delivers failure notifications.
    FAILURE_NOTIFICATION_EVENTS = frozenset({
        'BACKUP_JOB_FAILED', 'BACKUP_JOB_COMPLETED', 'BACKUP_JOB_EXPIRED',
        'COPY_JOB_FAILED',
    })
    # CloudWatch metrics (namespace AWS/Backup) that count job failures.
    FAILURE_METRICS = frozenset({
        'NumberOfBackupJobsFailed', 'NumberOfBackupJobsAborted',
        'NumberOfBackupJobsExpired', 'NumberOfCopyJobsFailed',
    })

    def __init__(self, account, backupClient, eventsClient=None, cloudwatchClient=None,
                 vaultLookup=None):
        super().__init__()
        self.account = account
        self.backupClient = backupClient
        self.eventsClient = eventsClient
        self.cloudwatchClient = cloudwatchClient
        self.vaultLookup = vaultLookup

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

    # ------------------------------------------------------------------ #
    # 7. Backup / copy jobs failing (last 7 days)
    # ------------------------------------------------------------------ #
    def _checkBackupJobsFailing(self):
        key = 'backupJobsFailing'
        since = datetime.now(timezone.utc) - timedelta(days=self.JOB_LOOKBACK_DAYS)
        failed = []   # (kind, state, resourceArn, creationTs)
        try:
            for state in self.FAILED_BACKUP_JOB_STATES:
                for job in self._paginate('list_backup_jobs', 'BackupJobs',
                                          ByState=state, ByCreatedAfter=since):
                    failed.append(('backup', job.get('State') or state, job.get('ResourceArn') or '?',
                                   self._ts(job.get('CreationDate'))))
            for state in self.FAILED_COPY_JOB_STATES:
                for job in self._paginate('list_copy_jobs', 'CopyJobs',
                                          ByState=state, ByCreatedAfter=since):
                    failed.append(('copy', job.get('State') or state, job.get('ResourceArn') or '?',
                                   self._ts(job.get('CreationDate'))))
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({self._code(e)})"]
            return

        if not failed:
            self.results[key] = [
                1, f"No failed, aborted or expired backup/copy jobs in the last {self.JOB_LOOKBACK_DAYS} days"
            ]
            return

        counts = {}
        for kind, state, _, _ in failed:
            counts[f"{kind}:{state}"] = counts.get(f"{kind}:{state}", 0) + 1
        # Distinct resources, most recent failure first.
        resources = []
        for _, _, arn, _ in sorted(failed, key=lambda f: f[3], reverse=True):
            short = self._shortArn(arn)
            if short not in resources:
                resources.append(short)
        self.results[key] = [
            -1,
            f"{len(failed)} job(s) did not complete in the last {self.JOB_LOOKBACK_DAYS} days "
            f"({', '.join(f'{k}={v}' for k, v in sorted(counts.items()))}); most recent resources: "
            f"{', '.join(resources[:5])}" + (f" (+{len(resources) - 5} more)" if len(resources) > 5 else "")
        ]

    # ------------------------------------------------------------------ #
    # 8. Restore jobs / restore-testing validations failing (last 30 days)
    # ------------------------------------------------------------------ #
    def _checkBackupRestoreJobsFailing(self):
        key = 'backupRestoreJobsFailing'
        since = datetime.now(timezone.utc) - timedelta(days=self.RESTORE_LOOKBACK_DAYS)
        failedRestore, failedValidation, timedOut = [], [], 0
        try:
            # One listing covers both conditions: ValidationStatus has no
            # server-side filter, so list every restore job in the window.
            for job in self._paginate('list_restore_jobs', 'RestoreJobs', ByCreatedAfter=since):
                entry = (self._ts(job.get('CreationDate')), job.get('RestoreJobId') or '?')
                if (job.get('Status') or '').upper() == 'FAILED':
                    failedRestore.append(entry)
                elif (job.get('ValidationStatus') or '').upper() == 'FAILED':
                    failedValidation.append(entry)
                elif (job.get('ValidationStatus') or '').upper() == 'TIMED_OUT':
                    # Not a proven failure (the validation never reported);
                    # surfaced in the message only.
                    timedOut += 1
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({self._code(e)})"]
            return

        if not failedRestore and not failedValidation:
            note = (f"; {timedOut} restore validation(s) TIMED_OUT - review the validation"
                    if timedOut else "")
            self.results[key] = [
                1, f"No failed restore jobs or failed restore validations in the last "
                   f"{self.RESTORE_LOOKBACK_DAYS} days{note}"
            ]
            return

        parts = []
        if failedRestore:
            parts.append(f"{len(failedRestore)} restore job(s) FAILED")
        if failedValidation:
            parts.append(f"{len(failedValidation)} restore validation(s) FAILED")
        # Most recent first.
        ids = [rid for _, rid in sorted(failedRestore + failedValidation, key=lambda x: x[0], reverse=True)]
        more = f" +{len(ids) - 5} more" if len(ids) > 5 else ""
        self.results[key] = [
            -1,
            f"In the last {self.RESTORE_LOOKBACK_DAYS} days: {'; '.join(parts)} "
            f"(most recent job ids: {', '.join(ids[:5])}{more})"
        ]

    # ------------------------------------------------------------------ #
    # 9. No backup rule copies to another account
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNoCrossAccountCopy(self):
        key = 'backupPlanNoCrossAccountCopy'
        plans = self.account.get('_plans') or []
        if not plans:
            self.results[key] = [0, "No backup plans in this region - see backupNoPlanExists"]
            return

        own = self.account.get('_accountId')
        if not own:
            self.results[key] = [0, "Unable to evaluate (caller account ID unknown)"]
            return

        crossAccount, airGapped, unreadable, unresolved = [], [], [], []
        for plan in plans:
            planName = plan.get('_name') or plan.get('_id')
            rules = plan.get('_rules')
            if rules is None:
                # Plan was checkpointed without its rules - fetch them.
                try:
                    resp = self.backupClient.get_backup_plan(BackupPlanId=plan.get('_id'))
                    rules = (resp.get('BackupPlan') or {}).get('Rules') or []
                except botocore.exceptions.ClientError as e:
                    unreadable.append(f"{planName}({self._code(e)})")
                    continue
            for rule in rules or []:
                if rule.get('TargetLogicallyAirGappedBackupVaultArn'):
                    airGapped.append(planName)
                for action in rule.get('CopyActions') or []:
                    dest = action.get('DestinationBackupVaultArn') or ''
                    parts = dest.split(':')
                    if len(parts) >= 5 and parts[4] and parts[4] != own:
                        crossAccount.append(f"{planName}->{parts[4]}")
                        continue
                    isLag, reason = self._isLagVaultArn(dest)
                    if isLag:
                        airGapped.append(planName)
                    elif reason:
                        unresolved.append(f"{self._shortArn(dest)}({reason})")

        if crossAccount:
            self.results[key] = [
                1, f"Cross-account copy configured: {', '.join(sorted(set(crossAccount))[:5])}"
            ]
        elif airGapped:
            self.results[key] = [
                1,
                "No cross-account CopyAction, but plan(s) "
                f"{', '.join(sorted(set(airGapped))[:5])} store backups in a logically air-gapped vault "
                "(AWS-managed account isolation)"
            ]
        elif unreadable:
            self.results[key] = [
                0, f"Unable to evaluate (get_backup_plan failed for {', '.join(unreadable[:5])})"
            ]
        elif unresolved:
            self.results[key] = [
                0, "Unable to evaluate (copy destination vault(s) could not be read: "
                   f"{', '.join(sorted(set(unresolved))[:5])})"
            ]
        else:
            self.results[key] = [
                -1,
                f"None of the {len(plans)} backup plan(s) copy recovery points to a vault in another "
                "account or to a logically air-gapped vault"
            ]

    # ------------------------------------------------------------------ #
    # 10. No alerting on backup / copy job failures
    # ------------------------------------------------------------------ #
    def _checkBackupNoFailureAlerting(self):
        """PASS when an account-wide alert covers backup/copy job failures
        (an enabled EventBridge rule whose pattern can match a failed
        Backup/Copy Job State Change event and has a target, or a CloudWatch
        alarm with actions on an AWS/Backup failure metric), or when every
        vault that backup rules write to has SNS notifications for failure
        events. Vault notifications are per vault, so one notifying vault
        does not cover jobs written to the others."""
        key = 'backupNoFailureAlerting'
        vaults = self.account.get('_vaults') or []
        plans = self.account.get('_plans') or []
        if not vaults and not plans:
            self.results[key] = [0, "AWS Backup not in use in this region (no vaults or plans)"]
            return

        evidence, unknown = [], []

        # a) Enabled EventBridge rule matching failed aws.backup job events
        if self.eventsClient is not None:
            try:
                for rule in self._paginateClient(self.eventsClient, 'list_rules', 'Rules'):
                    if (rule.get('State') or '').upper() != 'ENABLED':
                        continue
                    if not self._patternMatchesBackupFailure(rule.get('EventPattern')):
                        continue
                    targets = self.eventsClient.list_targets_by_rule(
                        Rule=rule['Name'], EventBusName=rule.get('EventBusName') or 'default'
                    ).get('Targets') or []
                    if targets:
                        evidence.append(f"EventBridge rule {rule['Name']}")
                        break
            except botocore.exceptions.ClientError as e:
                unknown.append(f"events:{self._code(e)}")

        # b) CloudWatch alarm with actions on an AWS/Backup failure metric
        if not evidence and self.cloudwatchClient is not None:
            try:
                for alarm in self._paginateClient(self.cloudwatchClient, 'describe_alarms',
                                                  'MetricAlarms', AlarmTypes=['MetricAlarm']):
                    if not alarm.get('ActionsEnabled', True) or not alarm.get('AlarmActions'):
                        continue
                    if self._alarmWatchesBackupFailures(alarm):
                        evidence.append(f"CloudWatch alarm {alarm.get('AlarmName')}")
                        break
            except botocore.exceptions.ClientError as e:
                unknown.append(f"cloudwatch:{self._code(e)}")

        if evidence:
            self.results[key] = [1, f"Failure alerting found: {evidence[0]}"]
            return

        # c) Vault notifications (SNS) for failure events, on every vault
        #    that backup rules write to.
        allNames = [v.get('_name') for v in vaults if v.get('_name')]
        targeted = self._ruleTargetVaultNames()
        names = [n for n in allNames if targeted is None or n in targeted] or allNames
        covered, uncovered = [], []
        for name in names:
            try:
                resp = self.backupClient.get_backup_vault_notifications(BackupVaultName=name)
                hit = set(resp.get('BackupVaultEvents') or []) & self.FAILURE_NOTIFICATION_EVENTS
                (covered if hit and resp.get('SNSTopicArn') else uncovered).append(name)
            except botocore.exceptions.ClientError as e:
                code = self._code(e)
                # ResourceNotFoundException == no notifications configured.
                if code == 'ResourceNotFoundException':
                    uncovered.append(name)
                else:
                    unknown.append(f"get_backup_vault_notifications:{code}")

        if covered and not uncovered and not unknown:
            self.results[key] = [
                1, f"Failure alerting found: vault notifications for job failures on all "
                   f"{len(covered)} vault(s) used by backup rules"
            ]
        elif unknown:
            self.results[key] = [
                0,
                f"Unable to evaluate ({', '.join(sorted(set(unknown))[:3])}); "
                "no failure alerting found in the sources that could be read"
            ]
        else:
            more = f" (+{len(uncovered) - 5} more)" if len(uncovered) > 5 else ""
            vaultPart = (f"vault(s) without failure notifications: {', '.join(uncovered[:5])}{more}"
                         if uncovered else "no vaults to notify from")
            self.results[key] = [
                -1,
                "No enabled EventBridge rule matching failed aws.backup job events with a target, "
                f"no CloudWatch alarm on AWS/Backup failure metrics, and {vaultPart}"
                + (f" ({len(covered)} vault(s) do notify)" if covered else "")
            ]

    def _ruleTargetVaultNames(self):
        """Names of vaults that backup rules write to, or None when any plan's
        rules are unknown (checkpointed / unreadable) - then all vaults count."""
        names = set()
        for plan in self.account.get('_plans') or []:
            rules = plan.get('_rules')
            if rules is None:
                return None
            for rule in rules:
                if rule.get('TargetBackupVaultName'):
                    names.add(rule['TargetBackupVaultName'])
        return names

    # ------------------------------------------------------------------ #
    # 11. No restore testing plan (or plan with no selections)
    # ------------------------------------------------------------------ #
    def _checkBackupNoRestoreTestingPlan(self):
        key = 'backupNoRestoreTestingPlan'
        if not (self.account.get('_plans') or []):
            self.results[key] = [0, "No backup plans in this region - see backupNoPlanExists"]
            return
        empty, ok = [], []
        try:
            plans = list(self._paginate('list_restore_testing_plans', 'RestoreTestingPlans'))
            if not plans:
                self.results[key] = [-1, "No AWS Backup restore testing plan exists in this region"]
                return
            for p in plans:
                name = p.get('RestoreTestingPlanName')
                if not name:
                    continue
                sels = list(self._paginate('list_restore_testing_selections',
                                           'RestoreTestingSelections',
                                           RestoreTestingPlanName=name))
                (ok if sels else empty).append(name)
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({self._code(e)})"]
            return

        if empty:
            self.results[key] = [
                -1,
                f"Restore testing plan(s) with no resource selections: {', '.join(empty[:5])}"
                + (f" (+{len(empty) - 5} more)" if len(empty) > 5 else "")
                + (f"; {len(ok)} plan(s) have selections" if ok else "")
            ]
        else:
            self.results[key] = [
                1, f"{len(ok)} restore testing plan(s), all with resource selections"
            ]

    # ------------------------------------------------------------------ #
    # 12. No AWS Backup Audit Manager framework
    # ------------------------------------------------------------------ #
    # Frameworks in these deployment states do not evaluate any control.
    INEFFECTIVE_FRAMEWORK_STATES = frozenset({'FAILED', 'DELETE_IN_PROGRESS'})

    def _checkBackupAuditFrameworkMissing(self):
        key = 'backupAuditFrameworkMissing'
        if not (self.account.get('_plans') or []):
            self.results[key] = [0, "No backup plans in this region - see backupNoPlanExists"]
            return
        try:
            frameworks = self._listAllTokens('list_frameworks', 'Frameworks')
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({self._code(e)})"]
            return

        active = [f for f in frameworks
                  if str(f.get('DeploymentStatus') or '').upper() not in self.INEFFECTIVE_FRAMEWORK_STATES]
        if not active:
            if frameworks:
                states = ', '.join(sorted({str(f.get('DeploymentStatus')) for f in frameworks}))
                msg = (f"{len(frameworks)} Backup Audit Manager framework(s) exist but none is "
                       f"deployed (DeploymentStatus: {states})")
            else:
                msg = "No AWS Backup Audit Manager framework exists in this region"
            self.results[key] = [-1, msg]
            return

        # Report plans deliver the audit evidence; informational only - a
        # deployed framework already evaluates compliance through AWS Config.
        reportNote = ''
        try:
            reportPlans = self._listAllTokens('list_report_plans', 'ReportPlans')
            reportNote = f"; {len(reportPlans)} report plan(s)"
        except botocore.exceptions.ClientError:
            reportNote = '; report plans not readable'
        names = ', '.join(str(f.get('FrameworkName')) for f in active[:5])
        self.results[key] = [
            1, f"{len(active)} Backup Audit Manager framework(s) deployed: {names}{reportNote}"
        ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _listAllTokens(self, op, listKey, **kwargs):
        """List every item of a NextToken-paginated backup API that has no
        boto3 paginator (list_frameworks, list_report_plans)."""
        items, token = [], None
        while True:
            args = dict(kwargs)
            if token:
                args['NextToken'] = token
            resp = getattr(self.backupClient, op)(**args)
            items.extend(resp.get(listKey) or [])
            token = resp.get('NextToken')
            if not token:
                return items

    def _paginate(self, op, listKey, **kwargs):
        yield from self._paginateClient(self.backupClient, op, listKey, **kwargs)

    @staticmethod
    def _paginateClient(client, op, listKey, **kwargs):
        if client.can_paginate(op):
            for page in client.get_paginator(op).paginate(**kwargs):
                for item in page.get(listKey) or []:
                    yield item
        else:
            for item in getattr(client, op)(**kwargs).get(listKey) or []:
                yield item

    @staticmethod
    def _code(e):
        return e.response.get('Error', {}).get('Code', 'ClientError')

    @staticmethod
    def _ts(value):
        """Sortable POSIX timestamp for a datetime (0 when missing)."""
        try:
            return value.timestamp()
        except (AttributeError, TypeError, ValueError, OverflowError):
            return 0

    @staticmethod
    def _shortArn(arn):
        if '/' in arn:
            return arn.split('/')[-1]
        return arn.split(':')[-1]

    def _isLagVaultArn(self, arn):
        """Classify a same-account copy destination vault ARN.

        Returns (True, None) if it is a logically air-gapped vault,
        (False, None) if it is a readable non-air-gapped vault, and
        (False, reason) if the vault could not be read (the caller must not
        FAIL on that basis). Vaults in this Region are resolved from the
        discovered vault list; vaults in other Regions through vaultLookup
        (Backup._lookupVault, a cached describe_backup_vault)."""
        parts = (arn or '').split(':')
        if len(parts) < 7 or parts[2] != 'backup' or parts[5] != 'backup-vault':
            return False, 'unparseable ARN'
        region, name = parts[3], ':'.join(parts[6:])
        if region == self.account.get('_region'):
            localVaults = self.account.get('_vaults') or []
            if not localVaults:
                return False, 'vault list unavailable'
            for v in localVaults:
                if v.get('_name') == name:
                    return (v.get('_vaultType') or '').upper() == self.LOGICALLY_AIR_GAPPED, None
            # Not in this Region's vault list (deleted / renamed): a copy to
            # it cannot be isolating anything.
            return False, None
        if self.vaultLookup is None:
            return False, 'other Region not resolvable'
        try:
            summary, reason = self.vaultLookup(arn)
        except Exception as e:  # defensive: never let a lookup crash the check
            return False, type(e).__name__
        if summary is None:
            return False, reason or 'unknown'
        return (summary.get('VaultType') or '').upper() == self.LOGICALLY_AIR_GAPPED, None

    # EventBridge detail-types / detail.state values of a failed job.
    JOB_DETAIL_TYPES = ('Backup Job State Change', 'Copy Job State Change')
    FAILED_EVENT_STATES = ('FAILED', 'ABORTED', 'EXPIRED')

    @classmethod
    def _patternMatchesBackupFailure(cls, pattern):
        """True if an EventBridge EventPattern can match a failed AWS Backup
        backup / copy job event: source aws.backup, a detail-type filter (if
        any) that admits a Backup/Copy Job State Change, and a detail.state
        filter (if any) that admits FAILED/ABORTED/EXPIRED. Rules that only
        match COMPLETED jobs or plan/vault changes do not count."""
        if not pattern:
            return False
        try:
            parsed = json.loads(pattern)
        except (TypeError, ValueError):
            return False
        if not isinstance(parsed, dict):
            return False
        if 'source' not in parsed or not cls._matcherAdmits(parsed.get('source'), ('aws.backup',)):
            return False
        if 'detail-type' in parsed and not cls._matcherAdmits(parsed['detail-type'], cls.JOB_DETAIL_TYPES):
            return False
        detail = parsed.get('detail')
        if isinstance(detail, dict) and 'state' in detail \
                and not cls._matcherAdmits(detail['state'], cls.FAILED_EVENT_STATES):
            return False
        return True

    @staticmethod
    def _matcherAdmits(spec, candidates):
        """True if an EventBridge field matcher can match at least one of the
        candidate string values. Unrecognised matcher forms are treated as
        admitting (benefit of the doubt - cannot be proven not to alert)."""
        if isinstance(spec, str):
            spec = [spec]
        if not isinstance(spec, list):
            return True
        for m in spec:
            if isinstance(m, str):
                if m in candidates:
                    return True
                continue
            if not isinstance(m, dict):
                continue
            if 'prefix' in m:
                p = m['prefix']
                if isinstance(p, dict):   # {"prefix": {"equals-ignore-case": ...}}
                    p = p.get('equals-ignore-case')
                    if isinstance(p, str) and any(c.lower().startswith(p.lower()) for c in candidates):
                        return True
                    continue
                if isinstance(p, str) and any(c.startswith(p) for c in candidates):
                    return True
            elif 'suffix' in m:
                sfx = m['suffix']
                if not isinstance(sfx, str) or any(c.endswith(sfx) for c in candidates):
                    return True
            elif 'equals-ignore-case' in m:
                v = m['equals-ignore-case']
                if not isinstance(v, str) or any(c.lower() == v.lower() for c in candidates):
                    return True
            elif 'wildcard' in m:
                import fnmatch
                w = m['wildcard']
                if not isinstance(w, str) or any(fnmatch.fnmatchcase(c, w) for c in candidates):
                    return True
            elif 'anything-but' in m:
                ex = m['anything-but']
                if isinstance(ex, str):
                    ex = [ex]
                if not isinstance(ex, list):
                    return True   # anything-but {prefix: ...} etc.
                if any(c not in ex for c in candidates):
                    return True
            else:
                return True       # exists / numeric / cidr / unknown
        return False

    @classmethod
    def _alarmWatchesBackupFailures(cls, alarm):
        if alarm.get('Namespace') == 'AWS/Backup' and alarm.get('MetricName') in cls.FAILURE_METRICS:
            return True
        for q in alarm.get('Metrics') or []:
            m = (q.get('MetricStat') or {}).get('Metric') or {}
            if m.get('Namespace') == 'AWS/Backup' and m.get('MetricName') in cls.FAILURE_METRICS:
                return True
        return False

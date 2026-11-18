import re

from services.Evaluator import Evaluator


class BackupPlan(Evaluator):
    """
    Per-plan checks. Seven checks in total:

      - backupPlanNoRules             (R/H)  Plan has zero rules
      - backupPlanNoLifecycle         (C/M)  Any rule lacks DeleteAfterDays
      - backupPlanNoCrossRegionCopy   (R/M)  No rule has cross-region CopyActions
      - backupPlanNotAssigned         (R/H)  Plan has zero selections
      - backupPlanInfrequentSchedule  (R/L)  Any rule fires < once per 24h
      - backupPlanNoCompletionWindow  (O/L)  Any rule missing CompletionWindowMinutes
      - backupPlanNoContinuousBackup  (R/L)  No rule sets EnableContinuousBackup=true
      - backupMalwareScanDisabled     (S/L)  EC2/EBS/S3 plan without malware scanning
      - backupPlanNotTargetingProtectedVault (S/M) No rule lands in a locked / air-gapped vault
      - backupRetentionBelowDetectionWindow  (S/M) Longest retention < RETENTION_FLOOR_DAYS

    Input:
      plan -- dict produced by Backup.py._describePlan.
      backupClient -- boto3 backup client (retained for future extension).

    Schedule parsing supports both rate(N units) and cron(min hour dayOfMonth
    month dayOfWeek year). The cron parser is conservative: if a rule's cron
    fires only on specific days-of-week or specific days-of-month it is
    treated as infrequent.
    """

    # PITR-capable resource types (used by backupPlanNoContinuousBackup).
    # Only meaningful when the plan actually protects one of these.
    PITR_RESOURCE_TYPES = frozenset({
        'RDS', 'Aurora', 'S3', 'DynamoDB',
    })

    # Resource types GuardDuty Malware Protection for AWS Backup can scan.
    MALWARE_SCANNABLE_ARN_RE = re.compile(
        r'^arn:aws[a-z-]*:(ec2:[^:]*:[^:]*:(instance|volume)/|s3:::)'
    )
    LOGICALLY_AIR_GAPPED = 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT'

    # Minimum retention (days) that still covers a typical ransomware /
    # compromise detection window. Policy-dependent; 35 days matches the
    # maximum continuous-backup (PITR) window and common guidance.
    RETENTION_FLOOR_DAYS = 35

    def __init__(self, plan, backupClient, vaultLookup=None, accountId=None, region=None):
        super().__init__()
        self.plan = plan
        self.backupClient = backupClient
        # vaultLookup(nameOrArn) -> (summary|None, reason|None); supplied by
        # Backup.py so plan checks can see whether target vaults are locked.
        self.vaultLookup = vaultLookup
        self.accountId = accountId
        self.region = region

        self._resourceName = plan.get('_name') or plan.get('_id', 'unknown')
        self.rules = plan.get('_rules') or []
        self.selections = plan.get('_selections') or []

        self.addII('planId', plan.get('_id', 'N/A'))
        self.addII('name', self._resourceName)
        self.addII('planArn', plan.get('_arn', 'N/A'))
        self.addII('rulesCount', len(self.rules))
        self.addII('selectionsCount', len(self.selections))

    # ------------------------------------------------------------------ #
    # 1. Plan has no rules
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNoRules(self):
        if not self.rules:
            self.results['backupPlanNoRules'] = [
                -1, "Plan contains 0 rules — no recovery points will be created"
            ]
        else:
            self.results['backupPlanNoRules'] = [
                1, f"{len(self.rules)} rule(s) configured"
            ]

    # ------------------------------------------------------------------ #
    # 2. Rule missing Lifecycle.DeleteAfterDays
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNoLifecycle(self):
        if not self.rules:
            self.results['backupPlanNoLifecycle'] = [
                0, "No rules to evaluate"
            ]
            return

        missing = []
        for rule in self.rules:
            lifecycle = rule.get('Lifecycle') or {}
            if lifecycle.get('DeleteAfterDays') is None:
                missing.append(rule.get('RuleName', '(unnamed)'))

        if missing:
            self.results['backupPlanNoLifecycle'] = [
                -1,
                f"Rule(s) without Lifecycle.DeleteAfterDays: {', '.join(missing[:5])}"
                + (f" (+{len(missing) - 5} more)" if len(missing) > 5 else "")
            ]
        else:
            self.results['backupPlanNoLifecycle'] = [
                1, "All rules have Lifecycle.DeleteAfterDays set"
            ]

    # ------------------------------------------------------------------ #
    # 3. No cross-region copy on any rule
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNoCrossRegionCopy(self):
        if not self.rules:
            self.results['backupPlanNoCrossRegionCopy'] = [
                0, "No rules to evaluate"
            ]
            return

        # Determine the plan's home region from any TargetBackupVault ARN or
        # the plan's own ARN.
        home_region = self._planHomeRegion()

        has_cross_region = False
        for rule in self.rules:
            for action in (rule.get('CopyActions') or []):
                dest = action.get('DestinationBackupVaultArn') or ''
                dest_region = self._regionFromArn(dest)
                if dest_region and home_region and dest_region != home_region:
                    has_cross_region = True
                    break
                # If we cannot determine either region, be conservative and
                # count any CopyAction as cross-region.
                if dest_region and not home_region:
                    has_cross_region = True
                    break
            if has_cross_region:
                break

        if has_cross_region:
            self.results['backupPlanNoCrossRegionCopy'] = [
                1, "At least one rule has a cross-region CopyAction"
            ]
        else:
            self.results['backupPlanNoCrossRegionCopy'] = [
                -1, "No rule has a cross-region CopyAction"
            ]

    # ------------------------------------------------------------------ #
    # 4. Plan has no resource selections
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNotAssigned(self):
        err = self.plan.get('_selectionsError')
        if err and not self.selections:
            # list_backup_selections failed: the plan may have selections.
            self.results['backupPlanNotAssigned'] = [
                0, f"Unable to evaluate ({err}) - list_backup_selections failed"
            ]
        elif not self.selections:
            self.results['backupPlanNotAssigned'] = [
                -1, "Plan has 0 resource selections — protects nothing"
            ]
        else:
            self.results['backupPlanNotAssigned'] = [
                1, f"{len(self.selections)} selection(s) attached"
            ]

    # ------------------------------------------------------------------ #
    # 5. Schedule fires less than daily
    # ------------------------------------------------------------------ #
    def _checkBackupPlanInfrequentSchedule(self):
        if not self.rules:
            self.results['backupPlanInfrequentSchedule'] = [
                0, "No rules to evaluate"
            ]
            return

        infrequent = []
        for rule in self.rules:
            expr = rule.get('ScheduleExpression') or ''
            freq = self._scheduleIsFrequent(expr)
            # freq: True (daily or more), False (less than daily), None (unknown)
            if freq is False:
                infrequent.append(f"{rule.get('RuleName', '(unnamed)')}={expr}")

        if infrequent:
            self.results['backupPlanInfrequentSchedule'] = [
                -1,
                f"Rule(s) with < daily frequency: {', '.join(infrequent[:5])}"
                + (f" (+{len(infrequent) - 5} more)" if len(infrequent) > 5 else "")
            ]
        else:
            self.results['backupPlanInfrequentSchedule'] = [
                1, "All rules fire at least once per 24h (or schedule unparseable)"
            ]

    # ------------------------------------------------------------------ #
    # 6. Rule missing CompletionWindowMinutes
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNoCompletionWindow(self):
        if not self.rules:
            self.results['backupPlanNoCompletionWindow'] = [
                0, "No rules to evaluate"
            ]
            return

        missing = []
        for rule in self.rules:
            if rule.get('CompletionWindowMinutes') is None:
                missing.append(rule.get('RuleName', '(unnamed)'))

        if missing:
            self.results['backupPlanNoCompletionWindow'] = [
                -1,
                f"Rule(s) without CompletionWindowMinutes: {', '.join(missing[:5])}"
                + (f" (+{len(missing) - 5} more)" if len(missing) > 5 else "")
            ]
        else:
            self.results['backupPlanNoCompletionWindow'] = [
                1, "All rules have CompletionWindowMinutes set"
            ]

    # ------------------------------------------------------------------ #
    # 7. No rule with EnableContinuousBackup=true
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNoContinuousBackup(self):
        if not self.rules:
            self.results['backupPlanNoContinuousBackup'] = [
                0, "No rules to evaluate"
            ]
            return

        # Only meaningful if the plan protects a PITR-capable resource. We
        # cannot always determine that from selection ARNs (tag-based
        # selections make it opaque), so degrade to INFO when uncertain and
        # only FAIL when we can prove the plan protects at least one
        # RDS/Aurora/S3/DynamoDB resource by ARN.
        protects_pitr = self._planProtectsPitrResources()

        any_continuous = any(
            bool(rule.get('EnableContinuousBackup')) for rule in self.rules
        )

        if any_continuous:
            self.results['backupPlanNoContinuousBackup'] = [
                1, "At least one rule has EnableContinuousBackup=true"
            ]
            return

        if protects_pitr:
            self.results['backupPlanNoContinuousBackup'] = [
                -1,
                "No rule has EnableContinuousBackup=true, but plan protects PITR-capable resources"
            ]
        else:
            self.results['backupPlanNoContinuousBackup'] = [
                0,
                "No continuous backup enabled — plan does not clearly protect PITR-capable resources"
            ]

    # ------------------------------------------------------------------ #
    # 8. EC2/EBS/S3 plan without GuardDuty malware scanning
    # ------------------------------------------------------------------ #
    def _checkBackupMalwareScanDisabled(self):
        key = 'backupMalwareScanDisabled'
        if not self.rules:
            self.results[key] = [0, "No rules to evaluate"]
            return
        if not self.selections:
            err = self.plan.get('_selectionsError')
            self.results[key] = [0, (f"Unable to evaluate ({err}) - list_backup_selections failed" if err
                                     else "Plan has no resource selections - see backupPlanNotAssigned")]
            return

        covers = self._selectionsCoverScannableTypes()
        if covers is None:
            self.results[key] = [
                0, "Selections are tag/condition based only - cannot tell whether EC2/EBS/S3 are protected"
            ]
            return
        if not covers:
            self.results[key] = [0, "Plan does not protect EC2/EBS/S3 resources (malware scanning not applicable)"]
            return

        ruleScan = [r.get('RuleName', '(unnamed)') for r in self.rules if r.get('ScanActions')]
        planScan = self.plan.get('_scanSettings') or []
        if ruleScan and planScan:
            self.results[key] = [
                1, f"Malware scanning configured (ScanSettings present; rule(s) with ScanActions: {', '.join(ruleScan[:5])})"
            ]
        elif ruleScan or planScan:
            self.results[key] = [
                0,
                "Malware scanning partially configured ("
                + ("rule ScanActions present but no plan ScanSettings" if ruleScan
                   else "plan ScanSettings present but no rule has ScanActions") + ")"
            ]
        else:
            self.results[key] = [
                -1, "Plan protects EC2/EBS/S3 resources but no rule has ScanActions and the plan has no ScanSettings"
            ]

    # ------------------------------------------------------------------ #
    # 9. Rule data never lands in a locked / logically air-gapped vault
    # ------------------------------------------------------------------ #
    def _checkBackupPlanNotTargetingProtectedVault(self):
        key = 'backupPlanNotTargetingProtectedVault'
        if not self.rules:
            self.results[key] = [0, "No rules to evaluate"]
            return
        if self.vaultLookup is None:
            self.results[key] = [0, "Unable to evaluate (vault index unavailable)"]
            return

        unprotected, indeterminate = [], []
        for rule in self.rules:
            name = rule.get('RuleName', '(unnamed)')
            state, notes = self._ruleProtection(rule)
            if state == 'unprotected':
                unprotected.append(name)
            elif state != 'protected':
                indeterminate.append(f"{name}({'; '.join(notes)})")

        if unprotected:
            self.results[key] = [
                -1,
                "Rule(s) whose target and copy vaults are neither Vault-Locked nor logically air-gapped: "
                + ', '.join(unprotected[:5]) + (f" (+{len(unprotected) - 5} more)" if len(unprotected) > 5 else "")
            ]
        elif indeterminate:
            self.results[key] = [
                0,
                "Protection relies on vaults that cannot be inspected from this account: "
                + ', '.join(indeterminate[:3])
            ]
        else:
            self.results[key] = [1, "Every rule stores or copies backups into a locked or air-gapped vault"]

    # ------------------------------------------------------------------ #
    # 10. Longest retention shorter than the detection window
    # ------------------------------------------------------------------ #
    def _checkBackupRetentionBelowDetectionWindow(self):
        key = 'backupRetentionBelowDetectionWindow'
        floor = self.RETENTION_FLOOR_DAYS
        if not self.rules:
            self.results[key] = [0, "No rules to evaluate"]
            return

        # The plan keeps a pre-compromise recovery point as long as its
        # longest-lived recovery point (rule or any copy) outlives the floor,
        # so a short daily rule next to a long monthly rule is fine.
        best = 0          # None == some recovery point is kept indefinitely
        details = []
        copiesWithoutLifecycle = []
        for rule in self.rules:
            name = rule.get('RuleName', '(unnamed)')
            rets = [self._retentionDays(rule.get('Lifecycle'), isRule=True)]
            for a in (rule.get('CopyActions') or []):
                if not (a.get('Lifecycle') or {}).get('DeleteAfterDays'):
                    # Copy retention not stated explicitly - do not guess.
                    copiesWithoutLifecycle.append(name)
                    continue
                rets.append(self._retentionDays(a.get('Lifecycle'), isRule=False))
            if any(r is None for r in rets):
                best = None
                break
            ruleMax = max(rets)
            best = max(best, ruleMax)
            details.append(f"{name}={ruleMax}d")

        if best is None:
            self.results[key] = [1, "At least one rule (or copy) retains recovery points indefinitely"]
        elif best < floor and copiesWithoutLifecycle:
            self.results[key] = [
                0,
                f"Rule retention is at most {best} days (< {floor}) but CopyActions in "
                f"{', '.join(sorted(set(copiesWithoutLifecycle))[:5])} have no explicit DeleteAfterDays - "
                "verify the retention of the copies"
            ]
        elif best >= floor:
            self.results[key] = [1, f"Longest retention is {best} days (>= {floor})"]
        else:
            self.results[key] = [
                -1,
                f"Longest retention across all rules and copies is {best} days (< {floor}): "
                + ', '.join(details[:5])
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _retentionDays(lifecycle, isRule):
        """Return retention in days, or None for indefinite retention.

        - No Lifecycle / no DeleteAfterDays / DeleteAfterDays <= 0 (-1 means
          'keep forever') -> indefinite.
        - DeleteAfterEvent=DELETE_AFTER_COPY on the rule without
          DeleteAfterDays -> the source point is short-lived (0); only the
          copies count."""
        lifecycle = lifecycle or {}
        days = lifecycle.get('DeleteAfterDays')
        if days is None:
            if isRule and lifecycle.get('DeleteAfterEvent'):
                return 0
            return None
        try:
            days = int(days)
        except (TypeError, ValueError):
            return None
        if days <= 0:
            return None
        return days

    def _selectionsCoverScannableTypes(self):
        """True if any selection explicitly (or via '*') includes EC2/EBS/S3;
        False if all selections list only other resource ARNs; None if the
        resource types depend on tags/conditions only."""
        opaque = False
        for sel in self.selections:
            resources = [r for r in (sel.get('Resources') or []) if isinstance(r, str)]
            if not resources:
                opaque = True
                continue
            for arn in resources:
                if arn == '*' or self.MALWARE_SCANNABLE_ARN_RE.match(arn):
                    return True
        return None if opaque else False

    def _ruleProtection(self, rule):
        """Classify one rule: 'protected' if its target or any copy vault is
        locked / logically air-gapped; 'unprotected' if every destination was
        inspected and none is; otherwise 'indeterminate'."""
        if rule.get('TargetLogicallyAirGappedBackupVaultArn'):
            return 'protected', []
        dests = []
        if rule.get('TargetBackupVaultName'):
            dests.append(rule['TargetBackupVaultName'])
        for action in rule.get('CopyActions') or []:
            if action.get('DestinationBackupVaultArn'):
                dests.append(action['DestinationBackupVaultArn'])
        if not dests:
            return 'indeterminate', ['no destination vault']

        notes = []
        for dest in dests:
            if dest.startswith('arn:'):
                parts = dest.split(':')
                acct = parts[4] if len(parts) > 4 else ''
                if self.accountId and acct and acct != self.accountId:
                    notes.append(f"copy to account {acct} assumed protected")
                    continue
            summary, reason = self.vaultLookup(dest)
            if summary is None:
                notes.append(f"{dest.split(':')[-1]}: {reason}")
                continue
            if bool(summary.get('Locked')) or \
                    (summary.get('VaultType') or '').upper() == self.LOGICALLY_AIR_GAPPED:
                return 'protected', []
        return ('indeterminate', notes) if notes else ('unprotected', [])

    def _planHomeRegion(self):
        for rule in self.rules:
            arn = rule.get('TargetBackupVaultArn') or ''
            r = self._regionFromArn(arn)
            if r:
                return r
        return self._regionFromArn(self.plan.get('_arn') or '')

    @staticmethod
    def _regionFromArn(arn):
        """ARN format: arn:aws:backup:<region>:<account>:...
        Returns the region string or empty."""
        if not arn:
            return ''
        parts = arn.split(':')
        return parts[3] if len(parts) >= 4 else ''

    _RATE_RE = re.compile(r'^\s*rate\(\s*(\d+)\s+(minute|minutes|hour|hours|day|days)\s*\)\s*$', re.IGNORECASE)
    _CRON_RE = re.compile(r'^\s*cron\(\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s*\)\s*$', re.IGNORECASE)

    @classmethod
    def _scheduleIsFrequent(cls, expr):
        """Return True (>= daily), False (< daily), or None (unparseable).

        Daily-or-better means the schedule fires at least once every 24 hours.
        """
        if not expr:
            return None

        m = cls._RATE_RE.match(expr)
        if m:
            value = int(m.group(1))
            unit = m.group(2).lower().rstrip('s')
            if unit == 'minute':
                minutes = value
            elif unit == 'hour':
                minutes = value * 60
            elif unit == 'day':
                minutes = value * 24 * 60
            else:
                return None
            return minutes <= 24 * 60

        m = cls._CRON_RE.match(expr)
        if m:
            minute_f, hour_f, dom_f, month_f, dow_f = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)

            # If day-of-week restricts to specific days (not '?' or '*'), the
            # schedule fires only on those weekdays → less than daily.
            if dow_f not in ('?', '*'):
                # Some special cases: '1-7', '*/1' still daily; explicit list
                # (e.g. '1,3,5' or '1' or 'MON') is not daily.
                if not cls._cronFieldMatchesAll(dow_f):
                    return False

            # If day-of-month restricts to specific days, the schedule fires
            # only on those calendar days → less than daily.
            if dom_f not in ('?', '*'):
                if not cls._cronFieldMatchesAll(dom_f):
                    return False

            # If month restricts to specific months, still less than daily.
            if month_f not in ('*',):
                if not cls._cronFieldMatchesAll(month_f):
                    return False

            # By this point DOW/DOM/MONTH allow any day. Hour must allow at
            # least one firing per day; even a single fixed hour still means
            # once-per-day = daily.
            return True

        return None

    @staticmethod
    def _cronFieldMatchesAll(field):
        """Return True if the cron field expression represents every value in
        its range (e.g. '*', '*/1', '1-7' for DOW, '1-31' for DOM)."""
        f = field.strip()
        if f in ('*', '?'):
            return True
        if f in ('*/1', '1/1'):
            return True
        # Rough heuristic: hyphen ranges are considered "every value" only
        # when explicitly full-range for that field. We do not attempt to
        # compute the field's max here — anything more complex is safest
        # treated as a restriction (i.e. return False so schedule is flagged
        # as infrequent).
        return False

    def _planProtectsPitrResources(self):
        """Return True if any selection ARN clearly references a PITR-capable
        resource type."""
        # ARN prefixes for PITR-capable resources.
        pitr_arn_prefixes = (
            'arn:aws:rds:',              # RDS + Aurora (Aurora clusters use rds)
            'arn:aws:s3:::',
            'arn:aws:dynamodb:',
        )
        for sel in self.selections:
            resources = sel.get('Resources') or []
            for arn in resources:
                if not isinstance(arn, str):
                    continue
                for p in pitr_arn_prefixes:
                    if arn.startswith(p):
                        return True
        return False

import datetime

import botocore

from services.Evaluator import Evaluator
from utils.Config import Config


class InspectorCommon(Evaluator):
    """
    Account/region-scoped Amazon Inspector checks (13).

    Input:
      detail -- from services/inspector/Inspector.py.getResources:
        '_accountStatus', '_coverageByStatus', '_severityCounts',
        '_exploitAvailable', '_fixAvailable', '_totalFindings'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    When Inspector is not enabled, only inspectorNotEnabled produces a finding
    and the per-scanner checks report INFO.
    """

    ## Coverage-gap threshold: fail if more than this fraction of resources are
    ## not actively scanned.
    COVERAGE_GAP_FRACTION = 0.10

    ## Remediation SLA (days) per severity for inspectorFindingsAged. Override
    ## at runtime with Config.set('INSPECTOR_FINDING_SLA_DAYS',
    ## {'CRITICAL': 7, 'HIGH': 14}).
    DEFAULT_FINDING_SLA_DAYS = {'CRITICAL': 15, 'HIGH': 30}
    ## list_findings is paginated over every matching finding; stop counting
    ## after this many pages (the check only needs to know "any" and roughly
    ## how many).
    AGED_FINDINGS_MAX_PAGES = 5

    ## Suppression-rule criteria that only describe "how bad / what kind" of
    ## finding, not WHICH finding or resource. A SUPPRESS filter built only from
    ## these hides an entire class of findings.
    BROAD_FILTER_KEYS = frozenset((
        'severity', 'resourceType', 'findingType', 'findingStatus',
        'vendorSeverity', 'inspectorScore', 'epssScore',
    ))

    ## Member relationship states that do not represent a coverage gap.
    MEMBER_IGNORED_STATUSES = frozenset((
        'ENABLED', 'ACCOUNT_SUSPENDED', 'REGION_DISABLED', 'DELETED',
    ))

    ## Error codes that, on org-level APIs, mean "this is not the Inspector
    ## delegated administrator".
    NOT_ADMIN_CODES = ('AccessDeniedException', 'AccessDenied',
                       'ValidationException')

    def __init__(self, detail, insClient):
        super().__init__()
        self.detail = detail
        self.insClient = insClient
        self._resourceName = 'Account'

        self.status = detail.get('_accountStatus') or {}
        self.state = (self.status.get('state') or {})
        self.resourceState = (self.status.get('resourceState') or {})
        self.coverage = detail.get('_coverageByStatus') or {}
        self.severity = detail.get('_severityCounts') or {}
        self.exploit = detail.get('_exploitAvailable')
        self.fix = detail.get('_fixAvailable')
        self.total = detail.get('_totalFindings')

        self.enabled = self.state.get('status') == 'ENABLED'

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('accountStatus', self.state.get('status', 'N/A'))
        for rt in ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository'):
            self.addII(f'{rt}Scanning',
                       (self.resourceState.get(rt) or {}).get('status', 'N/A'))
        self.addII('criticalFindings', str(self.severity.get('critical', 'N/A')))
        self.addII('exploitAvailable', str(self.exploit if self.exploit is not None else 'N/A'))

    def _na(self, key):
        self.results[key] = [
            0, "Inspector is not enabled in this region — see inspectorNotEnabled"
        ]

    def _resourceStatus(self, rt):
        return (self.resourceState.get(rt) or {}).get('status')

    # 1. Inspector not enabled
    def _checkInspectorNotEnabled(self):
        if self.enabled:
            self.results['inspectorNotEnabled'] = [
                1, "Amazon Inspector is enabled in this region"
            ]
        else:
            self.results['inspectorNotEnabled'] = [
                -1,
                "Amazon Inspector is not enabled — EC2 instances, container "
                "images and Lambda functions are not being continuously scanned "
                "for known CVEs"
            ]

    def _resourceCheck(self, key, rt, label, fail_status):
        if not self.enabled:
            return self._na(key)
        status = self._resourceStatus(rt)
        if status is None:
            self.results[key] = [
                0, f"{label} scanning status is not reported in this region"
            ]
        elif status == 'ENABLED':
            self.results[key] = [1, f"{label} scanning is enabled"]
        else:
            self.results[key] = [fail_status,
                                 f"{label} scanning is {status} — this resource "
                                 "type is not being scanned for vulnerabilities"]

    # 2-6. Per-resource-type scanning
    def _checkInspectorEc2ScanningDisabled(self):
        self._resourceCheck('inspectorEc2ScanningDisabled', 'ec2',
                           'EC2', -1)

    def _checkInspectorEcrScanningDisabled(self):
        self._resourceCheck('inspectorEcrScanningDisabled', 'ecr',
                           'ECR container image', -1)

    def _checkInspectorLambdaScanningDisabled(self):
        self._resourceCheck('inspectorLambdaScanningDisabled', 'lambda',
                           'Lambda standard', -1)

    def _checkInspectorLambdaCodeScanningDisabled(self):
        self._resourceCheck('inspectorLambdaCodeScanningDisabled', 'lambdaCode',
                           'Lambda code', 0)

    def _checkInspectorCodeRepositoryScanningDisabled(self):
        ## codeRepository is present in the live API response but not in the
        ## original spec. INFO when absent (not all regions/tiers offer it).
        if not self.enabled:
            return self._na('inspectorCodeRepositoryScanningDisabled')
        status = self._resourceStatus('codeRepository')
        if status is None:
            self.results['inspectorCodeRepositoryScanningDisabled'] = [
                0, "Code repository scanning is not reported in this region"
            ]
        elif status == 'ENABLED':
            self.results['inspectorCodeRepositoryScanningDisabled'] = [
                1, "Code repository scanning is enabled"
            ]
        else:
            self.results['inspectorCodeRepositoryScanningDisabled'] = [
                -1,
                f"Code repository scanning is {status} — connected source "
                "repositories are not being scanned for exposed secrets and "
                "vulnerable dependencies"
            ]

    # 7. Coverage gap
    def _checkInspectorCoverageGap(self):
        if not self.enabled:
            return self._na('inspectorCoverageGap')
        total = self.coverage.get('_total') or 0
        if total == 0:
            self.results['inspectorCoverageGap'] = [
                0, "No resources reported by Inspector coverage"
            ]
            return
        inactive = self.coverage.get('INACTIVE', 0)
        fraction = inactive / total
        if fraction > self.COVERAGE_GAP_FRACTION:
            self.results['inspectorCoverageGap'] = [
                -1,
                "{} of {} resources ({:.0%}) have INACTIVE scan coverage — those "
                "resources are enrolled but not actually being scanned, so their "
                "vulnerabilities are unknown".format(inactive, total, fraction)
            ]
        else:
            self.results['inspectorCoverageGap'] = [
                1,
                "{} of {} resources actively scanned".format(
                    total - inactive, total)
            ]

    # 8. Critical findings
    def _checkInspectorCriticalFindings(self):
        if not self.enabled:
            return self._na('inspectorCriticalFindings')
        critical = self.severity.get('critical')
        if critical is None:
            self.results['inspectorCriticalFindings'] = [
                0, "Finding counts are not reported"
            ]
        elif critical > 0:
            self.results['inspectorCriticalFindings'] = [
                -1,
                f"{critical} CRITICAL Inspector finding(s) — critical CVEs on "
                "internet-adjacent or data-handling resources are the highest "
                "priority for patching"
            ]
        else:
            self.results['inspectorCriticalFindings'] = [
                1, "No CRITICAL Inspector findings"
            ]

    # 9. Exploitable findings
    def _checkInspectorExploitableFindings(self):
        if not self.enabled:
            return self._na('inspectorExploitableFindings')
        if self.exploit is None:
            self.results['inspectorExploitableFindings'] = [
                0, "Exploit-availability counts are not reported"
            ]
        elif self.exploit > 0:
            self.results['inspectorExploitableFindings'] = [
                -1,
                f"{self.exploit} finding(s) have a KNOWN EXPLOIT available — a "
                "vulnerability with a published exploit and a fix that has not "
                "been applied is the single highest-priority patching class"
            ]
        else:
            self.results['inspectorExploitableFindings'] = [
                1, "No findings with a known available exploit"
            ]

    # 10. Fixable findings not patched
    def _checkInspectorFixAvailableNotApplied(self):
        if not self.enabled:
            return self._na('inspectorFixAvailableNotApplied')
        if self.fix is None or not self.total:
            self.results['inspectorFixAvailableNotApplied'] = [
                0, "Fix-availability counts are not reported"
            ]
            return
        ## A high proportion of findings having an available-but-unapplied fix
        ## indicates patching is not keeping up. Report the raw numbers.
        if self.fix > 0:
            self.results['inspectorFixAvailableNotApplied'] = [
                -1,
                "{} of {} finding(s) have a fix available that has not been "
                "applied — these are patchable today; the vulnerability persists "
                "only because the update has not been rolled out".format(
                    self.fix, self.total)
            ]
        else:
            self.results['inspectorFixAvailableNotApplied'] = [
                1, "No findings with an unapplied available fix"
            ]

    # ------------------------------------------------------------------ #
    # Helpers for live (lazy) reads
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def _slaDays(self):
        sla = dict(self.DEFAULT_FINDING_SLA_DAYS)
        override = Config.get('INSPECTOR_FINDING_SLA_DAYS', None)
        if isinstance(override, dict):
            for sev, days in override.items():
                try:
                    if str(sev).upper() in sla and int(days) > 0:
                        sla[str(sev).upper()] = int(days)
                except (TypeError, ValueError):
                    pass
        return sla

    def _countAgedFindings(self, severity, cutoff):
        """Returns (count, truncated). Raises ClientError on failure."""
        criteria = {
            'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}],
            'severity': [{'comparison': 'EQUALS', 'value': severity}],
            'firstObservedAt': [{'endInclusive': cutoff}],
        }
        paginator = self.insClient.get_paginator('list_findings')
        count = 0
        pages = 0
        for page in paginator.paginate(filterCriteria=criteria,
                                       PaginationConfig={'PageSize': 100}):
            count += len(page.get('findings', []) or [])
            pages += 1
            if pages >= self.AGED_FINDINGS_MAX_PAGES and page.get('nextToken'):
                return count, True
        return count, False

    # 11. CRITICAL/HIGH findings open beyond remediation SLA
    def _checkInspectorFindingsAged(self):
        key = 'inspectorFindingsAged'
        if not self.enabled:
            return self._na(key)
        sla = self._slaDays()
        now = datetime.datetime.now(datetime.timezone.utc)
        breaches = []
        try:
            for sev in ('CRITICAL', 'HIGH'):
                cutoff = now - datetime.timedelta(days=sla[sev])
                count, truncated = self._countAgedFindings(sev, cutoff)
                if count:
                    breaches.append('{}{} {} (open > {}d)'.format(
                        count, '+' if truncated else '', sev, sla[sev]))
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return
        if breaches:
            self.results[key] = [
                -1,
                "Active Inspector findings older than the remediation SLA: "
                + ", ".join(breaches)
                + " — vulnerabilities are not being remediated within the "
                "expected timeframe"
            ]
        else:
            self.results[key] = [
                1,
                "No active CRITICAL findings older than {}d or HIGH findings "
                "older than {}d".format(sla['CRITICAL'], sla['HIGH'])
            ]

    # 12. Org auto-enable incomplete (delegated administrator only)
    def _checkInspectorOrgAutoEnableIncomplete(self):
        key = 'inspectorOrgAutoEnableIncomplete'
        try:
            org = self.insClient.describe_organization_configuration()
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if code in self.NOT_ADMIN_CODES:
                self.results[key] = [
                    0, "Not evaluable from member account (this account is not "
                       "the Inspector delegated administrator)"]
            else:
                self.results[key] = [0, f"Unable to evaluate ({code})"]
            return

        auto = org.get('autoEnable') or {}
        problems = []
        missing = [rt for rt in ('ec2', 'ecr', 'lambda')
                   if auto.get(rt) is not True]
        if missing:
            problems.append("auto-enable is off for " + ", ".join(missing))
        if org.get('maxAccountLimitReached'):
            problems.append("the maximum member account limit is reached, so "
                            "new accounts are not auto-enabled")

        try:
            notEnabled = []
            paginator = self.insClient.get_paginator('list_members')
            for page in paginator.paginate(onlyAssociated=False):
                for m in page.get('members', []) or []:
                    st = m.get('relationshipStatus')
                    if st and st not in self.MEMBER_IGNORED_STATUSES:
                        notEnabled.append(f"{m.get('accountId')}={st}")
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return
        if notEnabled:
            shown = ", ".join(notEnabled[:10])
            more = f" (+{len(notEnabled) - 10} more)" if len(notEnabled) > 10 else ""
            problems.append(f"{len(notEnabled)} member account(s) not ENABLED: "
                            f"{shown}{more}")

        advisory = [rt for rt in ('lambdaCode', 'codeRepository')
                    if rt in auto and auto.get(rt) is not True]
        note = (" (advisory: auto-enable is also off for "
                + ", ".join(advisory) + ")") if advisory else ""

        if problems:
            self.results[key] = [
                -1, "Inspector organization coverage is incomplete: "
                    + "; ".join(problems) + note]
        else:
            self.results[key] = [
                1, "Inspector auto-enables EC2, ECR and Lambda scanning for new "
                   "member accounts and all member accounts are ENABLED" + note]

    # 13. Broad suppression rules
    def _isBroadSuppression(self, criteria):
        used = {k for k, v in (criteria or {}).items() if v}
        if not used:
            return True  # empty criteria suppress every finding
        if not used.issubset(self.BROAD_FILTER_KEYS):
            return False
        ## Suppressing only INFORMATIONAL findings is common, accepted noise
        ## reduction; do not treat a filter that only does that as broad.
        if used == {'severity'}:
            sev = criteria.get('severity') or []
            if all(f.get('comparison') == 'EQUALS'
                   and f.get('value') == 'INFORMATIONAL' for f in sev):
                return False
        return True

    def _checkInspectorSuppressionBroad(self):
        key = 'inspectorSuppressionBroad'
        broad = []
        try:
            paginator = self.insClient.get_paginator('list_filters')
            for page in paginator.paginate(action='SUPPRESS'):
                for f in page.get('filters', []) or []:
                    if f.get('action') != 'SUPPRESS':
                        continue
                    crit = f.get('criteria') or {}
                    if self._isBroadSuppression(crit):
                        keys = sorted(k for k, v in crit.items() if v) or ['<none>']
                        broad.append("{} [{}]".format(
                            f.get('name') or f.get('arn'), ", ".join(keys)))
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
            return
        if broad:
            self.results[key] = [
                -1,
                "{} suppression rule(s) hide whole severities/resource types "
                "without scoping to a resource, vulnerability or tag: {}".format(
                    len(broad), "; ".join(broad[:10]))
            ]
        else:
            self.results[key] = [
                1, "No suppression rules suppress entire severities or "
                   "resource types"]

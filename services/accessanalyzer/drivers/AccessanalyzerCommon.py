import datetime

import botocore

from services.Evaluator import Evaluator


class AccessanalyzerCommon(Evaluator):
    """
    Account/region-scoped IAM Access Analyzer checks (+ RAM org sharing).

    Input:
      detail -- from services/accessanalyzer/Accessanalyzer.py.getResources:
        '_region', '_analyzers', '_activeExternalFindings', '_findingsCapped',
        '_archiveRuleCount'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ANALYZER_EXTERNAL = ('ACCOUNT', 'ORGANIZATION')
    ANALYZER_UNUSED = ('ACCOUNT_UNUSED_ACCESS', 'ORGANIZATION_UNUSED_ACCESS')
    ANALYZER_INTERNAL = ('ACCOUNT_INTERNAL_ACCESS', 'ORGANIZATION_INTERNAL_ACCESS')

    UNUSED_FINDING_TYPES = ('UnusedIAMRole', 'UnusedIAMUserAccessKey',
                            'UnusedIAMUserPassword', 'UnusedPermission')
    ## An unused-access finding left ACTIVE longer than this is treated as
    ## unresolved rather than "still being triaged".
    UNUSED_FINDING_AGE_DAYS = 30
    UNUSED_FINDINGS_PAGE_CAP = 20   # x100 findings per page

    def __init__(self, detail, aaClient, orgClient=None):
        super().__init__()
        self.detail = detail
        self.aaClient = aaClient
        self.orgClient = orgClient
        self._resourceName = 'Account'

        self.analyzers = detail.get('_analyzers') or []
        self.activeFindings = detail.get('_activeExternalFindings')
        self.findingsCapped = bool(detail.get('_findingsCapped'))
        self.archiveRuleCount = detail.get('_archiveRuleCount') or 0

        self.types = [a.get('type') for a in self.analyzers]
        self.active = [a for a in self.analyzers if a.get('status') == 'ACTIVE']

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('analyzerCount', str(len(self.analyzers)))
        self.addII('activeAnalyzerCount', str(len(self.active)))
        self.addII('analyzerTypes', ', '.join(sorted(set(self.types))) or 'none')

    def _hasType(self, types):
        return any(t in types for t in self.types)

    def _hasActiveType(self, types):
        return any(a.get('type') in types for a in self.active)

    # 1. No analyzer at all
    def _checkAaNoAnalyzerConfigured(self):
        if self.analyzers:
            self.results['aaNoAnalyzerConfigured'] = [
                1, f"{len(self.analyzers)} Access Analyzer analyzer(s) configured"
            ]
        else:
            self.results['aaNoAnalyzerConfigured'] = [
                -1,
                "No IAM Access Analyzer analyzer exists in this region — nothing "
                "is continuously evaluating resource policies for access granted "
                "outside the account"
            ]

    # 2. No external-access analyzer
    def _checkAaNoAccountAnalyzer(self):
        if not self.analyzers:
            self.results['aaNoAccountAnalyzer'] = [
                0, "No analyzer at all — see aaNoAnalyzerConfigured"
            ]
            return
        if self._hasType(self.ANALYZER_EXTERNAL):
            self.results['aaNoAccountAnalyzer'] = [
                1, "An account or organization external-access analyzer exists"
            ]
        else:
            self.results['aaNoAccountAnalyzer'] = [
                -1,
                "No external-access analyzer (type ACCOUNT or ORGANIZATION) — "
                "external access to S3 buckets, IAM roles, KMS keys and the like "
                "is not being detected"
            ]

    # 3. No unused-access analyzer
    def _checkAaUnusedAccessAnalyzerMissing(self):
        if self._hasType(self.ANALYZER_UNUSED):
            self.results['aaUnusedAccessAnalyzerMissing'] = [
                1, "An unused-access analyzer exists"
            ]
        else:
            self.results['aaUnusedAccessAnalyzerMissing'] = [
                -1,
                "No unused-access analyzer (type ACCOUNT_UNUSED_ACCESS) — unused "
                "IAM roles, access keys and permissions are not being surfaced "
                "for least-privilege review"
            ]

    # 4. No internal-access analyzer (newer type)
    def _checkAaNoInternalAccessAnalyzer(self):
        if self._hasType(self.ANALYZER_INTERNAL):
            self.results['aaNoInternalAccessAnalyzer'] = [
                1, "An internal-access analyzer exists"
            ]
        else:
            self.results['aaNoInternalAccessAnalyzer'] = [
                0,
                "No internal-access analyzer (type ACCOUNT_INTERNAL_ACCESS) — "
                "this newer analyzer surfaces which principals inside the account "
                "can reach critical resources; consider enabling it"
            ]

    # 5. An analyzer exists but is not ACTIVE
    def _checkAaAnalyzerNotActive(self):
        if not self.analyzers:
            self.results['aaAnalyzerNotActive'] = [
                0, "No analyzer at all — see aaNoAnalyzerConfigured"
            ]
            return
        inactive = [
            a.get('name', 'unknown') for a in self.analyzers
            if a.get('status') != 'ACTIVE'
        ]
        if inactive:
            self.results['aaAnalyzerNotActive'] = [
                -1,
                "{} analyzer(s) are not in the ACTIVE state ({}) — an analyzer "
                "that is not active produces no findings".format(
                    len(inactive), ', '.join(inactive[:5]))
            ]
        else:
            self.results['aaAnalyzerNotActive'] = [
                1, f"All {len(self.analyzers)} analyzer(s) are ACTIVE"
            ]

    # 6. Unresolved external-access findings
    def _checkAaUnresolvedExternalAccess(self):
        if not self._hasActiveType(self.ANALYZER_EXTERNAL):
            self.results['aaUnresolvedExternalAccess'] = [
                0, "No active external-access analyzer to report findings"
            ]
            return
        if self.activeFindings is None:
            self.results['aaUnresolvedExternalAccess'] = [
                0, "Access Analyzer findings could not be read"
            ]
            return
        if self.activeFindings == 0:
            self.results['aaUnresolvedExternalAccess'] = [
                1, "No active external-access findings"
            ]
            return

        atLeast = "at least " if self.findingsCapped else ""
        self.results['aaUnresolvedExternalAccess'] = [
            -1,
            f"{atLeast}{self.activeFindings} active external-access finding(s) — "
            "each is a resource granting access outside the account that has not "
            "been reviewed and archived or remediated"
        ]

    # 7. No archive rules (known-good findings not auto-archived)
    def _checkAaNoArchiveRules(self):
        if not self._hasActiveType(self.ANALYZER_EXTERNAL):
            self.results['aaNoArchiveRules'] = [
                0, "No active external-access analyzer"
            ]
            return
        if self.archiveRuleCount > 0:
            self.results['aaNoArchiveRules'] = [
                1, f"{self.archiveRuleCount} archive rule(s) configured"
            ]
        else:
            self.results['aaNoArchiveRules'] = [
                -1,
                "No archive rules — every intended cross-account grant reappears "
                "as an active finding on each scan, so real findings are harder "
                "to see among the known-good ones"
            ]

    # 8. No organization analyzer when in an org
    def _checkAaNoOrganizationAnalyzer(self):
        from utils.Config import Config
        info = Config.get('stsInfo', {})
        ## Only meaningful inside an AWS Organization. We do not have a cheap
        ## org-membership signal here, so report INFO rather than FAIL when no
        ## ORGANIZATION analyzer exists — a standalone account correctly has none.
        orgTypes = ('ORGANIZATION', 'ORGANIZATION_UNUSED_ACCESS',
                    'ORGANIZATION_INTERNAL_ACCESS')
        if any(t in orgTypes for t in self.types):
            self.results['aaNoOrganizationAnalyzer'] = [
                1, "An organization-level analyzer exists"
            ]
        else:
            self.results['aaNoOrganizationAnalyzer'] = [
                0,
                "No organization-level analyzer. If this account is the "
                "delegated administrator for an AWS Organization, an ORGANIZATION "
                "analyzer gives a single cross-account view; a standalone account "
                "does not need one"
            ]

    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    # 9. Unused-access analyzer has stale ACTIVE findings
    def _checkAaUnusedAccessFindingsOpen(self):
        key = 'aaUnusedAccessFindingsOpen'
        analyzers = [a for a in self.active if a.get('type') in self.ANALYZER_UNUSED]
        if not analyzers:
            self.results[key] = [
                0, "No active unused-access analyzer — see aaUnusedAccessAnalyzerMissing"
            ]
            return

        cutoff = datetime.datetime.now(datetime.timezone.utc) - \
            datetime.timedelta(days=self.UNUSED_FINDING_AGE_DAYS)
        stale, total, capped = [], 0, False
        for analyzer in analyzers:
            pages = 0
            try:
                paginator = self.aaClient.get_paginator('list_findings_v2')
                for page in paginator.paginate(
                        analyzerArn=analyzer.get('arn'),
                        filter={'status': {'eq': ['ACTIVE']}},
                        PaginationConfig={'PageSize': 100}):
                    for f in page.get('findings', []) or []:
                        if f.get('findingType') not in self.UNUSED_FINDING_TYPES:
                            continue
                        if f.get('status', 'ACTIVE') != 'ACTIVE':
                            continue
                        total += 1
                        created = f.get('createdAt')
                        if isinstance(created, datetime.datetime):
                            if created.tzinfo is None:
                                created = created.replace(tzinfo=datetime.timezone.utc)
                            if created <= cutoff:
                                stale.append(f.get('resource', f.get('id', 'unknown')))
                    pages += 1
                    if pages >= self.UNUSED_FINDINGS_PAGE_CAP:
                        capped = bool(page.get('nextToken'))
                        break
            except botocore.exceptions.ClientError as e:
                self.results[key] = [0, f"Unable to evaluate ({self._errCode(e)})"]
                return

        if stale:
            atLeast = "at least " if capped else ""
            self.results[key] = [
                -1,
                "{}{} unused-access finding(s) (unused roles, access keys, passwords "
                "or permissions) have been ACTIVE for more than {} days, e.g. {}".format(
                    atLeast, len(stale), self.UNUSED_FINDING_AGE_DAYS,
                    ', '.join(str(r) for r in stale[:3]))
            ]
        elif capped:
            self.results[key] = [
                0,
                f"Unable to evaluate (more than {total} active unused-access findings; "
                "only the first pages were read)"
            ]
        elif total:
            self.results[key] = [
                1,
                f"{total} active unused-access finding(s), all raised within the last "
                f"{self.UNUSED_FINDING_AGE_DAYS} days"
            ]
        else:
            self.results[key] = [1, "No active unused-access findings"]

    def _isPrimaryRegion(self):
        """Org-wide settings are global: report them once, in the first
        selected region, rather than once per region."""
        from utils.Config import Config
        regions = [r for r in (Config.get('REGIONS_SELECTED', []) or [])
                   if r and r != 'GLOBAL']
        return not regions or self.detail.get('_region') == regions[0]

    # 10. RAM sharing with AWS Organizations not enabled
    def _checkRamOrgSharingDisabled(self):
        key = 'ramOrgSharingDisabled'
        if self.orgClient is None or not self._isPrimaryRegion():
            return
        from utils.Config import Config
        accountId = (Config.get('stsInfo', {}) or {}).get('Account')

        try:
            org = self.orgClient.describe_organization().get('Organization', {}) or {}
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if code == 'AWSOrganizationsNotInUseException':
                self.results[key] = [0, "Account is not a member of an AWS Organization"]
            else:
                self.results[key] = [0, f"Unable to evaluate ({code})"]
            return
        isMgmt = bool(accountId) and org.get('MasterAccountId') == accountId

        principals = set()
        try:
            paginator = self.orgClient.get_paginator(
                'list_aws_service_access_for_organization')
            for page in paginator.paginate():
                principals |= {p.get('ServicePrincipal') for p in
                               page.get('EnabledServicePrincipals', []) or []}
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if not isMgmt and code in ('AccessDeniedException', 'AccessDenied'):
                self.results[key] = [0, "Not evaluable from member account"]
            else:
                self.results[key] = [0, f"Unable to evaluate ({code})"]
            return

        if 'ram.amazonaws.com' in principals:
            self.results[key] = [
                1, "AWS RAM trusted access with AWS Organizations is enabled"
            ]
        else:
            self.results[key] = [
                -1,
                "AWS RAM trusted access with AWS Organizations is not enabled — "
                "resources can only be shared with individual accounts by "
                "invitation, not with the organization or its OUs"
            ]

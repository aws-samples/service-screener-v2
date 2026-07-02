import datetime
import fnmatch
import re

from services.Evaluator import Evaluator


class EcrCommon(Evaluator):
    """
    All 20 ECR checks per docs/ecr-checks-research.md.

    Input:
      repo -- dict produced by Ecr.py._hydrateRepo. Keys of interest:
        'repositoryName', 'repositoryArn', 'registryId',
        'imageScanningConfiguration', 'imageTagMutability',
        'encryptionConfiguration',
        '_lifecyclePolicy'   -- parsed lifecycle policy dict, or
                                {'_missing': True} when no policy set, or
                                None on lookup error
        '_repositoryPolicy'  -- parsed access policy dict or None
        '_images'            -- list of describe_images imageDetails (bounded)
        '_tagList'           -- list of {'Key','Value'} tags
        '_registryScanningConfig' -- registry scanning config (shared)
        '_replicationRules'       -- replication rules list (shared)
        '_pullThroughCacheRules'  -- pull-through cache rules (shared)
        '_reportRegistryChecks'   -- True only for the first repo per region
        '_ownAccount'             -- caller account id (str)
      ecrClient -- boto3 ecr client (used for describe_image_scan_findings
                    if a deeper look at findings is needed; the summary path
                    in describe_images is sufficient for the current checks).
    """

    STALE_IMAGE_DAYS = 90
    OLD_IMAGE_PUSHED_DAYS = 365
    SCAN_FINDINGS_STALE_DAYS = 30
    MAX_LISTED_IMAGES = 5  # cap for image tags shown in a finding message

    # Recognised scoping condition keys — presence of any indicates the
    # wildcard-principal Allow is at least somewhat constrained.
    SCOPING_CONDITION_KEYS = {
        'aws:SourceAccount', 'aws:SourceArn', 'aws:SourceOwner',
        'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths',
        'aws:PrincipalAccount', 'aws:PrincipalArn',
    }

    def __init__(self, repo, ecrClient):
        super().__init__()
        self.repo = repo
        self.ecrClient = ecrClient

        self._resourceName = repo.get('repositoryName') or 'unknown'
        self.images = repo.get('_images') or []
        self.regScan = repo.get('_registryScanningConfig') or {}
        self.replicationRules = repo.get('_replicationRules') or []
        self.pullThroughRules = repo.get('_pullThroughCacheRules') or []
        self.reportRegistry = bool(repo.get('_reportRegistryChecks'))
        self.ownAccount = repo.get('_ownAccount')

        self.addII('repositoryName', self._resourceName)
        self.addII('repositoryArn', repo.get('repositoryArn', 'N/A'))
        self.addII('registryId', repo.get('registryId', 'N/A'))
        self.addII('imageTagMutability', repo.get('imageTagMutability', 'MUTABLE'))
        enc = repo.get('encryptionConfiguration') or {}
        self.addII('encryptionType', enc.get('encryptionType', 'AES256'))
        self.addII('imageCount', len(self.images))

    # ================================================================== #
    # TIER 1 — Must-Have Checks
    # ================================================================== #

    # ------------------------------------------------------------------ #
    # 1. Image scanning not configured
    # ------------------------------------------------------------------ #
    def _checkEcrScanOnPush(self):
        # Repo-level scanOnPush wins if True. Otherwise consult registry-level
        # scanning rules — a matching rule with SCAN_ON_PUSH or CONTINUOUS_SCAN
        # means the repo IS being scanned on push.
        cfg = self.repo.get('imageScanningConfiguration') or {}
        repoName = self._resourceName
        if cfg.get('scanOnPush'):
            self.results['ecrScanOnPush'] = [1, "scanOnPush=true at repo level"]
            return

        # Fall back to registry-level rules
        for rule in self.regScan.get('rules', []) or []:
            freq = rule.get('scanFrequency', '')
            if freq not in ('SCAN_ON_PUSH', 'CONTINUOUS_SCAN'):
                continue
            for f in rule.get('repositoryFilters', []) or []:
                pattern = f.get('filter', '')
                if not pattern:
                    continue
                # ECR filters use simple wildcards (* and ?) — fnmatch matches.
                if fnmatch.fnmatchcase(repoName, pattern):
                    self.results['ecrScanOnPush'] = [
                        1,
                        f"Registry rule '{pattern}' covers repo with scanFrequency={freq}"
                    ]
                    return

        self.results['ecrScanOnPush'] = [
            -1,
            "scanOnPush=false and no registry-level SCAN_ON_PUSH/CONTINUOUS_SCAN rule matches"
        ]

    # ------------------------------------------------------------------ #
    # 2. Tag immutability not enabled
    # ------------------------------------------------------------------ #
    def _checkEcrTagImmutability(self):
        mut = self.repo.get('imageTagMutability', 'MUTABLE')
        if mut in ('IMMUTABLE', 'IMMUTABLE_WITH_EXCLUSION'):
            self.results['ecrTagImmutability'] = [
                1, f"imageTagMutability={mut}"
            ]
        elif mut == 'MUTABLE_WITH_EXCLUSION':
            # Partial protection — worth flagging as advisory.
            self.results['ecrTagImmutability'] = [
                0, "imageTagMutability=MUTABLE_WITH_EXCLUSION (partial protection)"
            ]
        else:
            self.results['ecrTagImmutability'] = [
                -1, f"imageTagMutability={mut} (tags can be overwritten)"
            ]

    # ------------------------------------------------------------------ #
    # 3. No lifecycle policy configured
    # ------------------------------------------------------------------ #
    def _checkEcrLifecyclePolicy(self):
        lcp = self.repo.get('_lifecyclePolicy')
        if isinstance(lcp, dict) and lcp.get('_missing'):
            self.results['ecrLifecyclePolicy'] = [
                -1, "No lifecycle policy configured"
            ]
        elif lcp is None:
            # Lookup failed (access denied etc.) — treat as INFO
            self.results['ecrLifecyclePolicy'] = [
                0, "Could not evaluate lifecycle policy (access denied or error)"
            ]
        else:
            rules = lcp.get('rules', []) if isinstance(lcp, dict) else []
            self.results['ecrLifecyclePolicy'] = [
                1, f"Lifecycle policy present with {len(rules)} rule(s)"
            ]

    # ------------------------------------------------------------------ #
    # 4. Not encrypted with KMS CMK
    # ------------------------------------------------------------------ #
    def _checkEcrEncryptionKms(self):
        enc = self.repo.get('encryptionConfiguration') or {}
        encType = enc.get('encryptionType', 'AES256')

        if encType == 'AES256':
            self.results['ecrEncryptionKms'] = [
                -1, "encryptionType=AES256 (no customer-managed key)"
            ]
            return

        if encType in ('KMS', 'KMS_DSSE'):
            kmsKey = enc.get('kmsKey', '') or ''
            if 'alias/aws/ecr' in kmsKey or not kmsKey:
                # AWS-managed key — still KMS but not a CMK
                self.results['ecrEncryptionKms'] = [
                    0,
                    f"encryptionType={encType} using AWS-managed key ({kmsKey or 'default'})"
                ]
            else:
                self.results['ecrEncryptionKms'] = [
                    1, f"encryptionType={encType} with CMK: {kmsKey}"
                ]
        else:
            self.results['ecrEncryptionKms'] = [
                -1, f"Unknown encryptionType={encType}"
            ]

    # ------------------------------------------------------------------ #
    # 5. Images with CRITICAL vulnerabilities
    # ------------------------------------------------------------------ #
    def _checkEcrCriticalVulnerabilities(self):
        offenders = []
        total = 0
        for img in self.images:
            summary = img.get('imageScanFindingsSummary') or {}
            counts = summary.get('findingSeverityCounts') or {}
            c = int(counts.get('CRITICAL', 0) or 0)
            if c > 0:
                total += c
                label = self._imageLabel(img)
                offenders.append(f"{label}({c})")

        if offenders:
            self.results['ecrCriticalVulnerabilities'] = [
                -1,
                f"{len(offenders)} image(s) with CRITICAL findings ({total} total): "
                + self._truncateList(offenders)
            ]
        else:
            self.results['ecrCriticalVulnerabilities'] = [
                1, "No images with CRITICAL findings"
            ]

    # ------------------------------------------------------------------ #
    # 6. Images with HIGH vulnerabilities
    # ------------------------------------------------------------------ #
    def _checkEcrHighVulnerabilities(self):
        offenders = []
        total = 0
        for img in self.images:
            summary = img.get('imageScanFindingsSummary') or {}
            counts = summary.get('findingSeverityCounts') or {}
            c = int(counts.get('HIGH', 0) or 0)
            if c > 0:
                total += c
                label = self._imageLabel(img)
                offenders.append(f"{label}({c})")

        if offenders:
            self.results['ecrHighVulnerabilities'] = [
                -1,
                f"{len(offenders)} image(s) with HIGH findings ({total} total): "
                + self._truncateList(offenders)
            ]
        else:
            self.results['ecrHighVulnerabilities'] = [
                1, "No images with HIGH findings"
            ]

    # ================================================================== #
    # TIER 2 — High-Value Checks
    # ================================================================== #

    # ------------------------------------------------------------------ #
    # 7. Registry not using Enhanced scanning (Inspector)
    # ------------------------------------------------------------------ #
    def _checkEcrEnhancedScanning(self):
        if not self.reportRegistry:
            self.results['ecrEnhancedScanning'] = [
                0, "Registry-level finding — see the first repository in the region"
            ]
            return

        scanType = self.regScan.get('scanType', 'BASIC')
        if scanType == 'ENHANCED':
            self.results['ecrEnhancedScanning'] = [
                1, "Registry scanType=ENHANCED (Amazon Inspector)"
            ]
        else:
            self.results['ecrEnhancedScanning'] = [
                -1, f"Registry scanType={scanType} (basic Clair only)"
            ]

    # ------------------------------------------------------------------ #
    # 8. No continuous scan rule
    # ------------------------------------------------------------------ #
    def _checkEcrScanFrequency(self):
        if not self.reportRegistry:
            self.results['ecrScanFrequency'] = [
                0, "Registry-level finding — see the first repository in the region"
            ]
            return

        rules = self.regScan.get('rules', []) or []
        hasContinuous = any(r.get('scanFrequency') == 'CONTINUOUS_SCAN' for r in rules)
        if hasContinuous:
            self.results['ecrScanFrequency'] = [
                1, "At least one registry rule uses CONTINUOUS_SCAN"
            ]
        else:
            self.results['ecrScanFrequency'] = [
                -1,
                "No registry rule with scanFrequency=CONTINUOUS_SCAN "
                "(newly-disclosed CVEs in existing images will not surface until re-push)"
            ]

    # ------------------------------------------------------------------ #
    # 9. Repository policy allows public access
    # ------------------------------------------------------------------ #
    def _checkEcrRepoPublicAccess(self):
        policy = self.repo.get('_repositoryPolicy')
        if policy is None:
            self.results['ecrRepoPublicAccess'] = [
                1, "No repository policy — no external Allow statements"
            ]
            return

        offenders = []
        for i, stmt in enumerate(self._policyStatements(policy)):
            if stmt.get('Effect') != 'Allow':
                continue
            if not self._principalIsWildcard(stmt.get('Principal')):
                continue
            sid = stmt.get('Sid', f"stmt{i}")
            if not self._conditionScopes(stmt.get('Condition')):
                offenders.append(f"{sid}(unrestricted)")
            else:
                offenders.append(f"{sid}(conditioned)")

        if not offenders:
            self.results['ecrRepoPublicAccess'] = [
                1, "No wildcard-principal Allow statements"
            ]
        else:
            unrestricted = [o for o in offenders if 'unrestricted' in o]
            if unrestricted:
                self.results['ecrRepoPublicAccess'] = [
                    -1,
                    "Wildcard Principal Allow without scoping Condition: "
                    + ", ".join(unrestricted[:5])
                ]
            else:
                self.results['ecrRepoPublicAccess'] = [
                    0,
                    "Wildcard Principal Allow with scoping Condition (review): "
                    + ", ".join(offenders[:5])
                ]

    # ------------------------------------------------------------------ #
    # 10. Broad cross-account access
    # ------------------------------------------------------------------ #
    def _checkEcrRepoCrossAccount(self):
        policy = self.repo.get('_repositoryPolicy')
        if policy is None:
            self.results['ecrRepoCrossAccount'] = [
                1, "No repository policy"
            ]
            return

        owner = self._repoOwner()
        if not owner:
            self.results['ecrRepoCrossAccount'] = [
                0, "Could not determine repo owner account"
            ]
            return

        offenders = []
        for i, stmt in enumerate(self._policyStatements(policy)):
            if stmt.get('Effect') != 'Allow':
                continue
            # Wildcard principals are handled by #9 — skip here.
            if self._principalIsWildcard(stmt.get('Principal')):
                continue
            externals = self._externalAccountsInPrincipal(stmt.get('Principal'), owner)
            if not externals:
                continue
            # If the statement has a tight PrincipalOrgID condition it's
            # acceptable; otherwise flag.
            if self._hasPrincipalOrgIDCondition(stmt.get('Condition')):
                continue
            sid = stmt.get('Sid', f"stmt{i}")
            offenders.append(f"{sid}({','.join(sorted(externals)[:3])})")

        if offenders:
            self.results['ecrRepoCrossAccount'] = [
                -1,
                "Cross-account Allow without aws:PrincipalOrgID: "
                + "; ".join(offenders[:5])
            ]
        else:
            self.results['ecrRepoCrossAccount'] = [
                1, "No unrestricted cross-account Allow statements"
            ]

    # ------------------------------------------------------------------ #
    # 11. Untagged images present
    # ------------------------------------------------------------------ #
    def _checkEcrUntaggedImages(self):
        untagged = [img for img in self.images if not (img.get('imageTags') or [])]
        if untagged:
            self.results['ecrUntaggedImages'] = [
                -1,
                f"{len(untagged)} untagged image(s) present "
                f"(possible orphaned layers / cleanup candidates)"
            ]
        else:
            self.results['ecrUntaggedImages'] = [
                1, "No untagged images"
            ]

    # ------------------------------------------------------------------ #
    # 12. Images not pulled in STALE_IMAGE_DAYS+ days
    # ------------------------------------------------------------------ #
    def _checkEcrStaleImages(self):
        if not self.images:
            self.results['ecrStaleImages'] = [
                0, "No images in repository"
            ]
            return

        threshold = self._utcNow() - datetime.timedelta(days=self.STALE_IMAGE_DAYS)
        stale = []
        for img in self.images:
            lastPull = img.get('lastRecordedPullTime')
            lastPull = self._toUtc(lastPull)
            if lastPull is None or lastPull < threshold:
                stale.append(self._imageLabel(img))

        if stale:
            self.results['ecrStaleImages'] = [
                -1,
                f"{len(stale)} image(s) not pulled in {self.STALE_IMAGE_DAYS}+ days: "
                + self._truncateList(stale)
            ]
        else:
            self.results['ecrStaleImages'] = [
                1, f"All images pulled within {self.STALE_IMAGE_DAYS} days"
            ]

    # ------------------------------------------------------------------ #
    # 13. Images with no scan results
    # ------------------------------------------------------------------ #
    def _checkEcrImageNeverScanned(self):
        if not self.images:
            self.results['ecrImageNeverScanned'] = [
                0, "No images in repository"
            ]
            return

        bad = []
        BAD_STATUSES = {'FAILED', 'UNSUPPORTED_IMAGE', 'SCAN_ELIGIBILITY_EXPIRED'}
        for img in self.images:
            scanStatus = (img.get('imageScanStatus') or {}).get('status')
            if scanStatus is None or scanStatus in BAD_STATUSES:
                bad.append(f"{self._imageLabel(img)}[{scanStatus or 'none'}]")

        if bad:
            self.results['ecrImageNeverScanned'] = [
                -1,
                f"{len(bad)} image(s) without usable scan results: "
                + self._truncateList(bad)
            ]
        else:
            self.results['ecrImageNeverScanned'] = [
                1, f"All {len(self.images)} image(s) have completed scans"
            ]

    # ------------------------------------------------------------------ #
    # 14. No cross-region/cross-account replication configured
    # ------------------------------------------------------------------ #
    def _checkEcrReplicationNotConfigured(self):
        if not self.reportRegistry:
            self.results['ecrReplicationNotConfigured'] = [
                0, "Registry-level finding — see the first repository in the region"
            ]
            return

        if self.replicationRules:
            self.results['ecrReplicationNotConfigured'] = [
                1, f"{len(self.replicationRules)} replication rule(s) configured"
            ]
        else:
            self.results['ecrReplicationNotConfigured'] = [
                -1, "No registry replication configuration set"
            ]

    # ================================================================== #
    # TIER 3 — Nice-to-Have Checks
    # ================================================================== #

    # ------------------------------------------------------------------ #
    # 15. No pull-through cache rules configured
    # ------------------------------------------------------------------ #
    def _checkEcrPullThroughCache(self):
        if not self.reportRegistry:
            self.results['ecrPullThroughCache'] = [
                0, "Registry-level finding — see the first repository in the region"
            ]
            return

        if self.pullThroughRules:
            self.results['ecrPullThroughCache'] = [
                1, f"{len(self.pullThroughRules)} pull-through cache rule(s) configured"
            ]
        else:
            self.results['ecrPullThroughCache'] = [
                -1,
                "No pull-through cache rules "
                "(depending on external registries like Docker Hub)"
            ]

    # ------------------------------------------------------------------ #
    # 16. Very old images (pushed > OLD_IMAGE_PUSHED_DAYS + never/rarely pulled)
    # ------------------------------------------------------------------ #
    def _checkEcrImageAge(self):
        if not self.images:
            self.results['ecrImageAge'] = [
                0, "No images in repository"
            ]
            return

        pushedThreshold = self._utcNow() - datetime.timedelta(days=self.OLD_IMAGE_PUSHED_DAYS)
        pullThreshold = self._utcNow() - datetime.timedelta(days=self.STALE_IMAGE_DAYS)
        old = []
        for img in self.images:
            pushed = self._toUtc(img.get('imagePushedAt'))
            lastPull = self._toUtc(img.get('lastRecordedPullTime'))
            if pushed and pushed < pushedThreshold:
                if lastPull is None or lastPull < pullThreshold:
                    old.append(self._imageLabel(img))

        if old:
            self.results['ecrImageAge'] = [
                -1,
                f"{len(old)} image(s) older than {self.OLD_IMAGE_PUSHED_DAYS}d "
                f"and not pulled recently: " + self._truncateList(old)
            ]
        else:
            self.results['ecrImageAge'] = [
                1, "No very-old, un-pulled images"
            ]

    # ------------------------------------------------------------------ #
    # 17. Public repository / general tagging governance
    #
    # For private-registry repos we check that the repo has any tags at all —
    # this doubles as the ECR.4 governance signal for public repos and as a
    # generic "resources without tags" check for private ones.
    # ------------------------------------------------------------------ #
    def _checkEcrPublicRepoTagging(self):
        tags = self.repo.get('_tagList') or []
        if not tags:
            self.results['ecrPublicRepoTagging'] = [
                -1, "No tags applied to repository"
            ]
        else:
            keys = [t.get('Key') for t in tags if t.get('Key')]
            self.results['ecrPublicRepoTagging'] = [
                1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
            ]

    # ------------------------------------------------------------------ #
    # 18. Not using KMS_DSSE (dual-layer encryption)
    # ------------------------------------------------------------------ #
    def _checkEcrKmsDsseEncryption(self):
        enc = self.repo.get('encryptionConfiguration') or {}
        encType = enc.get('encryptionType', 'AES256')
        if encType == 'KMS_DSSE':
            self.results['ecrKmsDsseEncryption'] = [
                1, "encryptionType=KMS_DSSE (dual-layer)"
            ]
        else:
            # This is informational — most orgs won't need KMS_DSSE.
            self.results['ecrKmsDsseEncryption'] = [
                0,
                f"encryptionType={encType} (KMS_DSSE not in use — advisory only "
                "for regulated workloads)"
            ]

    # ------------------------------------------------------------------ #
    # 19. Lifecycle policy present but missing key cleanup rules
    # ------------------------------------------------------------------ #
    def _checkEcrLifecyclePolicyEffectiveness(self):
        lcp = self.repo.get('_lifecyclePolicy')
        if lcp is None or (isinstance(lcp, dict) and lcp.get('_missing')):
            # Missing entirely — flagged by #3, defer here.
            self.results['ecrLifecyclePolicyEffectiveness'] = [
                0,
                "No lifecycle policy to evaluate — see ecrLifecyclePolicy"
            ]
            return

        rules = lcp.get('rules', []) if isinstance(lcp, dict) else []
        hasUntaggedCleanup = False
        hasAgeCleanup = False
        for r in rules:
            sel = r.get('selection') or {}
            if sel.get('tagStatus') == 'untagged':
                hasUntaggedCleanup = True
            if sel.get('countType') == 'sinceImagePushed':
                hasAgeCleanup = True

        gaps = []
        if not hasUntaggedCleanup:
            gaps.append("no untagged cleanup rule")
        if not hasAgeCleanup:
            gaps.append("no age-based cleanup rule")

        if gaps:
            self.results['ecrLifecyclePolicyEffectiveness'] = [
                -1,
                "Lifecycle policy present but " + " and ".join(gaps)
            ]
        else:
            self.results['ecrLifecyclePolicyEffectiveness'] = [
                1, "Lifecycle policy has both untagged and age-based cleanup rules"
            ]

    # ------------------------------------------------------------------ #
    # 20. Scan results older than SCAN_FINDINGS_STALE_DAYS days
    # ------------------------------------------------------------------ #
    def _checkEcrScanFindingsStale(self):
        if not self.images:
            self.results['ecrScanFindingsStale'] = [
                0, "No images in repository"
            ]
            return

        threshold = self._utcNow() - datetime.timedelta(days=self.SCAN_FINDINGS_STALE_DAYS)
        stale = []
        for img in self.images:
            summary = img.get('imageScanFindingsSummary') or {}
            completed = self._toUtc(summary.get('imageScanCompletedAt'))
            if completed is not None and completed < threshold:
                stale.append(self._imageLabel(img))

        if stale:
            self.results['ecrScanFindingsStale'] = [
                -1,
                f"{len(stale)} image(s) with scan results older than "
                f"{self.SCAN_FINDINGS_STALE_DAYS}d: " + self._truncateList(stale)
            ]
        else:
            self.results['ecrScanFindingsStale'] = [
                1,
                f"No image(s) with scan results older than "
                f"{self.SCAN_FINDINGS_STALE_DAYS}d"
            ]

    # ================================================================== #
    # Helpers
    # ================================================================== #

    def _repoOwner(self):
        # ECR describe_repositories returns 'registryId' which is the owner
        # account id. Fallback to the caller account for standalone runs.
        return self.repo.get('registryId') or self.ownAccount

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
    def _accountFromPrincipalValue(v):
        if not isinstance(v, str) or v == '*':
            return None
        if v.isdigit() and len(v) == 12:
            return v
        if ':iam::' in v:
            tail = v.split(':iam::', 1)[1]
            acct = tail.split(':', 1)[0]
            if acct.isdigit() and len(acct) == 12:
                return acct
        return None

    @classmethod
    def _externalAccountsInPrincipal(cls, principal, owner):
        accts = set()
        if principal is None or principal == '*':
            return accts
        if isinstance(principal, str):
            a = cls._accountFromPrincipalValue(principal)
            if a and a != owner:
                accts.add(a)
            return accts
        if isinstance(principal, dict):
            for v in principal.values():
                if isinstance(v, str):
                    a = cls._accountFromPrincipalValue(v)
                    if a and a != owner:
                        accts.add(a)
                elif isinstance(v, list):
                    for item in v:
                        a = cls._accountFromPrincipalValue(item)
                        if a and a != owner:
                            accts.add(a)
        return accts

    @staticmethod
    def _hasPrincipalOrgIDCondition(condition):
        if not condition or not isinstance(condition, dict):
            return False
        for op_block in condition.values():
            if isinstance(op_block, dict) and 'aws:PrincipalOrgID' in op_block:
                return True
        return False

    @staticmethod
    def _utcNow():
        return datetime.datetime.now(datetime.timezone.utc)

    @staticmethod
    def _toUtc(val):
        if val is None:
            return None
        if isinstance(val, datetime.datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=datetime.timezone.utc)
            return val
        if isinstance(val, str):
            try:
                parsed = datetime.datetime.fromisoformat(val.replace('Z', '+00:00'))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=datetime.timezone.utc)
                return parsed
            except (ValueError, TypeError):
                return None
        return None

    @staticmethod
    def _imageLabel(img):
        tags = img.get('imageTags') or []
        if tags:
            return tags[0]
        digest = img.get('imageDigest', '') or ''
        # Trim the sha256: prefix + long hash for readability.
        if digest.startswith('sha256:'):
            return digest[:14] + '...'
        return digest[:12] + '...' if digest else '<untagged>'

    def _truncateList(self, items):
        head = items[:self.MAX_LISTED_IMAGES]
        extra = len(items) - len(head)
        s = ', '.join(head)
        if extra > 0:
            s += f" (+{extra} more)"
        return s

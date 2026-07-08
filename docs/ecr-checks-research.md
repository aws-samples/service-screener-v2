# Amazon ECR — Programmatic Security Checks for Service-Screener-v2

## Executive Summary

This document enumerates **all programmatically checkable configurations** for Amazon ECR (private & public registries) using `boto3` clients `ecr` and `ecr-public`. Each check includes the API call, FAIL condition, severity, Well-Architected pillar, and usefulness rating.

---

## API Surface Available

| Client | Key APIs | Scope |
|--------|----------|-------|
| `ecr` | `describe_repositories`, `get_lifecycle_policy`, `get_repository_policy`, `describe_images`, `describe_image_scan_findings`, `get_registry_scanning_configuration`, `describe_registry`, `describe_pull_through_cache_rules` | Private registry |
| `ecr-public` | `describe_repositories`, `describe_images`, `list_tags_for_resource` | Public registry |

---

## TIER 1 — Must-Have Checks (Security Hub Parity + High-Value Security)

These align with AWS Security Hub controls and represent the minimum viable check set.

| # | Check ID | Check Name | API Call(s) | FAIL Condition | Severity | Pillar | SH Control | Usefulness |
|---|----------|-----------|-------------|----------------|----------|--------|------------|------------|
| 1 | `ecrScanOnPush` | Image scanning not configured | `describe_repositories` → `imageScanningConfiguration.scanOnPush` | `scanOnPush == False` | **HIGH** | Security | ECR.1 | ⭐⭐⭐⭐⭐ |
| 2 | `ecrTagImmutability` | Tag immutability not enabled | `describe_repositories` → `imageTagMutability` | `imageTagMutability == 'MUTABLE'` | **MEDIUM** | Security | ECR.2 | ⭐⭐⭐⭐⭐ |
| 3 | `ecrLifecyclePolicy` | No lifecycle policy configured | `get_lifecycle_policy(repositoryName=X)` | Raises `LifecyclePolicyNotFoundException` | **MEDIUM** | Cost Optimization | ECR.3 | ⭐⭐⭐⭐⭐ |
| 4 | `ecrEncryptionKms` | Repository not encrypted with KMS CMK | `describe_repositories` → `encryptionConfiguration` | `encryptionType == 'AES256'` (no CMK) | **MEDIUM** | Security | ECR.5 | ⭐⭐⭐⭐ |
| 5 | `ecrCriticalVulnerabilities` | Images with CRITICAL vulnerabilities | `describe_images` → `imageScanFindingsSummary.findingSeverityCounts` | `findingSeverityCounts['CRITICAL'] > 0` | **CRITICAL** | Security | — | ⭐⭐⭐⭐⭐ |
| 6 | `ecrHighVulnerabilities` | Images with HIGH vulnerabilities | `describe_images` → `imageScanFindingsSummary.findingSeverityCounts` | `findingSeverityCounts['HIGH'] > 0` | **HIGH** | Security | — | ⭐⭐⭐⭐⭐ |

---

## TIER 2 — High-Value Checks (Best Practice & Operational Excellence)

| # | Check ID | Check Name | API Call(s) | FAIL Condition | Severity | Pillar | Usefulness |
|---|----------|-----------|-------------|----------------|----------|--------|------------|
| 7 | `ecrEnhancedScanning` | Registry not using Enhanced scanning (Inspector) | `get_registry_scanning_configuration` → `scanningConfiguration` | `scanType == 'BASIC'` (not `'ENHANCED'`) | **MEDIUM** | Security | ⭐⭐⭐⭐ |
| 8 | `ecrScanFrequency` | Scanning not set to continuous | `get_registry_scanning_configuration` → `rules[].scanFrequency` | No rule with `scanFrequency == 'CONTINUOUS_SCAN'` | **LOW** | Security | ⭐⭐⭐ |
| 9 | `ecrRepoPublicAccess` | Repository policy allows public access | `get_repository_policy(repositoryName=X)` → parse JSON policyText | Policy contains `"Principal": "*"` or `"Principal": {"AWS": "*"}` without `Condition` restrictions | **CRITICAL** | Security | ⭐⭐⭐⭐⭐ |
| 10 | `ecrRepoCrossAccount` | Repository policy allows broad cross-account access | `get_repository_policy(repositoryName=X)` → parse JSON policyText | Policy `Principal` references external account IDs without tight `Condition` constraints | **HIGH** | Security | ⭐⭐⭐⭐ |
| 11 | `ecrUntaggedImages` | Repository contains untagged images (cleanup candidates) | `describe_images(repositoryName=X, filter={'tagStatus':'UNTAGGED'})` | Count of untagged images > 0 | **LOW** | Cost Optimization | ⭐⭐⭐⭐ |
| 12 | `ecrStaleImages` | Images not pulled in 90+ days | `describe_images` → `lastRecordedPullTime` | `lastRecordedPullTime` is older than 90 days (or `None` = never pulled) | **LOW** | Cost Optimization | ⭐⭐⭐⭐ |
| 13 | `ecrImageNeverScanned` | Images with no scan results | `describe_images` → `imageScanStatus` | `imageScanStatus` is `None` or status in (`'FAILED'`, `'UNSUPPORTED_IMAGE'`, `'SCAN_ELIGIBILITY_EXPIRED'`) | **MEDIUM** | Security | ⭐⭐⭐⭐ |
| 14 | `ecrReplicationNotConfigured` | No cross-region/cross-account replication | `describe_registry` → `replicationConfiguration.rules` | `rules` is empty list `[]` | **LOW** | Reliability | ⭐⭐⭐ |

---

## TIER 3 — Nice-to-Have Checks (Operational / Informational)

| # | Check ID | Check Name | API Call(s) | FAIL Condition | Severity | Pillar | Usefulness |
|---|----------|-----------|-------------|----------------|----------|--------|------------|
| 15 | `ecrPullThroughCache` | No pull-through cache rules configured | `describe_pull_through_cache_rules` | `pullThroughCacheRules` is empty list | **LOW** | Operational Excellence | ⭐⭐⭐ |
| 16 | `ecrImageAge` | Very old images (pushed > 365 days, never pulled) | `describe_images` → `imagePushedAt`, `lastRecordedPullTime` | `imagePushedAt` > 365 days ago AND (`lastRecordedPullTime` is None OR > 90 days) | **LOW** | Cost Optimization | ⭐⭐⭐ |
| 17 | `ecrPublicRepoTagging` | Public repository missing required tags | `ecr-public` → `list_tags_for_resource(resourceArn=X)` | No tags present (or missing expected keys) | **LOW** | Operational Excellence | ⭐⭐ |
| 18 | `ecrKmsDsseEncryption` | Repository not using KMS_DSSE (dual-layer encryption) | `describe_repositories` → `encryptionConfiguration.encryptionType` | `encryptionType != 'KMS_DSSE'` | **LOW** | Security | ⭐⭐ |
| 19 | `ecrLifecyclePolicyEffectiveness` | Lifecycle policy exists but no cleanup rules for untagged | `get_lifecycle_policy` → parse JSON rules | No rule targeting `tagStatus: untagged` or `countType: sinceImagePushed` | **LOW** | Cost Optimization | ⭐⭐⭐ |
| 20 | `ecrScanFindingsStale` | Scan results older than 30 days | `describe_images` → `imageScanFindingsSummary.imageScanCompletedAt` | `imageScanCompletedAt` > 30 days ago | **LOW** | Security | ⭐⭐⭐ |

---

## Detailed Check Specifications

### 1. `ecrScanOnPush` — Image Scanning Not Configured

```python
# API Call
response = ecr.describe_repositories()

# Check Logic
for repo in response['repositories']:
    scan_config = repo.get('imageScanningConfiguration', {})
    if not scan_config.get('scanOnPush', False):
        # FAIL — Also check registry-level scanning config
        reg_scan = ecr.get_registry_scanning_configuration()
        scan_type = reg_scan['scanningConfiguration']['scanType']
        rules = reg_scan['scanningConfiguration'].get('rules', [])
        
        # A repo passes if registry-level rules cover it with SCAN_ON_PUSH or CONTINUOUS_SCAN
        repo_covered = False
        for rule in rules:
            if rule['scanFrequency'] in ('SCAN_ON_PUSH', 'CONTINUOUS_SCAN'):
                for f in rule.get('repositoryFilters', []):
                    if matches_wildcard(f['filter'], repo['repositoryName']):
                        repo_covered = True
        
        if not repo_covered:
            flag_fail(repo['repositoryName'])
```

**Why**: Unscanned images may contain known CVEs deployed to production. ECR.1 equivalent.

---

### 2. `ecrTagImmutability` — Tag Immutability Not Enabled

```python
# API Call
response = ecr.describe_repositories()

# Check Logic
for repo in response['repositories']:
    if repo['imageTagMutability'] == 'MUTABLE':
        flag_fail(repo['repositoryName'])
    # Note: 'MUTABLE_WITH_EXCLUSION' should be flagged as INFO (partial protection)
    # Note: 'IMMUTABLE_WITH_EXCLUSION' is acceptable
```

**Why**: Mutable tags allow tag overwriting (e.g., replacing `latest` with a malicious image). ECR.2 equivalent.

---

### 3. `ecrLifecyclePolicy` — No Lifecycle Policy

```python
# API Call (per repository)
for repo in repos:
    try:
        ecr.get_lifecycle_policy(repositoryName=repo['repositoryName'])
    except ecr.exceptions.LifecyclePolicyNotFoundException:
        flag_fail(repo['repositoryName'])
```

**Why**: Without lifecycle policies, old/unused images accumulate, increasing costs and attack surface. ECR.3 equivalent.

---

### 4. `ecrEncryptionKms` — Not Encrypted with KMS CMK

```python
# API Call
response = ecr.describe_repositories()

# Check Logic
for repo in response['repositories']:
    enc = repo.get('encryptionConfiguration', {})
    enc_type = enc.get('encryptionType', 'AES256')
    
    if enc_type == 'AES256':
        flag_fail(repo['repositoryName'])  # No CMK control
    elif enc_type == 'KMS':
        kms_key = enc.get('kmsKey', '')
        if 'alias/aws/ecr' in kms_key or not kms_key:
            flag_info(repo['repositoryName'])  # AWS-managed key, not customer-managed
```

**Why**: KMS CMK provides key rotation control, audit trail via CloudTrail, and ability to revoke access. ECR.5 equivalent.

---

### 5–6. `ecrCriticalVulnerabilities` / `ecrHighVulnerabilities` — Vulnerable Images

```python
# API Call
for repo in repos:
    images = ecr.describe_images(repositoryName=repo['repositoryName'])
    for image in images['imageDetails']:
        summary = image.get('imageScanFindingsSummary', {})
        counts = summary.get('findingSeverityCounts', {})
        
        critical = counts.get('CRITICAL', 0)
        high = counts.get('HIGH', 0)
        
        if critical > 0:
            flag_critical(repo['repositoryName'], image.get('imageTags', []), critical)
        if high > 0:
            flag_high(repo['repositoryName'], image.get('imageTags', []), high)

# For detailed findings (optional, expensive):
# ecr.describe_image_scan_findings(repositoryName=X, imageId={'imageDigest': Y})
```

**Why**: Images with known CRITICAL/HIGH CVEs represent active exploitable risk in running workloads.

---

### 7. `ecrEnhancedScanning` — Not Using Enhanced Scanning

```python
# API Call
response = ecr.get_registry_scanning_configuration()
scan_config = response['scanningConfiguration']

if scan_config['scanType'] == 'BASIC':
    flag_fail()  # Registry-level finding
```

**Why**: Enhanced scanning (via Amazon Inspector) provides continuous monitoring, OS + language package scanning, and integration with Security Hub. Basic scanning only checks on push with Clair.

---

### 8. `ecrScanFrequency` — No Continuous Scan Rule

```python
# API Call
response = ecr.get_registry_scanning_configuration()
rules = response['scanningConfiguration'].get('rules', [])

has_continuous = any(r['scanFrequency'] == 'CONTINUOUS_SCAN' for r in rules)
if not has_continuous:
    flag_info()  # Only scan-on-push, no continuous monitoring
```

**Why**: CONTINUOUS_SCAN catches newly-disclosed CVEs in already-pushed images.

---

### 9. `ecrRepoPublicAccess` — Repository Policy Allows Public Access

```python
import json

for repo in repos:
    try:
        policy_resp = ecr.get_repository_policy(repositoryName=repo['repositoryName'])
        policy = json.loads(policy_resp['policyText'])
        
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                # Check for wildcard principal
                if principal == '*' or principal == {'AWS': '*'}:
                    # Check if Condition constrains it
                    if 'Condition' not in statement:
                        flag_critical(repo['repositoryName'])
                    else:
                        flag_high(repo['repositoryName'])  # Conditioned but still broad
    except ecr.exceptions.RepositoryPolicyNotFoundException:
        pass  # No policy = no external access = OK
```

**Why**: Public access to private ECR repos exposes container images (potentially with secrets/proprietary code) to anyone.

---

### 10. `ecrRepoCrossAccount` — Broad Cross-Account Access

```python
import json, re

ACCOUNT_ID_PATTERN = re.compile(r'\d{12}')
own_account = sts.get_caller_identity()['Account']

for repo in repos:
    try:
        policy_resp = ecr.get_repository_policy(repositoryName=repo['repositoryName'])
        policy = json.loads(policy_resp['policyText'])
        
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principals = extract_principals(statement.get('Principal', {}))
                external_accounts = [p for p in principals 
                                    if ACCOUNT_ID_PATTERN.search(p) 
                                    and own_account not in p]
                if external_accounts:
                    flag_medium(repo['repositoryName'], external_accounts)
    except ecr.exceptions.RepositoryPolicyNotFoundException:
        pass
```

**Why**: Overly broad cross-account access increases blast radius if partner accounts are compromised.

---

### 11. `ecrUntaggedImages` — Untagged Images Present

```python
for repo in repos:
    images = ecr.describe_images(
        repositoryName=repo['repositoryName'],
        filter={'tagStatus': 'UNTAGGED'}
    )
    untagged_count = len(images['imageDetails'])
    if untagged_count > 0:
        flag_low(repo['repositoryName'], count=untagged_count)
```

**Why**: Untagged images are usually orphaned layers from tag overwrites — cost waste and potential confusion.

---

### 12. `ecrStaleImages` — Images Not Pulled in 90+ Days

```python
from datetime import datetime, timedelta, timezone

threshold = datetime.now(timezone.utc) - timedelta(days=90)

for repo in repos:
    images = ecr.describe_images(repositoryName=repo['repositoryName'])
    for image in images['imageDetails']:
        last_pull = image.get('lastRecordedPullTime')
        if last_pull is None or last_pull < threshold:
            flag_low(repo['repositoryName'], image.get('imageTags', [image['imageDigest']]))
```

**Why**: Stale images occupy storage, may have unpatched vulnerabilities, and indicate unused resources.

---

### 13. `ecrImageNeverScanned` — No Scan Results

```python
for repo in repos:
    images = ecr.describe_images(repositoryName=repo['repositoryName'])
    for image in images['imageDetails']:
        scan_status = image.get('imageScanStatus', {}).get('status')
        if scan_status is None or scan_status in ('FAILED', 'UNSUPPORTED_IMAGE', 'SCAN_ELIGIBILITY_EXPIRED'):
            flag_medium(repo['repositoryName'], image.get('imageTags', []))
```

**Why**: Images without scan results have unknown vulnerability posture — blind spots in security coverage.

---

### 14. `ecrReplicationNotConfigured` — No Replication Rules

```python
response = ecr.describe_registry()
rules = response.get('replicationConfiguration', {}).get('rules', [])

if not rules:
    flag_low()  # Registry-level, no cross-region DR for images
```

**Why**: Without replication, a regional outage could prevent image pulls for container deployments.

---

### 15. `ecrPullThroughCache` — No Pull-Through Cache Rules

```python
response = ecr.describe_pull_through_cache_rules()
rules = response.get('pullThroughCacheRules', [])

if not rules:
    flag_info()  # Informational — not a security risk
```

**Why**: Pull-through cache reduces dependency on external registries (Docker Hub rate limits, availability).

---

### 16. `ecrImageAge` — Very Old Images

```python
threshold_pushed = datetime.now(timezone.utc) - timedelta(days=365)
threshold_pull = datetime.now(timezone.utc) - timedelta(days=90)

for repo in repos:
    images = ecr.describe_images(repositoryName=repo['repositoryName'])
    for image in images['imageDetails']:
        pushed = image.get('imagePushedAt')
        last_pull = image.get('lastRecordedPullTime')
        
        if pushed and pushed < threshold_pushed:
            if last_pull is None or last_pull < threshold_pull:
                flag_low(repo['repositoryName'], image.get('imageTags', []))
```

---

### 19. `ecrLifecyclePolicyEffectiveness` — Lifecycle Policy Missing Key Rules

```python
import json

for repo in repos:
    try:
        lcp = ecr.get_lifecycle_policy(repositoryName=repo['repositoryName'])
        policy = json.loads(lcp['lifecyclePolicyText'])
        rules = policy.get('rules', [])
        
        has_untagged_cleanup = any(
            r.get('selection', {}).get('tagStatus') == 'untagged' 
            for r in rules
        )
        has_age_cleanup = any(
            r.get('selection', {}).get('countType') == 'sinceImagePushed'
            for r in rules
        )
        
        if not has_untagged_cleanup:
            flag_info(repo['repositoryName'], "No untagged image cleanup rule")
        if not has_age_cleanup:
            flag_info(repo['repositoryName'], "No age-based cleanup rule")
    except:
        pass  # Already caught by ecrLifecyclePolicy check
```

---

### 20. `ecrScanFindingsStale` — Stale Scan Results

```python
threshold = datetime.now(timezone.utc) - timedelta(days=30)

for repo in repos:
    images = ecr.describe_images(repositoryName=repo['repositoryName'])
    for image in images['imageDetails']:
        summary = image.get('imageScanFindingsSummary', {})
        completed_at = summary.get('imageScanCompletedAt')
        
        if completed_at and completed_at < threshold:
            flag_low(repo['repositoryName'], image.get('imageTags', []))
```

---

## API Rate Limiting & Implementation Notes

### API Call Budget per Repository

| API | Calls Needed | Rate Limit (TPS) | Notes |
|-----|-------------|-------------------|-------|
| `describe_repositories` | 1 (paginated) | 100 | Returns all repo metadata in bulk |
| `get_lifecycle_policy` | 1 per repo | 100 | Must catch exception for "no policy" |
| `get_repository_policy` | 1 per repo | 100 | Must catch exception for "no policy" |
| `describe_images` | 1+ per repo (paginated) | 100 | Can be expensive for repos with 1000s of images |
| `describe_image_scan_findings` | 1 per image | 100 | **Very expensive** — only call for flagged images |
| `get_registry_scanning_configuration` | 1 total | 10 | Registry-level, call once |
| `describe_registry` | 1 total | 10 | Registry-level, call once |
| `describe_pull_through_cache_rules` | 1 total | 100 | Registry-level, call once |

### Recommended Implementation Order

1. **Registry-level calls first** (1 call each): `get_registry_scanning_configuration`, `describe_registry`, `describe_pull_through_cache_rules`
2. **Bulk repository metadata**: `describe_repositories` (paginated, all repos)
3. **Per-repo checks**: `get_lifecycle_policy`, `get_repository_policy` (with exception handling)
4. **Image-level checks**: `describe_images` per repo (expensive — consider sampling for large registries)
5. **Scan findings details**: `describe_image_scan_findings` only for images with CRITICAL/HIGH counts

### Cost-Conscious Scanning Strategy

```python
# For repos with 100+ images, use sampling:
MAX_IMAGES_PER_REPO = 50  # Check most recent 50 images

# For describe_image_scan_findings, only call for:
# - Images that show CRITICAL/HIGH in findingSeverityCounts
# - The "latest" tagged image in each repo
```

---

## Security Hub Control Mapping

| Security Hub Control | Check ID | Match Level |
|---------------------|----------|-------------|
| ECR.1 — Image scanning configured | `ecrScanOnPush` | ✅ Exact |
| ECR.2 — Tag immutability enabled | `ecrTagImmutability` | ✅ Exact |
| ECR.3 — Lifecycle policy configured | `ecrLifecyclePolicy` | ✅ Exact |
| ECR.4 — Public repos should be tagged | `ecrPublicRepoTagging` | ✅ Exact |
| ECR.5 — KMS CMK encryption | `ecrEncryptionKms` | ✅ Exact |

---

## Well-Architected Pillar Mapping

| Pillar | Checks |
|--------|--------|
| **Security** | `ecrScanOnPush`, `ecrTagImmutability`, `ecrEncryptionKms`, `ecrCriticalVulnerabilities`, `ecrHighVulnerabilities`, `ecrEnhancedScanning`, `ecrScanFrequency`, `ecrRepoPublicAccess`, `ecrRepoCrossAccount`, `ecrImageNeverScanned`, `ecrScanFindingsStale`, `ecrKmsDsseEncryption` |
| **Cost Optimization** | `ecrLifecyclePolicy`, `ecrUntaggedImages`, `ecrStaleImages`, `ecrImageAge`, `ecrLifecyclePolicyEffectiveness` |
| **Reliability** | `ecrReplicationNotConfigured` |
| **Operational Excellence** | `ecrPullThroughCache`, `ecrPublicRepoTagging` |

---

## Full Check Summary Table

| # | Check ID | Tier | Severity | Pillar | SH Ctrl | API Complexity | Usefulness |
|---|----------|------|----------|--------|---------|----------------|------------|
| 1 | `ecrScanOnPush` | T1 | HIGH | SEC | ECR.1 | Low | ⭐⭐⭐⭐⭐ |
| 2 | `ecrTagImmutability` | T1 | MEDIUM | SEC | ECR.2 | Low | ⭐⭐⭐⭐⭐ |
| 3 | `ecrLifecyclePolicy` | T1 | MEDIUM | COST | ECR.3 | Low | ⭐⭐⭐⭐⭐ |
| 4 | `ecrEncryptionKms` | T1 | MEDIUM | SEC | ECR.5 | Low | ⭐⭐⭐⭐ |
| 5 | `ecrCriticalVulnerabilities` | T1 | CRITICAL | SEC | — | Med | ⭐⭐⭐⭐⭐ |
| 6 | `ecrHighVulnerabilities` | T1 | HIGH | SEC | — | Med | ⭐⭐⭐⭐⭐ |
| 7 | `ecrEnhancedScanning` | T2 | MEDIUM | SEC | — | Low | ⭐⭐⭐⭐ |
| 8 | `ecrScanFrequency` | T2 | LOW | SEC | — | Low | ⭐⭐⭐ |
| 9 | `ecrRepoPublicAccess` | T2 | CRITICAL | SEC | — | Med | ⭐⭐⭐⭐⭐ |
| 10 | `ecrRepoCrossAccount` | T2 | HIGH | SEC | — | Med | ⭐⭐⭐⭐ |
| 11 | `ecrUntaggedImages` | T2 | LOW | COST | — | Med | ⭐⭐⭐⭐ |
| 12 | `ecrStaleImages` | T2 | LOW | COST | — | Med | ⭐⭐⭐⭐ |
| 13 | `ecrImageNeverScanned` | T2 | MEDIUM | SEC | — | Med | ⭐⭐⭐⭐ |
| 14 | `ecrReplicationNotConfigured` | T2 | LOW | REL | — | Low | ⭐⭐⭐ |
| 15 | `ecrPullThroughCache` | T3 | LOW | OPS | — | Low | ⭐⭐⭐ |
| 16 | `ecrImageAge` | T3 | LOW | COST | — | Med | ⭐⭐⭐ |
| 17 | `ecrPublicRepoTagging` | T3 | LOW | OPS | ECR.4 | Low | ⭐⭐ |
| 18 | `ecrKmsDsseEncryption` | T3 | LOW | SEC | — | Low | ⭐⭐ |
| 19 | `ecrLifecyclePolicyEffectiveness` | T3 | LOW | COST | — | Low | ⭐⭐⭐ |
| 20 | `ecrScanFindingsStale` | T3 | LOW | SEC | — | Med | ⭐⭐⭐ |

---

## Implementation Architecture

```
ECR Scanner
├── Registry-Level (call once)
│   ├── get_registry_scanning_configuration → ecrEnhancedScanning, ecrScanFrequency
│   ├── describe_registry → ecrReplicationNotConfigured
│   └── describe_pull_through_cache_rules → ecrPullThroughCache
│
├── Repository-Level (per repo from describe_repositories)
│   ├── From describe_repositories response:
│   │   ├── imageScanningConfiguration → ecrScanOnPush
│   │   ├── imageTagMutability → ecrTagImmutability
│   │   └── encryptionConfiguration → ecrEncryptionKms, ecrKmsDsseEncryption
│   │
│   ├── get_lifecycle_policy (per repo):
│   │   ├── Exception → ecrLifecyclePolicy
│   │   └── Parse rules → ecrLifecyclePolicyEffectiveness
│   │
│   └── get_repository_policy (per repo):
│       ├── Parse principals → ecrRepoPublicAccess
│       └── Parse principals → ecrRepoCrossAccount
│
└── Image-Level (per repo, paginated describe_images)
    ├── Filter UNTAGGED → ecrUntaggedImages
    ├── lastRecordedPullTime → ecrStaleImages
    ├── imagePushedAt → ecrImageAge
    ├── imageScanStatus → ecrImageNeverScanned
    ├── imageScanFindingsSummary → ecrCriticalVulnerabilities, ecrHighVulnerabilities
    └── imageScanCompletedAt → ecrScanFindingsStale
```

---

## ECR Public Registry Checks (ecr-public client)

| # | Check ID | API | FAIL Condition | Severity |
|---|----------|-----|----------------|----------|
| P1 | `ecrPublicRepoTagging` | `ecr-public.list_tags_for_resource` | No tags | LOW |
| P2 | `ecrPublicRepoDescription` | `ecr-public.describe_repositories` | Missing `repositoryDescription` | LOW |

**Note**: Public ECR repos have limited security controls — they are intentionally public. The main checks are governance/tagging oriented rather than security-focused.

---

## Recommended MVP (Minimum Viable Product) — 8 Checks

For initial service-screener-v2 implementation, prioritize these 8 checks:

1. ✅ `ecrScanOnPush` (ECR.1)
2. ✅ `ecrTagImmutability` (ECR.2)
3. ✅ `ecrLifecyclePolicy` (ECR.3)
4. ✅ `ecrEncryptionKms` (ECR.5)
5. ✅ `ecrEnhancedScanning`
6. ✅ `ecrRepoPublicAccess`
7. ✅ `ecrCriticalVulnerabilities`
8. ✅ `ecrImageNeverScanned`

These cover Security Hub parity, the most critical security risks, and are implementable with moderate API complexity.

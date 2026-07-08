# ECR Simulation Testing

Scripts to create two intentionally-configured ECR repositories that
exercise most of the `ecr*` service-screener checks.

## Resources Created

All prefixed with `ss-test-ecr-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| Standard ECR repo `ss-test-ecr-standard-*` | `scanOnPush=false`, `imageTagMutability=MUTABLE`, `encryptionType=AES256`, no lifecycle policy, wildcard-`*` `Principal` repo policy, no tags | #1 scanOnPush, #2 tagImmutability, #3 lifecyclePolicy (missing), #4 encryptionKms, #9 repoPublicAccess, #17 publicRepoTagging |
| Debian:8 image tagged `:v1` in the standard repo | End-of-life base — surfaces known CVEs on scan | #5 criticalVulnerabilities, #6 highVulnerabilities, #13 imageNeverScanned (until scan completes) |
| Untagged sibling image in the standard repo | Same digest as `:v1` initially tagged `:v2`, then `:v2` tag deleted | #11 untaggedImages |
| Hardened ECR repo `ss-test-ecr-hardened-*` | `scanOnPush=true`, `imageTagMutability=IMMUTABLE`, tags applied, lifecycle policy present **but** rules only cover `tagStatus=tagged` (no untagged, no age) | Passes #1/#2/#17/#3 — fires **#19 lifecyclePolicyEffectiveness** |

## Registry-Level Findings

The following checks are registry-level (per region, not per repo) — they
reflect the account/region baseline configuration and are not modified by
this script. Expect them to FAIL if the region has not been hardened:

| Check | Fires When |
|---|---|
| #7 ecrEnhancedScanning | Registry `scanType=BASIC` (the default) |
| #8 ecrScanFrequency | No registry rule with `scanFrequency=CONTINUOUS_SCAN` |
| #14 ecrReplicationNotConfigured | Registry has no replication rules |
| #15 ecrPullThroughCache | Registry has no pull-through cache rules |

## Cost

Effectively **$0**:
- ECR storage for the small debian:8-based image is a few MB (~$0.01/mo).
- No `docker pull` traffic is generated; the scan is included in ECR pricing.
- Both repos are destroyed by the cleanup script.

## Prerequisites

- AWS CLI configured with credentials that can `ecr:CreateRepository`,
  `ecr:PutLifecyclePolicy`, `ecr:SetRepositoryPolicy`,
  `ecr:BatchDeleteImage`, `ecr:DeleteRepository`.
- Docker daemon running (optional — use `--skip-push` to skip the image push
  step and validate config-only checks).

## Usage

```bash
cd services/ecr/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

# Create resources (default region ap-southeast-1)
./create_test_resources.sh --region ap-southeast-1

# Skip Docker interaction if daemon isn't available
./create_test_resources.sh --region ap-southeast-1 --skip-push

# Wait 1-3 minutes for ECR to complete the image scan (async).

# Run the screener
cd ../../..
python3 main.py --regions ap-southeast-1 --services ecr --beta 1 --sequential 1

# Clean up (uses most-recent manifest by default)
cd services/ecr/simulation
./cleanup_test_resources.sh --force
```

## Coverage

| # | Check | Directly Simulated? | Notes |
|---:|---|---|---|
| 1 | ecrScanOnPush | ✓ FAIL on standard, PASS on hardened |
| 2 | ecrTagImmutability | ✓ FAIL on standard, PASS on hardened |
| 3 | ecrLifecyclePolicy | ✓ FAIL on standard, PASS on hardened |
| 4 | ecrEncryptionKms | ✓ FAIL on standard (AES256), still FAIL on hardened (also AES256 — set to KMS+CMK to pass) |
| 5 | ecrCriticalVulnerabilities | ✓ FAIL once scan completes (depends on debian:8 findings) |
| 6 | ecrHighVulnerabilities | ✓ FAIL once scan completes |
| 7 | ecrEnhancedScanning | ⚠ registry-level, reflects account state |
| 8 | ecrScanFrequency | ⚠ registry-level, reflects account state |
| 9 | ecrRepoPublicAccess | ✓ FAIL on standard, PASS on hardened |
| 10 | ecrRepoCrossAccount | ✗ not simulated (needs a real external account ID; would fire without one via wildcard, but that's #9 territory) |
| 11 | ecrUntaggedImages | ✓ FAIL on standard when Step 3 succeeded |
| 12 | ecrStaleImages | ✗ not simulated (requires images > 90d old — outside a one-shot script) |
| 13 | ecrImageNeverScanned | ✓ FAIL until scan completes (transient) |
| 14 | ecrReplicationNotConfigured | ⚠ registry-level, reflects account state |
| 15 | ecrPullThroughCache | ⚠ registry-level, reflects account state |
| 16 | ecrImageAge | ✗ not simulated (requires images > 365d old) |
| 17 | ecrPublicRepoTagging | ✓ FAIL on standard (no tags), PASS on hardened |
| 18 | ecrKmsDsseEncryption | ✗ INFO on both (KMS_DSSE not used) |
| 19 | ecrLifecyclePolicyEffectiveness | ✓ FAIL on hardened (partial lifecycle) |
| 20 | ecrScanFindingsStale | ✗ not simulated (requires scan > 30d old) |

**Directly FAIL: 12 of 20.** Remaining checks are either transient (13),
require aged data (12/16/20), depend on external state (10), or are
advisory (18).

## Warnings

- The wildcard-`Principal` repo policy in the standard repo grants
  **anonymous pull** to any container image pushed there. Do not push
  anything sensitive to it. The cleanup script destroys the repo.
- `debian:8` is end-of-life and unsupported by the Debian security team.
  We use it only as a controlled CVE source for scanner validation.

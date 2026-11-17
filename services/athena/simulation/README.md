# Athena Simulation Testing

Creates one intentionally-misconfigured workgroup plus an S3 results bucket,
and one workgroup that uses managed query results.

## Resources Created

| Resource | Configuration | Directly Validates |
|---|---|---|
| S3 bucket `ss-test-athena-<acct>-*` | Results destination | *(supporting)* |
| Workgroup `ss-test-athena-wg-*` | No result encryption, `EnforceWorkGroupConfiguration=false`, no minimum-encryption enforcement, metrics off, no bytes-scanned cutoff, output at bucket **root**, no tags | `athenaWorkgroupNotEncrypted`, `athenaWorkgroupNoEnforcement`, `athenaPublishMetricsDisabled`, `athenaBytesScannedNoLimit`, `athenaWorkgroupS3OutputNoPrefix`, `athenaNoTags` |
| Workgroup `ss-test-athena-wg-managed-*` | Managed query results, AWS owned key (otherwise defaults: metrics off, no bytes-scanned cutoff, no tags) | `athenaWorkgroupNotEncrypted` PASS; `athenaMinimumEncryptionDisabled`, `athenaWorkgroupS3OutputNoPrefix`, `athenaS3OutputNotEncrypted` INFO (not applicable) |

## Coverage

Verified against a test account in `ap-southeast-1` — 6 FAIL on the
fixture, and the account's 3 pre-existing workgroups exercise the remaining
branches.

| Check | Simulated? |
|---|---|
| `athenaWorkgroupNotEncrypted` | ✓ FAIL |
| `athenaWorkgroupNoEnforcement` | ✓ FAIL |
| `athenaPublishMetricsDisabled` | ✓ FAIL |
| `athenaBytesScannedNoLimit` | ✓ FAIL |
| `athenaWorkgroupS3OutputNoPrefix` | ✓ FAIL |
| `athenaNoTags` | ✓ FAIL |
| `athenaMinimumEncryptionDisabled` | ✗ INFO on the fixture — it is gated on encryption being configured at all, which the fixture deliberately omits. The account's real workgroups cover the FAIL branch. |
| `athenaS3OutputNotEncrypted` | ✗ PASS branch only — AWS enables SSE-S3 by default on new buckets, so a fixture bucket cannot be unencrypted |
| `athenaWorkgroupDisabled` | ✗ the account's ENABLED workgroups cover PASS; disabling one to force FAIL is not worth the churn |
| `athenaEngineVersionOutdated` | ✗ **unreachable** — AWS no longer permits selecting an engine older than version 3 |

### Managed query results workgroup

Verified in `eu-central-1`:

| Check | Result |
|---|---|
| `athenaWorkgroupNotEncrypted` | ✓ PASS: managed query results are always encrypted |
| `athenaMinimumEncryptionDisabled` | ✓ INFO: not applicable, the API rejects minimum encryption on such a workgroup |
| `athenaWorkgroupS3OutputNoPrefix` | ✓ INFO: not applicable, no customer results location |
| `athenaS3OutputNotEncrypted` | ✓ INFO: not applicable, no customer results location (no S3 call is made) |
| `athenaWorkgroupNoEnforcement` | PASS (enforcement is on by default) |
| `athenaPublishMetricsDisabled`, `athenaBytesScannedNoLimit`, `athenaNoTags` | FAIL, from the creation defaults, unrelated to managed query results |

## Usage

```bash
cd services/athena/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1
cd ../../.. && python3 main.py --regions ap-southeast-1 --services athena --beta 1 --sequential 1
cd services/athena/simulation && ./cleanup_test_resources.sh --force
```

## Cost

Zero. **No queries are ever run**, so no Athena per-byte-scanned charges are
incurred. The bucket holds nothing.

## Safety

Cleanup deletes only names read from the manifest. `delete-work-group` uses
`--recursive-delete-option` to remove the workgroup's named queries; no other
workgroup is touched.

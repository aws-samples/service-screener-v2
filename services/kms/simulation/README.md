# KMS Simulation Scripts

This directory contains scripts to create and cleanup test KMS resources for validating the new KMS checks.

## Overview

The simulation scripts create KMS keys with various configurations that trigger the new security checks across all tiers:

### Tier 1 Checks (Security & Operational)
1. **Key without rotation** - Tests `KeyRotationEnabled` check
2. **Key with rotation** - Validates rotation check passes
3. **Key with overly permissive grant** - Tests `GrantOverlyPermissive` check
4. **Key with duplicate grants** - Tests `GrantDuplicate` check
5. **Key with wildcard action in policy** - Tests `KeyPolicyWildcardAction` check
6. **Key without root access** - Tests `KeyPolicyMissingRootAccess` check

### Tier 2 Checks (Enhanced Security & Cost)
7. **Key with grant missing encryption context** - Tests `GrantMissingEncryptionContext` check
8. **Key with policy missing sensitive actions** - Tests `KeyPolicySensitiveActionsNotRestricted` check
9. **Key with policy without conditions** - Tests `KeyPolicyNoConditions` check
10. **Disabled/unused key** - Tests `KeyUnused` check

### Not Simulated (Limitations)
- **GrantOldAge** - Requires grants >180 days old (cannot simulate without backdating)
- **KeyCentralizedManagement** - Requires multi-account setup (Tier 3 informational check)

## Prerequisites

- AWS CLI configured with appropriate credentials
- Permissions to create and delete KMS keys
- Permissions to create grants and modify key policies
- `jq` installed (optional, for JSON parsing)

## Usage

### 1. Create Test Resources

```bash
cd service-screener-v2/services/kms/simulation
chmod +x create_test_resources.sh
./create_test_resources.sh
```

The script will:
- Create 6 KMS keys with different configurations
- Tag all keys with `ServiceScreenerTest=kms-test-<timestamp>`
- Create grants on some keys
- Apply custom policies to some keys
- Output a summary with key IDs and cleanup instructions

**Example Output:**
```
==========================================
Test Resources Created Successfully
==========================================

Summary of created resources:
Tier 1 Checks:
1. Key without rotation: 12345678-1234-1234-1234-123456789012
2. Key with rotation: 23456789-2345-2345-2345-234567890123
3. Key with permissive grant: 34567890-3456-3456-3456-345678901234
4. Key with duplicate grants: 45678901-4567-4567-4567-456789012345
5. Key with wildcard action: 56789012-5678-5678-5678-567890123456
6. Key without root access: 67890123-6789-6789-6789-678901234567

Tier 2 Checks:
7. Key with grant missing encryption context: 78901234-7890-7890-7890-789012345678
8. Key with policy missing sensitive actions: 89012345-8901-8901-8901-890123456789
9. Key with policy without conditions: 90123456-9012-9012-9012-901234567890
10. Disabled/unused key: 01234567-0123-0123-0123-012345678901

Note: GrantOldAge check requires grants >180 days old (cannot simulate)
Note: KeyCentralizedManagement check requires multi-account setup (cannot simulate)

All keys are tagged with: ServiceScreenerTest=kms-test-20240101-120000

To run Service Screener on these keys:
  python3 main.py --regions us-east-1 --services kms --tags ServiceScreenerTest=kms-test-20240101-120000

To cleanup these resources:
  ./cleanup_test_resources.sh kms-test-20240101-120000
```

### 2. Run Service Screener

After creating test resources, run Service Screener to validate the checks:

```bash
cd ../../../  # Back to service-screener-v2 root
python3 main.py --regions us-east-1 --services kms --tags ServiceScreenerTest=kms-test-20240101-120000
```

### 3. Review Results

Check the generated report for the following expected findings:

#### Tier 1 Checks

| Check | Expected Result | Key |
|-------|----------------|-----|
| `KeyRotationEnabled` | FAIL | Key #1 (no rotation) |
| `KeyRotationEnabled` | PASS | Key #2 (with rotation) |
| `GrantOverlyPermissive` | FAIL | Key #3 (6+ operations) |
| `GrantDuplicate` | FAIL | Key #4 (duplicate grants) |
| `KeyPolicyWildcardAction` | FAIL | Key #5 (wildcard action) |
| `KeyPolicyMissingRootAccess` | FAIL | Key #6 (no root access) |

#### Tier 2 Checks

| Check | Expected Result | Key |
|-------|----------------|-----|
| `GrantMissingEncryptionContext` | FAIL | Key #7 (no encryption context) |
| `KeyPolicySensitiveActionsNotRestricted` | FAIL | Key #8 (missing sensitive actions) |
| `KeyPolicyNoConditions` | FAIL | Key #9 (no conditions) |
| `KeyUnused` | FAIL | Key #10 (disabled, no grants) |

#### Not Simulated

| Check | Reason |
|-------|--------|
| `GrantOldAge` | Requires grants >180 days old (cannot simulate) |
| `KeyCentralizedManagement` | Requires multi-account setup (Tier 3) |

### 4. Cleanup Test Resources

After testing, cleanup the resources:

```bash
cd services/kms/simulation
./cleanup_test_resources.sh kms-test-20240101-120000
```

**Note:** KMS keys have a mandatory 7-30 day waiting period before deletion. The cleanup script schedules keys for deletion with the minimum 7-day waiting period.

## Script Details

### create_test_resources.sh

**What it does:**
- Creates 10 KMS keys with descriptive names
- Tags all keys for easy identification
- Creates aliases for each key
- Configures rotation on one key
- Creates grants with various permission levels and constraints
- Applies custom key policies
- Disables one key to simulate unused state

**Environment Variables:**
- `AWS_REGION` - AWS region (default: us-east-1)

**Tags Applied:**
- `ServiceScreenerTest=kms-test-<timestamp>`

### cleanup_test_resources.sh

**What it does:**
- Finds all keys with the specified tag
- Deletes aliases associated with the keys
- Retires all grants on the keys
- Schedules keys for deletion (7-day waiting period)

**Usage:**
```bash
./cleanup_test_resources.sh <tag-value>
```

**Example:**
```bash
./cleanup_test_resources.sh kms-test-20240101-120000
```

## Expected Check Results

### Pass Scenarios

| Check | Key | Reason |
|-------|-----|--------|
| `KeyRotationEnabled` | Key #2 | Rotation is enabled |
| `GrantOverlyPermissive` | Keys #1, #2, #5, #6, #8, #9, #10 | No grants or limited grants |
| `GrantWildcardPrincipal` | All keys | No wildcard principals in grants |
| `GrantDuplicate` | Keys #1, #2, #3, #5, #6, #7, #8, #9, #10 | No duplicate grants |
| `GrantMissingEncryptionContext` | Keys without grants | No grants to check |
| `KeyPolicyCrossAccount` | All keys | No cross-account access |
| `KeyPolicyWildcardPrincipal` | All keys | No wildcard principals in policies |
| `KeyPolicyWildcardAction` | Keys #1-4, #6-10 | No wildcard actions |
| `KeyPolicyMissingRootAccess` | Keys #1-5, #7-10 | Root access present |
| `KeyPolicySensitiveActionsNotRestricted` | Keys #1-7, #9-10 | Sensitive actions in policy |
| `KeyPolicyNoConditions` | Keys #1-8, #10 | Has conditions or root-only |
| `KeyUnused` | Keys #1-9 | Active or has grants |

### Fail Scenarios

| Check | Key | Reason |
|-------|-----|--------|
| `KeyRotationEnabled` | Key #1 | Rotation not enabled |
| `GrantOverlyPermissive` | Key #3 | Grant has 6+ operations |
| `GrantDuplicate` | Key #4 | Two identical grants |
| `GrantMissingEncryptionContext` | Key #7 | Grant without encryption context |
| `KeyPolicyWildcardAction` | Key #5 | Policy has wildcard action |
| `KeyPolicyMissingRootAccess` | Key #6 | No root account in policy |
| `KeyPolicySensitiveActionsNotRestricted` | Key #8 | Missing PutKeyPolicy/ScheduleKeyDeletion |
| `KeyPolicyNoConditions` | Key #9 | User statement without conditions |
| `KeyUnused` | Key #10 | Disabled with no grants |

### Not Testable

| Check | Reason |
|-------|--------|
| `GrantOldAge` | Requires grants >180 days old (cannot simulate without backdating) |
| `KeyCentralizedManagement` | Requires multi-account setup (Tier 3 informational check) |

## Troubleshooting

### Permission Errors

If you encounter permission errors, ensure your IAM user/role has:
- `kms:CreateKey`
- `kms:CreateAlias`
- `kms:CreateGrant`
- `kms:PutKeyPolicy`
- `kms:EnableKeyRotation`
- `kms:ScheduleKeyDeletion`
- `kms:ListKeys`
- `kms:ListResourceTags`
- `kms:DescribeKey`

### Cleanup Issues

If cleanup fails:
1. Manually list keys with the tag:
   ```bash
   aws kms list-keys --region us-east-1
   ```

2. For each key, schedule deletion:
   ```bash
   aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7
   ```

### Key Already Exists

If you see "alias already exists" errors:
- The alias names include timestamps to avoid conflicts
- If running multiple times quickly, wait a few seconds between runs
- Or manually delete old aliases first

## Cost Considerations

**KMS Key Costs:**
- Customer managed keys: $1/month per key
- API requests: $0.03 per 10,000 requests

**Test Duration:**
- Creating resources: ~2-3 minutes
- Running Service Screener: ~1-2 minutes
- Total test time: ~5 minutes

**Estimated Cost:**
- 6 keys for 1 hour: ~$0.01
- API requests: negligible
- **Total: < $0.01 for a complete test run**

**Note:** Keys scheduled for deletion still incur charges until actually deleted (after 7-day waiting period).

## Safety Features

1. **Tagging:** All resources are tagged for easy identification
2. **Timestamps:** Unique timestamps prevent naming conflicts
3. **Aliases:** Human-readable aliases for easy identification
4. **Waiting Period:** 7-day deletion waiting period allows recovery
5. **Error Handling:** Scripts use `set -e` to stop on errors

## Advanced Usage

### Custom Region

```bash
AWS_REGION=eu-west-1 ./create_test_resources.sh
```

### Custom Tag Value

Edit the script to change `TAG_VALUE`:
```bash
TAG_VALUE="my-custom-tag"
```

### Selective Cleanup

To cleanup only specific keys, modify the cleanup script or use AWS CLI directly:
```bash
aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7
```

## Integration with CI/CD

These scripts can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Create KMS test resources
  run: ./services/kms/simulation/create_test_resources.sh

- name: Run Service Screener
  run: python3 main.py --regions us-east-1 --services kms --tags ServiceScreenerTest=kms-test-${{ github.run_id }}

- name: Cleanup test resources
  if: always()
  run: ./services/kms/simulation/cleanup_test_resources.sh kms-test-${{ github.run_id }}
```

## References

- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [AWS KMS API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/)
- [Service Screener Documentation](../../README.md)

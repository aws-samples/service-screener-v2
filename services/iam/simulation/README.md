# IAM Service Review - Simulation Scripts

## Overview

These scripts help test the new IAM checks by creating test resources in your AWS account that should trigger the checks, then cleaning them up afterward.

## Prerequisites

- AWS CLI configured with appropriate credentials
- Permissions to create/delete IAM resources:
  - `iam:CreatePolicy`
  - `iam:CreateUser`
  - `iam:CreateAccessKey`
  - `iam:AttachUserPolicy`
  - `iam:DeletePolicy`
  - `iam:DeleteUser`
  - `iam:DeleteAccessKey`
  - `iam:ListAccessKeys`
  - `iam:DetachUserPolicy`
  - `iam:CreateRole`
  - `iam:AttachRolePolicy`
  - `iam:DetachRolePolicy`
  - `iam:DeleteRole`

## Scripts

### `create_test_resources.sh`

Creates test IAM resources that should trigger both Tier 1 and Tier 2 checks:

**Tier 1 Checks:**
1. **Unused Customer Managed Policy** - Creates a policy not attached to any entity
2. **IAM Users with Federation Available** - Creates a user with access keys when SAML/OIDC exists
3. **Wildcard Actions Detection** - Creates policies with service-level wildcards
4. **Unnecessary Custom Policies** - Creates custom policies that duplicate AWS managed ones

**Tier 2 Checks:**
5. **Missing Policy Conditions** - Creates policy with sensitive IAM actions but no MFA/IP/SecureTransport conditions
6. **Missing Permissions Boundaries** - Creates delegated admin role without permissions boundary
7. **SCP Best Practices** - Note provided (requires Organizations to be enabled)

**Usage:**
```bash
./create_test_resources.sh
```

**Output:**
- Creates resources with prefix `ss-test-`
- Prints resource ARNs for verification
- Saves resource identifiers to `test_resources.txt`

### `cleanup_test_resources.sh`

Removes all test resources created by the create script.

**Usage:**
```bash
./cleanup_test_resources.sh
```

**Safety:**
- Only deletes resources with `ss-test-` prefix
- Confirms before deletion
- Handles dependencies (detaches policies before deletion)

## Testing Workflow

### 1. Create Test Resources
```bash
cd service-screener-v2/services/iam/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh
```

### 2. Run Service Screener
```bash
cd ../../..
python screener.py --services iam --regions us-east-1
```

### 3. Verify Results

Check the output for the following checks:

**Tier 1 Checks:**
- **unusedCustomerManagedPolicy**: Should detect `ss-test-unused-policy`
- **iamUsersWithFederationAvailable**: Should detect `ss-test-user-with-keys` (if federation configured)
- **wildcardActionsDetection**: Should detect policies with wildcards
- **unnecessaryCustomPolicies**: Should detect `ss-test-ReadOnlyAccess-Custom`

**Tier 2 Checks:**
- **missingPolicyConditions**: Should detect `ss-test-no-conditions-policy` (missing MFA/IP/SecureTransport)
- **missingPermissionsBoundaries**: Should detect `ss-test-delegated-admin-role` (no permissions boundary)
- **scpBestPractices**: Only runs if AWS Organizations is enabled

### 4. Clean Up
```bash
cd services/iam/simulation
./cleanup_test_resources.sh
```

## Test Resources Created

### Tier 1 Policies
- `ss-test-unused-policy` - Unused customer managed policy
- `ss-test-s3-wildcard-policy` - Policy with `s3:*` actions
- `ss-test-ec2-wildcard-policy` - Policy with `ec2:*` actions
- `ss-test-ReadOnlyAccess-Custom` - Duplicates AWS managed ReadOnlyAccess

### Tier 1 Users
- `ss-test-user-with-keys` - User with access keys (for federation check)

### Tier 2 Policies
- `ss-test-no-conditions-policy` - Policy with sensitive IAM actions but no security conditions
- `ss-test-delegated-admin-policy` - Policy granting IAM management permissions

### Tier 2 Roles
- `ss-test-delegated-admin-role` - Role with IAM management permissions but no permissions boundary

## Notes

- All resources use the `ss-test-` prefix for easy identification
- Resources are tagged with `Purpose: ServiceScreenerTest`
- Scripts are idempotent - safe to run multiple times
- Cleanup script will skip resources that don't exist

## Troubleshooting

### Permission Denied
Ensure your AWS credentials have the required IAM permissions listed above.

### Resources Already Exist
Run the cleanup script first, then try again.

### Cleanup Fails
Manually delete resources with `ss-test-` prefix using AWS Console or CLI.

## Cost

These test resources should incur minimal to no cost:
- IAM policies: Free
- IAM users: Free
- Access keys: Free (not used for API calls)

## Security

**Important:** These scripts create IAM resources with intentionally insecure configurations for testing purposes. Always run the cleanup script after testing to remove these resources.

Do not use these scripts in production accounts without proper review and approval.

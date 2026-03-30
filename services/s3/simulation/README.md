# S3 Simulation Scripts

This directory contains scripts to create and cleanup test S3 resources for validating the new Tier 1, Tier 2, and Tier 3 security checks implemented in Service Screener v2.

## Overview

The simulation scripts create various S3 bucket configurations that test both passing and failing scenarios for ALL 26 implemented checks in Service Screener v2.

### Security Checks (14 checks)
1. **ServerSideEncrypted** - SSE encryption enabled
2. **SSEWithKMS** - SSE with KMS encryption
3. **AccessControlList** - ACL usage detection
4. **PublicAccessBlock** - Public access block settings
5. **PublicReadAccessBlock** - Public read access
6. **PublicWriteAccessBlock** - Public write access
7. **MFADelete** - MFA delete protection
8. **ObjectLock** - Object lock configuration
9. **BucketLogging** - Server access logging
10. **TlsEnforced** - HTTPS/TLS enforcement
11. **S3AccountPublicAccessBlock** - Account-level public access block
12. **BucketOwnerEnforced** - Bucket owner enforced setting
13. **WildcardPrincipalsActions** - Wildcard principals/actions in policies
14. **SSECBlocking** - SSE-C blocking
15. **PublicAccessDocumentation** - Public bucket approval tags
16. **UnpredictableBucketNames** - Bucket naming patterns
17. **MacieToEnable** - Macie enablement (informational)

### Reliability & Resilience Checks (3 checks)
18. **BucketVersioning** - Versioning enabled
19. **BucketReplication** - Replication configuration
20. **CrossRegionReplication** - Cross-region replication

### Cost Optimization Checks (4 checks)
21. **BucketLifecycle** - Lifecycle policies
22. **ObjectsInIntelligentTier** - Intelligent-Tiering usage
23. **StorageLens** - Storage Lens configuration

### Operational Excellence Checks (3 checks)
24. **EventNotification** - Event notifications
25. **CloudWatchRequestMetrics** - CloudWatch request metrics

### Performance Checks (1 check)
26. **TransferAcceleration** - Transfer acceleration

## Prerequisites

### Required Tools
- **AWS CLI** - Version 2.x or later
- **jq** - JSON processor for parsing responses
- **bash** - Shell environment (Linux/macOS/WSL)

### AWS Permissions

The scripts require the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:PutBucketOwnershipControls",
        "s3:PutBucketAccelerateConfiguration",
        "s3:PutBucketMetricsConfiguration",
        "s3:PutBucketTagging",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketEncryption",
        "s3control:PutStorageLensConfiguration",
        "s3control:DeleteStorageLensConfiguration",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### AWS Configuration

Ensure your AWS CLI is configured with credentials:

```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

## Usage

### 1. Create Test Resources

Run the creation script to set up all test S3 resources:

```bash
cd service-screener-v2/services/s3/simulation
chmod +x create_test_resources.sh
./create_test_resources.sh
```

**What it creates:**

The script creates approximately 40+ test scenarios covering all 26 checks:

| Category | Test Scenarios | Checks Covered |
|----------|----------------|----------------|
| **Security** | 28 scenarios | SSE, KMS, ACLs, Public Access, MFA Delete, Object Lock, Logging, TLS, Wildcards, SSE-C, Documentation, Naming |
| **Reliability** | 6 scenarios | Versioning, Replication, Cross-Region Replication |
| **Cost Optimization** | 6 scenarios | Lifecycle, Intelligent-Tiering, Storage Lens |
| **Operational** | 4 scenarios | Event Notifications, CloudWatch Metrics |
| **Performance** | 2 scenarios | Transfer Acceleration |

Each check has both PASS and FAIL scenarios to validate detection accuracy.

**Output:**

The script creates a JSON file with all resource IDs:
```
simulation/test_resources_<timestamp>.json
```

### 2. Run Service Screener

After creating test resources, run Service Screener to validate the checks:

```bash
# Navigate to Service Screener root
cd ../../..

# Run Service Screener for S3
python screener.py --services s3 --regions us-east-1
```

### 3. Verify Results

Check the Service Screener output to verify all checks detect the expected pass/fail scenarios.

### 4. Cleanup Test Resources

After testing, cleanup all created resources:

```bash
# Using timestamp from creation
./cleanup_test_resources.sh 1234567890

# Or let it auto-detect the most recent resource file
./cleanup_test_resources.sh
```

**What it does:**
- Deletes all test buckets (26+ buckets)
- Deletes Storage Lens configurations
- Archives the resource JSON file to `simulation/archive/`

## Test Scenarios

### Tier 1 Scenarios

#### Scenario 1: ACL Enforcement
**Purpose:** Verify that buckets without "bucket owner enforced" setting are flagged.

**Test Buckets:**
- `ss-test-s3-acl-enforced-*` - Has BucketOwnerEnforced (PASS)
- `ss-test-s3-acl-not-enforced-*` - No ownership controls (FAIL)

#### Scenario 2: Transfer Acceleration
**Purpose:** Verify that buckets without transfer acceleration are flagged.

**Test Buckets:**
- `ss-test-s3-acceleration-enabled-*` - Has acceleration enabled (PASS)
- `ss-test-s3-acceleration-disabled-*` - No acceleration (FAIL)

#### Scenario 3: CloudWatch Monitoring
**Purpose:** Verify that buckets without CloudWatch metrics are flagged.

**Test Buckets:**
- `ss-test-s3-metrics-enabled-*` - Has metrics configuration (PASS)
- `ss-test-s3-metrics-disabled-*` - No metrics (FAIL)

### Tier 2 Scenarios

#### Scenario 4: Wildcard Principals/Actions
**Purpose:** Verify that buckets with wildcard principals or actions are flagged.

**Test Buckets:**
- `ss-test-s3-safe-policy-*` - Specific principals and actions (PASS)
- `ss-test-s3-wildcard-policy-*` - Wildcard principal "*" (FAIL)

#### Scenario 5: SSE-C Blocking
**Purpose:** Verify that buckets not blocking SSE-C are flagged.

**Test Buckets:**
- `ss-test-s3-ssec-blocked-*` - Policy denies SSE-C (PASS)
- `ss-test-s3-ssec-allowed-*` - No SSE-C blocking (FAIL)

#### Scenario 6: Storage Lens
**Purpose:** Verify that accounts without Storage Lens are flagged.

**Test Configuration:**
- Creates enabled Storage Lens configuration (PASS)

#### Scenario 7: Public Access Documentation
**Purpose:** Verify that public buckets without approval tags are flagged.

**Test Buckets:**
- `ss-test-s3-public-approved-*` - Public with approval tags (PASS)
- `ss-test-s3-public-not-approved-*` - Public without tags (FAIL)

### Tier 3 Scenarios

#### Scenario 8: Unpredictable Bucket Names
**Purpose:** Verify that buckets with predictable names are flagged.

**Test Buckets:**
- Random UUID-based name - Unpredictable (PASS)
- `ss-test-s3-bucket-001-*` - Sequential number pattern (FAIL)

## Troubleshooting

### Issue: "jq: command not found"

**Solution:** Install jq:
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Amazon Linux
sudo yum install jq
```

### Issue: "Access Denied" errors

**Solution:** Verify IAM permissions include all required S3 and S3Control actions.

### Issue: Bucket name conflicts

**Solution:** The script uses timestamps to ensure unique names. If conflicts occur, wait a few seconds and retry.

### Issue: Resources not deleted

**Solution:** Check if buckets contain objects:
```bash
# List all buckets
aws s3 ls

# Check bucket contents
aws s3 ls s3://bucket-name

# Empty bucket before deletion
aws s3 rm s3://bucket-name --recursive

# Manually delete bucket
aws s3 rb s3://bucket-name
```

## Cost Considerations

These test resources incur minimal AWS costs:

- **S3 Buckets:** No cost for empty buckets
- **Storage Lens:** Free tier includes organization-level dashboard
- **CloudWatch Metrics:** First 10 custom metrics free per month

**Estimated cost:** $0.00 - $0.01 per test run (within free tier)

**Best Practice:** Always run cleanup script after testing to avoid any charges.

## Additional Resources

- [S3 Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [Service Screener Documentation](../../../README.md)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Service Screener logs
3. Verify AWS CLI configuration and permissions
4. Check the main Service Screener documentation

## License

These scripts are part of Service Screener v2 and follow the same license.

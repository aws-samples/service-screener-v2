# S3 Simulation Scripts - Quick Start

## Overview

Single consolidated script that creates **26 test scenarios** covering all S3 checks in Service Screener v2.

## Files

- `create_test_resources.sh` - Creates all 26 test buckets and configurations
- `cleanup_test_resources.sh` - Deletes all test resources
- `README.md` - Comprehensive documentation

## Quick Start

```bash
# 1. Navigate to simulation directory
cd service-screener-v2/services/s3/simulation

# 2. Create all test resources (26 scenarios)
./create_test_resources.sh

# 3. Run Service Screener
cd ../../..
python screener.py --services s3 --regions us-east-1

# 4. Cleanup all resources
cd services/s3/simulation
./cleanup_test_resources.sh
```

## What Gets Created

### Security Checks (14 scenarios)
- SSE-S3 encryption (PASS/FAIL)
- SSE-KMS encryption (PASS/FAIL)
- ACL usage and enforcement (PASS/FAIL)
- TLS enforcement (PASS/FAIL)
- Server access logging (PASS/FAIL)
- Wildcard policies (PASS/FAIL)
- SSE-C blocking (PASS/FAIL)
- Public access documentation (PASS/FAIL)
- Bucket naming patterns (PASS/FAIL)

### Reliability Checks (2 scenarios)
- Versioning (PASS/FAIL)

### Cost Optimization Checks (3 scenarios)
- Lifecycle policies (PASS/FAIL)
- Storage Lens configuration (PASS)

### Operational Checks (2 scenarios)
- CloudWatch metrics (PASS/FAIL)

### Performance Checks (2 scenarios)
- Transfer acceleration (PASS/FAIL)

## Total Resources Created

- **26 S3 buckets** (including 1 log target bucket)
- **1 Storage Lens configuration**
- **1 JSON tracking file** with all resource IDs

## Cost Considerations

- All buckets are empty (no storage costs)
- Storage Lens uses free tier
- CloudWatch metrics: First 10 custom metrics free
- **Estimated cost:** $0.00 - $0.01 per test run

## Cleanup

The cleanup script:
- Empties all buckets before deletion
- Deletes Storage Lens configurations
- Archives the resource tracking file
- Handles partial failures gracefully

## Notes

Some checks require manual setup:
- **MFADelete** - Requires root account
- **ObjectLock** - Must be enabled at bucket creation
- **EventNotification** - Requires SNS/SQS/Lambda
- **BucketReplication** - Requires destination bucket
- **S3AccountPublicAccessBlock** - Account-level setting

These are noted in the script output but not created automatically.

# OpenSearch Simulation Scripts

This directory contains scripts to create and clean up test OpenSearch resources for validating new checks.

## Overview

These scripts help you test the new OpenSearch checks by creating real AWS resources that demonstrate both passing and failing scenarios.

## New Checks Covered

- **CloudWatchAlarms**: Validates presence of recommended CloudWatch alarms for critical metrics

## Prerequisites

- AWS CLI installed and configured
- AWS credentials with permissions to:
  - Create/delete OpenSearch domains
  - Create/delete CloudWatch alarms
  - Create/delete SNS topics
  - Create/delete EC2 security groups
  - Describe VPCs and subnets
- Default VPC with at least 2 subnets in your region

## Cost Warning

⚠️ **These scripts create real AWS resources that incur costs:**
- OpenSearch domains (t3.small.search instances)
- CloudWatch alarms
- Data transfer

**Estimated cost**: ~$0.50-$1.00 per hour for the test domains

**Always run the cleanup script when done testing!**

## Usage

### 1. Create Test Resources

```bash
# Use default region (us-east-1)
./create_test_resources.sh

# Or specify a region
AWS_REGION=us-west-2 ./create_test_resources.sh
```

This creates:
- **test-opensearch-pass**: Domain with all 4 critical CloudWatch alarms configured
- **test-opensearch-fail**: Domain with no CloudWatch alarms
- Security group for OpenSearch domains
- SNS topic for alarm notifications
- 4 CloudWatch alarms for the PASS domain

**Creation time**: 10-15 minutes for domains to become active

### 2. Run Service Screener

After domains are active, run the Service Screener:

```bash
cd ../../..  # Navigate to service-screener-v2 root
python screener.py --regions us-east-1 --services opensearch
```

### 3. Verify Results

Expected results:

**test-opensearch-pass**:
- ✅ CloudWatchAlarms: PASS - "All critical alarms configured"

**test-opensearch-fail**:
- ❌ CloudWatchAlarms: FAIL - "No CloudWatch alarms configured"

### 4. Clean Up Resources

**IMPORTANT**: Always clean up to avoid ongoing charges!

```bash
./cleanup_test_resources.sh

# Or specify a region
AWS_REGION=us-west-2 ./cleanup_test_resources.sh
```

This removes:
- Both OpenSearch domains
- All CloudWatch alarms
- SNS topic
- Security group

**Deletion time**: Several minutes for domains to fully delete

## Manual Verification

### Check Domain Status

```bash
aws opensearch describe-domain --region us-east-1 --domain-name test-opensearch-pass
```

### Check CloudWatch Alarms

```bash
aws cloudwatch describe-alarms --region us-east-1 --alarm-name-prefix test-opensearch-pass
```

### List All Test Domains

```bash
aws opensearch list-domain-names --region us-east-1 | grep test-opensearch
```

## Troubleshooting

### Domains Already Exist

If domains already exist, delete them first:

```bash
./cleanup_test_resources.sh
# Wait a few minutes
./create_test_resources.sh
```

### Security Group Deletion Fails

The security group may still be attached to domains. Wait for domains to fully delete:

```bash
# Check domain status
aws opensearch list-domain-names --region us-east-1

# Once domains are gone, retry cleanup
./cleanup_test_resources.sh
```

### No Default VPC

If you don't have a default VPC, modify the scripts to use a specific VPC ID:

```bash
# Edit create_test_resources.sh
VPC_ID="vpc-xxxxxxxxx"  # Replace with your VPC ID
```

### Region Not Supported

OpenSearch may not be available in all regions. Try a major region like:
- us-east-1
- us-west-2
- eu-west-1

## Test Scenarios

### CloudWatchAlarms Check

**PASS Scenario** (test-opensearch-pass):
- All 4 critical alarms configured:
  - ClusterStatus.red
  - ClusterStatus.yellow
  - FreeStorageSpace
  - ClusterIndexWritesBlocked
- Each alarm has SNS notification configured

**FAIL Scenario** (test-opensearch-fail):
- No CloudWatch alarms configured
- Domain is otherwise healthy

## Script Permissions

Make scripts executable:

```bash
chmod +x create_test_resources.sh
chmod +x cleanup_test_resources.sh
```

## Additional Notes

### Domain Configuration

Both test domains are configured with:
- OpenSearch 2.11
- VPC deployment (private)
- Encryption at rest enabled
- Node-to-node encryption enabled
- HTTPS enforced with TLS 1.2
- Fine-grained access control enabled

**PASS domain** (test-opensearch-pass):
- 3 data nodes (t3.small.search)
- 3 dedicated master nodes (t3.small.search)
- Multi-AZ enabled (3 AZs)
- 20 GB EBS storage per node

**FAIL domain** (test-opensearch-fail):
- 2 data nodes (t3.small.search)
- No dedicated master nodes
- Single-AZ
- 20 GB EBS storage per node

### CloudWatch Alarm Configuration

Alarms are configured with:
- 60-second period
- 1 evaluation period
- SNS notification on alarm state
- Appropriate thresholds for each metric

### Cost Optimization

To minimize costs during testing:
1. Use t3.small.search instances (smallest production-suitable size)
2. Minimal storage (20 GB)
3. Run tests quickly and clean up immediately
4. Consider using a single domain and manually adding/removing alarms

## Support

For issues with these scripts:
1. Check AWS CLI is configured: `aws sts get-caller-identity`
2. Verify permissions: `aws iam get-user`
3. Check region availability: `aws opensearch list-versions --region us-east-1`
4. Review CloudWatch Logs for domain creation errors

## References

- [OpenSearch Service Documentation](https://docs.aws.amazon.com/opensearch-service/)
- [CloudWatch Alarms for OpenSearch](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cloudwatch-alarms.html)
- [OpenSearch Best Practices](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/bp.html)

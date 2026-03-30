# CloudTrail Test Resources Simulation

This directory contains scripts to create and cleanup test CloudTrail resources for validating the 6 new Tier 1 Service Screener checks:

1. **GuardDutyIntegration** - Validates GuardDuty is enabled for threat detection
2. **SecurityHubIntegration** - Validates Security Hub is enabled for security posture management
3. **IAMFullAccessRestriction** - Detects IAM principals with CloudTrail full access
4. **KMSPolicySourceArn** - Validates KMS key policies include aws:SourceArn condition
5. **OrganizationTrailEnabled** - Validates organization trails for multi-account logging
6. **CloudWatchAlarmsConfigured** - Validates CloudWatch metric filters and alarms

## Prerequisites

- AWS CLI installed and configured
- AWS credentials with permissions to:
  - Create/delete CloudTrail trails
  - Create/delete S3 buckets and bucket policies
  - Create/delete KMS keys and key policies
  - Create/delete IAM users, roles, and policies
  - Create/delete CloudWatch Logs log groups, metric filters, and alarms
  - Get caller identity (for account ID)
  - (Optional) Enable GuardDuty and Security Hub
  - (Optional) Manage AWS Organizations
- Sufficient AWS service quotas for test resources

## Quick Start

### 1. Create Test Resources

```bash
cd service-screener-v2/services/cloudtrail/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh
```

This creates:
- 1 S3 bucket for CloudTrail logs
- 2 KMS keys (with/without SourceArn condition)
- 3 CloudTrail trails (no KMS, KMS without SourceArn, KMS with SourceArn)
- 1 CloudWatch Logs log group
- 1 IAM role for CloudWatch Logs integration
- 1 Metric filter and CloudWatch alarm
- 1 IAM test user with CloudTrail full access

### 2. Manual Setup (Optional)

For complete testing, manually enable:

**GuardDuty:**
```bash
aws guardduty create-detector --enable --region us-east-1
```

**Security Hub:**
```bash
aws securityhub enable-security-hub --region us-east-1
aws securityhub batch-enable-standards \
  --standards-subscription-requests StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0 \
  --region us-east-1
```

**Organization Trail (if in management account):**
```bash
aws cloudtrail create-trail \
  --name org-trail \
  --s3-bucket-name <bucket-name> \
  --is-organization-trail \
  --is-multi-region-trail \
  --region us-east-1
```

### 3. Run Service Screener

```bash
cd ../../..  # Back to service-screener-v2 root
python screener.py --regions us-east-1 --services cloudtrail
```

### 4. Review Results

Check the generated report for the 6 new checks:
- **GuardDutyIntegration**: Should pass if GuardDuty is enabled
- **SecurityHubIntegration**: Should pass if Security Hub is enabled with standards
- **IAMFullAccessRestriction**: Should flag the test user with full access
- **KMSPolicySourceArn**: Should flag trail with KMS but no SourceArn
- **OrganizationTrailEnabled**: Should pass if organization trail exists (management account only)
- **CloudWatchAlarmsConfigured**: Should pass for trail with metric filters and alarms

### 5. Cleanup Test Resources

```bash
cd services/cloudtrail/simulation
./cleanup_test_resources.sh
```

## Detailed Usage

### Environment Variables

Both scripts support the following environment variable:

- `AWS_REGION` - AWS region to use (default: `us-east-1`)

Example:
```bash
export AWS_REGION=us-west-2
./create_test_resources.sh
```

### Test Resource Details

#### GuardDutyIntegration Test

| Setup | Expected Result |
|-------|-----------------|
| No GuardDuty detector | FAIL (Critical) |
| Detector exists but suspended | WARNING |
| Active GuardDuty detector | PASS |

**Manual Setup Required:** Enable GuardDuty via Console or CLI

#### SecurityHubIntegration Test

| Setup | Expected Result |
|-------|-----------------|
| Security Hub not enabled | FAIL (Critical) |
| Hub enabled, no standards | WARNING |
| Hub enabled with standards | PASS |

**Manual Setup Required:** Enable Security Hub and subscribe to standards

#### IAMFullAccessRestriction Test

| Setup | Expected Result |
|-------|-----------------|
| No principals with full access | PASS |
| 1-4 principals with full access | WARNING |
| 5+ principals with full access | FAIL (Critical) |

**Script Creates:** 1 test user with AWSCloudTrail_FullAccess policy

#### KMSPolicySourceArn Test

| Trail Configuration | Expected Result |
|---------------------|-----------------|
| No KMS encryption | SKIP (check not applicable) |
| KMS without aws:SourceArn | FAIL (Critical) |
| KMS with aws:SourceArn | PASS |

**Script Creates:** 
- Trail without KMS (skipped)
- Trail with KMS but no SourceArn (fails)
- Trail with KMS and SourceArn (passes)

#### OrganizationTrailEnabled Test

| Setup | Expected Result |
|-------|-----------------|
| Not in AWS Organizations | SKIP (check not applicable) |
| Member account | SKIP (check not applicable) |
| Management account, no org trail | FAIL (Critical) |
| Management account with org trail | PASS |

**Manual Setup Required:** Create organization trail if in management account

#### CloudWatchAlarmsConfigured Test

| Trail Configuration | Expected Result |
|---------------------|-----------------|
| No CloudWatch Logs integration | SKIP (check not applicable) |
| CloudWatch Logs, no metric filters | FAIL (Critical) |
| Metric filters, no alarms | WARNING |
| Metric filters with alarms | PASS |

**Script Creates:** Trail with CloudWatch Logs, metric filter, and alarm

### Troubleshooting

#### Permission Errors

If you encounter permission errors, ensure your AWS credentials have the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:*",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:DeleteObject",
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:GetKeyPolicy",
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:PutMetricFilter",
        "logs:DeleteMetricFilter",
        "cloudwatch:PutMetricAlarm",
        "cloudwatch:DeleteAlarms",
        "sts:GetCallerIdentity",
        "guardduty:CreateDetector",
        "guardduty:DeleteDetector",
        "securityhub:EnableSecurityHub",
        "securityhub:DisableSecurityHub",
        "organizations:DescribeOrganization"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Bucket Already Exists

If the S3 bucket name is already taken, the script will note this and continue. You may need to manually specify a unique bucket name or clean up existing buckets.

#### IAM Role Propagation

The script includes a 10-second wait for IAM role propagation. If you encounter errors about the role not existing, increase this wait time in the script.

#### KMS Key Deletion

KMS keys cannot be immediately deleted. The cleanup script schedules them for deletion with a 7-day waiting period. You can cancel deletion within 7 days:

```bash
aws kms cancel-key-deletion --key-id <key-id> --region us-east-1
```

#### Timestamp File

The `create_test_resources.sh` script saves a timestamp to `.last_test_timestamp`. This helps the cleanup script identify the exact resources created. If this file is lost, the cleanup script will still work by searching for all resources with the `ss-test-cloudtrail` prefix.

## Cost Considerations

- **CloudTrail**: $2.00 per 100,000 management events (first trail free)
- **S3**: Storage costs for logs (minimal for testing)
- **KMS**: $1.00/month per key + $0.03 per 10,000 requests
- **CloudWatch Logs**: $0.50/GB ingested + $0.03/GB stored
- **CloudWatch Alarms**: $0.10 per alarm per month
- **GuardDuty**: $4.00 per million events (30-day free trial)
- **Security Hub**: $0.0010 per security check (30-day free trial)

**Estimated Cost:** Less than $5 if cleaned up within 24 hours. Always run cleanup after testing to avoid unnecessary costs.

## Integration with CI/CD

You can integrate these scripts into your CI/CD pipeline:

```bash
#!/bin/bash
set -e

# Create test resources
cd services/cloudtrail/simulation
./create_test_resources.sh

# Run Service Screener
cd ../../..
python screener.py --regions us-east-1 --services cloudtrail --output-format json > results.json

# Validate results (example)
python -c "
import json
with open('results.json') as f:
    results = json.load(f)
    # Add your validation logic here
"

# Cleanup (always run, even if tests fail)
cd services/cloudtrail/simulation
./cleanup_test_resources.sh || true
```

## Manual Testing

If you prefer to test individual checks manually:

### Test GuardDutyIntegration

```bash
# Enable GuardDuty
aws guardduty create-detector --enable --region us-east-1

# Run Service Screener
python screener.py --regions us-east-1 --services cloudtrail

# Cleanup
DETECTOR_ID=$(aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[0]' --output text)
aws guardduty delete-detector --detector-id $DETECTOR_ID --region us-east-1
```

### Test SecurityHubIntegration

```bash
# Enable Security Hub
aws securityhub enable-security-hub --region us-east-1
aws securityhub batch-enable-standards \
  --standards-subscription-requests StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0 \
  --region us-east-1

# Run Service Screener
python screener.py --regions us-east-1 --services cloudtrail

# Cleanup
aws securityhub disable-security-hub --region us-east-1
```

### Test IAMFullAccessRestriction

```bash
# Create test user
aws iam create-user --user-name test-cloudtrail-user
aws iam attach-user-policy \
  --user-name test-cloudtrail-user \
  --policy-arn arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess

# Run Service Screener
python screener.py --regions us-east-1 --services cloudtrail

# Cleanup
aws iam detach-user-policy \
  --user-name test-cloudtrail-user \
  --policy-arn arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess
aws iam delete-user --user-name test-cloudtrail-user
```

### Test KMSPolicySourceArn

```bash
# Create KMS key without SourceArn
KEY_ID=$(aws kms create-key \
  --description "Test CloudTrail Key" \
  --query 'KeyMetadata.KeyId' \
  --output text)

# Create trail with KMS
aws cloudtrail create-trail \
  --name test-trail \
  --s3-bucket-name <existing-bucket> \
  --kms-key-id $KEY_ID

# Run Service Screener
python screener.py --regions us-east-1 --services cloudtrail

# Cleanup
aws cloudtrail delete-trail --name test-trail
aws kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7
```

### Test CloudWatchAlarmsConfigured

```bash
# Create log group
aws logs create-log-group --log-group-name /aws/cloudtrail/test

# Create metric filter
aws logs put-metric-filter \
  --log-group-name /aws/cloudtrail/test \
  --filter-name UnauthorizedAPICalls \
  --filter-pattern '{ ($.errorCode = "*UnauthorizedOperation") }' \
  --metric-transformations \
    metricName=UnauthorizedAPICalls,metricNamespace=CloudTrailMetrics,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name UnauthorizedAPICallsAlarm \
  --metric-name UnauthorizedAPICalls \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold

# Run Service Screener
python screener.py --regions us-east-1 --services cloudtrail

# Cleanup
aws cloudwatch delete-alarms --alarm-names UnauthorizedAPICallsAlarm
aws logs delete-metric-filter --log-group-name /aws/cloudtrail/test --filter-name UnauthorizedAPICalls
aws logs delete-log-group --log-group-name /aws/cloudtrail/test
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the Service Screener documentation
3. Check AWS CloudTrail documentation for configuration details

## References

- [AWS CloudTrail Best Practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html)
- [CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [GuardDuty Best Practices](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_best-practices.html)
- [Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [CloudTrail KMS Encryption](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)
- [CloudWatch Alarms for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)

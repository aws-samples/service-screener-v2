# CloudWatch Service Screener Simulation

This directory contains simulation scripts to create test AWS resources for validating CloudWatch Service Screener checks.

## Overview

The simulation scripts create real AWS resources to test CloudWatch Service Screener checks across three tiers:

### Tier 1 Checks (Initial Implementation)
1. **alarmsWithoutSNS** - Validates that CloudWatch alarms have SNS notifications configured
2. **missingBillingAlarms** - Checks for billing alarms (us-east-1 only)

### Tier 2 Checks (High Priority)
3. **missingServiceQuotaAlarms** - Validates service quota monitoring alarms
4. **cloudwatchResourcesWithoutTags** - Checks for required cost allocation tags
5. **logGroupsWithoutLogInsightsUsage** - Identifies log groups without recent query activity
6. **missingCrossAccountDashboards** - Validates cross-account dashboard configuration

### Tier 3 Checks (Optimization)
7. **alarmsWithoutAutoScalingActions** - Checks Auto Scaling alarm integration
8. **missingApplicationSignals** - Validates Application Signals SLO configuration
9. **missingXRayIntegration** - Checks X-Ray sampling rules
10. **missingCloudWatchDashboards** - Validates dashboard existence
11. **missingCustomMetrics** - Checks for custom metric usage
12. **alarmsWithoutMetricMath** - Identifies opportunities for metric math
13. **missingCompositeAlarms** - Validates composite alarm configuration
14. **failedScheduledQueries** - Detects failed Log Insights queries
15. **missingVendedDashboards** - Checks for vended dashboard usage

## Prerequisites

### Required Tools
- **AWS CLI** - Version 2.x or later
  - Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
  - Verify: `aws --version`

### AWS Credentials
- AWS credentials must be configured with appropriate permissions
- Configure using: `aws configure`
- Or set environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`

### Required IAM Permissions

The AWS credentials must have the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricAlarm",
        "cloudwatch:DeleteAlarms",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:PutDashboard",
        "cloudwatch:DeleteDashboards",
        "cloudwatch:ListDashboards",
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:DescribeLogGroups",
        "logs:TagLogGroup",
        "logs:UntagLogGroup",
        "sns:CreateTopic",
        "sns:DeleteTopic",
        "sns:GetTopicAttributes",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Usage

### 1. Create Test Resources

Run the creation script to create test resources for all CloudWatch checks (Tier 1, 2, and 3):

```bash
cd service-screener-v2/services/cloudwatch/simulation
./create_test_resources.sh
```

**Optional: Specify a different region**
```bash
AWS_REGION=us-west-2 ./create_test_resources.sh
```

**What it creates:**

**Tier 1 Resources:**
- SNS topic: `service-screener-test-topic`
- CloudWatch alarm WITH SNS notification: `test-alarm-with-sns`
- CloudWatch alarm WITHOUT SNS notification: `test-alarm-without-sns`
- Billing alarm (us-east-1 only): `test-billing-alarm`

**Tier 2 & 3 Resources:**
- 4 CloudWatch alarms (service quota, untagged, autoscaling, metric math)
- 2 Log groups (untagged, no insights usage)
- 1 Dashboard (single-account, non-vended)

### 2. Run Service Screener

Navigate to the Service Screener root directory and run:

```bash
cd ../../..  # Go to service-screener-v2 root
python screener.py --regions us-east-1 --services cloudwatch
```

Or for a different region:
```bash
python screener.py --regions us-west-2 --services cloudwatch
```

### 3. Verify Results

Check the Service Screener output for the following expected results:

#### alarmsWithoutSNS Check
- **Should PASS**: `test-alarm-with-sns` (has SNS notification configured)
- **Should FAIL**: `test-alarm-without-sns` (no SNS notification)

#### missingBillingAlarms Check
- **In us-east-1**: Should PASS (billing alarm exists)
- **In other regions**: Check is skipped (billing metrics only available in us-east-1)

### 4. Clean Up Resources

After testing, delete all created resources:

```bash
cd services/cloudwatch/simulation
./cleanup_test_resources.sh
```

**Optional: Specify the same region used for creation**
```bash
AWS_REGION=us-west-2 ./cleanup_test_resources.sh
```

The cleanup script is **idempotent** - safe to run multiple times even if resources are already deleted. It will clean up all Tier 1, 2, and 3 test resources.

## Expected Service Screener Results

### Tier 1 Checks

#### alarmsWithoutSNS Check

**Expected Output:**
```
[FAIL] test-alarm-without-sns
  Reason: No SNS notifications configured
  Recommendation: Configure SNS topic actions for alarm notifications
```

**Expected PASS:**
```
[PASS] test-alarm-with-sns
```

#### missingBillingAlarms Check (us-east-1 only)

**Expected Output (when billing alarm exists):**
```
[PASS] Billing alarms configured
```

**Expected Output (when no billing alarm):**
```
[FAIL] No billing alarms configured
  Reason: No billing alarms found in us-east-1
  Recommendation: Configure billing alarms to monitor AWS costs
```

### Tier 2 and Tier 3 Checks

#### Expected Findings from Tier 2/3 Test Resources

**missingServiceQuotaAlarms:**
```
[FAIL] test-tier2-no-service-quota-alarm
  Reason: Alarm monitors AWS/EC2 but not service quotas
```

**cloudwatchResourcesWithoutTags:**
```
[FAIL] test-tier2-untagged-alarm
  Reason: Missing required tags: Environment, Project, CostCenter
[FAIL] /test/tier2/untagged-log-group
  Reason: Missing required tags: Environment, Project, CostCenter
```

**logGroupsWithoutLogInsightsUsage:**
```
[FAIL] /test/tier2/no-insights-usage
  Reason: No Log Insights queries executed in the last 30 days
```

**missingCrossAccountDashboards:**
```
[FAIL] test-tier2-single-account-dashboard
  Reason: Dashboard does not contain cross-account metrics
```

**alarmsWithoutAutoScalingActions:**
```
[FAIL] test-tier3-ec2-no-autoscaling
  Reason: Alarm monitors AWS/EC2 but has no Auto Scaling actions configured
```

**alarmsWithoutMetricMath:**
```
[FAIL] test-tier3-no-metric-math
  Reason: Alarm does not use metric math expressions
```

**missingVendedDashboards:**
```
[FAIL] test-tier2-single-account-dashboard
  Reason: Dashboard does not appear to be a vended dashboard
```

#### Account-Level Checks

These checks may trigger depending on your account configuration:

- **missingCompositeAlarms**: Triggers if no composite alarms exist
- **missingCloudWatchDashboards**: Passes if test dashboard exists
- **missingCustomMetrics**: Triggers if no custom metrics published
- **missingApplicationSignals**: Triggers if no SLOs configured
- **missingXRayIntegration**: Triggers if no X-Ray sampling rules

## Troubleshooting

### AWS CLI Not Found
```bash
# Install AWS CLI
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Windows
# Download and run: https://awscli.amazonaws.com/AWSCLIV2.msi
```

### AWS Credentials Not Configured
```bash
# Configure credentials interactively
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
```

### Permission Denied Errors
```bash
# Make scripts executable
chmod +x create_test_resources.sh
chmod +x cleanup_test_resources.sh
```

### SNS Topic Already Exists
The creation script handles existing SNS topics gracefully. If the topic already exists, it will reuse the existing topic ARN.

### Alarms Already Exist
The creation script will overwrite existing alarms with the same names. Use the cleanup script first if you want to start fresh.

### Billing Alarm Not Created
Billing alarms are only created when running in us-east-1 region. AWS billing metrics are only available in us-east-1.

## Cost Considerations

The test resources created by these scripts incur minimal AWS costs:

- **SNS Topic**: Free tier includes 1,000 notifications/month
- **CloudWatch Alarms**: $0.10 per alarm per month (first 10 alarms free)
- **CloudWatch Metrics**: Standard metrics are free

**Estimated monthly cost**: $0.00 - $0.30 (if within free tier)

**Note**: Remember to run the cleanup script after testing to avoid ongoing charges.

## Script Details

### create_test_resources.sh

Creates test resources for all CloudWatch checks (Tier 1, 2, and 3):

- **Tier 1 Resources**: SNS topic, alarms with/without SNS, billing alarm
- **Tier 2 Resources**: Untagged resources, log groups without insights usage, single-account dashboard
- **Tier 3 Resources**: Alarms without Auto Scaling actions, alarms without metric math
- **Error Handling**: Gracefully handles existing resources
- **Output**: Color-coded status messages with comprehensive summary

### cleanup_test_resources.sh

Deletes all test resources (Tier 1, 2, and 3):

- **Idempotent**: Safe to run multiple times
- **Error Handling**: Continues even if resources don't exist
- **Verification**: Checks for resource existence before deletion
- **Comprehensive**: Removes alarms, log groups, dashboards, and SNS topics
- **Output**: Confirms each deletion with detailed summary

## Integration with Service Screener

These simulation scripts are designed to work with the CloudWatch Service Screener checks:

1. **alarmsWithoutSNS** - Implemented in `drivers/CloudwatchAlarms.py`
   - Method: `_checkSNSNotifications()`
   - Validates: AlarmActions contain SNS topic ARNs

2. **missingBillingAlarms** - Implemented in `Cloudwatch.py`
   - Method: `checkBillingAlarms()`
   - Validates: Billing alarms exist in us-east-1

## Additional Resources

- [CloudWatch Alarm Best Practices](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Best-Practice-Alarms.html)
- [CloudWatch Billing Alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/monitor_estimated_charges_with_cloudwatch.html)
- [AWS CLI CloudWatch Commands](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/)
- [AWS CLI SNS Commands](https://docs.aws.amazon.com/cli/latest/reference/sns/)

## Support

For issues or questions:
1. Check the Troubleshooting section above
2. Verify AWS credentials and permissions
3. Review Service Screener logs for detailed error messages
4. Consult AWS CloudWatch documentation

## Version

- **Version**: 1.0
- **Last Updated**: 2024
- **Compatible with**: Service Screener v2

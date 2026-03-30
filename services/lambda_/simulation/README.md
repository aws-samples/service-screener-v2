# Lambda Service - Simulation Scripts

This directory contains scripts to create and cleanup test AWS resources for validating the new Lambda Service Screener checks.

## Overview

The simulation scripts create Lambda functions and related resources that intentionally trigger the new checks, allowing you to verify that the checks work correctly in a real AWS environment.

## Prerequisites

- AWS CLI installed and configured
- AWS credentials with permissions to create/delete:
  - Lambda functions
  - IAM roles
  - SQS queues
  - Kinesis streams
  - CloudWatch alarms
  - Event source mappings
- Bash shell (Linux, macOS, or WSL on Windows)

## Scripts

### 1. create_test_resources.sh

Creates test resources to validate new Lambda checks.

**Usage:**
```bash
./create_test_resources.sh [region]
```

**Example:**
```bash
# Create resources in us-east-1 (default)
./create_test_resources.sh

# Create resources in a specific region
./create_test_resources.sh us-west-2
```

**What it creates:**

| Resource | Purpose | Expected Check Result |
|----------|---------|----------------------|
| IAM Role (Basic) | Execution role for Lambda functions | - |
| IAM Role (Permissive) | Role with wildcard permissions for testing | - |
| SQS Queue | Queue with low visibility timeout (30s) | - |
| Kinesis Stream | Stream for testing stream-related checks | - |
| **Tier 1 Test Functions** | | |
| Lambda Function 1 | SQS trigger with timeout=60s | **FAIL**: lambdaSQSVisibilityTimeout |
| Lambda Function 2 | No async retry configuration | **FAIL**: lambdaAsyncRetryNotConfigured |
| Lambda Function 3 | No CloudWatch alarms | **FAIL**: lambdaNoCloudWatchAlarms |
| Lambda Function 4 | Kinesis trigger without partial batch response | **FAIL**: lambdaPartialBatchResponseDisabled |
| Lambda Function 5 | Kinesis trigger without batching window | **FAIL**: lambdaBatchingWindowNotConfigured |
| **Tier 2 Test Functions** | | |
| Lambda Function 6 | No environment variables | **FAIL**: lambdaNoEnvironmentVariables |
| Lambda Function 7 | Over-provisioned memory (3008MB) | **FAIL**: lambdaMemoryNotOptimized (requires invocations) |
| Lambda Function 8 | Low timeout (3s) | **FAIL**: lambdaTimeoutNotOptimized (requires invocations) |
| Lambda Function 9 | Permissive IAM role (wildcard permissions) | **FAIL**: lambdaRoleTooPermissive |
| **Pass Scenario** | | |
| Lambda Function 10 | Properly configured (async config + alarms + env vars) | **PASS**: All checks |

**Output:**
- Creates a resource file: `test_resources_<timestamp>.txt`
- This file contains resource names needed for cleanup

### 2. cleanup_test_resources.sh

Deletes all test resources created by `create_test_resources.sh`.

**Usage:**
```bash
./cleanup_test_resources.sh <resource_file>
```

**Example:**
```bash
./cleanup_test_resources.sh test_resources_1234567890.txt
```

**What it deletes:**
1. All Lambda functions
2. Event source mappings
3. CloudWatch alarms
4. Kinesis stream
5. SQS queue
6. IAM role and attached policies

## Testing Workflow

### Step 1: Make scripts executable
```bash
chmod +x create_test_resources.sh cleanup_test_resources.sh
```

### Step 2: Create test resources
```bash
./create_test_resources.sh us-east-1
```

**Expected output:**
```
Creating test resources in region: us-east-1
Account ID: 123456789012
Resource prefix: ss-lambda-test-1234567890

1. Creating IAM execution role...
   Created role: arn:aws:iam::123456789012:role/ss-lambda-test-1234567890-role
   ...
   
========================================
Test resources created successfully!
========================================

Summary:
  - IAM Roles: 2 (basic + permissive)
  - SQS Queue: ss-lambda-test-1234567890-queue
  - Kinesis Stream: ss-lambda-test-1234567890-stream
  - Lambda Functions: 10

Expected Check Results (Tier 1):
  - ss-lambda-test-1234567890-sqs-fail: FAIL (SQS visibility timeout)
  - ss-lambda-test-1234567890-no-async-config: FAIL (No async retry config)
  - ss-lambda-test-1234567890-no-alarms: FAIL (No CloudWatch alarms)
  - ss-lambda-test-1234567890-kinesis-fail: FAIL (No partial batch response)
  - ss-lambda-test-1234567890-no-batching: FAIL (No batching window)

Expected Check Results (Tier 2):
  - ss-lambda-test-1234567890-no-env-vars: FAIL (No environment variables)
  - ss-lambda-test-1234567890-memory-over: FAIL (Over-provisioned memory)
  - ss-lambda-test-1234567890-timeout-low: FAIL (Low timeout)
  - ss-lambda-test-1234567890-permissive-role: FAIL (Permissive IAM role)

Expected Check Results (PASS):
  - ss-lambda-test-1234567890-pass: PASS (Proper configuration)

To cleanup resources, run:
  ./cleanup_test_resources.sh test_resources_1234567890.txt
```

### Step 3: Run Service Screener

Navigate to the Service Screener root directory and run:

```bash
cd ../../..  # Go to service-screener-v2 root

# Run Service Screener for Lambda service
python screener.py --services lambda --regions us-east-1
```

### Step 4: Verify results

Check the Service Screener output for the new checks:

**Expected findings:**

**Tier 1 Checks:**

1. **lambdaSQSVisibilityTimeout** - Should flag `ss-lambda-test-*-sqs-fail`
   - Function timeout: 60s
   - SQS visibility timeout: 30s
   - Required: >= 360s (6 * 60)

2. **lambdaAsyncRetryNotConfigured** - Should flag `ss-lambda-test-*-no-async-config`
   - Using default retry configuration

3. **lambdaNoCloudWatchAlarms** - Should flag multiple functions
   - Functions without CloudWatch alarms for critical metrics

4. **lambdaPartialBatchResponseDisabled** - Should flag `ss-lambda-test-*-kinesis-fail`
   - Kinesis event source without ReportBatchItemFailures

5. **lambdaBatchingWindowNotConfigured** - Should flag `ss-lambda-test-*-no-batching`
   - Kinesis event source with batching window = 0

6. **lambdaNoIteratorAgeAlarm** - Should flag Kinesis consumers
   - Functions consuming streams without IteratorAge alarms

7. **lambdaGuardDutyProtectionDisabled** - Account-level check
   - Only flagged if GuardDuty Lambda Protection is not enabled

**Tier 2 Checks:**

8. **lambdaNoEnvironmentVariables** - Should flag `ss-lambda-test-*-no-env-vars`
   - Function without environment variables configured

9. **lambdaMemoryNotOptimized** - Should flag `ss-lambda-test-*-memory-over`
   - Over-provisioned memory (3008MB)
   - **Note:** Requires function invocations and CloudWatch Logs data to detect

10. **lambdaTimeoutNotOptimized** - Should flag `ss-lambda-test-*-timeout-low`
    - Low timeout configuration (3s)
    - **Note:** Requires function invocations and CloudWatch Metrics data to detect

11. **lambdaRoleTooPermissive** - Should flag `ss-lambda-test-*-permissive-role`
    - IAM role with wildcard permissions (Action: "*", Resource: "*")

12. **lambdaQuotasNotMonitored** - Account-level check
    - Flags if concurrent executions usage > 80% of quota

13. **lambdaNoReservedConcurrencyForThrottling** - Depends on throttling activity
    - Flags functions with throttles but no reserved concurrency

**Functions that should PASS:**
- `ss-lambda-test-*-pass` - Has async retry config, CloudWatch alarms, and environment variables

### Step 5: Cleanup resources

After testing, delete all resources:

```bash
cd services/lambda_/simulation
./cleanup_test_resources.sh test_resources_1234567890.txt
```

**Expected output:**
```
Loading resource information from: test_resources_1234567890.txt
Cleaning up test resources...
Region: us-east-1

1. Deleting Lambda functions...
   Deleting function: ss-lambda-test-1234567890-sqs-fail
   ...

========================================
Cleanup completed!
========================================

All test resources have been deleted.
Resource file: test_resources_1234567890.txt (you can delete this manually)
```

## Cost Considerations

**Estimated costs for running simulation:**
- Lambda functions: ~$0.00 (free tier covers this)
- SQS queue: ~$0.00 (minimal usage)
- Kinesis stream: ~$0.015/hour (1 shard)
- CloudWatch alarms: ~$0.10/month per alarm
- Data transfer: Negligible

**Total estimated cost:** < $0.50 for a 1-hour test

**Important:** Always run cleanup script after testing to avoid ongoing charges, especially for the Kinesis stream.

## Troubleshooting

### Issue: "Role not found" error when creating Lambda functions

**Solution:** The script includes a 10-second wait for IAM role propagation. If you still see this error, increase the wait time in `create_test_resources.sh`:

```bash
# Change from:
sleep 10

# To:
sleep 20
```

### Issue: "Stream not active" error

**Solution:** The script waits for the Kinesis stream to become active. If this times out, check your AWS service limits for Kinesis.

### Issue: Cleanup script fails to delete resources

**Solution:** Run the cleanup script again. Some resources (like event source mappings) may need time to fully delete before dependent resources can be removed.

### Issue: Permission denied when running scripts

**Solution:** Make scripts executable:
```bash
chmod +x *.sh
```

### Issue: Tier 2 memory/timeout checks not detecting issues

**Problem:** Memory and timeout optimization checks require CloudWatch Logs/Metrics data from actual function invocations.

**Solution:** 
1. Invoke the test functions multiple times:
   ```bash
   # For memory optimization check (function 7)
   for i in {1..10}; do
     aws lambda invoke --function-name ss-lambda-test-*-memory-over /dev/null
   done
   
   # For timeout optimization check (function 8)
   for i in {1..10}; do
     aws lambda invoke --function-name ss-lambda-test-*-timeout-low /dev/null
   done
   ```

2. Wait 5-10 minutes for CloudWatch data to be available

3. Run Service Screener again to detect the issues

### Issue: lambdaRoleTooPermissive not flagging function 9

**Problem:** IAM policy analysis may not detect all permission issues.

**Solution:** Verify the IAM role has wildcard permissions:
```bash
aws iam get-role-policy \
  --role-name ss-lambda-test-*-permissive-role \
  --policy-name WildcardPolicy
```

Expected output should show `"Action": "*"` and `"Resource": "*"`

## Check-Specific Notes

### Tier 1 Checks

### lambdaSQSVisibilityTimeout
- **Test scenario:** Function timeout = 60s, SQS visibility = 30s
- **Expected:** FAIL (visibility should be >= 360s)
- **Validation:** Check that function is flagged with appropriate message

### lambdaAsyncRetryNotConfigured
- **Test scenario:** No custom async invocation config
- **Expected:** FAIL (using defaults)
- **Validation:** Verify function is flagged for not having customized retry settings

### lambdaNoCloudWatchAlarms
- **Test scenario:** Functions without alarms on Errors, Duration, or Throttles
- **Expected:** FAIL for functions 1-9, PASS for function 10
- **Validation:** Only function 10 should have alarms configured

### lambdaPartialBatchResponseDisabled
- **Test scenario:** Kinesis event source without ReportBatchItemFailures
- **Expected:** FAIL
- **Validation:** Check event source mapping configuration

### lambdaBatchingWindowNotConfigured
- **Test scenario:** Kinesis event source with MaximumBatchingWindowInSeconds = 0
- **Expected:** FAIL
- **Validation:** Verify batching window is not configured

### lambdaNoIteratorAgeAlarm
- **Test scenario:** Kinesis consumers without IteratorAge alarms
- **Expected:** FAIL for functions 4 and 5
- **Validation:** Check CloudWatch alarms for IteratorAge metric

### lambdaGuardDutyProtectionDisabled
- **Test scenario:** Account-level check
- **Expected:** Depends on account configuration
- **Validation:** Check GuardDuty console for Lambda Protection status

### Tier 2 Checks

### lambdaNoEnvironmentVariables
- **Test scenario:** Function without environment variables
- **Expected:** FAIL for function 6
- **Validation:** Verify function has no Environment.Variables configured

### lambdaMemoryNotOptimized
- **Test scenario:** Function with 3008MB memory (over-provisioned)
- **Expected:** FAIL if actual usage < 50% of configured memory
- **Validation:** Requires function invocations to generate CloudWatch Logs data
- **Important:** You must invoke function 7 multiple times to generate usage data:
  ```bash
  aws lambda invoke --function-name ss-lambda-test-*-memory-over /dev/null
  ```
- **Wait time:** Allow 5-10 minutes for CloudWatch Logs to be available
- **Check:** Run Service Screener after invocations to detect over-provisioning

### lambdaTimeoutNotOptimized
- **Test scenario:** Function with 3s timeout (low)
- **Expected:** FAIL if max duration > 90% of timeout or < 10% of timeout
- **Validation:** Requires function invocations to generate CloudWatch Metrics
- **Important:** You must invoke function 8 multiple times to generate metrics:
  ```bash
  aws lambda invoke --function-name ss-lambda-test-*-timeout-low /dev/null
  ```
- **Wait time:** Allow 5-10 minutes for CloudWatch Metrics to be available
- **Check:** Run Service Screener after invocations to detect timeout issues

### lambdaRoleTooPermissive
- **Test scenario:** IAM role with wildcard permissions (Action: "*", Resource: "*")
- **Expected:** FAIL for function 9
- **Validation:** Check IAM role policies for wildcards
- **Note:** Path wildcards like `arn:aws:s3:::bucket/*` are excluded from detection

### lambdaQuotasNotMonitored
- **Test scenario:** Account-level check for concurrent executions quota
- **Expected:** FAIL if usage > 80% of quota
- **Validation:** Check Service Quotas for concurrent executions limit
- **Note:** This check runs once per scan, not per function

### lambdaNoReservedConcurrencyForThrottling
- **Test scenario:** Functions with throttles but no reserved concurrency
- **Expected:** FAIL if throttles detected in last 7 days
- **Validation:** Requires actual throttling events in CloudWatch Metrics
- **Note:** Difficult to test without generating real throttling

## Additional Resources

- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [AWS Lambda with Amazon SQS](https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html)
- [AWS Lambda with Kinesis](https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html)
- [Asynchronous invocation](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html)
- [Reporting batch item failures](https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html#services-kinesis-batchfailurereporting)

## Support

For issues or questions about these simulation scripts, please refer to the main Service Screener documentation or create an issue in the project repository.

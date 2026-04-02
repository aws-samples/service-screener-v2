# SQS Test Resources Simulation

This directory contains scripts to create and cleanup test SQS queues for validating the 3 new Service Screener checks:

1. **LongPollingConfiguration** - Detects queues using short polling (cost optimization)
2. **WildcardPrincipalDetection** - Detects queues with wildcard principals in policies (security)
3. **MaxReceiveCountDetection** - Detects queues with maxReceiveCount=1 (reliability anti-pattern)

## Prerequisites

- AWS CLI installed and configured
- AWS credentials with permissions to:
  - Create/delete SQS queues
  - Set queue attributes and policies
  - Get caller identity (for account ID)
- `jq` command-line JSON processor (for policy formatting)

## Quick Start

### 1. Create Test Resources

```bash
cd service-screener-v2/services/sqs/simulation
./create_test_resources.sh
```

This creates 12 test queues:
- 1 Dead Letter Queue
- 3 Long Polling test queues (short, suboptimal, optimal)
- 4 Wildcard Principal test queues (no policy, wildcard, wildcard with conditions, specific)
- 4 MaxReceiveCount test queues (1, 2, 3, 5)

### 2. Run Service Screener

```bash
cd ../../..  # Back to service-screener-v2 root
python screener.py --regions us-east-1 --services sqs
```

### 3. Review Results

Check the generated report for the 3 new checks:
- **LongPollingConfiguration**: Should flag short polling and suboptimal queues
- **WildcardPrincipalDetection**: Should flag wildcard principal queues
- **MaxReceiveCountDetection**: Should flag maxReceiveCount=1 and =2 queues

### 4. Cleanup Test Resources

```bash
cd services/sqs/simulation
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

### Test Queue Details

#### LongPollingConfiguration Test Queues

| Queue Name | ReceiveMessageWaitTimeSeconds | Expected Result |
|------------|------------------------------|-----------------|
| `ss-test-sqs-short-polling-*` | 0 | FAIL (Critical) |
| `ss-test-sqs-suboptimal-polling-*` | 3 | WARNING |
| `ss-test-sqs-long-polling-*` | 10 | PASS |

#### WildcardPrincipalDetection Test Queues

| Queue Name | Policy | Expected Result |
|------------|--------|-----------------|
| `ss-test-sqs-no-policy-*` | None | PASS |
| `ss-test-sqs-wildcard-principal-*` | Principal: "*" | FAIL (Critical) |
| `ss-test-sqs-wildcard-with-conditions-*` | Principal: "*" with Condition | WARNING |
| `ss-test-sqs-specific-principal-*` | Principal: specific ARN | PASS |

#### MaxReceiveCountDetection Test Queues

| Queue Name | maxReceiveCount | Expected Result |
|------------|-----------------|-----------------|
| `ss-test-sqs-max-receive-1-*` | 1 | FAIL (Anti-pattern) |
| `ss-test-sqs-max-receive-2-*` | 2 | WARNING |
| `ss-test-sqs-max-receive-3-*` | 3 | PASS |
| `ss-test-sqs-max-receive-5-*` | 5 | PASS |

*Note: Queue names include a timestamp suffix for uniqueness*

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
        "sqs:CreateQueue",
        "sqs:DeleteQueue",
        "sqs:SetQueueAttributes",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

#### jq Not Found

The `create_test_resources.sh` script requires `jq` for JSON formatting. Install it:

- **macOS**: `brew install jq`
- **Ubuntu/Debian**: `sudo apt-get install jq`
- **Amazon Linux**: `sudo yum install jq`

#### Cleanup Issues

If cleanup fails due to dependency issues (e.g., DLQ still referenced), the script automatically:
1. Deletes source queues first
2. Waits 5 seconds
3. Deletes DLQ queues

If issues persist, manually delete queues from AWS Console or wait a few minutes and retry.

#### Timestamp File

The `create_test_resources.sh` script saves a timestamp to `.last_test_timestamp`. This helps the cleanup script identify the exact queues created. If this file is lost, the cleanup script will still work by searching for all queues with the `ss-test-sqs` prefix.

## Cost Considerations

- SQS queues themselves are free (no charge for queue creation)
- You only pay for API requests and data transfer
- These test queues should cost less than $0.01 if cleaned up promptly
- Always run cleanup after testing to avoid unnecessary costs

## Integration with CI/CD

You can integrate these scripts into your CI/CD pipeline:

```bash
#!/bin/bash
set -e

# Create test resources
./create_test_resources.sh

# Run Service Screener
cd ../../..
python screener.py --regions us-east-1 --services sqs --output-format json > results.json

# Validate results (example)
python -c "
import json
with open('results.json') as f:
    results = json.load(f)
    # Add your validation logic here
"

# Cleanup (always run, even if tests fail)
cd services/sqs/simulation
./cleanup_test_resources.sh || true
```

## Manual Testing

If you prefer to test individual checks manually:

### Test LongPollingConfiguration

```bash
# Create a queue with short polling
aws sqs create-queue --queue-name test-short-polling \
  --attributes '{"ReceiveMessageWaitTimeSeconds":"0"}'

# Run Service Screener
python screener.py --regions us-east-1 --services sqs

# Cleanup
aws sqs delete-queue --queue-url <queue-url>
```

### Test WildcardPrincipalDetection

```bash
# Create a queue
QUEUE_URL=$(aws sqs create-queue --queue-name test-wildcard \
  --query 'QueueUrl' --output text)

# Set wildcard policy
aws sqs set-queue-attributes --queue-url $QUEUE_URL \
  --attributes 'Policy={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}]}'

# Run Service Screener
python screener.py --regions us-east-1 --services sqs

# Cleanup
aws sqs delete-queue --queue-url $QUEUE_URL
```

### Test MaxReceiveCountDetection

```bash
# Create DLQ
DLQ_URL=$(aws sqs create-queue --queue-name test-dlq \
  --query 'QueueUrl' --output text)
DLQ_ARN=$(aws sqs get-queue-attributes --queue-url $DLQ_URL \
  --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)

# Create queue with maxReceiveCount=1
aws sqs create-queue --queue-name test-max-receive-1 \
  --attributes "{\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"$DLQ_ARN\\\",\\\"maxReceiveCount\\\":1}\"}"

# Run Service Screener
python screener.py --regions us-east-1 --services sqs

# Cleanup
aws sqs delete-queue --queue-url <source-queue-url>
aws sqs delete-queue --queue-url $DLQ_URL
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the Service Screener documentation
3. Check AWS SQS documentation for queue configuration details

## References

- [AWS SQS Best Practices](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-best-practices.html)
- [SQS Long Polling](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-short-and-long-polling.html)
- [SQS Security Best Practices](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html)
- [SQS Dead Letter Queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)

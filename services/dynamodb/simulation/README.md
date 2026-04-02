# DynamoDB Simulation Scripts

This directory contains scripts to create and clean up test DynamoDB tables for validating the new checks implemented in the DynamoDB service review.

## New Checks Covered

These simulation scripts help test the following 3 new DynamoDB checks:

1. **Encryption at Rest** (`encryptionAtRest`)
   - Verifies tables have encryption enabled with AWS KMS keys
   - Criticality: High
   - Category: Security

2. **Global Table Version** (`globalTableVersion`)
   - Checks that global tables use current version (2019.11.21) instead of legacy (2017.11.29)
   - Criticality: Medium
   - Category: Reliability

3. **Table Class Optimization** (`tableClassOptimization`)
   - Recommends Standard-IA table class for large tables with infrequent access
   - Criticality: Low
   - Category: Cost Optimization

## Prerequisites

- AWS CLI installed and configured
- AWS credentials with permissions to:
  - Create/delete DynamoDB tables
  - Update table settings (encryption, table class, replicas)
  - List tables
- Bash shell environment

## Scripts

### 1. create_test_resources.sh

Creates test DynamoDB tables to validate all three new checks.

**Usage:**
```bash
./create_test_resources.sh
```

**Environment Variables:**
- `AWS_REGION` - Primary region for tables (default: us-east-1)
- `AWS_REPLICA_REGION` - Region for global table replica (default: us-west-2)

**Example:**
```bash
# Use default regions
./create_test_resources.sh

# Specify custom regions
AWS_REGION=eu-west-1 AWS_REPLICA_REGION=eu-central-1 ./create_test_resources.sh
```

**Created Resources:**

The script creates 6 test tables:

| Table Name Pattern | Check | Expected Result |
|-------------------|-------|-----------------|
| `ss-test-dynamodb-no-encryption-*` | Encryption at Rest | FAIL - No encryption |
| `ss-test-dynamodb-kms-encryption-*` | Encryption at Rest | PASS - KMS encryption |
| `ss-test-dynamodb-global-*` | Global Table Version | PASS - Current version |
| `ss-test-dynamodb-standard-large-*` | Table Class | FAIL - Large Standard table |
| `ss-test-dynamodb-standard-ia-*` | Table Class | PASS - Using Standard-IA |
| `ss-test-dynamodb-standard-small-*` | Table Class | PASS - Small Standard table |

**Notes:**
- All tables use PAY_PER_REQUEST billing mode to avoid ongoing costs
- The script includes an optional step to add test data to increase table size
- Global table creation may take several minutes
- Tables are tagged with timestamp for easy identification

### 2. cleanup_test_resources.sh

Deletes all test tables created by the create script.

**Usage:**
```bash
./cleanup_test_resources.sh
```

**Environment Variables:**
- `AWS_REGION` - Region where tables were created (default: us-east-1)
- `AWS_REPLICA_REGION` - Region where replicas were created (default: us-west-2)

**Example:**
```bash
# Use default region
./cleanup_test_resources.sh

# Specify custom region
AWS_REGION=eu-west-1 ./cleanup_test_resources.sh
```

**Features:**
- Lists all tables with prefix `ss-test-dynamodb`
- Prompts for confirmation before deletion
- Removes global table replicas before deleting primary table
- Disables deletion protection if enabled
- Provides summary of deleted resources

## Testing Workflow

### Step 1: Create Test Resources

```bash
cd service-screener-v2/services/dynamodb/simulation
chmod +x *.sh
./create_test_resources.sh
```

Wait for all tables to be created (typically 2-5 minutes).

### Step 2: Run Service Screener

```bash
cd ../../..  # Back to service-screener-v2 root
python screener.py --regions us-east-1 --services dynamodb
```

### Step 3: Review Results

Check the output for the new checks:

**Expected Results:**

1. **Encryption at Rest**
   - `ss-test-dynamodb-no-encryption-*`: Should FAIL (no encryption)
   - `ss-test-dynamodb-kms-encryption-*`: Should PASS (KMS encryption)

2. **Global Table Version**
   - `ss-test-dynamodb-global-*`: Should PASS (current version 2019.11.21)

3. **Table Class Optimization**
   - `ss-test-dynamodb-standard-large-*`: Should FAIL if >10GB (recommend Standard-IA)
   - `ss-test-dynamodb-standard-ia-*`: Should PASS (already using Standard-IA)
   - `ss-test-dynamodb-standard-small-*`: Should PASS (too small for recommendation)

### Step 4: Clean Up Resources

```bash
cd services/dynamodb/simulation
./cleanup_test_resources.sh
```

Confirm deletion when prompted.

## Cost Considerations

- **PAY_PER_REQUEST billing**: No cost when tables are idle
- **Storage costs**: Minimal for empty tables (~$0.25/GB/month)
- **Global table replication**: May incur small data transfer costs
- **Recommendation**: Clean up resources promptly after testing

**Estimated costs for full test cycle**: < $0.10 USD

## Troubleshooting

### Issue: Permission Denied

**Error:**
```
bash: ./create_test_resources.sh: Permission denied
```

**Solution:**
```bash
chmod +x create_test_resources.sh cleanup_test_resources.sh
```

### Issue: Table Already Exists

**Error:**
```
An error occurred (ResourceInUseException) when calling the CreateTable operation
```

**Solution:**
- Tables may exist from previous test run
- Run cleanup script first: `./cleanup_test_resources.sh`
- Wait a few minutes for deletion to complete
- Retry creation script

### Issue: Global Table Replica Creation Fails

**Error:**
```
An error occurred (ValidationException) when calling the UpdateTable operation
```

**Possible Causes:**
- Insufficient permissions in replica region
- Replica region doesn't support DynamoDB
- Table streams not enabled (script handles this)

**Solution:**
- Verify AWS credentials have permissions in both regions
- Check that replica region supports DynamoDB
- The script will continue even if replica creation fails

### Issue: Table Size Not Increasing

**Problem:**
Table remains small even after adding items.

**Solution:**
- DynamoDB table size updates are not immediate
- Wait 6-24 hours for accurate size metrics
- Alternatively, add more items (increase count in script)
- For testing purposes, the check logic can be verified with unit tests

## Manual Testing

If you prefer to create tables manually:

### Encryption at Rest - FAIL Case
```bash
aws dynamodb create-table \
    --table-name test-no-encryption \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1
```

### Encryption at Rest - PASS Case
```bash
aws dynamodb create-table \
    --table-name test-kms-encryption \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --sse-specification Enabled=true,SSEType=KMS \
    --region us-east-1
```

### Table Class - Standard-IA
```bash
aws dynamodb create-table \
    --table-name test-standard-ia \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --table-class STANDARD_INFREQUENT_ACCESS \
    --region us-east-1
```

## Additional Resources

- [DynamoDB Encryption at Rest](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html)
- [Global Tables Version Comparison](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables.V2.html)
- [DynamoDB Table Classes](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.TableClasses.html)
- [Service Screener Documentation](../../README.md)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review unit tests in `tests/test_dynamodb_new_checks.py`
3. Consult the implementation in `drivers/DynamoDbCommon.py`
4. Review the check definitions in `dynamodb.reporter.json`

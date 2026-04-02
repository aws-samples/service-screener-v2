# ElastiCache Simulation Scripts

This directory contains scripts to create and clean up test ElastiCache resources for validating the new checks implemented in the service review.

## New Checks Validated

1. **ClusterModeEnabled**: Verifies Redis replication groups have cluster mode enabled
2. **MultiAZEnabled**: Checks Multi-AZ with automatic failover is configured
3. **BackupEnabled**: Validates automatic backups are enabled with retention
4. **IdleTimeout**: Checks server-side idle timeout is properly configured
5. **ServerlessReadReplica**: Verifies serverless caches have reader endpoints

## Prerequisites

- AWS CLI installed and configured
- AWS credentials with permissions to create/delete ElastiCache resources
- Default VPC with at least 2 subnets in the target region

## Scripts

### create_test_resources.sh

Creates test ElastiCache resources including:
- 1 cache subnet group
- 1 custom parameter group (with timeout=300)
- 4 replication groups:
  - `test-rg-pass`: All checks pass (cluster mode, Multi-AZ, backups enabled)
  - `test-rg-fail-cluster`: Cluster mode disabled (FAIL ClusterModeEnabled)
  - `test-rg-fail-multiaz`: Multi-AZ disabled (FAIL MultiAZEnabled)
  - `test-rg-fail-backup`: Backups disabled (FAIL BackupEnabled)
- 2 serverless caches (if supported in region):
  - `test-serverless-pass`: Reader endpoint enabled (PASS)
  - `test-serverless-fail`: No reader endpoint (FAIL ServerlessReadReplica)

**Usage:**
```bash
# Use default region (us-east-1)
./create_test_resources.sh

# Specify region
AWS_REGION=us-west-2 ./create_test_resources.sh
```

**Note**: Resources take 10-15 minutes to become available.

### cleanup_test_resources.sh

Deletes all test resources created by `create_test_resources.sh`.

**Usage:**
```bash
# Use default region (us-east-1)
./cleanup_test_resources.sh

# Specify region
AWS_REGION=us-west-2 ./cleanup_test_resources.sh
```

**Note**: Cleanup takes 5-10 minutes to complete.

## Testing Workflow

1. **Create test resources:**
   ```bash
   chmod +x create_test_resources.sh cleanup_test_resources.sh
   ./create_test_resources.sh
   ```

2. **Wait for resources to be available:**
   ```bash
   aws elasticache describe-replication-groups --region us-east-1 \
       --query 'ReplicationGroups[?starts_with(ReplicationGroupId, `test-rg`)].{ID:ReplicationGroupId,Status:Status}'
   ```

3. **Run Service Screener:**
   ```bash
   cd ../../../
   python screener.py --services elasticache --regions us-east-1
   ```

4. **Verify expected results:**
   - `test-rg-pass`: Should pass all checks
   - `test-rg-fail-cluster`: Should fail ClusterModeEnabled
   - `test-rg-fail-multiaz`: Should fail MultiAZEnabled
   - `test-rg-fail-backup`: Should fail BackupEnabled
   - `test-serverless-pass`: Should pass ServerlessReadReplica
   - `test-serverless-fail`: Should fail ServerlessReadReplica

5. **Clean up resources:**
   ```bash
   ./cleanup_test_resources.sh
   ```

## Cost Considerations

Test resources incur AWS charges:
- Replication groups: ~$0.017/hour per cache.t3.micro node (4 groups × 2-4 nodes = ~$0.14/hour)
- Serverless caches: ~$0.125/hour per cache (2 caches = ~$0.25/hour)
- **Total estimated cost**: ~$0.40/hour or ~$9.60/day

**Recommendation**: Delete resources immediately after testing to minimize costs.

## Troubleshooting

### Subnet group creation fails
- Ensure default VPC exists in the region
- Verify at least 2 subnets are available
- Check AWS CLI credentials have necessary permissions

### Replication group creation fails
- Check ElastiCache service limits in the region
- Verify subnet group was created successfully
- Ensure no naming conflicts with existing resources

### Serverless cache creation fails
- ElastiCache Serverless may not be available in all regions
- Check if the region supports serverless caches
- Verify subnet configuration meets serverless requirements

### Resources not deleting
- Some resources may have dependencies (e.g., snapshots)
- Check AWS Console for detailed error messages
- Manually delete dependent resources if needed

## Region Support

### Replication Groups
Supported in all AWS regions where ElastiCache is available.

### Serverless Caches
ElastiCache Serverless is available in select regions. Check AWS documentation for current availability:
https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/serverless.html

## Security Notes

- Resources are created in default VPC with default security groups
- Transit encryption is enabled for replication groups
- At-rest encryption is enabled for replication groups
- For production testing, use dedicated VPCs and security groups

## Additional Resources

- [ElastiCache User Guide](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/)
- [ElastiCache API Reference](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/)
- [AWS CLI ElastiCache Commands](https://docs.aws.amazon.com/cli/latest/reference/elasticache/)

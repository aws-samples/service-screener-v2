# EFS Service Screener - Simulation Scripts

This directory contains scripts to create and clean up AWS EFS test resources for validating the Service Screener checks.

## Overview

The simulation scripts create three test file systems with different configurations to validate all 11 implemented EFS checks:

1. **Compliant File System** - Passes all checks
2. **Non-Compliant File System** - Fails multiple checks
3. **Partially Compliant File System** - Passes some checks, fails others

## Prerequisites

Before running the simulation scripts, ensure you have:

- AWS CLI installed and configured
- AWS credentials with permissions to:
  - Create/delete EFS file systems, mount targets, access points
  - Create/delete VPC, subnets, security groups
  - Create/delete IAM policies
  - Enable EFS replication (optional)
- `jq` installed for JSON parsing (optional, for enhanced output)
- Sufficient AWS service quotas for EFS resources

## Files

- `create_test_resources.sh` - Creates test EFS resources
- `cleanup_test_resources.sh` - Removes all test resources
- `README.md` - This file

## Usage

### 1. Create Test Resources

```bash
# Make the script executable
chmod +x create_test_resources.sh

# Run the script (uses us-east-1 by default)
./create_test_resources.sh

# Or specify a different region
AWS_REGION=us-west-2 ./create_test_resources.sh
```

The script will:
- Create a VPC, subnet, and security group
- Create 3 EFS file systems with different configurations
- Create mount targets, access points, and policies as needed
- Output resource IDs for later cleanup

**Important:** Save the resource IDs output at the end. You can copy the provided command to create a `test_resources.env` file.

### 2. Run Service Screener

After creating the test resources, run the Service Screener against your AWS account:

```bash
# Navigate to the service-screener-v2 directory
cd ../../..

# Run the screener (adjust command based on your setup)
python screener.py --region us-east-1 --services efs
```

### 3. Verify Results

Compare the Service Screener output against the expected results:

#### Test Case 1: Compliant File System
**Expected:** Should PASS all checks
- ✅ EncryptedAtRest
- ✅ EnabledLifecycle
- ✅ AutomatedBackup
- ✅ ElasticThroughput
- ✅ ReplicationEnabled
- ✅ ThroughputModeOptimized
- ✅ FileSystemPolicy
- ✅ MountTargetSecurityGroups
- ✅ AccessPointsConfigured
- ✅ ComprehensiveSecurity
- ✅ TLSRequired
- ✅ PerformanceModeOptimized
- ✅ StorageOptimization
- ✅ NoSensitiveDataInTags

#### Test Case 2: Non-Compliant File System
**Expected:** Should FAIL multiple checks
- ✅ EncryptedAtRest (passes - encryption enabled)
- ❌ EnabledLifecycle (fails - no lifecycle policy)
- ❌ AutomatedBackup (fails - backup not enabled)
- ❌ ElasticThroughput (fails - using bursting mode)
- ❌ ReplicationEnabled (fails - no replication)
- ❌ ThroughputModeOptimized (fails - using bursting mode)
- ❌ FileSystemPolicy (fails - no policy)
- ❌ MountTargetSecurityGroups (fails - no security group)
- ❌ AccessPointsConfigured (fails - no access points)
- ❌ ComprehensiveSecurity (fails - missing all 3 controls)
- ❌ TLSRequired (fails - no policy)
- ❌ PerformanceModeOptimized (fails - using maxIO)
- ✅ StorageOptimization (passes - empty file system)
- ❌ NoSensitiveDataInTags (fails - has 'password' and 'api-key' tags)

#### Test Case 3: Partially Compliant File System
**Expected:** Should PASS some checks and FAIL others
- ✅ EncryptedAtRest (passes)
- ✅ EnabledLifecycle (passes)
- ✅ AutomatedBackup (passes)
- ❌ ElasticThroughput (fails - using provisioned mode)
- ❌ ReplicationEnabled (fails - no replication)
- ❌ ThroughputModeOptimized (fails - using provisioned mode)
- ✅ FileSystemPolicy (passes - policy exists)
- ✅ MountTargetSecurityGroups (passes)
- ❌ AccessPointsConfigured (fails - no access points)
- ❌ ComprehensiveSecurity (fails - missing access points)
- ❌ TLSRequired (fails - policy doesn't require TLS)
- ✅ PerformanceModeOptimized (passes - using generalPurpose)
- ✅ StorageOptimization (passes)
- ✅ NoSensitiveDataInTags (passes)

### 4. Clean Up Test Resources

After testing, remove all created resources:

```bash
# Make the cleanup script executable
chmod +x cleanup_test_resources.sh

# Source the resource IDs (if you saved them)
source test_resources.env

# Run the cleanup script
./cleanup_test_resources.sh
```

**Important:** The cleanup script requires resource IDs. Either:
- Source the `test_resources.env` file created during setup
- Set environment variables manually before running cleanup

## Resource Details

### Test Case 1: Compliant File System
- **Encryption:** At rest (enabled)
- **Performance Mode:** General Purpose
- **Throughput Mode:** Elastic
- **Lifecycle:** Enabled (30 days to IA)
- **Backup:** Enabled
- **Replication:** Enabled (to us-west-2)
- **Mount Target:** With security group
- **Access Point:** Configured
- **File System Policy:** Configured with TLS requirement
- **Tags:** Clean (no sensitive data)

### Test Case 2: Non-Compliant File System
- **Encryption:** At rest (enabled)
- **Performance Mode:** Max I/O
- **Throughput Mode:** Bursting
- **Lifecycle:** Disabled
- **Backup:** Disabled
- **Replication:** Disabled
- **Mount Target:** Without security group
- **Access Point:** None
- **File System Policy:** None
- **Tags:** Contains sensitive patterns ('password', 'api-key')

### Test Case 3: Partially Compliant File System
- **Encryption:** At rest (enabled)
- **Performance Mode:** General Purpose
- **Throughput Mode:** Provisioned (10 MiB/s)
- **Lifecycle:** Enabled (7 days to IA)
- **Backup:** Enabled
- **Replication:** Disabled
- **Mount Target:** With security group
- **Access Point:** None
- **File System Policy:** Configured (but no TLS requirement)
- **Tags:** Clean

## Cost Considerations

Running these simulation scripts will incur AWS charges:
- EFS file systems (minimal if empty)
- EFS mount targets
- EFS access points
- VPC resources (usually free tier eligible)
- Data transfer for replication (if enabled)

**Estimated cost:** < $1 USD for a few hours of testing

**Important:** Always run the cleanup script after testing to avoid ongoing charges.

## Troubleshooting

### Script Fails with Permission Errors
- Verify your AWS credentials have the required permissions
- Check IAM policies allow EFS, EC2, and VPC operations

### Replication Fails
- Replication may not be available in all regions
- The script will continue even if replication fails
- This is expected and won't affect other checks

### Cleanup Script Can't Find Resources
- Ensure you've sourced the `test_resources.env` file
- Verify resource IDs are set as environment variables
- Check resources weren't manually deleted

### Mount Target Deletion Hangs
- Mount targets can take 1-2 minutes to delete
- The script waits automatically
- If it times out, wait a few minutes and re-run cleanup

## Manual Cleanup

If the cleanup script fails, you can manually delete resources:

```bash
# Delete file systems
aws efs delete-file-system --file-system-id <FS_ID> --region us-east-1

# Delete mount targets (must be done before file system)
aws efs delete-mount-target --mount-target-id <MT_ID> --region us-east-1

# Delete access points
aws efs delete-access-point --access-point-id <AP_ID> --region us-east-1

# Delete security group
aws ec2 delete-security-group --group-id <SG_ID> --region us-east-1

# Delete subnet
aws ec2 delete-subnet --subnet-id <SUBNET_ID> --region us-east-1

# Delete VPC
aws ec2 delete-vpc --vpc-id <VPC_ID> --region us-east-1
```

## Support

For issues or questions:
1. Check the Service Screener documentation
2. Review AWS EFS documentation
3. Verify AWS CLI is properly configured
4. Check AWS service quotas and limits

## Notes

- These scripts are for testing purposes only
- Do not run in production environments
- Always clean up resources after testing
- Resource IDs are unique per execution
- Scripts use tags for easy identification (`Project=efs-service-screener-test`)

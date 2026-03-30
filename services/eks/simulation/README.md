# EKS Service Review - Simulation Scripts

This directory contains AWS CLI scripts to create test EKS resources that trigger the 6 new Tier 1 checks implemented in the EKS service review.

## Purpose

These scripts help validate the new EKS checks by creating real AWS resources with specific configurations that should trigger each check:

1. **eksNoManagedNodeGroups** - Cluster without managed node groups
2. **eksNodeGroupSingleAZ** - Node group deployed in a single availability zone
3. **eksClusterLoggingIncomplete** - Cluster with incomplete control plane logging
4. **eksSecretsEncryptionNoKMS** - Cluster without customer-managed KMS key for secrets encryption
5. **eksNoSpotInstances** - Cluster without Spot instance node groups
6. **eksNoKarpenter** - Cluster without Karpenter add-on installed

## Prerequisites

### Required Tools
- **AWS CLI** - Version 2.x or later
- **jq** - JSON processor (optional, for parsing outputs)
- **Bash** - Version 4.0 or later

### AWS Permissions

The IAM user/role running these scripts needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:CreateCluster",
        "eks:DeleteCluster",
        "eks:DescribeCluster",
        "eks:CreateNodegroup",
        "eks:DeleteNodegroup",
        "eks:DescribeNodegroup",
        "eks:ListNodegroups",
        "eks:ListAddons",
        "eks:TagResource",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:PassRole",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

### AWS Infrastructure

You need an existing VPC with:
- **At least 2 subnets** in different availability zones
- Subnets must have internet connectivity (NAT Gateway or Internet Gateway)
- Appropriate security groups allowing EKS control plane communication

## Usage

### Step 1: Create Test Resources

```bash
./create_test_resources.sh \
  --vpc-id vpc-xxxxxxxxx \
  --subnet-ids subnet-aaaaa,subnet-bbbbb \
  --region us-east-1 \
  --cluster-name eks-test
```

**Parameters:**
- `--vpc-id` (required) - VPC ID where clusters will be created
- `--subnet-ids` (required) - Comma-separated list of subnet IDs (minimum 2, in different AZs)
- `--region` (optional) - AWS region (default: us-east-1)
- `--cluster-name` (optional) - Cluster name prefix (default: eks-test)

**Output:**
- Creates 6 EKS clusters with specific configurations
- Generates a resource file: `created_resources_YYYYMMDD-HHMMSS.txt`
- Displays progress and status for each resource

**Duration:** Approximately 30-45 minutes (clusters are created sequentially)

**Example:**
```bash
./create_test_resources.sh \
  --vpc-id vpc-0123456789abcdef0 \
  --subnet-ids subnet-0a1b2c3d,subnet-4e5f6g7h,subnet-8i9j0k1l \
  --region us-west-2 \
  --cluster-name my-test
```

### Step 2: Run Service Screener

After all resources are created and active:

```bash
cd ../../..  # Navigate to service-screener-v2 root
python screener.py --regions us-east-1 --services eks
```

### Step 3: Verify Results

Check the Service Screener output to confirm all 6 checks are triggered:

```
✓ eksNoManagedNodeGroups - FAIL (expected)
✓ eksNodeGroupSingleAZ - FAIL (expected)
✓ eksClusterLoggingIncomplete - FAIL (expected)
✓ eksSecretsEncryptionNoKMS - FAIL (expected)
✓ eksNoSpotInstances - FAIL (expected)
✓ eksNoKarpenter - FAIL (expected)
```

### Step 4: Clean Up Resources

**IMPORTANT:** Clean up resources to avoid ongoing AWS charges!

```bash
./cleanup_test_resources.sh created_resources_YYYYMMDD-HHMMSS.txt --region us-east-1
```

**Parameters:**
- First argument (required) - Path to the resource file from create script
- `--region` (optional) - AWS region (default: us-east-1)
- `--force` (optional) - Skip confirmation prompts

**Duration:** Approximately 15-20 minutes

**Example:**
```bash
./cleanup_test_resources.sh created_resources_20240115-143022.txt --region us-west-2 --force
```

## Resource Details

### Test 1: eksNoManagedNodeGroups
**Cluster:** `eks-test-no-ng-TIMESTAMP`
- Creates cluster without any managed node groups
- Triggers check that validates managed node group usage

### Test 2: eksNodeGroupSingleAZ
**Cluster:** `eks-test-single-az-TIMESTAMP`
- Creates cluster with node group in single AZ only
- Uses only the first subnet from provided list
- Triggers check that validates multi-AZ deployment

### Test 3: eksClusterLoggingIncomplete
**Cluster:** `eks-test-no-logging-TIMESTAMP`
- Creates cluster with only API logging enabled
- Missing: audit, authenticator, controllerManager, scheduler logs
- Triggers check that validates complete logging configuration

### Test 4: eksSecretsEncryptionNoKMS
**Cluster:** `eks-test-no-kms-TIMESTAMP`
- Creates cluster without secrets encryption configuration
- Uses default AWS-managed encryption
- Triggers check that validates customer-managed KMS key usage

### Test 5: eksNoSpotInstances
**Cluster:** `eks-test-no-spot-TIMESTAMP`
- Creates cluster with ON_DEMAND capacity type only
- No Spot instance node groups
- Triggers check that validates Spot instance usage for cost optimization

### Test 6: eksNoKarpenter
**Cluster:** `eks-test-no-karpenter-TIMESTAMP`
- Creates cluster without Karpenter add-on
- Uses standard managed node groups
- Triggers check that validates Karpenter installation

## Cost Considerations

**Estimated Costs (per hour):**
- EKS Control Plane: $0.10/hour × 6 clusters = **$0.60/hour**
- EC2 Instances (t3.medium): $0.0416/hour × 4 node groups = **$0.17/hour**
- **Total: ~$0.77/hour** or **~$18.50/day**

**Cost Optimization Tips:**
1. Run tests during business hours only
2. Clean up immediately after validation
3. Use smaller instance types if testing logic only (not performance)
4. Consider using a single test cluster at a time

## Troubleshooting

### Issue: "Cluster creation failed"
**Possible causes:**
- Insufficient IAM permissions
- VPC/subnet configuration issues
- Service quotas exceeded
- Region doesn't support EKS

**Solution:**
- Check CloudTrail logs for detailed error messages
- Verify IAM permissions match prerequisites
- Check EKS service quotas in AWS Console
- Ensure subnets have proper tags and routing

### Issue: "Node group creation stuck"
**Possible causes:**
- Subnets don't have internet connectivity
- Security groups blocking traffic
- IAM role trust policy issues

**Solution:**
- Verify NAT Gateway or Internet Gateway exists
- Check security group rules
- Verify IAM role trust relationships

### Issue: "Cleanup script fails"
**Possible causes:**
- Resources still in use
- Dependency ordering issues
- IAM permission issues

**Solution:**
- Wait for all resources to reach stable state
- Run cleanup script again (it's idempotent)
- Manually delete resources via AWS Console if needed

### Issue: "Service Screener doesn't detect issues"
**Possible causes:**
- Resources not fully created
- Wrong region specified
- Check logic issues

**Solution:**
- Verify all clusters show ACTIVE status
- Confirm region matches where resources were created
- Check Service Screener logs for errors

## Manual Verification

You can manually verify each test scenario using AWS CLI:

```bash
# Test 1: Verify no managed node groups
aws eks list-nodegroups --cluster-name eks-test-no-ng-TIMESTAMP --region us-east-1

# Test 2: Verify single-AZ node group
aws eks describe-nodegroup \
  --cluster-name eks-test-single-az-TIMESTAMP \
  --nodegroup-name single-az-ng \
  --region us-east-1 \
  --query 'nodegroup.subnets'

# Test 3: Verify incomplete logging
aws eks describe-cluster \
  --name eks-test-no-logging-TIMESTAMP \
  --region us-east-1 \
  --query 'cluster.logging'

# Test 4: Verify no KMS encryption
aws eks describe-cluster \
  --name eks-test-no-kms-TIMESTAMP \
  --region us-east-1 \
  --query 'cluster.encryptionConfig'

# Test 5: Verify no Spot instances
aws eks describe-nodegroup \
  --cluster-name eks-test-no-spot-TIMESTAMP \
  --nodegroup-name on-demand-ng \
  --region us-east-1 \
  --query 'nodegroup.capacityType'

# Test 6: Verify no Karpenter add-on
aws eks list-addons \
  --cluster-name eks-test-no-karpenter-TIMESTAMP \
  --region us-east-1
```

## Files

- **create_test_resources.sh** - Creates all test resources
- **cleanup_test_resources.sh** - Deletes all test resources
- **README.md** - This documentation file
- **created_resources_*.txt** - Generated resource tracking file (created by create script)

## Best Practices

1. **Always clean up** - Don't leave test resources running
2. **Use dedicated test account** - Avoid running in production accounts
3. **Tag resources** - All resources are tagged with `Purpose=ServiceScreenerTest`
4. **Monitor costs** - Set up billing alerts for the test account
5. **Document results** - Save Service Screener output for validation
6. **Version control** - Keep resource files for audit trail

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review AWS CloudTrail logs for detailed error messages
3. Verify IAM permissions and VPC configuration
4. Check Service Screener logs in `service-screener-v2/logs/`

## References

- [Amazon EKS User Guide](https://docs.aws.amazon.com/eks/latest/userguide/)
- [Amazon EKS Best Practices Guide](https://docs.aws.amazon.com/eks/latest/best-practices/)
- [AWS CLI EKS Reference](https://docs.aws.amazon.com/cli/latest/reference/eks/)
- [Service Screener Documentation](../../../README.md)
- [EKS New Checks Summary](../../../.kiro/specs/service-review-eks/NEW_CHECKS_SUMMARY.md)

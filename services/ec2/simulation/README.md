# EC2 Service Screener - Simulation Scripts

Simulation scripts to create AWS resources that trigger both PASS and FAIL scenarios for all 18 EC2 checks (Tier 1, 2, and 3).

## Prerequisites

- AWS CLI v2 configured with valid credentials
- `jq` installed
- IAM permissions for: EC2, ELB, Auto Scaling, Service Quotas, Compute Optimizer
- A default VPC in the target region (or the script will attempt to create one)

## Usage

### Create Test Resources

```bash
# Use default region (us-east-1 or AWS_DEFAULT_REGION)
./create_test_resources.sh

# Specify a region
./create_test_resources.sh --region ap-southeast-1
```

The script will prompt for confirmation before creating any resources.

### Run Service Screener

After creating resources, run Service Screener to validate the checks:

```bash
cd ../../..  # Navigate to service-screener-v2 root
python3 main.py --regions <region> --services ec2
```

### Clean Up

```bash
./cleanup_test_resources.sh --region <same-region-used-for-create>
```

The cleanup script finds resources by the `ServiceScreenerTest=ec2-simulation` tag and removes them in dependency order.

## Check Coverage

### Tier 1

| # | Check ID | FAIL Scenario | PASS Scenario |
|---|----------|---------------|---------------|
| 1 | EBSEncryptionByDefault | Default state (encryption disabled) | Run `aws ec2 enable-ebs-encryption-by-default` |
| 2 | EBSVolumeDataClassification | Volume without classification tags | Volume with `DataClassification` tag |
| 3 | EBSSnapshotFirstArchived | Archive the first snapshot (after 72h) | Standard-tier snapshot (default) |
| 4 | EBSSnapshotComplianceArchive | Compliance-tagged snapshot >90 days old, not archived | Archive old compliance snapshots |
| 5 | EC2EbsOptimized | t2.micro with `--no-ebs-optimized` | t3.micro (EBS-optimized by default) |
| 6 | EC2RootVolumeImplications | Instance with no root volume snapshot | Instance with recent root volume snapshot |
| 7 | EBSSnapshotLatestArchived | Archive the latest snapshot (after 72h) | Standard-tier snapshot (default) |
| 8 | VPCMultiAZ | VPC with subnet in 1 AZ only | Default VPC with subnets in multiple AZs |
| 9 | ELBMultiAZ | NLB in single AZ | ALB across 2 AZs |
| 10 | ASGMultiAZ | ASG in single AZ | ASG across 2 AZs |
| 11 | ASGTargetTrackingPolicy | ASG with no scaling policies | ASG with target tracking policy |
| 12 | EC2ServiceQuotas | Account usage >80% of quota | Account usage below quota limits |

### Tier 2

| # | Check ID | FAIL Scenario | PASS Scenario |
|---|----------|---------------|---------------|
| 13 | ASGScalingCooldowns | ASG with cooldown set to 0s | ASG with default cooldown (300s) |
| 14 | ComputeOptimizerEnhancedMetrics | Enhanced metrics not enabled (account-level) | Enable enhanced metrics in Compute Optimizer console |

### Tier 3

| # | Check ID | FAIL Scenario | PASS Scenario |
|---|----------|---------------|---------------|
| 15 | EC2SeparateOSDataVolumes | Instance with only root volume | Instance with root + data volume attached |
| 16 | EC2InstanceStoreUsage | Instance store type without ephemeral mappings (requires m5d/c5d) | Instance type without instance store (skipped) |
| 17 | ComputeOptimizerRightsizingPrefs | Default lookBackPeriod (DAYS_14) (account-level) | Customize rightsizing preferences in Compute Optimizer console |
| 18 | ComputeOptimizerExportRecommendations | No export jobs configured (account-level) | Configure recommendation export in Compute Optimizer console |

## Notes

- **Costs**: The scripts create real AWS resources (t2.micro, t3.micro instances, EBS volumes, ALB, NLB). Costs are minimal but non-zero. Clean up promptly.
- **Snapshot archiving** (checks 3, 4, 7): Archiving requires snapshots to exist for 72+ hours. These checks can only be fully tested after that waiting period.
- **Compliance archive** (check 4): Triggers only for snapshots older than 90 days.
- **Service quotas** (check 12): Depends on actual account usage vs limits. Cannot be simulated with test resources.
- **Compute Optimizer checks** (14, 17, 18): Account-level settings that require Compute Optimizer enrollment. Cannot be simulated with resource creation; configure via the Compute Optimizer console.
- **Instance store** (check 16): Requires instance types with instance store (e.g., m5d.large, c5d.large) which are more expensive. The script logs instructions instead of launching them.
- **Resource IDs**: Saved to `resources.env` after creation for reference.
- **Tagging**: All resources are tagged with `ServiceScreenerTest=ec2-simulation` for easy identification and cleanup.

## Files

| File | Description |
|------|-------------|
| `create_test_resources.sh` | Creates PASS/FAIL resources for all 18 checks |
| `cleanup_test_resources.sh` | Removes all tagged simulation resources |
| `resources.env` | Auto-generated file with created resource IDs |
| `simulation.log` | Creation script log |
| `cleanup.log` | Cleanup script log |

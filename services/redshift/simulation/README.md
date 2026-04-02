# Redshift Service Screener Simulation

This directory contains simulation scripts to create test AWS resources for validating Redshift Service Screener checks.

## Overview

The simulation scripts create real AWS resources to test Redshift Service Screener checks:

### Implemented Checks
1. **VpcDeployment** (Tier 1) - Validates that Redshift clusters are deployed in VPC for network isolation
2. **AdvisorRecommendations** (Tier 1) - Checks for unaddressed Redshift Advisor recommendations
3. **EventNotifications** (Tier 2) - Validates SNS event notifications are configured for cluster events
4. **QueryMonitoringRules** (Tier 2) - Validates Query Monitoring Rules are configured in WLM
5. **SecurityGroups** (Tier 3) - Validates VPC security groups are attached to cluster

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
        "redshift:CreateCluster",
        "redshift:DeleteCluster",
        "redshift:DescribeClusters",
        "redshift:CreateClusterSubnetGroup",
        "redshift:DeleteClusterSubnetGroup",
        "redshift:DescribeClusterSubnetGroups",
        "redshift:DescribeClusterSnapshots",
        "redshift:DeleteClusterSnapshot",
        "redshift:ListRecommendations",
        "redshift:DescribeEventSubscriptions",
        "redshift:DescribeClusterParameters",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Cost Warning

**IMPORTANT**: Creating a Redshift cluster incurs costs!

- **Estimated cost**: ~$0.25/hour for dc2.large single-node cluster
- **Minimum runtime**: Cluster takes 5-10 minutes to create and delete
- **Total cost for testing**: ~$0.10 - $0.50 (depending on how long you keep it running)

**Always remember to run the cleanup script after testing!**

## Usage

### 1. Create Test Resources

Run the creation script to create a test Redshift cluster in VPC:

```bash
cd service-screener-v2/services/redshift/simulation
./create_test_resources.sh
```

**Optional: Specify a different region**
```bash
AWS_REGION=us-west-2 ./create_test_resources.sh
```

**What it creates:**

- Cluster Subnet Group: `test-screener-subnet-group`
- Redshift Cluster: `test-screener-redshift`
  - Node Type: dc2.large
  - Cluster Type: single-node
  - Deployed in default VPC
  - Master Username: testadmin
  - Publicly accessible (for testing purposes)

**Creation time**: 5-10 minutes

### 2. Run Service Screener

Navigate to the Service Screener root directory and run:

```bash
cd ../../..  # Go to service-screener-v2 root
python screener.py --regions us-east-1 --services redshift
```

Or for a different region:
```bash
python screener.py --regions us-west-2 --services redshift
```

### 3. Verify Results

Check the Service Screener output for the following expected results:

#### VpcDeployment Check
- **Should PASS**: `test-screener-redshift` (cluster is deployed in VPC)
- **Expected Output**:
  ```
  [PASS] test-screener-redshift
    Cluster deployed in VPC: vpc-xxxxxxxx
  ```

#### AdvisorRecommendations Check
- **May vary**: Depends on whether Advisor has generated recommendations
- **If no recommendations**:
  ```
  [PASS] test-screener-redshift
    No outstanding Advisor recommendations
  ```
- **If recommendations exist**:
  ```
  [FAIL] test-screener-redshift
    X high-impact recommendation(s) need attention
  ```
  or
  ```
  [WARN] test-screener-redshift
    X medium-impact recommendation(s) exist
  ```

**Note**: Redshift Advisor may take a few minutes to analyze the cluster and generate recommendations. If you run the screener immediately after cluster creation, you may see "No outstanding Advisor recommendations".

#### EventNotifications Check
- **Should FAIL**: `test-screener-redshift` (no SNS event notifications configured by default)
- **Expected Output**:
  ```
  [FAIL] test-screener-redshift
    No SNS event notifications configured for this cluster
  ```

**Note**: To make this check pass, you would need to create an SNS topic and event subscription for the cluster.

#### QueryMonitoringRules Check
- **Should FAIL**: `test-screener-redshift` (no Query Monitoring Rules configured by default)
- **Expected Output**:
  ```
  [FAIL] test-screener-redshift
    No Query Monitoring Rules configured in WLM
  ```

**Note**: To make this check pass, you would need to configure WLM with query monitoring rules in the cluster parameter group.

#### SecurityGroups Check
- **Should PASS**: `test-screener-redshift` (VPC security groups are attached by default)
- **Expected Output**:
  ```
  [PASS] test-screener-redshift
    VPC security groups attached: sg-xxxxxxxx
  ```

### 4. Clean Up Resources

**IMPORTANT**: After testing, delete all created resources to avoid ongoing charges:

```bash
cd services/redshift/simulation
./cleanup_test_resources.sh
```

**Optional: Specify the same region used for creation**
```bash
AWS_REGION=us-west-2 ./cleanup_test_resources.sh
```

The cleanup script is **idempotent** - safe to run multiple times even if resources are already deleted.

**Cleanup time**: 5-10 minutes (cluster deletion)

## Expected Service Screener Results

### VpcDeployment Check

**Expected Output (PASS):**
```
[PASS] test-screener-redshift
  Cluster deployed in VPC: vpc-xxxxxxxx
```

This check validates that the Redshift cluster is deployed in Amazon VPC for enhanced security and network isolation.

### AdvisorRecommendations Check

**Expected Output (varies):**

**Scenario 1: No recommendations**
```
[PASS] test-screener-redshift
  No outstanding Advisor recommendations
```

**Scenario 2: High-impact recommendations**
```
[FAIL] test-screener-redshift
  2 high-impact recommendation(s) need attention
```

**Scenario 3: Medium/Low-impact recommendations**
```
[WARN] test-screener-redshift
  1 medium-impact recommendation(s) exist
```

This check validates that Redshift Advisor recommendations are being addressed. Advisor analyzes your cluster and provides recommendations for:
- Table design optimization
- Compression encoding
- Query performance
- Cluster configuration

### EventNotifications Check

**Expected Output (FAIL):**
```
[FAIL] test-screener-redshift
  No SNS event notifications configured for this cluster
```

This check validates that SNS event notifications are configured for cluster events. The test cluster does not have event notifications configured by default, so this check will fail. To make it pass, you would need to:
1. Create an SNS topic
2. Create a Redshift event subscription for the cluster

### QueryMonitoringRules Check

**Expected Output (FAIL):**
```
[FAIL] test-screener-redshift
  No Query Monitoring Rules configured in WLM
```

This check validates that Query Monitoring Rules (QMR) are configured in Workload Management (WLM). The test cluster uses the default parameter group which does not have QMR configured, so this check will fail. To make it pass, you would need to:
1. Create a custom parameter group
2. Configure WLM with query monitoring rules
3. Associate the parameter group with the cluster

### SecurityGroups Check

**Expected Output (PASS):**
```
[PASS] test-screener-redshift
  VPC security groups attached: sg-xxxxxxxx
```

This check validates that VPC security groups are attached to the cluster. The test cluster automatically gets a default security group attached when created in VPC, so this check should pass.

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

### No Default VPC Found
If you don't have a default VPC in your region:

1. Create a default VPC:
   ```bash
   aws ec2 create-default-vpc --region us-east-1
   ```

2. Or modify the script to use a specific VPC ID

### Cluster Already Exists
The creation script will detect if the cluster already exists and skip creation. Use the cleanup script first if you want to start fresh.

### Cluster Creation Timeout
Cluster creation typically takes 5-10 minutes. If it takes longer:
- Check AWS Console for cluster status
- Verify no service limits are being hit
- Check CloudTrail logs for errors

### Cleanup Script Hangs
If the cleanup script hangs during cluster deletion:
- Press Ctrl+C to cancel
- Check cluster status in AWS Console
- Wait for deletion to complete manually
- Run cleanup script again to remove remaining resources

## Cost Considerations

The test resources created by these scripts incur AWS costs:

### Redshift Cluster Costs
- **Node Type**: dc2.large
- **Pricing**: ~$0.25/hour (varies by region)
- **Minimum test duration**: ~15-20 minutes (create + test + delete)
- **Estimated cost**: $0.10 - $0.50 per test run

### Additional Costs
- **Snapshots**: $0.024 per GB-month (if you keep final snapshots)
- **Data Transfer**: Minimal for testing (usually free tier)

### Cost Optimization Tips
1. **Delete immediately after testing**: Run cleanup script as soon as testing is complete
2. **Delete final snapshots**: Choose "yes" when cleanup script asks about snapshots
3. **Use smallest node type**: Script uses dc2.large (smallest available)
4. **Test in off-peak hours**: No cost difference, but faster provisioning

**Total estimated cost for one complete test cycle**: $0.10 - $0.50

## Script Details

### create_test_resources.sh

Creates test Redshift cluster in VPC:

- **Checks**: AWS CLI installation and credentials
- **VPC Discovery**: Finds default VPC and subnet automatically
- **Subnet Group**: Creates cluster subnet group
- **Cluster Creation**: Creates single-node dc2.large cluster
- **Wait Logic**: Waits for cluster to become available
- **Error Handling**: Gracefully handles existing resources
- **Output**: Color-coded status messages with cost warnings

### cleanup_test_resources.sh

Deletes all test resources:

- **Idempotent**: Safe to run multiple times
- **Cluster Deletion**: Deletes cluster with final snapshot
- **Subnet Group**: Removes cluster subnet group
- **Snapshot Management**: Optionally deletes final snapshots
- **Wait Logic**: Waits for cluster deletion to complete
- **Error Handling**: Continues even if resources don't exist
- **Output**: Confirms each deletion with detailed summary

## Integration with Service Screener

These simulation scripts are designed to work with the Redshift Service Screener checks:

1. **VpcDeployment** (Tier 1) - Implemented in `drivers/RedshiftCluster.py`
   - Method: `_checkCluster()`
   - Validates: Cluster has VpcId field

2. **AdvisorRecommendations** (Tier 1) - Implemented in `drivers/RedshiftCluster.py`
   - Method: `_checkAdvisorRecommendations()`
   - Validates: Checks for high/medium/low impact recommendations

3. **EventNotifications** (Tier 2) - Implemented in `drivers/RedshiftCluster.py`
   - Method: `_checkEventNotifications()`
   - Validates: SNS event subscriptions configured for cluster

4. **QueryMonitoringRules** (Tier 2) - Implemented in `drivers/RedshiftCluster.py`
   - Method: `_checkQueryMonitoringRules()`
   - Validates: Query Monitoring Rules configured in WLM

5. **SecurityGroups** (Tier 3) - Implemented in `drivers/RedshiftCluster.py`
   - Method: `_checkCluster()`
   - Validates: VPC security groups attached to cluster

## Additional Resources

- [Amazon Redshift VPC](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#working-with-clusters-overview)
- [Amazon Redshift Advisor](https://docs.aws.amazon.com/redshift/latest/dg/advisor.html)
- [Amazon Redshift Event Notifications](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-event-notifications.html)
- [WLM Query Monitoring Rules](https://docs.aws.amazon.com/redshift/latest/dg/cm-c-wlm-query-monitoring-rules.html)
- [Amazon Redshift Cluster Security Groups](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-security-groups.html)
- [AWS CLI Redshift Commands](https://docs.aws.amazon.com/cli/latest/reference/redshift/)
- [Redshift Pricing](https://aws.amazon.com/redshift/pricing/)

## Support

For issues or questions:
1. Check the Troubleshooting section above
2. Verify AWS credentials and permissions
3. Review Service Screener logs for detailed error messages
4. Consult AWS Redshift documentation

## Version

- **Version**: 2.0
- **Last Updated**: 2024
- **Compatible with**: Service Screener v2
- **Checks Covered**: VpcDeployment, AdvisorRecommendations, EventNotifications, QueryMonitoringRules, SecurityGroups (5 checks total)

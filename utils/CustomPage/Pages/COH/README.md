# Cost Optimization Hub (COH) Setup Guide

## Overview

The Cost Optimization Hub feature in Service Screener provides unified cost optimization recommendations across multiple AWS services. This experimental feature requires access to several AWS services to function properly.

## Required AWS Services

To get complete Cost Optimization Hub data, you need to enable and configure the following AWS services:

### 1. AWS Cost Optimization Hub
### 2. AWS Compute Optimizer
### 3. AWS Savings Plans Recommendations
### 4. AWS Cost Explorer (for historical data)

---

## Step-by-Step Setup Guide

### 1. Enable AWS Cost Optimization Hub

**What it provides:** Unified view of cost optimization recommendations across AWS services.

#### Console Setup:
1. Navigate to the [AWS Cost Optimization Hub Console](https://console.aws.amazon.com/cost-optimization-hub/)
2. Click **"Get started"** or **"Enable Cost Optimization Hub"**
3. Review and accept the service terms
4. Wait for the service to initialize (can take up to 24 hours for first recommendations)

#### Required IAM Permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cost-optimization-hub:GetRecommendation",
                "cost-optimization-hub:ListRecommendations",
                "cost-optimization-hub:ListRecommendationSummaries",
                "cost-optimization-hub:GetPreferences",
                "cost-optimization-hub:UpdatePreferences"
            ],
            "Resource": "*"
        }
    ]
}
```

#### CLI Verification:
```bash
# Check if Cost Optimization Hub is enabled
aws cost-optimization-hub list-recommendations --region us-east-1 --max-results 5

# Get recommendation summaries grouped by resource type
aws cost-optimization-hub list-recommendation-summaries \
    --group-by "ResourceType" \
    --region us-east-1

# Or group by recommendation source
aws cost-optimization-hub list-recommendation-summaries \
    --group-by "RecommendationSourceType" \
    --region us-east-1
```

---

### 2. Enable AWS Compute Optimizer

**What it provides:** Right-sizing recommendations for EC2 instances, Auto Scaling groups, EBS volumes, and Lambda functions.

#### Console Setup:
1. Navigate to the [AWS Compute Optimizer Console](https://console.aws.amazon.com/compute-optimizer/)
2. Click **"Opt in"** to enable Compute Optimizer
3. Choose your opt-in preferences:
   - **Account-level opt-in:** Enable for current account
   - **Organization-level opt-in:** Enable for all accounts in organization (if using AWS Organizations)
4. Wait 12-24 hours for initial analysis and recommendations

#### Required IAM Permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "compute-optimizer:GetRecommendationSummaries",
                "compute-optimizer:GetEC2InstanceRecommendations",
                "compute-optimizer:GetAutoScalingGroupRecommendations",
                "compute-optimizer:GetEBSVolumeRecommendations",
                "compute-optimizer:GetLambdaFunctionRecommendations",
                "compute-optimizer:GetEnrollmentStatus",
                "compute-optimizer:DescribeRecommendationExportJobs"
            ],
            "Resource": "*"
        }
    ]
}
```

#### CLI Verification:
```bash
# Check Compute Optimizer enrollment status
aws compute-optimizer get-enrollment-status --region us-east-1

# Get EC2 recommendations
aws compute-optimizer get-ec2-instance-recommendations --region us-east-1
```

---

### 3. Enable Savings Plans Recommendations

**What it provides:** Recommendations for Reserved Instances and Savings Plans to reduce costs.

#### Console Setup:
1. Navigate to [AWS Cost Explorer](https://console.aws.amazon.com/cost-management/home#/savings-plans/recommendations)
2. Go to **"Savings Plans"** → **"Recommendations"**
3. The service is automatically available if you have Cost Explorer enabled
4. Configure recommendation preferences:
   - **Lookback period:** 7, 30, or 60 days (SEVEN_DAYS, THIRTY_DAYS, or SIXTY_DAYS in CLI)
   - **Payment option:** No upfront, Partial upfront, All upfront
   - **Term length:** 1 year or 3 years

#### Required IAM Permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ce:GetSavingsPlansUtilization",
                "ce:GetSavingsPlansCoverage",
                "ce:GetReservationCoverage",
                "ce:GetReservationPurchaseRecommendation",
                "ce:GetReservationUtilization",
                "ce:ListCostCategoryDefinitions",
                "ce:GetUsageAndCosts"
            ],
            "Resource": "*"
        }
    ]
}
```

#### CLI Verification:
```bash
# Get Savings Plans recommendations (1-year, no upfront, 30-day lookback)
aws ce get-savings-plans-purchase-recommendation \
    --savings-plans-type COMPUTE_SP \
    --term-in-years ONE_YEAR \
    --payment-option NO_UPFRONT \
    --lookback-period-in-days THIRTY_DAYS

# Get Reserved Instance recommendations
aws ce get-reservation-purchase-recommendation \
    --service "Amazon Elastic Compute Cloud - Compute"
```

---

### 4. Enable AWS Cost Explorer (Optional but Recommended)

**What it provides:** Historical cost data and trends for better optimization insights.

#### Console Setup:
1. Navigate to [AWS Cost Explorer](https://console.aws.amazon.com/cost-management/home#/cost-explorer)
2. Click **"Enable Cost Explorer"**
3. Wait 24 hours for initial data processing
4. Configure cost allocation tags if needed

#### Required IAM Permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ce:GetCostAndUsage",
                "ce:GetUsageAndCosts",
                "ce:GetReservationCoverage",
                "ce:GetReservationPurchaseRecommendation",
                "ce:GetReservationUtilization",
                "ce:ListCostCategoryDefinitions"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Complete IAM Policy

Here's a complete IAM policy that includes all required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CostOptimizationHubAccess",
            "Effect": "Allow",
            "Action": [
                "cost-optimization-hub:GetRecommendation",
                "cost-optimization-hub:ListRecommendations",
                "cost-optimization-hub:ListRecommendationSummaries",
                "cost-optimization-hub:GetPreferences",
                "cost-optimization-hub:UpdatePreferences"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ComputeOptimizerAccess",
            "Effect": "Allow",
            "Action": [
                "compute-optimizer:GetRecommendationSummaries",
                "compute-optimizer:GetEC2InstanceRecommendations",
                "compute-optimizer:GetAutoScalingGroupRecommendations",
                "compute-optimizer:GetEBSVolumeRecommendations",
                "compute-optimizer:GetLambdaFunctionRecommendations",
                "compute-optimizer:GetEnrollmentStatus",
                "compute-optimizer:DescribeRecommendationExportJobs"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CostExplorerAccess",
            "Effect": "Allow",
            "Action": [
                "ce:GetSavingsPlansUtilization",
                "ce:GetSavingsPlansCoverage",
                "ce:GetReservationCoverage",
                "ce:GetReservationPurchaseRecommendation",
                "ce:GetReservationUtilization",
                "ce:GetUsageAndCosts",
                "ce:GetCostAndUsage",
                "ce:ListCostCategoryDefinitions"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. "Cost Optimization Hub data not available"
**Possible causes:**
- Cost Optimization Hub not enabled
- Insufficient IAM permissions
- Service still initializing (wait 24 hours after enabling)

**Solutions:**
- Verify service is enabled in the AWS Console
- Check IAM permissions match the policy above
- Wait for initial data collection to complete

#### 2. "No recommendations available"
**Possible causes:**
- Resources are already well-optimized
- Insufficient usage data (need 14+ days of usage)
- Services not generating recommendations yet

**Solutions:**
- Wait for more usage data to accumulate
- Check individual service consoles for recommendations
- Verify resources are running and generating costs

#### 3. "Incomplete or missing data"
**Possible causes:**
- Some services not enabled
- Regional availability issues
- Partial IAM permissions

**Solutions:**
- Enable all required services listed above
- Check service availability in your region
- Use the complete IAM policy provided

#### 4. "Access denied" errors
**Possible causes:**
- Missing IAM permissions
- Service not available in region
- Account-level restrictions

**Solutions:**
- Apply the complete IAM policy
- Check service regional availability
- Contact AWS support for account-level issues

---

## Regional Availability

### Cost Optimization Hub
Available in: `us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`, `ap-northeast-1`

### Compute Optimizer
Available in most AWS regions. Check [AWS Regional Services](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/) for current availability.

### Savings Plans & Cost Explorer
Available globally, but data is aggregated in `us-east-1`.

---

## Data Collection Timeline

| Service | Initial Setup Time | First Recommendations | Full Data Available |
|---------|-------------------|----------------------|-------------------|
| Cost Optimization Hub | 5 minutes | 24 hours | 24-48 hours |
| Compute Optimizer | 5 minutes | 12 hours | 24 hours |
| Savings Plans | Immediate | Immediate | Immediate |
| Cost Explorer | 5 minutes | 24 hours | 24 hours |

---

## Testing Your Setup

After enabling all services, you can test the setup using the Service Screener diagnostic tool:

```bash
# Run the COH diagnostic script
python3 diagnose_coh_issues.py

# Or run Service Screener with COH enabled
python3 main.py --regions us-east-1 --services coh --beta 1
```

---

## Support

If you encounter issues:

1. **Check the diagnostic script output:** `python3 diagnose_coh_issues.py`
2. **Review AWS service health:** [AWS Service Health Dashboard](https://status.aws.amazon.com/)
3. **Verify IAM permissions:** Use the AWS IAM Policy Simulator
4. **Contact AWS Support:** For service-specific issues

---

## Additional Resources

- [AWS Cost Optimization Hub Documentation](https://docs.aws.amazon.com/cost-optimization-hub/)
- [AWS Compute Optimizer User Guide](https://docs.aws.amazon.com/compute-optimizer/)
- [AWS Cost Explorer User Guide](https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html)
- [AWS Savings Plans User Guide](https://docs.aws.amazon.com/savingsplans/)
# API Gateway Simulation Scripts

This directory contains scripts to create and cleanup test API Gateway resources for validating the new Tier 1 security checks implemented in Service Screener v2.

## Overview

The simulation scripts create various API Gateway configurations that test both passing and failing scenarios for the 10 new Tier 1 checks:

1. **ResourcePolicy** - Resource policy configuration
2. **IAMAuthentication** - Method authentication types
3. **RequestThrottling** - Stage-level throttling settings
4. **PrivateAPI** - Private API VPC endpoint configuration
5. **LambdaAuthorizer** - Lambda authorizer configuration
6. **CognitoAuthorizer** - Cognito user pool authorizer configuration
7. **MutualTLS** - Mutual TLS for custom domains
8. **UsagePlanThrottling** - Usage plan throttling and quota limits
9. **VPCEndpointAssociation** - VPC endpoint association for private APIs
10. **RequestValidation** - Request validator configuration

## Prerequisites

### Required Tools
- **AWS CLI** - Version 2.x or later
- **jq** - JSON processor for parsing responses
- **bash** - Shell environment (Linux/macOS/WSL)

### AWS Permissions

The scripts require the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "apigateway:CreateRestApi",
        "apigateway:DeleteRestApi",
        "apigateway:UpdateRestApi",
        "apigateway:GetRestApi",
        "apigateway:GetResources",
        "apigateway:CreateResource",
        "apigateway:PutMethod",
        "apigateway:PutIntegration",
        "apigateway:CreateDeployment",
        "apigateway:UpdateStage",
        "apigateway:CreateUsagePlan",
        "apigateway:DeleteUsagePlan",
        "apigateway:CreateAuthorizer",
        "apigateway:CreateRequestValidator"
      ],
      "Resource": "*"
    }
  ]
}
```

### AWS Configuration

Ensure your AWS CLI is configured with credentials:

```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

## Usage

### 1. Create Test Resources

Run the creation script to set up test API Gateway resources:

```bash
cd service-screener-v2/services/apigateway/simulation
chmod +x create_test_resources.sh
./create_test_resources.sh
```

**What it creates:**

| Test Case | Resource | Expected Check Result |
|-----------|----------|----------------------|
| 1 | API with resource policy | ✅ PASS ResourcePolicy |
| 2 | API without resource policy | ❌ FAIL ResourcePolicy |
| 3 | API with IAM authentication | ✅ PASS IAMAuthentication |
| 4 | API with NONE authentication | ❌ FAIL IAMAuthentication |
| 5 | API with throttling configured | ✅ PASS RequestThrottling |
| 6 | API without throttling | ❌ FAIL RequestThrottling |
| 7 | Usage plan with limits | ✅ PASS UsagePlanThrottling |
| 8 | Usage plan without limits | ❌ FAIL UsagePlanThrottling |

**Output:**

The script creates a JSON file with all resource IDs:
```
simulation/test_resources_<timestamp>.json
```

Example output:
```json
{
  "timestamp": "1234567890",
  "region": "us-east-1",
  "resources": {
    "api_with_policy": "abc123xyz",
    "api_without_policy": "def456uvw",
    "api_with_iam_auth": "ghi789rst",
    ...
  }
}
```

### 2. Run Service Screener

After creating test resources, run Service Screener to validate the checks:

```bash
# Navigate to Service Screener root
cd ../../..

# Run Service Screener for API Gateway
python screener.py --services apigateway --regions us-east-1
```

### 3. Verify Results

Check the Service Screener output to verify:

- **ResourcePolicy check** detects APIs without resource policies
- **IAMAuthentication check** flags methods with NONE authorization
- **RequestThrottling check** identifies stages without throttling
- **UsagePlanThrottling check** finds usage plans without limits

Expected results:
```
✅ API with resource policy - PASS
❌ API without resource policy - FAIL (flagged)
✅ API with IAM auth - PASS
❌ API with NONE auth - FAIL (flagged)
✅ API with throttling - PASS
❌ API without throttling - FAIL (flagged)
```

### 4. Cleanup Test Resources

After testing, cleanup all created resources:

```bash
# Using timestamp from creation
./cleanup_test_resources.sh 1234567890

# Or let it auto-detect the most recent resource file
./cleanup_test_resources.sh
```

**What it does:**
- Deletes all usage plans
- Deletes all test APIs
- Archives the resource JSON file to `simulation/archive/`

## Test Scenarios

### Scenario 1: Resource Policy Validation

**Purpose:** Verify that APIs without resource policies are flagged.

**Test APIs:**
- `ss-test-api-with-policy-*` - Has IP-based resource policy (PASS)
- `ss-test-api-no-policy-*` - No resource policy (FAIL)

**Expected Behavior:**
- Check should PASS for APIs with resource policies
- Check should FAIL for APIs without resource policies

### Scenario 2: Authentication Validation

**Purpose:** Verify that methods with NONE authorization are flagged.

**Test APIs:**
- `ss-test-api-iam-auth-*` - GET /users with AWS_IAM auth (PASS)
- `ss-test-api-no-auth-*` - GET /public with NONE auth (FAIL)

**Expected Behavior:**
- Check should PASS when all methods have authentication
- Check should FAIL when any method has NONE authorization

### Scenario 3: Throttling Validation

**Purpose:** Verify that stages without throttling are flagged.

**Test APIs:**
- `ss-test-api-with-throttling-*` - Stage with burst/rate limits (PASS)
- `ss-test-api-no-throttling-*` - Stage without throttling (FAIL)

**Expected Behavior:**
- Check should PASS when throttling is configured
- Check should FAIL when no throttling is set

### Scenario 4: Usage Plan Validation

**Purpose:** Verify that usage plans without limits are flagged.

**Test Usage Plans:**
- `ss-test-api-plan-with-limits-*` - Has throttle and quota (PASS)
- `ss-test-api-plan-no-limits-*` - No throttle or quota (FAIL)

**Expected Behavior:**
- Check should PASS when usage plans have limits
- Check should FAIL when usage plans lack limits

## Advanced Testing

### Testing Private APIs

Private API checks require VPC setup. To test manually:

1. Create a VPC with private subnets
2. Create a VPC endpoint for execute-api
3. Create a private API with VPC endpoint association
4. Run Service Screener to verify PrivateAPI and VPCEndpointAssociation checks

```bash
# Create VPC endpoint
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxxxx \
  --service-name com.amazonaws.us-east-1.execute-api \
  --route-table-ids rtb-xxxxx

# Create private API
aws apigateway create-rest-api \
  --name "private-api-test" \
  --endpoint-configuration types=PRIVATE,vpcEndpointIds=vpce-xxxxx
```

### Testing Custom Domains with mTLS

Mutual TLS checks require custom domain setup:

1. Create a custom domain in API Gateway
2. Configure mutual TLS with a trust store in S3
3. Map the domain to your API
4. Run Service Screener to verify MutualTLS check

```bash
# Create custom domain with mTLS
aws apigateway create-domain-name \
  --domain-name api.example.com \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/xxxxx \
  --mutual-tls-authentication truststoreUri=s3://bucket/truststore.pem
```

### Testing Lambda/Cognito Authorizers

To test authorizer checks:

1. Create a Lambda function for custom authorization
2. Create a Lambda authorizer in API Gateway
3. Create a Cognito user pool
4. Create a Cognito authorizer in API Gateway
5. Run Service Screener to verify LambdaAuthorizer and CognitoAuthorizer checks

## Troubleshooting

### Issue: "jq: command not found"

**Solution:** Install jq:
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Amazon Linux
sudo yum install jq
```

### Issue: "Access Denied" errors

**Solution:** Verify IAM permissions include all required API Gateway actions.

### Issue: Resources not deleted

**Solution:** Check if resources are in use or have dependencies:
```bash
# List all APIs
aws apigateway get-rest-apis --region us-east-1

# Manually delete specific API
aws apigateway delete-rest-api --rest-api-id <api-id> --region us-east-1
```

### Issue: Script fails mid-execution

**Solution:** The cleanup script can handle partial failures. Run it to clean up any created resources:
```bash
./cleanup_test_resources.sh
```

## Cost Considerations

These test resources incur minimal AWS costs:

- **API Gateway REST APIs:** Free tier includes 1 million API calls per month
- **Usage Plans:** No additional cost
- **Stages/Deployments:** No additional cost

**Estimated cost:** $0.00 - $0.01 per test run (within free tier)

**Best Practice:** Always run cleanup script after testing to avoid any charges.

## Integration with CI/CD

You can integrate these scripts into your CI/CD pipeline:

```yaml
# Example GitHub Actions workflow
name: Test API Gateway Checks

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Create test resources
        run: |
          cd service-screener-v2/services/apigateway/simulation
          ./create_test_resources.sh
      
      - name: Run Service Screener
        run: |
          cd service-screener-v2
          python screener.py --services apigateway --regions us-east-1
      
      - name: Cleanup resources
        if: always()
        run: |
          cd service-screener-v2/services/apigateway/simulation
          ./cleanup_test_resources.sh
```

## Additional Resources

- [API Gateway Best Practices](https://docs.aws.amazon.com/apigateway/latest/developerguide/best-practices.html)
- [API Gateway Security](https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html)
- [Service Screener Documentation](../../../README.md)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Service Screener logs
3. Verify AWS CLI configuration and permissions
4. Check the main Service Screener documentation

## License

These scripts are part of Service Screener v2 and follow the same license.

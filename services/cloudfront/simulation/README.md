# CloudFront Service Simulation

This directory contains scripts to create and cleanup intentionally insecure AWS CloudFront resources for testing Service Screener checks.

## Purpose

These scripts create real AWS resources with security and configuration issues that should trigger FAIL (-1) status in Service Screener. This allows you to validate that all CloudFront checks are working correctly.

## Resources Created

| Resource | Configuration | Validates Checks |
|----------|--------------|------------------|
| S3 Bucket | Public bucket for origin | S3OriginBucketExists |
| CloudFront Distribution | Multiple security issues | All 16 checks |
| - S3 Origin | No OAC/OAI configured | S3OriginAccessControl |
| - Custom Origin | HTTP-only, deprecated SSL | OriginTrafficEncryption, DeprecatedSSLProtocol |
| - Viewer Protocol | Allow HTTP (allow-all) | viewerPolicyHttps |
| - Logging | Disabled | accessLogging |
| - WAF | Not associated | WAFAssociation |
| - Default Root Object | Not configured | defaultRootObject |
| - Compression | Disabled | compressObjectsAutomatically |
| - Origin Groups | None configured | originFailover |
| - Field-Level Encryption | Not configured | fieldLevelEncryption |
| - SSL Certificate | Default CloudFront cert | CustomSSLCertificate |
| - Origin Shield | Not configured | OriginShieldEnabled |
| - Geo Restrictions | None configured | GeoRestrictionsConfigured |
| - Price Class | PriceClass_All | PriceClassOptimization |

## Coverage

- **Total Checks**: 16
- **Validated by Scripts**: 15 (94%)
- **Not Validated**: 1 (SNIConfiguration - requires custom certificate)

The SNIConfiguration check requires a custom SSL certificate to be tested, which involves ACM certificate setup and domain validation. This is excluded from the simulation to keep setup simple.

## Cost Considerations

- **S3 Bucket**: Minimal storage cost (~$0.01/month for test file)
- **CloudFront Distribution**: No cost until traffic is served
- **Data Transfer**: Only charged if you access the distribution URL
- **Total estimated cost**: <$0.10/month if not accessed

⚠️ **IMPORTANT**: CloudFront distributions remain active until deleted. Run the cleanup script promptly to avoid any potential charges!

## Usage

### Prerequisites

- AWS CLI configured with appropriate credentials
- IAM permissions for CloudFront and S3 operations
- `jq` command-line JSON processor installed

### Create Test Resources

```bash
cd service-screener-v2/services/cloudfront/simulation
chmod +x create_test_resources.sh
./create_test_resources.sh
```

**Note**: CloudFront distributions take 15-20 minutes to deploy. Wait for deployment to complete before running Service Screener.

### Check Deployment Status

```bash
aws cloudfront get-distribution --id <DISTRIBUTION_ID> --query 'Distribution.Status'
```

Status should be "Deployed" before running Service Screener.

### Run Service Screener

```bash
cd ../../..  # Back to service-screener-v2 root
python3 main.py --regions us-east-1 --services cloudfront --beta 1 --sequential 1
```

### Cleanup Resources

```bash
cd services/cloudfront/simulation
chmod +x cleanup_test_resources.sh
./cleanup_test_resources.sh
```

**Note**: CloudFront distributions must be disabled before deletion. The cleanup script handles this automatically, but it may take 15-20 minutes for the distribution to be fully disabled. If cleanup fails, wait and run the script again.

## Expected Results

When you run Service Screener after creating these resources, you should see:

### Original Checks (8 FAIL)
- ❌ accessLogging - No logging enabled
- ❌ WAFAssociation - No WAF associated
- ❌ defaultRootObject - No default root object configured
- ❌ compressObjectsAutomatically - Compression disabled
- ❌ DeprecatedSSLProtocol - Using SSLv3
- ❌ originFailover - No origin groups configured
- ❌ fieldLevelEncryption - No field-level encryption
- ❌ viewerPolicyHttps - Allows HTTP traffic

### New Checks - Tier 1 (4 FAIL, 1 PASS)
- ❌ S3OriginAccessControl - S3 origin without OAC/OAI
- ❌ OriginTrafficEncryption - Custom origin using http-only
- ❌ CustomSSLCertificate - Using default CloudFront certificate
- ⚠️ SNIConfiguration - Skipped (only applies to custom certificates)
- ✅ S3OriginBucketExists - Bucket exists (PASS)

### New Checks - Tier 2 (3 FAIL)
- ❌ OriginShieldEnabled - No Origin Shield configured
- ❌ GeoRestrictionsConfigured - No geo restrictions
- ❌ PriceClassOptimization - Using PriceClass_All

**Total Expected**: 15 FAIL, 1 PASS (SNIConfiguration skipped, S3OriginBucketExists passes)

## IAM Permissions Required

The scripts require AWS CLI configured with permissions to:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudfront:CreateDistribution",
        "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig",
        "cloudfront:UpdateDistribution",
        "cloudfront:DeleteDistribution",
        "cloudfront:ListDistributions",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

## Troubleshooting

### Distribution Creation Fails

**Error**: "Distribution already exists"  
**Solution**: Check for existing test distributions and delete them first:
```bash
aws cloudfront list-distributions --query "DistributionList.Items[?Comment=='Test distribution with intentional security issues']"
```

### Distribution Deletion Fails

**Error**: "Distribution must be disabled before deletion"  
**Solution**: The cleanup script handles this automatically. Wait 15-20 minutes for the distribution to be disabled, then run cleanup again.

### Bucket Deletion Fails

**Error**: "Bucket not empty"  
**Solution**: The cleanup script empties the bucket first. If it fails, manually empty and delete:
```bash
aws s3 rm s3://test-cloudfront-origin-<ACCOUNT_ID> --recursive
aws s3 rb s3://test-cloudfront-origin-<ACCOUNT_ID>
```

### CloudFront Takes Too Long

CloudFront distributions can take 15-20 minutes to deploy or disable. This is normal AWS behavior. You can:
- Check status: `aws cloudfront get-distribution --id <ID> --query 'Distribution.Status'`
- Continue with other tasks while waiting
- The distribution will eventually reach "Deployed" status

## Testing Workflow

1. **Create Resources** (~2 minutes)
   ```bash
   ./create_test_resources.sh
   ```

2. **Wait for Deployment** (~15-20 minutes)
   - CloudFront distribution must be fully deployed
   - Check status periodically

3. **Run Service Screener** (~1 minute)
   ```bash
   cd ../../..
   python3 main.py --regions us-east-1 --services cloudfront --beta 1 --sequential 1
   ```

4. **Verify Results**
   - Check that 15 checks show FAIL status
   - Verify S3OriginBucketExists shows PASS
   - Confirm SNIConfiguration is skipped or shows PASS

5. **Cleanup Resources** (~2 minutes + 15-20 minutes wait)
   ```bash
   cd services/cloudfront/simulation
   ./cleanup_test_resources.sh
   ```
   - If distribution is still enabled, wait and run again

## Notes

- CloudFront is a global service but distributions are managed in us-east-1
- The test distribution will not serve actual traffic unless you access it
- All resources are tagged/named with "test" prefix for easy identification
- The S3 bucket name includes your AWS account ID to ensure uniqueness
- Distribution ID is saved to `/tmp/cloudfront-test-distribution-id.txt` for cleanup

## Security Considerations

These resources are intentionally insecure for testing purposes:
- S3 bucket is accessible via CloudFront without OAC/OAI
- Distribution allows HTTP traffic
- No WAF protection
- Deprecated SSL protocols enabled
- No logging or monitoring

**Do not use these configurations in production!**

## Additional Resources

- [CloudFront Developer Guide](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/)
- [CloudFront Security Best Practices](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/security-best-practices.html)
- [Service Screener Documentation](../../README.md)

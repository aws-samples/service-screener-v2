# SOC2 Remediation Guide

This guide provides remediation steps for common findings identified by the SOC2 framework in Service Screener.

## Security Controls

### IAM Controls

#### Finding: Root account MFA not enabled (iam.rootMfaActive)

**Remediation:**
```bash
# Enable MFA for root account through AWS Console
# 1. Sign in to the AWS Management Console as the root user
# 2. Choose your account name in the navigation bar, and then choose Security credentials
# 3. In the Multi-factor authentication (MFA) section, choose Activate MFA
# 4. Follow the wizard to set up your MFA device
```

#### Finding: Weak password policy (iam.passwordPolicy)

**Remediation:**
```bash
# Set a strong password policy
aws iam update-account-password-policy \
    --minimum-password-length 14 \
    --require-symbols \
    --require-numbers \
    --require-uppercase-characters \
    --require-lowercase-characters \
    --max-password-age 90 \
    --password-reuse-prevention 24
```

#### Finding: MFA not enabled for console users (iam.mfaEnabledForConsoleUsers)

**Remediation:**
```bash
# List users without MFA
aws iam list-users --query 'Users[?UserName!=`null`].[UserName]' --output text | while read user; do
  if ! aws iam list-mfa-devices --user-name "$user" --query 'MFADevices[*]' --output text | grep -q .; then
    echo "User without MFA: $user"
  fi
done

# Enable MFA for each user through AWS Console
# 1. Sign in to the AWS Management Console
# 2. Go to IAM > Users > [Username] > Security credentials
# 3. In the Multi-factor authentication (MFA) section, choose Assign MFA device
# 4. Follow the wizard to set up the MFA device
```

### CloudTrail Controls

#### Finding: Multi-region trail not enabled (cloudtrail.multiRegionTrailEnabled)

**Remediation:**
```bash
# Create a multi-region CloudTrail
aws cloudtrail create-trail \
    --name soc2-compliance-trail \
    --s3-bucket-name your-cloudtrail-bucket \
    --is-multi-region-trail \
    --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name soc2-compliance-trail
```

#### Finding: Log file validation not enabled (cloudtrail.logFileValidationEnabled)

**Remediation:**
```bash
# Update existing trail to enable log file validation
aws cloudtrail update-trail \
    --name your-trail-name \
    --enable-log-file-validation
```

#### Finding: CloudWatch Logs integration not enabled (cloudtrail.cloudwatchLogsEnabled)

**Remediation:**
```bash
# Create CloudWatch Logs group
aws logs create-log-group --log-group-name CloudTrail/Logs

# Create IAM role for CloudTrail to CloudWatch Logs
# (Follow AWS documentation for creating the role with appropriate permissions)

# Update trail to use CloudWatch Logs
aws cloudtrail update-trail \
    --name your-trail-name \
    --cloud-watch-logs-log-group-arn arn:aws:logs:region:account-id:log-group:CloudTrail/Logs:* \
    --cloud-watch-logs-role-arn arn:aws:iam::account-id:role/CloudTrail_CloudWatchLogs_Role
```

## Availability Controls

### RDS Controls

#### Finding: RDS instances not configured for Multi-AZ (rds.instanceMultiAZ)

**Remediation:**
```bash
# Modify RDS instance to enable Multi-AZ
aws rds modify-db-instance \
    --db-instance-identifier your-db-instance \
    --multi-az \
    --apply-immediately
```

#### Finding: RDS backups not enabled (rds.instanceBackupEnabled)

**Remediation:**
```bash
# Enable automated backups for RDS instance
aws rds modify-db-instance \
    --db-instance-identifier your-db-instance \
    --backup-retention-period 7 \
    --preferred-backup-window "03:00-05:00" \
    --apply-immediately
```

### EC2 Controls

#### Finding: EC2 detailed monitoring not enabled (ec2.instanceDetailedMonitoringEnabled)

**Remediation:**
```bash
# Enable detailed monitoring for EC2 instance
aws ec2 monitor-instances --instance-ids i-1234567890abcdef0
```

#### Finding: EBS optimization not enabled (ec2.ebsOptimizedEnabled)

**Remediation:**
```bash
# Enable EBS optimization (if instance type supports it)
aws ec2 modify-instance-attribute \
    --instance-id i-1234567890abcdef0 \
    --ebs-optimized
```

## Confidentiality Controls

### S3 Controls

#### Finding: S3 bucket encryption not enabled (s3.bucketEncryption)

**Remediation:**
```bash
# Enable default encryption for S3 bucket
aws s3api put-bucket-encryption \
    --bucket your-bucket-name \
    --server-side-encryption-configuration '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                },
                "BucketKeyEnabled": true
            }
        ]
    }'
```

#### Finding: S3 bucket public access not blocked (s3.bucketPublicAccessBlock)

**Remediation:**
```bash
# Block public access for S3 bucket
aws s3api put-public-access-block \
    --bucket your-bucket-name \
    --public-access-block-configuration '{
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }'
```

#### Finding: S3 bucket versioning not enabled (s3.bucketVersioning)

**Remediation:**
```bash
# Enable versioning for S3 bucket
aws s3api put-bucket-versioning \
    --bucket your-bucket-name \
    --versioning-configuration Status=Enabled
```

### KMS Controls

#### Finding: KMS key rotation not enabled (kms.keyRotationEnabled)

**Remediation:**
```bash
# Enable automatic key rotation for customer managed KMS key
aws kms enable-key-rotation --key-id 1234abcd-12ab-34cd-56ef-1234567890ab
```

## Processing Integrity Controls

### CloudWatch Controls

#### Finding: CloudWatch alarms not configured (cloudwatch.hasAlarms)

**Remediation:**
```bash
# Create CloudWatch alarm for high CPU utilization
aws cloudwatch put-metric-alarm \
    --alarm-name high-cpu-utilization \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2 \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --period 300 \
    --statistic Average \
    --threshold 80 \
    --alarm-description "Alarm when CPU exceeds 80%" \
    --dimensions "Name=InstanceId,Value=i-1234567890abcdef0" \
    --alarm-actions arn:aws:sns:region:account-id:topic-name
```

### CloudFront Controls

#### Finding: CloudFront not using HTTPS (cloudfront.viewerPolicyHttps)

**Remediation:**
```bash
# Update CloudFront distribution to enforce HTTPS
aws cloudfront get-distribution-config --id DISTRIBUTION_ID > dist-config.json
# Edit dist-config.json to set ViewerProtocolPolicy to "redirect-to-https" or "https-only"
# Then update the distribution with the modified config
```

## Privacy Controls

### S3 Controls

#### Finding: S3 bucket lifecycle policies not configured (s3.bucketLifecycleEnabled)

**Remediation:**
```bash
# Configure lifecycle policy for S3 bucket
aws s3api put-bucket-lifecycle-configuration \
    --bucket your-bucket-name \
    --lifecycle-configuration '{
        "Rules": [
            {
                "ID": "Delete old data",
                "Status": "Enabled",
                "Prefix": "",
                "Expiration": {
                    "Days": 365
                }
            }
        ]
    }'
```

## Monitoring Controls

### GuardDuty Controls

#### Finding: GuardDuty not enabled (guardduty.isEnabled)

**Remediation:**
```bash
# Enable GuardDuty
aws guardduty create-detector \
    --enable \
    --finding-publishing-frequency FIFTEEN_MINUTES
```

### Security Hub Controls

#### Finding: Security Hub not enabled (securityhub.isEnabled)

**Remediation:**
```bash
# Enable Security Hub
aws securityhub enable-security-hub
```

### AWS Config Controls

#### Finding: AWS Config not enabled (config.isEnabled)

**Remediation:**
```bash
# Enable AWS Config
aws configservice put-configuration-recorder \
    --configuration-recorder name=default,roleARN=arn:aws:iam::account-id:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig \
    --recording-group allSupported=true,includeGlobalResources=true

aws configservice put-delivery-channel \
    --delivery-channel name=default,s3BucketName=your-config-bucket,configSnapshotDeliveryProperties="{\"deliveryFrequency\":\"Six_Hours\"}"

aws configservice start-configuration-recorder --configuration-recorder-name default
```

## Conclusion

This remediation guide provides steps to address common SOC2 compliance findings identified by Service Screener. After implementing these remediation steps, re-run the SOC2 framework assessment to verify that the issues have been resolved.

Remember to document all changes made for audit purposes and maintain ongoing compliance through regular assessments.

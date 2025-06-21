# SOC2 Framework for AWS - Detailed Mapping Guide

## Overview

This document provides a detailed mapping between SOC2 Trust Service Criteria (TSC) and AWS services. The SOC2 framework evaluates an organization's information systems based on five trust service categories:

1. **Security** - The system is protected against unauthorized access (both physical and logical)
2. **Availability** - The system is available for operation and use as committed or agreed
3. **Processing Integrity** - System processing is complete, valid, accurate, timely, and authorized
4. **Confidentiality** - Information designated as confidential is protected as committed or agreed
5. **Privacy** - Personal information is collected, used, retained, disclosed, and disposed of in conformity with commitments

## How to Use This Framework

To use the SOC2 framework with Service Screener:

```bash
screener --regions YOUR_REGION --beta 1 --frameworks SOC2
```

For example, to run in the us-east-1 region:

```bash
screener --regions us-east-1 --beta 1 --frameworks SOC2
```

## SOC2 Trust Service Criteria to AWS Service Mapping

### Common Criteria (CC)

#### CC1.0 - Control Environment

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC1.5 - Enforces accountability | IAM | iam.passwordPolicy, iam.rootMfaActive |

#### CC2.0 - Communication and Information

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC2.1 - Information to support internal control | CloudTrail | cloudtrail.multiRegionTrailEnabled, cloudtrail.logFileValidationEnabled |
| CC2.3 - Communication with external parties | IAM | iam.hasAlternateContact |

#### CC3.0 - Risk Assessment

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC3.2 - Identifies and analyzes risk | GuardDuty, Security Hub | guardduty.isEnabled, securityhub.isEnabled |
| CC3.3 - Considers potential for fraud | CloudTrail | cloudtrail.cloudwatchLogsEnabled |
| CC3.4 - Identifies and assesses significant change | Config | config.isEnabled |

#### CC4.0 - Monitoring Activities

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC4.1 - Evaluates and communicates deficiencies | CloudWatch | cloudwatch.hasAlarms |
| CC4.2 - Evaluates and communicates deficiencies | CloudTrail | cloudtrail.cloudwatchLogsEnabled |

#### CC5.0 - Control Activities

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC5.1 - Selects and develops control activities | IAM | iam.hasOrganization |
| CC5.2 - Selects and develops general controls over technology | IAM | iam.accessKeysRotated, iam.mfaEnabledForConsoleUsers |
| CC5.3 - Deploys through policies and procedures | IAM | iam.noRootUserAccessKey |

#### CC6.0 - Logical and Physical Access Controls

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC6.1 - Restricts logical access to authorized users | IAM | iam.usersMfaEnabled, iam.noInlinePolicy, iam.noUserPolicies |
| CC6.2 - Manages identification and authentication | IAM | iam.passwordPolicy |
| CC6.3 - Manages logical access | IAM | iam.supportRoleExists, iam.noFullAdminPolicies |
| CC6.6 - Restricts logical access to information assets | S3 | s3.bucketEncryption, s3.bucketPublicAccessBlock, s3.bucketVersioning |
| CC6.7 - Restricts the transmission, movement, and removal of information | S3 | s3.bucketLoggingEnabled, s3.bucketPublicAccessBlock |
| CC6.8 - Manages endpoints | EC2 | ec2.securityGroupsHasDescription, ec2.securityGroupsRestrictedSSH, ec2.securityGroupsRestrictedRDP |

#### CC7.0 - System Operations

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC7.1 - Manages infrastructure, software, and data | EC2 | ec2.instanceDetailedMonitoringEnabled, ec2.ebsOptimizedEnabled |
| CC7.2 - Manages security incidents | GuardDuty, Security Hub | guardduty.isEnabled, securityhub.isEnabled |
| CC7.3 - Manages business continuity | AWS Backup, RDS | backup.resourcesProtectedByBackupPlan, rds.instanceBackupEnabled |
| CC7.4 - Recovers from incidents | RDS, EC2 | rds.instanceMultiAZ, ec2.instanceEbsBackupEnabled |

#### CC8.0 - Change Management

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC8.1 - Manages changes to infrastructure, software, and data | CloudTrail | cloudtrail.multiRegionTrailEnabled |

#### CC9.0 - Risk Mitigation

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| CC9.1 - Identifies, selects, and develops risk mitigation activities | KMS | kms.cmkBackingKeyRotationEnabled, kms.keyRotationEnabled |

### Additional Criteria

#### A1.0 - Availability

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| A1.1 - Maintains, monitors, and evaluates current processing capacity | CloudWatch, EC2 | cloudwatch.hasAlarms, ec2.instanceDetailedMonitoringEnabled |
| A1.2 - Maintains redundancy, data backup, and disaster recovery | RDS, EC2, AWS Backup | rds.instanceMultiAZ, ec2.instanceEbsBackupEnabled, backup.resourcesProtectedByBackupPlan |
| A1.3 - Maintains recovery plan | AWS Backup | backup.resourcesProtectedByBackupPlan |

#### C1.0 - Confidentiality

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| C1.1 - Identifies confidential information | S3 | s3.bucketTaggingEnabled |
| C1.2 - Protects confidential information | S3, RDS, KMS | s3.bucketEncryption, rds.instanceEncryptionEnabled, kms.cmkBackingKeyRotationEnabled |

#### P4.0 - Use, Retention, and Disposal (Privacy)

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| P4.1 - Limits use of personal information | S3 | s3.bucketLifecycleEnabled |
| P4.2 - Retains personal information consistent with objectives | S3 | s3.bucketLifecycleEnabled |
| P4.3 - Disposes of personal information | S3 | s3.bucketLifecycleEnabled |

#### P8.0 - Monitoring and Enforcement (Privacy)

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| P8.1 - Monitors compliance with privacy policies | CloudTrail | cloudtrail.multiRegionTrailEnabled, cloudtrail.cloudwatchLogsEnabled |

#### PI1.0 - Processing Integrity

| SOC2 Criteria | AWS Services | Service Screener Checks |
|---------------|-------------|-------------------------|
| PI1.1 - Processes inputs accurately, completely, and timely | CloudWatch | cloudwatch.hasAlarms |
| PI1.2 - Maintains integrity during processing | CloudTrail | cloudtrail.logFileValidationEnabled |
| PI1.3 - Processes outputs accurately and completely | CloudWatch | cloudwatch.hasAlarms |
| PI1.4 - Maintains integrity during storage | S3, RDS | s3.bucketVersioning, s3.bucketEncryption, rds.instanceEncryptionEnabled |
| PI1.5 - Maintains integrity during transmission | CloudFront, API Gateway | cloudfront.viewerPolicyHttps, apigateway.endpointTypesPrivate |

## Extending the Framework

To extend this framework:

1. Add new mappings to the `map.json` file
2. Create custom checks in the appropriate service directories
3. Update this documentation to reflect new mappings

## SOC2 Compliance Recommendations

1. **Documentation**: Maintain comprehensive documentation of AWS configurations and controls
2. **Regular Assessment**: Run Service Screener regularly to identify compliance gaps
3. **Remediation**: Address identified issues promptly
4. **Evidence Collection**: Use Service Screener reports as evidence for SOC2 audits
5. **Continuous Monitoring**: Implement continuous monitoring using CloudWatch and other AWS services

# Glue Service Simulation

This directory contains scripts to create and cleanup intentionally insecure AWS Glue resources for testing Service Screener checks.

## Purpose

These scripts create real AWS resources with security misconfigurations that should trigger FAIL (-1) status in Service Screener. This allows you to validate that all Glue security checks are working correctly.

## Resources Created

| Resource | Configuration | Validates Checks |
|----------|--------------|------------------|
| Glue Job #1 | No SecurityConfiguration, bookmarks disabled | JobS3Encryption, JobCloudWatchLogsEncryption, JobBookmarkEncryption, JobLoggingEnabled, JobBookmarkEnabled |
| Glue Job #2 | Old Glue version (2.0) | GlueVersionCurrent |
| Glue Connection | SSL disabled | SslEnabled |
| Glue Crawler | No schedule configured | CrawlerScheduleConfigured |
| Glue Dev Endpoint | No SecurityConfiguration | DevEndpointCloudWatchLogsEncryption, DevEndpointBookmarkEncryption, DevEndpointS3Encryption |
| Glue ML Transform | No encryption | MLTransformEncryptionAtRest |
| Glue Database + Table | Supporting resources | (for ML Transform and Crawler) |

## Coverage

- **Total Checks**: 15
- **Validated by Scripts**: 12 (80%)
- **Account-Level Checks**: 3 (require manual configuration)

### Account-Level Checks (Not Covered)

These checks require AWS Console configuration at the account level:
1. `ConnectionPasswordEncryption` - Data Catalog encryption settings
2. `MetadataEncryption` - Data Catalog encryption settings
3. `PublicAccessibility` - Data Catalog resource policies

## Cost Considerations

⚠️ **WARNING**: The Glue Dev Endpoint costs approximately **$0.44/hour** (2 DPU nodes).

Other resources have minimal or no cost:
- Glue Jobs: No cost (not running)
- Glue Connection: No cost
- Glue Crawler: No cost (not running)
- Glue ML Transform: No cost (not running)
- Database/Table: No cost

**Always run cleanup script promptly to avoid unnecessary charges!**

## Usage

### Create Test Resources

```bash
cd service-screener-v2/services/glue/simulation
chmod +x create_test_resources.sh
./create_test_resources.sh
```

### Run Service Screener

```bash
cd ../../..  # Back to service-screener-v2 root
python3 main.py --regions us-east-1 --services glue --beta 1 --sequential 1
```

### Cleanup Resources

```bash
cd services/glue/simulation
chmod +x cleanup_test_resources.sh
./cleanup_test_resources.sh
```

## Expected Results

When you run Service Screener after creating these resources, you should see:

- **12 FAIL checks** (red flags) for the resources created
- **3 checks** may show PASS if your account has secure Data Catalog settings (this is expected)

## IAM Permissions Required

The scripts require AWS CLI configured with permissions to:
- Create/delete IAM roles and attach policies
- Create/delete Glue jobs, connections, crawlers, dev endpoints, ML transforms
- Create/delete Glue databases and tables

## Troubleshooting

**Dev Endpoint creation fails**: Dev endpoints may not be available in all regions or may require additional setup. This is optional - other resources will still validate 9 checks.

**IAM role already exists**: If you see warnings about existing roles, the script will continue using the existing role.

**Resources not appearing**: Wait 10-15 seconds after creation for resources to be fully provisioned before running Service Screener.

**Crawler not showing schedule issue**: The check validates that crawlers have a schedule configured. A crawler without a schedule will trigger the FAIL status.

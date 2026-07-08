# Service Simulation Testing

This document explains how to use the simulation testing framework to validate Service Screener security checks with real AWS resources.

## Overview

Each service in `services/{SERVICE_NAME}/simulation/` contains scripts to create intentionally insecure AWS resources. These resources trigger FAIL status in Service Screener checks, allowing you to validate that your security checks are working correctly.

## Available Simulations

| Service | Checks Validated | Resources Created | Estimated Cost |
|---------|------------------|-------------------|----------------|
| **Glue** | 9/12 (75%) | 5 resources | ~$0.44/hour (Dev Endpoint) |
| **SageMaker** | 11/11 (100%) | 4 resources | ~$0.50/run |

## Quick Start

### Test a Single Service

```bash
# Glue
cd service-screener-v2/services/glue/simulation
./create_test_resources.sh
cd ../../..
python3 main.py --regions us-east-1 --services glue --beta 1 --sequential 1
cd services/glue/simulation
./cleanup_test_resources.sh

# SageMaker
cd service-screener-v2/services/sagemaker/simulation
./create_test_resources.sh
cd ../../..
python3 main.py --regions us-east-1 --services sagemaker --beta 1 --sequential 1
cd services/sagemaker/simulation
./cleanup_test_resources.sh
```

### Test Both Services Together

```bash
# Create resources
cd service-screener-v2/services/glue/simulation
./create_test_resources.sh
cd ../../../sagemaker/simulation
./create_test_resources.sh

# Run Service Screener
cd ../../..
python3 main.py --regions us-east-1 --services glue,sagemaker --beta 1 --sequential 1

# Cleanup
cd services/glue/simulation
./cleanup_test_resources.sh
cd ../../../sagemaker/simulation
./cleanup_test_resources.sh
```

## Directory Structure

```
service-screener-v2/
├── SIMULATION_TESTING.md (this file)
└── services/
    ├── glue/
    │   ├── Glue.py
    │   ├── glue.reporter.json
    │   ├── drivers/
    │   └── simulation/
    │       ├── create_test_resources.sh
    │       ├── cleanup_test_resources.sh
    │       └── README.md
    └── sagemaker/
        ├── Sagemaker.py
        ├── sagemaker.reporter.json
        ├── drivers/
        └── simulation/
            ├── create_test_resources.sh
            ├── cleanup_test_resources.sh
            └── README.md
```

## What Gets Created

### Glue Resources
- 1 ETL Job (no security configuration)
- 1 Connection (SSL disabled)
- 1 Dev Endpoint (no security configuration) ⚠️ COSTS MONEY
- 1 ML Transform (no encryption)
- 1 Database + Table (supporting resources)
- 1 IAM Role

### SageMaker Resources
- 1 Notebook Instance (no encryption, root access, direct internet)
- 1 Model (no network isolation, no VPC)
- 1 Training Job (no encryption, no isolation, no VPC)
- 1 Endpoint Config (single instance)
- 1 IAM Role

## Cost Management

⚠️ **IMPORTANT**: Always run cleanup scripts after testing!

**Glue Dev Endpoint** is the most expensive resource at ~$0.44/hour. Other resources have minimal cost.

To check what resources exist:
```bash
# Glue
aws glue list-jobs --region us-east-1
aws glue get-connections --region us-east-1
aws glue get-dev-endpoints --region us-east-1
aws glue get-ml-transforms --region us-east-1

# SageMaker
aws sagemaker list-notebook-instances --region us-east-1
aws sagemaker list-models --region us-east-1
aws sagemaker list-training-jobs --region us-east-1
aws sagemaker list-endpoint-configs --region us-east-1
```

## Expected Results

After creating resources and running Service Screener, you should see:

- **Glue**: 9 FAIL checks (red flags)
- **SageMaker**: 11 FAIL checks (red flags)
- **Total**: 20 FAIL checks validating security misconfigurations

## IAM Permissions Required

Your AWS CLI must be configured with permissions to:
- Create/delete IAM roles and attach policies
- Create/delete Glue resources (jobs, connections, dev endpoints, ML transforms, databases, tables)
- Create/delete SageMaker resources (notebooks, models, training jobs, endpoint configs)
- Access S3 (for SageMaker training data)

## Troubleshooting

### Resources Not Appearing
Wait 10-15 seconds after creation for resources to be fully provisioned before running Service Screener.

### IAM Role Errors
If you see "Role already exists" warnings, the scripts will continue using the existing role. This is normal if you've run the scripts before.

### Dev Endpoint Creation Fails
Dev endpoints may not be available in all regions or may require additional setup. This is optional - other Glue resources will still validate 5 checks.

### Training Job Remains After Cleanup
SageMaker training jobs cannot be deleted from AWS. They remain in your account history but don't incur charges after completion.

## Best Practices

1. **Always cleanup**: Run cleanup scripts immediately after testing
2. **Test in non-production**: Use a dedicated test AWS account
3. **Monitor costs**: Check AWS Cost Explorer after testing
4. **One service at a time**: Test services individually first before combining
5. **Check results**: Review the Service Screener HTML report to verify all checks failed as expected

## Adding New Service Simulations

To add simulation testing for a new service:

1. Create directory: `services/{SERVICE_NAME}/simulation/`
2. Create `create_test_resources.sh` with insecure resource creation
3. Create `cleanup_test_resources.sh` with resource deletion
4. Create `README.md` documenting the simulation
5. Make scripts executable: `chmod +x *.sh`
6. Update this document with the new service

## Future Enhancements

Potential improvements for the simulation framework:
- Master script to run all simulations
- Simulation metadata (JSON) with cost estimates
- Validation script to verify expected resources exist
- Dry-run mode to preview what would be created
- Automated cost tracking and reporting

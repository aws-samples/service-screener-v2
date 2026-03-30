# SageMaker Service Simulation

This directory contains scripts to create and cleanup intentionally insecure AWS SageMaker resources for testing Service Screener checks.

## Purpose

These scripts create real AWS resources with security misconfigurations that should trigger FAIL (-1) status in Service Screener. This allows you to validate that all SageMaker security checks are working correctly.

## Resources Created

| Resource | Configuration | Validates Checks |
|----------|--------------|------------------|
| Notebook Instance | No KMS encryption, root access enabled, direct internet access, no VPC, no lifecycle config | EncryptionEnabled, RootAccessDisabled, NotebookVpcSettings, DirectInternetAccess, NotebookLifecycleConfigAttached |
| Model | Network isolation disabled, no VPC, external container image, external model data URL | NetworkIsolation, ModelVpcSettings, ModelContainerImageSource, ModelDataUrlValidation |
| Training Job | No inter-container encryption, no network isolation, no volume/output encryption, no VPC, no spot instances, no checkpoints | InterContainerEncryption, TrainingNetworkIsolation, VolumeAndOutputEncryption, TrainingVpcSettings, TrainingSpotInstancesEnabled, TrainingCheckpointConfigured |
| Endpoint Config | Single instance per variant (no HA), no data capture, mixed instance types | ProductionVariantInstanceCount, EndpointDataCaptureEnabled, EndpointInstanceTypeConsistency |
| Endpoint | No auto-scaling configured, unbalanced variant weights | EndpointAutoScalingConfigured, EndpointVariantWeightDistribution |
| Tuning Job | No early stopping enabled | HyperparameterTuningEarlyStopping |

## Coverage

- **Total Checks**: 21
- **Validated by Scripts**: 21 (100%)

All SageMaker checks are validated by these simulation scripts!

## Cost Considerations

- **Notebook Instance**: ~$0.058/hour (ml.t3.medium) - automatically stopped during cleanup
- **Training Job**: One-time cost (~$0.10-0.20 for short job), stops automatically after completion
- **Endpoint**: ~$0.065/hour (ml.t2.medium x2) - ⚠️ **COSTS MONEY** until cleaned up!
- **Tuning Job**: Will spawn multiple training jobs (~$1-2 total), stops automatically
- **Model**: No cost (not deployed to endpoint)
- **Endpoint Config**: No cost (not deployed)

**Total estimated cost per test run**: $1-3 if cleaned up within 1 hour

⚠️ **IMPORTANT**: The endpoint will continue to incur charges until deleted. Run the cleanup script promptly!

## Usage

### Create Test Resources

```bash
cd service-screener-v2/services/sagemaker/simulation
chmod +x create_test_resources.sh
./create_test_resources.sh
```

### Run Service Screener

```bash
cd ../../..  # Back to service-screener-v2 root
python3 main.py --regions us-east-1 --services sagemaker --beta 1 --sequential 1
```

### Cleanup Resources

```bash
cd services/sagemaker/simulation
chmod +x cleanup_test_resources.sh
./cleanup_test_resources.sh
```

## Expected Results

When you run Service Screener after creating these resources, you should see:

- **21 FAIL checks** (red flags) - one for each security/operational misconfiguration
- All checks should show -1 in the results
- 100% coverage of all SageMaker checks

## IAM Permissions Required

The scripts require AWS CLI configured with permissions to:
- Create/delete IAM roles and attach policies
- Create/delete SageMaker notebook instances, models, training jobs, endpoint configs
- Access to S3 (for training job data)

## Troubleshooting

**Model creation fails**: The script uses an external Docker Hub image intentionally to trigger the ModelContainerImageSource check. If Docker Hub is unavailable, the model creation may fail, but other checks will still work.

**Training job fails**: The training job uses public sample data from `s3://sagemaker-sample-files/`. If this fails, the job will error but won't affect other resources.

**Endpoint takes time to create**: Endpoints typically take 5-10 minutes to be in service. You can run Service Screener before the endpoint is fully ready - it will still detect the configuration issues.

**Tuning job spawns multiple training jobs**: The tuning job will create up to 10 training jobs. Each will stop automatically, but monitor costs if you don't clean up promptly.

**Training/Tuning jobs remain in history**: These jobs cannot be deleted from AWS. They remain in your account history but don't incur charges after completion.

## Notes

- The training job will run for up to 1 hour (MaxRuntimeInSeconds=3600) but typically completes or fails within minutes
- All resources are prefixed with `test-` for easy identification
- The IAM role created has full SageMaker access - this is intentional for testing but not recommended for production

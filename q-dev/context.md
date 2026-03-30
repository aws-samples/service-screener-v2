# AI Context Document
The purpose of this document is to provide an overview of this codebase to AI development tools.

## Project Overview
Service Screener is an open-source AWS environment assessment tool that runs automated checks against AWS services and provides recommendations based on AWS best 
practices. It's designed to complement the AWS Well-Architected Tool by focusing on service-level configurations.

## Tech Stack
- **Language**: Python 3
- **Key Dependencies**:
  - boto3: AWS SDK for Python
  - XlsxWriter/openpyxl: For Excel report generation
  - multiprocess: For parallel processing
  - requests: For API calls
  - simple-term-menu: For CLI interface

## Project Structure
- **main.py**: Entry point that handles command-line arguments and orchestrates the scanning process
- **Screener.py**: Core scanning engine that coordinates service checks
- **services/**: Contains modules for each AWS service that can be scanned
  - Each service folder (e.g., s3, rds, ec2) contains specific checks
  - Service.py: Base class for all service scanners
  - Reporter.py: Handles report generation
  - PageBuilder.py: Builds HTML report pages
  - **simulation/**: Testing framework for validating security checks
    - create_test_resources.sh: Creates intentionally insecure AWS resources
    - cleanup_test_resources.sh: Removes test resources
    - README.md: Documentation for the simulation
- **utils/**: Helper utilities
  - Config.py: Configuration settings and service mappings
  - ArguParser.py: Command-line argument parsing
  - Tools.py: Common utility functions
- **frameworks/**: Contains Well-Architected Framework integration
- **templates/**: HTML templates for report generation
- **adminlte/**: UI framework for the HTML reports
- **q-dev/**: Development guides and prompt templates for AI-assisted development
- **tests/**: Unit tests for service drivers

## How It Works
1. Execution Environment: Runs in AWS CloudShell (browser-based shell)
2. Data Collection: Makes multiple AWS API calls (describe and get) to collect configuration data
3. Analysis: Evaluates configurations against best practices
4. Report Generation: Creates an HTML report with findings and recommendations

## Key Components
1. Service Modules: Each AWS service has its own module with specific checks
2. Screener Engine: Coordinates scanning across services and regions
3. Reporter: Generates HTML and JSON reports
4. Config: Maintains settings and service mappings

## How to Run
As described in the README:
1. Install in AWS CloudShell using the provided script
2. Run using the screener command with appropriate parameters:
  bash
   screener --regions ap-southeast-1 --beta 1
   
3. Options include:
   - --regions: Specify AWS regions to scan (comma-separated or ALL)
   - --services: Specific services to scan (comma-separated)
   - --beta: Enable beta features
   - --tags: Filter resources by tags
   - --others: Additional parameters (JSON format) for Well-Architected Tool integration

## Output
- HTML report (index.html) with interactive dashboard
- JSON files with raw findings (api-raw.json and api-full.json)
- The report is downloaded as a zip file from CloudShell

## Key Features
1. Multi-region scanning: Can scan resources across multiple AWS regions
2. Service-specific checks: Tailored checks for each AWS service
3. Well-Architected integration: Can create workloads and milestones in the Well-Architected Tool
4. Tag-based filtering: Can filter resources based on tags
5. Cross-account support: Can scan resources across multiple AWS accounts

## Workflow
1. Parse command-line arguments
2. Determine which regions and services to scan
3. For each service and region, run the appropriate checks
4. Collect and aggregate findings
5. Generate HTML and JSON reports
6. Package everything into a downloadable zip file

The tool is designed to be lightweight and run within AWS CloudShell's free tier, making it accessible to all AWS customers without additional cost.

## Simulation Testing Framework

Service Screener includes a simulation testing framework that allows developers to validate security checks with real AWS resources. This is a critical part of the development workflow to ensure checks work correctly in production.

### What is Simulation Testing?

Simulation testing creates intentionally insecure AWS resources that should trigger FAIL (-1) status in Service Screener checks. This validates that:
1. The service discovery logic correctly finds resources
2. The driver classes properly evaluate configurations
3. The checks accurately identify security misconfigurations
4. The reporter correctly displays findings

### Directory Structure

Each service with simulation testing has a `simulation/` directory:

```
services/{SERVICE_NAME}/
├── ServiceName.py
├── service.reporter.json
├── drivers/
│   └── DriverName.py
└── simulation/              # Simulation testing framework
    ├── create_test_resources.sh    # Creates insecure test resources
    ├── cleanup_test_resources.sh   # Removes test resources
    └── README.md                   # Documentation and cost info
```

### Available Simulations

Currently implemented:
- **Glue**: Validates 9/12 checks (75% coverage)
- **SageMaker**: Validates 11/11 checks (100% coverage)

### Simulation Workflow

1. **Create Resources**: Run `create_test_resources.sh` to create intentionally insecure AWS resources
2. **Run Service Screener**: Execute Service Screener against the test resources
3. **Validate Results**: Verify that all expected checks show FAIL (-1) status
4. **Cleanup**: Run `cleanup_test_resources.sh` to remove resources and avoid costs

### Example Usage

```bash
# Create test resources for SageMaker
cd services/sagemaker/simulation
./create_test_resources.sh

# Run Service Screener
cd ../../..
python3 main.py --regions us-east-1 --services sagemaker --beta 1 --sequential 1

# Cleanup resources
cd services/sagemaker/simulation
./cleanup_test_resources.sh
```

### Key Features

1. **IAM Role Management**: Scripts automatically create and cleanup required IAM roles
2. **Cost Awareness**: Each simulation documents estimated costs
3. **Self-Contained**: Each service has its own isolated simulation
4. **Documentation**: README files explain what resources are created and which checks are validated
5. **Error Handling**: Scripts handle existing resources gracefully

### Cost Considerations

⚠️ **IMPORTANT**: Simulation testing creates real AWS resources that may incur costs:
- Most resources have minimal cost (< $0.50 per test run)
- Some resources like Glue Dev Endpoints cost ~$0.44/hour
- Always run cleanup scripts immediately after testing
- Use a dedicated test AWS account when possible

### When to Use Simulation Testing

Use simulation testing when:
- Developing new security checks
- Modifying existing driver logic
- Validating that checks work end-to-end
- Debugging why a check isn't triggering as expected
- Contributing new services to the project

### Creating Simulations for New Services

When adding a new service, create a simulation directory with:

1. **create_test_resources.sh**: 
   - Create IAM roles needed by the service
   - Create resources with insecure configurations
   - Document which checks each resource validates
   - Include cost warnings for expensive resources

2. **cleanup_test_resources.sh**:
   - Delete all created resources
   - Remove IAM roles
   - Handle resources that can't be deleted (like training jobs)

3. **README.md**:
   - List all resources created
   - Map resources to checks validated
   - Document estimated costs
   - Provide usage instructions
   - Include troubleshooting tips

### Best Practices

1. **Prefix Resources**: Use `test-` prefix for easy identification
2. **Document Costs**: Clearly state hourly/per-run costs
3. **Handle Errors**: Scripts should handle existing resources gracefully
4. **IAM Propagation**: Wait 10-15 seconds after creating IAM roles
5. **Cleanup Verification**: Verify all resources are deleted after cleanup
6. **Account-Level Checks**: Document checks that require manual AWS Console configuration

### Integration with Development Workflow

Simulation testing integrates with the standard development workflow:

1. Define checks in reporter.json
2. Implement driver classes with check methods
3. Create simulation scripts to validate checks
4. Run unit tests (pytest)
5. Run simulation tests (real AWS resources)
6. Review Service Screener HTML report
7. Iterate until all checks work correctly

See `./SIMULATION_TESTING.md` for complete documentation.

## Resources

Please also read the following documents for better understanding:
- ./README.md
- ./docs/DevelopmentGuide.md
- ./SIMULATION_TESTING.md (for testing security checks with real AWS resources)

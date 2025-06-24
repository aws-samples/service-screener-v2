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
- **utils/**: Helper utilities
  - Config.py: Configuration settings and service mappings
  - ArguParser.py: Command-line argument parsing
  - Tools.py: Common utility functions
- **frameworks/**: Contains Well-Architected Framework integration
- **templates/**: HTML templates for report generation
- **adminlte/**: UI framework for the HTML reports

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

## Resources

Please also read the following documents for better understanding:
- ./README.md
- ./docs/development-guide.md

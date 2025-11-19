# AWS Service Screener Summarizer Tools

Generate actionable summary reports from [AWS Service Screener V2](https://github.com/aws-samples/service-screener-v2) scan results using Kiro CLI.

## Overview

The AWS Service Screener Summarizer Tools translate Service Screener output data into technology/framework-specific HTML reports with:

- **Well-Architected Framework Analysis** - Comprehensive 6-pillar assessments with priority-based recommendations
- **Modernization Roadmaps** - Strategic guidance for containerization, database migration, and application modernization
- **FTR Compliance Reports** - Foundational Technical Review assessments with detailed remediation plans
- **Actionable Recommendations** - AWS CLI commands and step-by-step implementation guidance
- **Visual Reports** - Professional, interactive HTML reports with embedded diagrams and metrics

## Features

### Well-Architected Framework Analysis
- Analyzes top 5 services with the most findings
- Coverage across all 6 pillars: Security, Reliability, Performance Efficiency, Cost Optimization, Operational Excellence, Sustainability
- Priority-based recommendations (High/Medium/Low)
- Implementation roadmap with specific timelines
- Cost-benefit analysis with ROI calculations
- AWS CLI commands for immediate remediation

### Modernization Analysis (Extended WAF Report)
- **Database modernization** paths with MongoDB migration guidance
- **Container strategies** for ECS/EKS transformation
- **Vector database** implementation for GenAI applications
- **Phased modernization** roadmap with timeline and resource requirements
- **Architecture diagrams** (Current vs. Target state)
- **TCO analysis** and cost-benefit calculations

### Foundational Technical Review (FTR) Compliance
- Compliance assessment across all 14 FTR categories
- Criticality versus complexity prioritization
- Detailed remediation guidance for every non-compliant check
- Immediate/Short-term/Long-term action plans
- Success metrics and KPIs
- Path to FTR approval roadmap

## Prerequisites

### Required Tools

1. **Python**
   ```bash
   python3 --version
   ```

2. **jq** (for FTR script only)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install jq
   
   # macOS
   brew install jq
   
   # Verify installation
   jq --version
   ```

3. **AWS CLI** (configured with valid credentials)
   ```bash
   aws configure
   aws sts get-caller-identity
   ```

4. **Kiro CLI**
   ```bash
   # Install Kiro CLI
   # Visit: https://kiro.dev/cli/
   
   # Verify installation
   kiro-cli --version
   ```

### Service Screener Results

You must have completed Service Screener scan results with the following structure:

```
service-screener-results/
├── 123456789012/              # Account ID directory
│   ├── index.html             # Global summary (required for WAF)
│   ├── CPFindings.html        # Control plane findings (required for WAF)
│   ├── FTR.html               # FTR results (required for FTR script)
│   ├── api-full.json          # Full API results (required for FTR script)
│   ├── ec2.html               # Service-specific results
│   ├── s3.html
│   ├── iam.html
│   ├── rds.html
│   └── ...                    # Other service files
└── res/                       # CSS, JS, and image resources
    ├── dist/
    └── plugins/
```

## Installation

```bash
# Clone the repository
git clone https://github.com/aws-samples/service-screener-v2.git
cd service-screener-v2/usecases/wa-summarizer

# Make script executable
chmod +x run_summarizer.sh
```

## Quick Start

### Interactive Mode (Recommended)

The main launcher provides an interactive menu for easy use:

```bash
./run_summarizer.sh
```

This will:
1. Display available report types
2. Guide you through selecting the appropriate analyzer
3. Prompt for Service Screener results directory
4. Ask for output directory (or use default)
5. Execute the selected analyzer
6. Display results and next steps

### Command-Line Mode

For automation or scripting, use command-line arguments:

```bash
./run_summarizer.sh --report <TYPE> --input-dir <PATH> [--output-dir <PATH>]
```

**Options:**
- `--report TYPE` - Report type: `wa`, `wa_mod`, or `ftr`
- `--input-dir PATH` - Path to Service Screener results directory (required)
- `--output-dir PATH` - Output directory (optional, default: `./output`)
- `-h, --help` - Show help message

**Examples:**

```bash
# FTR report with custom paths
./run_summarizer.sh --report ftr --input-dir ./aws --output-dir ./reports

# WAF report with default output directory
./run_summarizer.sh --report wa --input-dir /path/to/aws

# WAF with modernization analysis
./run_summarizer.sh --report wa_mod --input-dir ./aws --output-dir ./output
```

### Direct Script Execution

You can also run individual scripts directly:

#### Well-Architected Framework Report
```bash
./summarizer_scripts/run_wa_summarizer.sh -d /path/to/screener-results -o ./output
```

#### WAF with Modernization Analysis
```bash
./summarizer_scripts/run_wa_summarizer_mod.sh -d /path/to/screener-results -o ./output
```

#### FTR Compliance Report
```bash
./summarizer_scripts/run_ftr_summarizer.sh -d /path/to/screener-results -o ./output
```

## Report Types

### 1. Well-Architected Framework Summary

**Best For:**
- Regular Well-Architected assessments
- Identifying security and operational gaps
- Performance and cost optimization reviews
- Quarterly compliance checks

**Report Sections:**
- Summary dashboard with severity breakdown
- Well-Architected 6 Pillars analysis
- Service-specific findings (top 5 services)
- Priority-based recommendations
- Implementation roadmap (0-90 days)
- Cost impact analysis
- Conclusion and next steps

**Typical Use Case:**
> "Our quarterly security review identified 1,694 findings across 5 services. The report prioritized 28 high-severity issues for immediate action, with detailed CLI commands for remediation."

### 2. Modernization Analysis Report

**Best For:**
- Planning cloud modernization initiatives
- Database migration projects
- Container adoption strategies
- Application transformation roadmaps

**Additional Sections:**
- Database modernization pathways (MongoDB)
- Container transformation analysis (ECS/EKS)
- Serverless opportunities
- Phased modernization roadmap (0-24 months)
- Current vs. target architecture diagrams
- TCO and ROI analysis

**Typical Use Case:**
> "Planning to modernize 50 EC2-based applications. The report provided a 12-month phased approach, identifying 15 ECS candidates, 8 Lambda transformations, and estimated $45K annual savings."

### 3. FTR Compliance Report

**Best For:**
- AWS Partner Network FTR preparation
- Compliance gap assessments
- Security baseline establishment
- Pre-certification audits

**Report Sections:**
- FTR category compliance breakdown (14 categories)
- Compliance rate and trend analysis
- Category-by-category findings
- Eisenhower Matrix prioritization
- Comprehensive appendix (all non-compliant checks)
- Success metrics and follow-up activities
- Path to FTR approval

**Typical Use Case:**
> "Preparing for AWS FTR certification. Report identified 54 findings across 14 categories with current 45% compliance. Prioritized 18 immediate actions to reach 95% compliance within 6 months."

## Generated Reports

All reports are:
- **Self-contained** - Single HTML file with embedded CSS/JavaScript
- **Interactive** - Collapsible sections, navigation menu, mobile-responsive
- **Timestamped** - Unique filenames for version tracking
- **Actionable** - Includes AWS CLI commands and step-by-step guidance
- **Professional** - Publication-ready for stakeholder presentations

### Sample Reports

See the `output_samples/` directory for example reports:
- `ftr_summarizer_sample_report.html` - FTR compliance report
- `wa_summarizer_sample_report.html` - Standard WAF report

## Contributing

Contributions are welcome! Please:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/new-analyzer`)
3. **Follow existing patterns** in script structure
4. **Test thoroughly** with real Service Screener data
5. **Update documentation** (this README and script READMEs)
6. **Submit a pull request**

### Adding New Analyzers

To add a new report type:

1. Create script in `summarizer_scripts/` following naming convention
2. Add corresponding prompt in `src/prompt/`
3. Update main launcher (`run_summarizer.sh`) with new option
4. Add sample report to `output_samples/`
5. Document in `summarizer_scripts/README.md`

## Support and Resources

### Documentation
- **Script Details**: See `summarizer_scripts/README.md`
- **Reference Docs**: See `references/README.md`
- **Sample Reports**: Check `output_samples/` directory

### Getting Help
- **Issues**: Open an issue in the GitHub repository
- **Discussions**: Use GitHub Discussions for questions
- **AWS Support**: For Service Screener or AWS service questions
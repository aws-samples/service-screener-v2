# Service Screener Summarizer Scripts

This directory contains specialized scripts for generating comprehensive summary reports from AWS Service Screener results.

## Available Scripts

### 1. run_wa_summarizer.sh
**Well-Architected Framework Standard Summary**

Generates a comprehensive Well-Architected Framework analysis report covering all six pillars.

**Features:**
- Analyzes top 5 services with most findings (always includes IAM)
- Security, Reliability, Performance Efficiency, Cost Optimization, Operational Excellence, and Sustainability assessments
- Priority-based recommendations (High/Medium/Low)
- Implementation roadmap with specific timelines
- Cost-benefit analysis with ROI calculations
- AWS CLI commands for remediation

**Usage:**
```bash
./run_wa_summarizer.sh -d <service-screener-dir> [-o <output-dir>]
```

**Example:**
```bash
./run_wa_summarizer.sh -d /path/to/screener/results -o ./reports
```

---

### 2. run_wa_summarizer_mod.sh
**Well-Architected Framework with Modernization Analysis**

Extended version of the standard WAF report with additional modernization recommendations.

**Features:**
- All features from standard WAF summary
- **MongoDB migration guidance** - Database modernization paths and vector database strategies for GenAI
- **ECS containerization** - Guidance on containerizing EC2-based applications
- **EKS best practices** - Kubernetes optimization recommendations
- **Phased modernization roadmap** - Strategic transformation timeline
- Current vs. target architecture diagrams (Mermaid)
- Technology-specific migration methods

**Usage:**
```bash
./run_wa_summarizer_mod.sh -d <service-screener-dir> [-o <output-dir>]
```

**Example:**
```bash
./run_wa_summarizer_mod.sh -d ./aws/012345678901 -o ./modernization-reports
```

**Note:** This script references additional documentation in the `../references/` directory:
- `migration-mongodb-atlas.md`
- `modernization-phased-approach.md`
- `ecs-bestpracticesguide.md`
- `strategy-modernizing-applications.md`
- `eks-bpg.md`

---

### 3. run_ftr_summarizer.sh
**Foundational Technical Review (FTR) Compliance Summary**

Generates a detailed FTR compliance assessment report with prioritized remediation guidance.

**Features:**
- Analysis across all 14 FTR categories
- Compliance rate calculation and tracking
- Eisenhower Matrix-based prioritization
- Immediate/Short-term/Long-term action plans
- Detailed appendix with ALL non-compliant findings
- Specific remediation steps with AWS CLI commands
- Success metrics and KPIs
- Path to FTR approval roadmap

**Processing:**
1. Converts FTR.html to structured JSON
2. Enriches with metadata from api-full.json
3. Generates comprehensive HTML report

**Usage:**
```bash
./run_ftr_summarizer.sh -d <service-screener-dir> [-o <output-dir>]
```

**Example:**
```bash
./run_ftr_summarizer.sh -d ./aws/012345678901 -o ./ftr-reports
```

**Required Files:**
- `<account-dir>/FTR.html` - FTR compliance results
- `<account-dir>/api-full.json` - Full API scan results

---

## Common Options

All scripts support the following command-line options:

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `-d, --dir` | Service Screener results directory | Yes | - |
| `-o, --output` | Output directory for generated reports | No | `./output` |
| `-h, --help` | Display help message | No | - |

## Prerequisites

Before running any script, ensure you have:

1. **Python 3.6+** - For data processing scripts
2. **jq** - For JSON parsing (FTR script)
3. **AWS CLI** - Configured with valid credentials
4. **Kiro CLI** - Installed and configured
5. **Service Screener Results** - Complete scan output with required files

### Checking Prerequisites

```bash
# Check Python version
python3 --version

# Check jq installation
jq --version

# Check AWS CLI configuration
aws sts get-caller-identity

# Check Kiro CLI
kiro-cli --version
```

## Service Screener Directory Structure

Your Service Screener results should follow this structure:

```
aws/
├── 012345678901/              # Account ID directory
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

## Output

Each script generates timestamped HTML reports:

- **WAF Standard**: `wa_summary_report_YYYYMMDD_HHMMSS.html`
- **WAF Modernization**: `wa_summary_report_mod_YYYYMMDD_HHMMSS.html`
- **FTR**: `ftr_summary_report_YYYYMMDD_HHMMSS.html`

Reports are self-contained HTML files with:
- Embedded CSS styling
- Interactive JavaScript elements
- No external dependencies
- Mobile-responsive design

## Troubleshooting

### Script Not Found Error
```bash
chmod +x run_*.sh
```

### Kiro CLI Not Found
```bash
# Install Kiro CLI
# Visit: https://kiro.dev/cli/
```

### AWS Credentials Not Configured
```bash
aws configure
```

### Missing Service Screener Files

Ensure you've run Service Screener successfully:
```bash
# From Service Screener V2 directory
python3 main.py --account-id 012345678901
```

### JSON Parsing Errors (FTR Script)

Ensure `jq` is installed and FTR.html contains valid data:
```bash
# Install jq (Ubuntu/Debian)
sudo apt-get install jq

# Install jq (macOS)
brew install jq
```

## Best Practices

1. **Run from root directory**: Use the main launcher `../run_summarizer.sh` for guided experience
2. **Keep results organized**: Use separate output directories for different report types
3. **Version control reports**: Include timestamps in filenames for tracking
4. **Review before implementing**: Always validate recommendations in a non-production environment first
5. **Update regularly**: Re-run reports quarterly to track improvement progress

## Support and Documentation

- **Main Documentation**: See `../README.md`
- **Sample Reports**: Check `../output_samples/` directory
- **Service Screener**: https://github.com/aws-samples/service-screener-v2
- **AWS Well-Architected Framework**: https://aws.amazon.com/architecture/well-architected/
- **FTR Documentation**: https://aws.amazon.com/partners/programs/ftr/

## Contributing

To add new summarizer scripts:

1. Create script in this directory following naming convention: `run_<type>_summarizer.sh`
2. Follow existing script structure (argument parsing, validation, Kiro CLI integration)
3. Add corresponding prompt file in `../src/prompt/`
4. Update this README with script documentation
5. Add sample output to `../output_samples/`
6. Update main launcher script `../run_summarizer.sh`
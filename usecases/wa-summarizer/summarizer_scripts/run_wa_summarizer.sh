#!/bin/bash
# AWS Service Screener Well-Architected Summarizer
# A tool to analyze AWS Service Screener output and generate Well-Architected Framework analysis reports
# Usage: ./run_wa_summarizer.sh -d <service-screener-dir> [-o <output-dir>]

set -e

# Color definitions for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default settings
SUMMARIZER_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT_DIR="$(cd "${SUMMARIZER_SCRIPT_DIR}/.." && pwd)"
DEFAULT_OUTPUT_DIR="${PROJECT_ROOT_DIR}/output"
PROMPT_FILE="${PROJECT_ROOT_DIR}/src/prompt/wa_summarizer.md"
KIRO_PROMPTS_DIR="${HOME}/.kiro/prompts"

# Variable to store prompt file path for cleanup
prompt_file=""

# Cleanup function
cleanup() {
    if [ -n "$prompt_file" ] && [ -f "$prompt_file" ]; then
        echo ""
        echo -e "${YELLOW}🧹 Cleaning up temporary prompt file...${NC}"
        rm -f "$prompt_file"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Temporary prompt file removed.${NC}"
        fi
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Help function
show_help() {
    echo -e "${BLUE}AWS Service Screener Well-Architected Summarizer${NC}"
    echo ""
    echo "A tool to analyze AWS Service Screener output and generate Well-Architected Framework analysis reports."
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -d, --dir DIRECTORY     Service Screener results directory (required)"
    echo "  -o, --output DIRECTORY  Output directory for reports (default: ./output)"
    echo "  -h, --help              Display this help message"
    echo ""
    echo "Example:"
    echo "  $0 -d /path/to/service-screener-results"
    echo "  $0 --dir ./screener-output --output ./my-reports"
}

# Main function
main() {
    local service_screener_dir=""
    local output_dir="$DEFAULT_OUTPUT_DIR"

    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dir)
                service_screener_dir="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # Check if service_screener_dir is provided
    if [ -z "$service_screener_dir" ]; then
        echo -e "${RED}❌ Service Screener directory is required.${NC}"
        show_help
        exit 1
    fi

    # Validate that the Service Screener directory exists
    if [ ! -d "$service_screener_dir" ]; then
        echo -e "${RED}❌ Service Screener directory does not exist: $service_screener_dir${NC}"
        exit 1
    fi

    # Check for required Service Screener files and structure
    # Look for at least one account directory
    account_dirs=$(find "$service_screener_dir" -maxdepth 1 -type d -not -path "$service_screener_dir" | wc -l)
    if [ "$account_dirs" -eq 0 ]; then
        echo -e "${RED}❌ No account directories found in Service Screener directory.${NC}"
        echo -e "${YELLOW}ℹ️ Service Screener directory should contain at least one account directory.${NC}"
        exit 1
    fi

    # Check for index.html in at least one account directory
    index_files=$(find "$service_screener_dir" -maxdepth 2 -name "index.html" | wc -l)
    if [ "$index_files" -eq 0 ]; then
        echo -e "${RED}❌ No index.html files found in Service Screener directory.${NC}"
        echo -e "${YELLOW}ℹ️ Service Screener directory should contain index.html files in account directories.${NC}"
        exit 1
    fi

    # Check for CPFindings.html in at least one account directory
    findings_files=$(find "$service_screener_dir" -maxdepth 2 -name "CPFindings.html" | wc -l)
    if [ "$findings_files" -eq 0 ]; then
        echo -e "${RED}❌ No CPFindings.html files found in Service Screener directory.${NC}"
        echo -e "${YELLOW}ℹ️ Service Screener directory should contain CPFindings.html files in account directories.${NC}"
        exit 1
    fi

    # Create output directory if it doesn't exist
    if [ ! -d "$output_dir" ]; then
        echo -e "${YELLOW}ℹ️ Creating output directory: $output_dir${NC}"
        mkdir -p "$output_dir"
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Failed to create output directory: $output_dir${NC}"
            exit 1
        fi
    fi

    # Check if output directory is writable
    if [ ! -w "$output_dir" ]; then
        echo -e "${RED}❌ Output directory is not writable: $output_dir${NC}"
        exit 1
    fi

    # Create Kiro prompts directory if it doesn't exist
    if [ ! -d "$KIRO_PROMPTS_DIR" ]; then
        echo -e "${YELLOW}ℹ️ Creating Kiro prompts directory: $KIRO_PROMPTS_DIR${NC}"
        mkdir -p "$KIRO_PROMPTS_DIR"
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Failed to create Kiro prompts directory: $KIRO_PROMPTS_DIR${NC}"
            exit 1
        fi
    fi

    # Generate timestamp for unique filenames
    timestamp=$(date +"%Y%m%d_%H%M%S")
    report_filename="wa_summary_report_${timestamp}.html"
    report_path="${output_dir}/${report_filename}"

    echo -e "${GREEN}📄 Report will be saved in: $report_path${NC}"
    echo -e "${YELLOW}🚀 Starting AWS Service Screener Well-Architected Framework Summarizer...${NC}"
    echo ""

    # Check for Kiro CLI
    if ! command -v kiro-cli --version &> /dev/null; then
        echo -e "${RED}❌ Kiro CLI is not installed.${NC}"
        echo -e "${YELLOW}ℹ️ Please install Kiro CLI before running this tool.${NC}"
        exit 1
    fi

    # Check for AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS credentials are not configured.${NC}"
        echo -e "${YELLOW}ℹ️ Please configure AWS credentials using 'aws configure' before running this tool.${NC}"
        exit 1
    fi

    # Check if prompt file exists
    if [ ! -f "$PROMPT_FILE" ]; then
        echo -e "${RED}❌ Prompt file does not exist: $PROMPT_FILE${NC}"
        exit 1
    fi

    echo -e "${YELLOW}📊 Analyzing Service Screener data...${NC}"
    
    # Prepare the prompt with the Service Screener directory path
    prompt_filename="summarizer-wa-prompt-${timestamp}"
    prompt_file="${KIRO_PROMPTS_DIR}/${prompt_filename}.md"
    sed "s|{SERVICE_SCREENER_DIR}|$service_screener_dir|g" "$PROMPT_FILE" > "$prompt_file"

    # Prepare the prompt with the default output directory path
    sed -i.bak "s|{DEFAULT_OUTPUT_DIR}|$output_dir|g" "$prompt_file" && rm -f "${prompt_file}.bak"
    
    # Send the prompt to Kiro CLI and save the output
    echo -e "${YELLOW}🤖 Sending request to Kiro...${NC}"

    kiro-cli settings chat.defaultModel claude-sonnet-4.5
    kiro-cli chat --trust-all-tools @${prompt_filename}
    
    # Check if the command was successful
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ AWS Service Screener Well-Architected Summarizer completed!${NC}"
    else
        echo -e "${RED}❌ Failed to generate report.${NC}"
        exit 1
    fi

    # Post-processing: Copy WA Lens Review Report PDF and inject download link
    echo -e "${YELLOW}📎 Checking for Well-Architected Lens Review Report (PDF)...${NC}"
    
    # Search for the WA lens review report PDF in the Service Screener results directory
    wa_pdf=$(find "$service_screener_dir" -maxdepth 2 -name "wa_lens_review_report_*.pdf" -type f 2>/dev/null | sort -r | head -1)
    
    if [ -n "$wa_pdf" ] && [ -f "$wa_pdf" ]; then
        # Copy PDF to output directory with a stable name for the HTML link
        cp "$wa_pdf" "${output_dir}/wa_lens_review_report.pdf"
        echo -e "${GREEN}✅ WA Lens Review Report copied to: ${output_dir}/wa_lens_review_report.pdf${NC}"
        
        # Find the generated HTML report and inject the download link
        generated_report=$(find "$output_dir" -maxdepth 1 -name "wa_summary_report_*.html" -type f 2>/dev/null | sort -r | head -1)
        
        if [ -n "$generated_report" ] && [ -f "$generated_report" ]; then
            # Check if the download link is already present
            if ! grep -q "wa_lens_review_report.pdf" "$generated_report"; then
                echo -e "${YELLOW}📝 Injecting WA Report download link into HTML report...${NC}"
                
                # Inject download link in sidebar navigation (after Overview link)
                sed -i.bak 's|<span class="nav-icon">🏠</span>Overview|<span class="nav-icon">🏠</span>Overview\
                    </a>\
                </div>\
                <div class="nav-section">\
                    <a href="wa_lens_review_report.pdf" class="nav-link" download>\
                        <span class="nav-icon">📄</span>Download WA Report (PDF)|' "$generated_report"
                
                # If sed sidebar injection didn't work cleanly, try a simpler approach
                if ! grep -q "wa_lens_review_report.pdf" "$generated_report"; then
                    # Fallback: inject after HEADER SECTION END comment
                    sed -i.bak '/<!-- ==================== HEADER SECTION END ====================.*-->/a\
\
                <!-- ==================== WA REPORT DOWNLOAD SECTION START ==================== -->\
                <div style="background: #e6f7e6; border: 1px solid #1D8102; border-radius: 4px; padding: 20px; margin-bottom: 20px;">\
                    <h3 style="color: #1D8102; margin-bottom: 10px;">📄 Well-Architected Lens Review Report</h3>\
                    <p style="color: #37475A; margin-bottom: 15px;">A PDF report has been generated from the AWS Well-Architected Tool for this workload. This report includes your responses to workload questions, notes, and a summary of identified high and medium risks along with improvement plans.</p>\
                    <a href="wa_lens_review_report.pdf" download style="display: inline-block; background: #0073bb; color: #fff; padding: 10px 20px; border-radius: 4px; text-decoration: none; font-weight: 600; font-size: 14px;">⬇️ Download WA Lens Review Report (PDF)</a>\
                    <p style="color: #687078; font-size: 12px; margin-top: 10px;">This report can be shared with stakeholders who do not have direct access to the AWS Well-Architected Tool.</p>\
                </div>\
                <!-- ==================== WA REPORT DOWNLOAD SECTION END ==================== -->' "$generated_report"
                fi
                
                # Clean up backup file from sed
                rm -f "${generated_report}.bak"
                
                if grep -q "wa_lens_review_report.pdf" "$generated_report"; then
                    echo -e "${GREEN}✅ Download link injected into report successfully!${NC}"
                else
                    echo -e "${YELLOW}⚠️ Could not inject download link automatically. PDF is available at: ${output_dir}/wa_lens_review_report.pdf${NC}"
                fi
            else
                echo -e "${GREEN}✅ Download link already present in report.${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}ℹ️ No WA Lens Review Report PDF found in Service Screener results.${NC}"
        echo -e "${YELLOW}   To generate one, run Service Screener with: --frameworks WAFS --others '{\"WA\": {\"region\": \"<region>\", \"reportName\": \"SS_Report\", \"newMileStone\": 1}}'${NC}"
    fi
}

# Execute the main function
main "$@"
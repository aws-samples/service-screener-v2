#!/bin/bash
# AWS Service Screener Well-Architected FTR Summarizer
# A tool to analyze AWS Service Screener output and generate Well-Architected Framework analysis reports
# Usage: ./run_ftr_summarizer.sh -d <service-screener-dir> [-o <output-dir>]

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
PROMPT_FILE="${PROJECT_ROOT_DIR}/src/prompt/ftr_summarizer.md"
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
    echo -e "${BLUE}AWS Service Screener Well-Architected FTR Summarizer${NC}"
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

    # Check for Python 3.6+
    echo -e "${YELLOW}🔍 Checking system requirements...${NC}"
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is not installed.${NC}"
        echo -e "${YELLOW}ℹ️ Please install Python 3.6 or higher before running this tool.${NC}"
        exit 1
    fi

    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    required_version="3.6"

    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
        echo -e "${RED}❌ Python version $python_version is installed, but version 3.6 or higher is required.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Python $python_version detected.${NC}"

    # Check for jq
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}❌ jq is not installed.${NC}"
        echo -e "${YELLOW}ℹ️ Please install jq before running this tool.${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ jq detected.${NC}"
    echo ""

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

    # Check for FTR.html in at least one account directory
    findings_files=$(find "$service_screener_dir" -maxdepth 2 -name "FTR.html" | wc -l)
    if [ "$findings_files" -eq 0 ]; then
        echo -e "${RED}❌ No FTR.html files found in Service Screener directory.${NC}"
        echo -e "${YELLOW}ℹ️ Service Screener directory should contain FTR.html files in account directories.${NC}"
        exit 1
    fi

    # Check for api-full.json in at least one account directory
    findings_files=$(find "$service_screener_dir" -maxdepth 2 -name "api-full.json" | wc -l)
    if [ "$findings_files" -eq 0 ]; then
        echo -e "${RED}❌ No api-full.json files found in Service Screener directory.${NC}"
        echo -e "${YELLOW}ℹ️ Service Screener directory should contain api-full.json files in account directories.${NC}"
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

    echo -e "${GREEN}✅ Service Screener directory validated: $service_screener_dir${NC}"
    echo ""

    # Find the FTR.html file path
    ftr_html_file=$(find "$service_screener_dir" -maxdepth 2 -name "FTR.html" | head -n 1)
    if [ -z "$ftr_html_file" ]; then
        echo -e "${RED}❌ Could not locate FTR.html file.${NC}"
        exit 1
    fi

    # Find the api-full.json file path
    api_full_json_file=$(find "$service_screener_dir" -maxdepth 2 -name "api-full.json" | head -n 1)
    if [ -z "$api_full_json_file" ]; then
        echo -e "${RED}❌ Could not locate api-full.json file.${NC}"
        exit 1
    fi

    echo -e "${YELLOW}📊 Processing FTR data from: $ftr_html_file${NC}"
    echo -e "${YELLOW}📊 Processing API data from: $api_full_json_file${NC}"

    # Run the HTML to JSON conversion script
    convert_script="${PROJECT_ROOT_DIR}/src/scripts/ftr_convert_html_to_json.sh"
    preliminary_json="${output_dir}/preliminary_ftr_results.json"

    if [ ! -f "$convert_script" ]; then
        echo -e "${RED}❌ Conversion script not found: $convert_script${NC}"
        exit 1
    fi

    echo -e "${YELLOW}🔄 Converting FTR.html to JSON...${NC}"
    bash "$convert_script" "$ftr_html_file" "$preliminary_json"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to convert FTR.html to JSON.${NC}"
        exit 1
    fi

    if [ ! -f "$preliminary_json" ]; then
        echo -e "${RED}❌ Preliminary JSON file was not created: $preliminary_json${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ FTR.html converted to JSON successfully.${NC}"

    # Run the JSON enrichment script
    enrich_script="${PROJECT_ROOT_DIR}/src/scripts/ftr_enrich_json.sh"
    final_json="${output_dir}/ftr_results.json"

    if [ ! -f "$enrich_script" ]; then
        echo -e "${RED}❌ Enrichment script not found: $enrich_script${NC}"
        exit 1
    fi

    echo -e "${YELLOW}🔄 Enriching JSON data...${NC}"
    bash "$enrich_script" "$preliminary_json" "$api_full_json_file" "$final_json"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Failed to enrich JSON data.${NC}"
        exit 1
    fi

    if [ ! -f "$final_json" ]; then
        echo -e "${RED}❌ Final JSON file was not created: $final_json${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ JSON data enriched successfully.${NC}"
    echo ""

    # Generate timestamp for unique filenames
    timestamp=$(date +"%Y%m%d_%H%M%S")
    report_filename="ftr_summary_report_${timestamp}.html"
    report_path="${output_dir}/${report_filename}"

    echo -e "${GREEN}📄 Report will be saved in: $report_path${NC}"
    echo -e "${YELLOW}🚀 Starting AWS Service Screener Well-Architected FTR Summarizer...${NC}"
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
    
    # Prepare the prompt with the default output directory path
    prompt_filename="summarizer-ftr-prompt-${timestamp}"
    prompt_file="${KIRO_PROMPTS_DIR}/${prompt_filename}.md"
    sed "s|{DEFAULT_OUTPUT_DIR}|$output_dir|g" "$PROMPT_FILE" > "$prompt_file"
    
    echo -e "${YELLOW}📝 Prompt saved to: $prompt_file${NC}"
    
    # Send the prompt to Kiro CLI and save the output
    echo -e "${YELLOW}🤖 Sending request to Kiro...${NC}"

    kiro-cli settings chat.defaultModel claude-sonnet-4.5
    kiro-cli chat --trust-all-tools @${prompt_filename}
    
    # Check if the command was successful
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ AWS Service Screener Well-Architected FTR Summarizer completed!${NC}"
    else
        echo -e "${RED}❌ Failed to generate report.${NC}"
        exit 1
    fi
}

# Execute the main function
main "$@"
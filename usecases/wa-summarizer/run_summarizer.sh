#!/bin/bash
# AWS Service Screener Summary Report Generator
# Main launcher script for generating Well-Architected and FTR summary reports

set -e

# Color definitions for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUMMARIZER_SCRIPTS_DIR="${SCRIPT_DIR}/summarizer_scripts"

# Function to display header
show_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}   ${CYAN}AWS Service Screener Summary Report Generator${NC}                ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to display usage information
show_usage() {
    echo "Usage: $(basename $0) [OPTIONS]"
    echo ""
    echo "Run interactively (wizard mode):"
    echo "  $(basename $0)"
    echo ""
    echo "Run with command-line arguments:"
    echo "  $(basename $0) --report <TYPE> --input-dir <PATH> [--output-dir <PATH>]"
    echo ""
    echo "Options:"
    echo "  --report TYPE        Report type: wa, wa_mod, or ftr"
    echo "                       wa      = Well-Architected Framework Summary"
    echo "                       wa_mod  = WAF with Modernization Analysis"
    echo "                       ftr     = Foundational Technical Review Summary"
    echo ""
    echo "  --input-dir PATH     Path to Service Screener results directory (aws/)"
    echo "                       This is the directory containing account folders"
    echo ""
    echo "  --output-dir PATH    Output directory for generated reports"
    echo "                       (optional, default: ./output)"
    echo ""
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Interactive wizard mode"
    echo "  $(basename $0)"
    echo ""
    echo "  # FTR report with custom paths"
    echo "  $(basename $0) --report ftr --input-dir ./aws --output-dir ./reports"
    echo ""
    echo "  # WAF report with default output directory"
    echo "  $(basename $0) --report wa --input-dir /path/to/aws"
    echo ""
    echo "  # WAF with modernization analysis"
    echo "  $(basename $0) --report wa_mod --input-dir ./aws --output-dir ./output"
    echo ""
}

# Function to parse command line arguments
parse_arguments() {
    REPORT_TYPE=""
    INPUT_DIR=""
    OUTPUT_DIR=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --report)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    echo -e "${RED}✗ Error: --report requires a value${NC}" >&2
                    exit 1
                fi
                REPORT_TYPE="$2"
                shift 2
                ;;
            --input-dir)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    echo -e "${RED}✗ Error: --input-dir requires a value${NC}" >&2
                    exit 1
                fi
                INPUT_DIR="$2"
                shift 2
                ;;
            --output-dir)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    echo -e "${RED}✗ Error: --output-dir requires a value${NC}" >&2
                    exit 1
                fi
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}✗ Error: Unknown option: $1${NC}" >&2
                echo "" >&2
                show_usage
                exit 1
                ;;
        esac
    done
}

# Function to display script selection menu
show_menu() {
    echo -e "${YELLOW}Available Summary Report Types:${NC}"
    echo ""
    echo -e "${GREEN}1)${NC} Well-Architected Framework (WAF) Summary"
    echo -e "   ${CYAN}→${NC} Standard Well-Architected Framework analysis report"
    echo -e "   ${CYAN}→${NC} Analyzes top 5 services with most findings"
    echo -e "   ${CYAN}→${NC} Covers all 6 pillars: Security, Reliability, Performance, Cost, Operational Excellence, Sustainability"
    echo ""
    echo -e "${GREEN}2)${NC} Well-Architected Framework (WAF) with Modernization Analysis"
    echo -e "   ${CYAN}→${NC} Extended WAF report with modernization recommendations"
    echo -e "   ${CYAN}→${NC} Includes MongoDB migration guidance"
    echo -e "   ${CYAN}→${NC} ECS containerization recommendations"
    echo -e "   ${CYAN}→${NC} EKS best practices assessment"
    echo -e "   ${CYAN}→${NC} Phased modernization roadmap"
    echo ""
    echo -e "${GREEN}3)${NC} Foundational Technical Review (FTR) Summary"
    echo -e "   ${CYAN}→${NC} FTR compliance assessment report"
    echo -e "   ${CYAN}→${NC} 14 FTR categories analysis"
    echo -e "   ${CYAN}→${NC} Prioritized remediation recommendations"
    echo -e "   ${CYAN}→${NC} Implementation roadmap with AWS CLI commands"
    echo ""
    echo -e "${RED}4)${NC} Exit"
    echo ""
}

# Function to validate directory
validate_directory() {
    local dir=$1
    if [ ! -d "$dir" ]; then
        echo -e "${RED}✗ Error: Directory does not exist: $dir${NC}"
        return 1
    fi
    return 0
}

# Function to validate report type
validate_report_type() {
    local report=$1
    case $report in
        wa|wa_mod|ftr)
            return 0
            ;;
        *)
            echo -e "${RED}✗ Error: Invalid report type: '$report'${NC}" >&2
            echo -e "${YELLOW}Valid types: wa, wa_mod, ftr${NC}" >&2
            return 1
            ;;
    esac
}

# Function to get script name from report type
get_script_name() {
    local report=$1
    case $report in
        wa)
            echo "run_wa_summarizer.sh"
            ;;
        wa_mod)
            echo "run_wa_summarizer_mod.sh"
            ;;
        ftr)
            echo "run_ftr_summarizer.sh"
            ;;
    esac
}

# Function to get report description
get_report_description() {
    local report=$1
    case $report in
        wa)
            echo "Well-Architected Framework Summary"
            ;;
        wa_mod)
            echo "Well-Architected Framework with Modernization Analysis"
            ;;
        ftr)
            echo "Foundational Technical Review Summary"
            ;;
    esac
}

# Function to get Service Screener directory with validation
get_screener_directory() {
    echo "" >&2
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${CYAN}Service Screener Results Directory${NC}" >&2
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo "" >&2
    echo -e "${YELLOW}Please provide the path to your Service Screener results directory.${NC}" >&2
    echo "" >&2
    echo -e "${CYAN}Expected structure:${NC}" >&2
    echo -e "  aws/                        ${YELLOW}← (Provide path to this) Service Screener results directory${NC}" >&2
    echo -e "  ├── 123456789012/           ${YELLOW}← Account directory${NC}" >&2
    echo -e "  │   ├── index.html" >&2
    echo -e "  │   ├── CPFindings.html" >&2
    echo -e "  │   ├── api-full.json" >&2
    echo -e "  │   ├── ec2.html" >&2
    echo -e "  │   ├── s3.html" >&2
    echo -e "  │   └── ..." >&2
    echo -e "  └── res/" >&2
    echo "" >&2
    echo -e "${CYAN}Examples:${NC}" >&2
    echo -e "  • Relative path: ${GREEN}./aws${NC}" >&2
    echo -e "  • Absolute path: ${GREEN}/home/user/Downloads/aws${NC}" >&2
    echo "" >&2
    
    while true; do
        read -p "$(echo -e ${CYAN}Enter Service Screener results \"aws\" directory path:${NC} )" screener_dir
        
        # Handle empty input
        if [ -z "$screener_dir" ]; then
            echo -e "${RED}✗ Directory path cannot be empty. Please try again.${NC}" >&2
            echo "" >&2
            continue
        fi
        
        # Expand tilde and validate
        screener_dir="${screener_dir/#\~/$HOME}"
        
        if validate_directory "$screener_dir"; then
            echo -e "${GREEN}✓ Directory validated: $screener_dir${NC}" >&2
            echo "$screener_dir"
            return 0
        else
            echo -e "${YELLOW}Please enter a valid directory path.${NC}" >&2
            echo "" >&2
        fi
    done
}

# Function to get output directory
get_output_directory() {
    local default_output="${SCRIPT_DIR}/output"
    
    echo "" >&2
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${CYAN}Output Directory Configuration${NC}" >&2
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo "" >&2
    echo -e "${YELLOW}Specify where to save the generated HTML report.${NC}" >&2
    echo -e "${CYAN}Default:${NC} ${GREEN}$default_output${NC}" >&2
    echo "" >&2
    
    read -p "$(echo -e ${CYAN}Output directory [press Enter for default]:${NC} )" output_dir
    
    # Use default if empty
    if [ -z "$output_dir" ]; then
        output_dir="$default_output"
        echo -e "${GREEN}✓ Using default output directory: $output_dir${NC}" >&2
    else
        # Expand tilde
        output_dir="${output_dir/#\~/$HOME}"
        echo -e "${GREEN}✓ Output directory set to: $output_dir${NC}" >&2
    fi
    
    echo "$output_dir"
}

# Function to run selected script
run_script() {
    local script_name=$1
    local screener_dir=$2
    local output_dir=$3
    local script_path="${SUMMARIZER_SCRIPTS_DIR}/${script_name}"
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Executing Report Generator${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}Script:${NC} $script_name"
    echo -e "${CYAN}Service Screener Directory:${NC} $screener_dir"
    echo -e "${CYAN}Output Directory:${NC} $output_dir"
    echo ""
    echo -e "${YELLOW}Starting report generation...${NC}"
    echo ""
    
    if [ ! -f "$script_path" ]; then
        echo -e "${RED}✗ Error: Script not found: $script_path${NC}"
        return 1
    fi
    
    # Make script executable if not already
    chmod +x "$script_path"
    
    # Run the script
    bash "$script_path" -d "$screener_dir" -o "$output_dir"
    local exit_code=$?
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}✓ Report generation completed successfully!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${CYAN}Your report has been saved to:${NC} ${GREEN}$output_dir${NC}"
        echo -e "${CYAN}Look for files matching pattern:${NC} ${GREEN}*_summary_report_*.html${NC}"
    else
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}✗ Report generation failed with exit code: $exit_code${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        return $exit_code
    fi
}

# Function to run in non-interactive (CLI) mode
run_non_interactive() {
    local report_type=$1
    local input_dir=$2
    local output_dir=$3
    
    # Validate report type
    if ! validate_report_type "$report_type"; then
        echo ""
        show_usage
        exit 1
    fi
    
    # Validate input directory is provided
    if [ -z "$input_dir" ]; then
        echo -e "${RED}✗ Error: --input-dir is required${NC}"
        echo ""
        show_usage
        exit 1
    fi
    
    # Expand tilde and validate input directory exists
    input_dir="${input_dir/#\~/$HOME}"
    
    echo -e "${CYAN}Validating input directory...${NC}"
    if ! validate_directory "$input_dir"; then
        exit 1
    fi
    echo -e "${GREEN}✓ Input directory validated${NC}"
    echo ""
    
    # Set default output directory if not provided
    if [ -z "$output_dir" ]; then
        output_dir="${SCRIPT_DIR}/output"
        echo -e "${CYAN}Using default output directory: ${GREEN}$output_dir${NC}"
    else
        output_dir="${output_dir/#\~/$HOME}"
        echo -e "${CYAN}Output directory set to: ${GREEN}$output_dir${NC}"
    fi
    echo ""
    
    # Get script name and description
    local script_name=$(get_script_name "$report_type")
    local report_desc=$(get_report_description "$report_type")
    
    echo -e "${GREEN}✓ Selected: $report_desc${NC}"
    echo ""
    
    # Run the script
    run_script "$script_name" "$input_dir" "$output_dir"
}

# Main function
main() {
    # Check if summarizer_scripts directory exists
    if [ ! -d "$SUMMARIZER_SCRIPTS_DIR" ]; then
        echo -e "${RED}✗ Error: Summarizer scripts directory not found: $SUMMARIZER_SCRIPTS_DIR${NC}"
        echo -e "${YELLOW}Please ensure you're running this script from the wa-summarizer root directory.${NC}"
        exit 1
    fi
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Determine mode: If REPORT_TYPE is set, run in CLI mode; otherwise, interactive mode
    if [ -n "$REPORT_TYPE" ]; then
        # Non-interactive (CLI) mode
        show_header
        run_non_interactive "$REPORT_TYPE" "$INPUT_DIR" "$OUTPUT_DIR"
        exit $?
    fi
    
    # Interactive wizard mode (original behavior)
    show_header
    
    while true; do
        show_menu
        read -p "$(echo -e ${CYAN}Select an option [1-4]:${NC} )" choice
        
        case $choice in
            1)
                echo -e "${GREEN}✓ Selected: Well-Architected Framework Summary${NC}"
                screener_dir=$(get_screener_directory)
                output_dir=$(get_output_directory)
                run_script "run_wa_summarizer.sh" "$screener_dir" "$output_dir"
                break
                ;;
            2)
                echo -e "${GREEN}✓ Selected: Well-Architected Framework with Modernization${NC}"
                screener_dir=$(get_screener_directory)
                output_dir=$(get_output_directory)
                run_script "run_wa_summarizer_mod.sh" "$screener_dir" "$output_dir"
                break
                ;;
            3)
                echo -e "${GREEN}✓ Selected: Foundational Technical Review Summary${NC}"
                screener_dir=$(get_screener_directory)
                output_dir=$(get_output_directory)
                run_script "run_ftr_summarizer.sh" "$screener_dir" "$output_dir"
                break
                ;;
            4)
                echo -e "${YELLOW}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}✗ Invalid option. Please select 1-4.${NC}"
                echo ""
                ;;
        esac
    done
}

# Execute main function
main "$@"
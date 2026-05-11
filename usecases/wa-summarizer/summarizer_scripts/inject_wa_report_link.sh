#!/bin/bash
# Inject WA Lens Review Report download link into wa-summarizer HTML reports
# 
# This script can be run standalone to add the PDF download link to any
# wa-summarizer HTML report that doesn't already have it.
#
# Usage:
#   ./inject_wa_report_link.sh                          # Auto-detect in ./output
#   ./inject_wa_report_link.sh -o /path/to/output       # Specify output directory
#   ./inject_wa_report_link.sh -f report.html -p wa.pdf # Specify files directly

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_OUTPUT_DIR="${PROJECT_ROOT_DIR}/output"

show_help() {
    echo -e "${BLUE}WA Lens Review Report Link Injector${NC}"
    echo ""
    echo "Injects a download link for the WA Lens Review Report PDF into"
    echo "wa-summarizer HTML reports."
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output-dir DIR    Output directory containing HTML reports (default: ./output)"
    echo "  -s, --screener-dir DIR  Service Screener results directory (to find PDF)"
    echo "  -f, --html-file FILE    Specific HTML report file to inject into"
    echo "  -p, --pdf-file FILE     Specific PDF file to link"
    echo "  -h, --help              Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                          # Auto-detect everything"
    echo "  $0 -o ./output -s ../adminlte/aws           # Specify directories"
    echo "  $0 -f report.html -p wa_report.pdf          # Specify files directly"
}

inject_link() {
    local html_file="$1"
    local pdf_filename="$2"

    if [ ! -f "$html_file" ]; then
        echo -e "${RED}❌ HTML file not found: $html_file${NC}"
        return 1
    fi

    # Check if link already exists
    if grep -q "wa_lens_review_report.pdf" "$html_file"; then
        echo -e "${GREEN}✅ Download link already present in: $(basename "$html_file")${NC}"
        return 0
    fi

    echo -e "${YELLOW}📝 Injecting download link into: $(basename "$html_file")${NC}"

    # Strategy 1: Inject after HEADER SECTION END comment
    if grep -q "HEADER SECTION END" "$html_file"; then
        sed -i.bak '/<!-- ==================== HEADER SECTION END ==================== -->/a\
\
                <!-- ==================== WA REPORT DOWNLOAD SECTION START ==================== -->\
                <div style="background: #e6f7e6; border: 1px solid #1D8102; border-radius: 4px; padding: 20px; margin-bottom: 20px;">\
                    <h3 style="color: #1D8102; margin-bottom: 10px;">📄 Well-Architected Lens Review Report</h3>\
                    <p style="color: #37475A; margin-bottom: 15px;">A PDF report has been generated from the AWS Well-Architected Tool for this workload. This report includes your responses to workload questions, notes, and a summary of identified high and medium risks along with improvement plans.</p>\
                    <a href="'"$pdf_filename"'" download style="display: inline-block; background: #0073bb; color: #fff; padding: 10px 20px; border-radius: 4px; text-decoration: none; font-weight: 600; font-size: 14px;">⬇️ Download WA Lens Review Report (PDF)</a>\
                    <p style="color: #687078; font-size: 12px; margin-top: 10px;">This report can be shared with stakeholders who do not have direct access to the AWS Well-Architected Tool.</p>\
                </div>\
                <!-- ==================== WA REPORT DOWNLOAD SECTION END ==================== -->' "$html_file"
        rm -f "${html_file}.bak"
    fi

    # Strategy 2: Also inject sidebar nav link
    if grep -q 'nav-icon.*🏠.*Overview' "$html_file" && ! grep -q "wa_lens_review_report.pdf" "$html_file" 2>/dev/null; then
        # If strategy 1 didn't add the link (different HTML structure), try sidebar
        sed -i.bak '/<span class="nav-icon">🏠<\/span>Overview/a\
                    </a>\
                </div>\
                <div class="nav-section">\
                    <a href="'"$pdf_filename"'" class="nav-link" download>\
                        <span class="nav-icon">📄</span>Download WA Report (PDF)' "$html_file"
        rm -f "${html_file}.bak"
    fi

    # Verify injection
    if grep -q "wa_lens_review_report.pdf" "$html_file"; then
        echo -e "${GREEN}✅ Download link injected successfully!${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️ Could not inject link automatically.${NC}"
        return 1
    fi
}

main() {
    local output_dir="$DEFAULT_OUTPUT_DIR"
    local screener_dir=""
    local html_file=""
    local pdf_file=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output-dir)
                output_dir="$2"
                shift 2
                ;;
            -s|--screener-dir)
                screener_dir="$2"
                shift 2
                ;;
            -f|--html-file)
                html_file="$2"
                shift 2
                ;;
            -p|--pdf-file)
                pdf_file="$2"
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

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  WA Lens Review Report Link Injector${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Step 1: Find or verify the PDF
    local pdf_filename="wa_lens_review_report.pdf"

    if [ -n "$pdf_file" ] && [ -f "$pdf_file" ]; then
        # User specified a PDF file directly
        pdf_filename=$(basename "$pdf_file")
        if [ "$(dirname "$pdf_file")" != "$output_dir" ]; then
            cp "$pdf_file" "${output_dir}/${pdf_filename}"
            echo -e "${GREEN}✅ PDF copied to output directory${NC}"
        fi
    elif [ -f "${output_dir}/wa_lens_review_report.pdf" ]; then
        echo -e "${GREEN}✅ PDF already in output directory: ${output_dir}/wa_lens_review_report.pdf${NC}"
    else
        # Try to find PDF in screener directory or common locations
        local found_pdf=""

        if [ -n "$screener_dir" ] && [ -d "$screener_dir" ]; then
            found_pdf=$(find "$screener_dir" -maxdepth 2 -name "wa_lens_review_report_*.pdf" -type f 2>/dev/null | sort -r | head -1)
        fi

        # Also try common relative paths
        if [ -z "$found_pdf" ]; then
            for search_dir in "../../adminlte/aws" "../../../adminlte/aws" "$PROJECT_ROOT_DIR/adminlte/aws"; do
                if [ -d "$search_dir" ]; then
                    found_pdf=$(find "$search_dir" -maxdepth 2 -name "wa_lens_review_report_*.pdf" -type f 2>/dev/null | sort -r | head -1)
                    if [ -n "$found_pdf" ]; then
                        break
                    fi
                fi
            done
        fi

        if [ -n "$found_pdf" ] && [ -f "$found_pdf" ]; then
            cp "$found_pdf" "${output_dir}/wa_lens_review_report.pdf"
            echo -e "${GREEN}✅ PDF found and copied: $(basename "$found_pdf") → ${output_dir}/wa_lens_review_report.pdf${NC}"
        else
            echo -e "${RED}❌ No WA Lens Review Report PDF found.${NC}"
            echo -e "${YELLOW}   Run Service Screener with: --frameworks WAFS --others '{\"WA\": {\"region\": \"<region>\", \"reportName\": \"SS_Report\", \"newMileStone\": 1}}'${NC}"
            echo -e "${YELLOW}   Or specify the PDF with: $0 -p /path/to/wa_report.pdf${NC}"
            exit 1
        fi
    fi

    # Step 2: Find and inject into HTML reports
    if [ -n "$html_file" ]; then
        # User specified a specific file
        inject_link "$html_file" "$pdf_filename"
    else
        # Process all wa_summary_report_*.html files in output directory
        local count=0
        for report in "${output_dir}"/wa_summary_report_*.html; do
            if [ -f "$report" ]; then
                inject_link "$report" "$pdf_filename"
                count=$((count + 1))
            fi
        done

        if [ $count -eq 0 ]; then
            echo -e "${YELLOW}⚠️ No wa_summary_report_*.html files found in: $output_dir${NC}"
        else
            echo ""
            echo -e "${GREEN}✅ Processed $count report(s)${NC}"
        fi
    fi

    echo ""
    echo -e "${BLUE}Done!${NC}"
}

main "$@"

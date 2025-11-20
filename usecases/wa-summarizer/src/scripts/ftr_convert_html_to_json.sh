#!/bin/bash

# Check if input file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <html_file> [output_json_file]"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="${2:-preliminary_ftr_results.json}"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: File '$INPUT_FILE' not found"
    exit 1
fi

# Python script to parse HTML and generate JSON
python3 - "$INPUT_FILE" "$OUTPUT_FILE" << 'EOF'
import sys
import json
import re
from html.parser import HTMLParser
from html import unescape

class TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_table = False
        self.in_tbody = False
        self.in_tr = False
        self.in_td = False
        self.current_td_index = 0
        self.current_row = []
        self.rows = []
        self.td_content = []
        self.tag_stack = []
        
    def handle_starttag(self, tag, attrs):
        self.tag_stack.append((tag, dict(attrs)))
        
        if tag == 'table':
            for attr, value in attrs:
                if attr == 'id' and value == 'screener-framework':
                    self.in_table = True
        elif tag == 'tbody' and self.in_table:
            self.in_tbody = True
        elif tag == 'tr' and self.in_tbody:
            self.in_tr = True
            self.current_row = []
            self.current_td_index = 0
        elif tag == 'td' and self.in_tr:
            self.in_td = True
            self.td_content = []
    
    def handle_endtag(self, tag):
        if self.tag_stack:
            self.tag_stack.pop()
        
        if tag == 'table':
            self.in_table = False
        elif tag == 'tbody':
            self.in_tbody = False
        elif tag == 'tr':
            self.in_tr = False
            if self.current_row:
                self.rows.append(self.current_row)
        elif tag == 'td':
            self.in_td = False
            self.current_row.append(''.join(self.td_content))
            self.td_content = []
            self.current_td_index += 1
    
    def handle_data(self, data):
        if self.in_td:
            self.td_content.append(data)

def extract_check_id(text):
    """Extract check ID from [checkId] format"""
    match = re.search(r'\[([^\]]+)\]', text)
    return match.group(1) if match else ""

def extract_short_description(text):
    """Extract description after ' - '"""
    parts = text.split(' - ', 1)
    return parts[1].strip() if len(parts) > 1 else ""

def determine_status(html_text):
    """Determine status based on class names"""
    if 'text-danger' in html_text or 'fa-times' in html_text:
        return 'not_compliant'
    elif 'text-success' in html_text or 'fa-check' in html_text:
        return 'compliant'
    return 'unknown'

def parse_description(html_text):
    """Parse the description column which contains dl/dt/ul/li structure"""
    if not html_text.strip():
        return []
    
    descriptions = []
    
    # Extract all dt elements with their positions
    dt_pattern = r"<dt class='([^']*)'><i class='[^']*'></i>\s*\[([^\]]+)\](?:\s*-\s*([^<]*))?"
    dt_matches = list(re.finditer(dt_pattern, html_text))
    
    for i, match in enumerate(dt_matches):
        css_class = match.group(1)
        check_id = match.group(2)
        short_desc = match.group(3).strip() if match.group(3) else ""
        
        status = 'compliant' if 'text-success' in css_class else 'not_compliant'
        
        # Extract resources for this dt
        resources = []
        
        # Find the position after current dt
        start_pos = match.end()
        
        # Find the position of the next dt (or end of string)
        if i + 1 < len(dt_matches):
            end_pos = dt_matches[i + 1].start()
        else:
            end_pos = len(html_text)
        
        # Look for ul only within the range [start_pos, end_pos)
        search_range = html_text[start_pos:end_pos]
        ul_match = re.search(r'<ul>(.*?)</ul>', search_range, re.DOTALL)
        
        if ul_match:
            ul_content = ul_match.group(1)
            # Extract all li items
            li_pattern = r'<li><b>\[([^\]]+)\]</b>([^<]*)</li>'
            li_matches = re.finditer(li_pattern, ul_content)
            for li_match in li_matches:
                region = li_match.group(1)
                resource_str = li_match.group(2).strip()
                
                # Split by comma and create separate entries
                if resource_str:
                    # Split by comma, strip whitespace, and filter empty strings
                    resource_items = [r.strip() for r in resource_str.split(',') if r.strip()]
                    
                    # Create a separate entry for each resource with the region prefix
                    for resource_item in resource_items:
                        resources.append(f"[{region}] - {resource_item}")
        
        descriptions.append({
            "checkId": check_id,
            "shortDescription": short_desc,
            "status": status,
            "resources": resources
        })
    
    return descriptions

def parse_references(html_text):
    """Extract all href links from the reference column"""
    if not html_text.strip():
        return []
    
    href_pattern = r"<a href='([^']*)'>"
    matches = re.findall(href_pattern, html_text)
    return matches

def parse_html_file(file_path):
    """Parse HTML file and extract table data"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the table section
    table_match = re.search(r"<table id='screener-framework'.*?</table>", content, re.DOTALL)
    if not table_match:
        return []
    
    table_html = table_match.group(0)
    
    # Extract tbody rows
    tbody_match = re.search(r"<tbody>(.*?)</tbody>", table_html, re.DOTALL)
    if not tbody_match:
        return []
    
    tbody_html = tbody_match.group(1)
    
    # Extract all rows
    rows = []
    row_pattern = r"<tr>(.*?)</tr>"
    row_matches = re.finditer(row_pattern, tbody_html, re.DOTALL)
    
    for row_match in row_matches:
        row_html = row_match.group(1)
        
        # Extract all td elements
        td_pattern = r"<td[^>]*>(.*?)</td>"
        td_matches = re.findall(td_pattern, row_html, re.DOTALL)
        
        if len(td_matches) >= 5:
            rows.append(td_matches)
    
    return rows

def main():
    if len(sys.argv) < 3:
        print("Error: Input and output file paths required")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Parse HTML file
    rows = parse_html_file(input_file)
    
    # Build categories list
    categories = []
    compliant_count = 0
    not_compliant_count = 0
    not_available_count = 0
    
    for row in rows:
        category_name = unescape(re.sub(r'<[^>]+>', '', row[0])).strip()
        rule_id = unescape(re.sub(r'<[^>]+>', '', row[1])).strip()
        compliance_status = unescape(re.sub(r'<[^>]+>', '', row[2])).strip()
        description_html = row[3]
        reference_html = row[4]
        
        # Count compliance statuses
        if compliance_status == 'Compliant':
            compliant_count += 1
        elif compliance_status == 'Need Attention':
            not_compliant_count += 1
        elif compliance_status == 'Not available':
            not_available_count += 1
        
        # Parse description and references
        description = parse_description(description_html)
        references = parse_references(reference_html)
        
        categories.append({
            "categoryName": category_name,
            "ruleId": rule_id,
            "complianceStatus": compliance_status,
            "checks": description,
            "reference": references
        })
    
    # Build final JSON structure
    result = {
        "framework": {
            "ftr": {
                "summary": {
                    "compliantCount": compliant_count,
                    "notCompliantCount": not_compliant_count,
                    "notAvailableCount": not_available_count
                },
                "categories": categories
            }
        }
    }
    
    # Write to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    print(f"Successfully converted HTML to JSON: {output_file}")
    print(f"Summary: {compliant_count} Compliant, {not_compliant_count} Need Attention, {not_available_count} Not available")

if __name__ == '__main__':
    main()
EOF

echo "Conversion complete: $OUTPUT_FILE"
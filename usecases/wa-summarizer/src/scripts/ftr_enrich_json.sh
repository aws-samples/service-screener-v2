#!/bin/bash

# Check if input files are provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 <compliance_json_file> <api_full_json_file> [output_json_file]"
    echo ""
    echo "Example: $0 compliance.json api-full.json ftr_results.json"
    exit 1
fi

COMPLIANCE_FILE="$1"
API_FULL_FILE="$2"
OUTPUT_FILE="${3:-ftr_results.json}"

# Check if input files exist
if [ ! -f "$COMPLIANCE_FILE" ]; then
    echo "Error: Compliance file '$COMPLIANCE_FILE' not found"
    exit 1
fi

if [ ! -f "$API_FULL_FILE" ]; then
    echo "Error: API full file '$API_FULL_FILE' not found"
    exit 1
fi

# Python script to enrich JSON
python3 - "$COMPLIANCE_FILE" "$API_FULL_FILE" "$OUTPUT_FILE" << 'EOF'
import sys
import json
import re
from html import unescape

def strip_html_tags(html_text):
    """Remove HTML tags from text"""
    if not html_text:
        return ""
    # Remove HTML tags
    clean = re.sub(r'<[^>]+>', '', html_text)
    # Unescape HTML entities
    clean = unescape(clean)
    return clean.strip()

def build_lookup_index(api_full_data):
    """
    Build a lookup index from api-full.json
    Maps checkId -> metadata
    """
    lookup = {}
    
    # Iterate through all services in api_full_data
    for service_name, service_data in api_full_data.items():
        if not isinstance(service_data, dict):
            continue
        
        # Check if 'summary' exists in this service
        if 'summary' not in service_data:
            continue
        
        summary = service_data['summary']
        if not isinstance(summary, dict):
            continue
        
        # Iterate through all checks in the summary
        for check_id, check_data in summary.items():
            if not isinstance(check_data, dict):
                continue
            
            # Extract the required fields
            metadata = {
                'extendedDescription': check_data.get('^description', ''),
                'criticality': check_data.get('criticality', ''),
                'waRelatedPillar': check_data.get('__categoryMain', ''),
                'service': service_name
            }
            
            # Store in lookup with checkId as key
            lookup[check_id] = metadata
    
    return lookup

def enrich_compliance_data(compliance_data, lookup_index):
    """
    Enrich compliance data with metadata from api-full.json
    """
    stats = {
        'total_checks': 0,
        'not_compliant_checks': 0,
        'enriched_checks': 0,
        'missing_checks': []
    }
    
    # Navigate to categories
    if 'framework' not in compliance_data:
        print("Warning: 'framework' key not found in compliance data")
        return compliance_data, stats
    
    if 'ftr' not in compliance_data['framework']:
        print("Warning: 'ftr' key not found in framework")
        return compliance_data, stats
    
    if 'categories' not in compliance_data['framework']['ftr']:
        print("Warning: 'categories' key not found in ftr")
        return compliance_data, stats
    
    categories = compliance_data['framework']['ftr']['categories']
    
    # Iterate through each category
    for category in categories:
        if 'checks' not in category:
            continue
        
        # Iterate through each check in the checks array
        for check in category['checks']:
            stats['total_checks'] += 1
            
            # Only process not_compliant checks
            if check.get('status') != 'not_compliant':
                continue
            
            stats['not_compliant_checks'] += 1
            check_id = check.get('checkId', '')
            
            if not check_id:
                continue
            
            # Look up the checkId in our index
            if check_id in lookup_index:
                metadata = lookup_index[check_id]
                
                # Add the new fields
                check['extendedDescription'] = metadata['extendedDescription']
                check['criticality'] = metadata['criticality']
                check['waRelatedPillar'] = metadata['waRelatedPillar']
                check['service'] = metadata['service']
                
                stats['enriched_checks'] += 1
            else:
                # Track missing checkIds
                stats['missing_checks'].append({
                    'checkId': check_id,
                    'category': category.get('categoryName', 'Unknown'),
                    'ruleId': category.get('ruleId', 'Unknown')
                })
    
    return compliance_data, stats

def main():
    if len(sys.argv) < 4:
        print("Error: Compliance file, API full file, and output file paths required")
        sys.exit(1)
    
    compliance_file = sys.argv[1]
    api_full_file = sys.argv[2]
    output_file = sys.argv[3]
    
    print(f"Loading compliance data from: {compliance_file}")
    try:
        with open(compliance_file, 'r', encoding='utf-8') as f:
            compliance_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse compliance JSON file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read compliance file: {e}")
        sys.exit(1)
    
    print(f"Loading API full data from: {api_full_file}")
    try:
        with open(api_full_file, 'r', encoding='utf-8') as f:
            api_full_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse API full JSON file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read API full file: {e}")
        sys.exit(1)
    
    print("Building lookup index from API full data...")
    lookup_index = build_lookup_index(api_full_data)
    print(f"  Found {len(lookup_index)} check definitions")
    
    print("Enriching compliance data...")
    enriched_data, stats = enrich_compliance_data(compliance_data, lookup_index)
    
    print(f"  Total checks processed: {stats['total_checks']}")
    
    if stats['missing_checks']:
        print("\nWarning: The following checkIds were not found in API full data:")
        for missing in stats['missing_checks'][:10]:  # Show first 10
            print(f"  - {missing['checkId']} (Category: {missing['category']}, Rule: {missing['ruleId']})")
        if len(stats['missing_checks']) > 10:
            print(f"  ... and {len(stats['missing_checks']) - 10} more")
    
    print(f"\nWriting enriched data to: {output_file}")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(enriched_data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Error: Failed to write output file: {e}")
        sys.exit(1)
    
    print("✓ Enrichment complete!")

if __name__ == '__main__':
    main()
EOF

echo ""
echo "Process completed: $OUTPUT_FILE"
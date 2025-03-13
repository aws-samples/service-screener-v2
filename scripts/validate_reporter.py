import ast
import sys
import json
from pathlib import Path
import argparse

def is_valid_category(category_str):
    """
    Validate if the category string contains only valid characters (S,R,O,P,C,T)
    and each character appears at most once.
    """
    valid_chars = set('SROPCT')
    category_set = set(category_str.upper())
    
    if not category_set.issubset(valid_chars):
        return False, f"Category contains invalid characters. Only S,R,O,P,C are allowed."
    
    if len(category_set) != len(category_str):
        return False, f"Category contains duplicate characters."
        
    return True, "Valid category"

def validate_reporter_structure(content):
    """Validate the structure of a reporter file"""
    try:
        # Check if it's valid Python code
        ast.parse(content)
        
        # Convert string content to dict
        data = json.loads(content)
        
        # Required fields
        required_fields = ['category', '^description', 'shortDesc', 'criticality']
        for field in required_fields:
            if not any(field in item for item in data.values()):
                return False, f"Missing required field: {field}"
        
        # Validate categories
        for item in data.values():
            if 'category' in item:
                is_valid, message = is_valid_category(item['category'])
                if not is_valid:
                    return False, f"Invalid category value '{item['category']}': {message}"
        
        # Validate criticality values
        valid_criticality = ['H', 'M', 'L']
        for item in data.values():
            if 'criticality' in item and item['criticality'] not in valid_criticality:
                return False, f"Invalid criticality value: {item['criticality']}"
        
        return True, "Validation passed"
    
    except SyntaxError as e:
        return False, f"Invalid Python syntax: {str(e)}"
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON structure: {str(e)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def validate_file(file_path):
    """Validate a single reporter file"""
    try:
        print(f"\nValidating {file_path}...")
        with open(file_path, 'r') as f:
            content = f.read()
        
        is_valid, message = validate_reporter_structure(content)
        
        if not is_valid:
            print(f"❌ Validation failed: {message}")
            return False
        else:
            print("✅ Validation passed")
            return True
            
    except Exception as e:
        print(f"❌ Error processing file: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Validate reporter files')
    parser.add_argument('files', nargs='*', help='Specific files to validate')
    args = parser.parse_args()

    exit_code = 0
    
    if args.files:
        # Validate specific files
        for file_path in args.files:
            if not validate_file(file_path):
                exit_code = 1
    else:
        # Validate all reporter files if no specific files provided
        reporter_files = Path('.').rglob('*.reporter.json')
        for file_path in reporter_files:
            if not validate_file(file_path):
                exit_code = 1
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

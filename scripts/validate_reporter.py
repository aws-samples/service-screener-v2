import ast
import sys
import json
from pathlib import Path

def is_valid_category(category_str):
    """
    Validate if the category string contains only valid characters (S,R,O,P,C)
    and each character appears at most once.
    """
    valid_chars = set('SROPC')
    category_set = set(category_str.upper())
    
    # Check if all characters in the category are valid
    if not category_set.issubset(valid_chars):
        return False, f"Category contains invalid characters. Only S,R,O,P,C are allowed."
    
    # Check if there are any duplicate characters
    if len(category_set) != len(category_str):
        return False, f"Category contains duplicate characters."
        
    return True, "Valid category"

def validate_reporter_structure(content):
    """Validate the basic structure of a reporter file"""
    try:
        # Check if it's valid Python code
        ast.parse(content)
        
        # Convert string content to dict (assuming JSON-like structure)
        data = json.loads(content)
        
        # Required fields
        required_fields = ['category', '^description', 'shortDesc', 'criticality']
        for field in required_fields:
            if not any(field in item for item in data.values()):
                return False, f"Missing required field: {field}"
        
        # Validate category values
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

def main():
    exit_code = 0
    
    # Find all reporter files
    reporter_files = Path('.').rglob('*.reporter.json')
    
    for file_path in reporter_files:
        print(f"\nValidating {file_path}...")
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            is_valid, message = validate_reporter_structure(content)
            
            if not is_valid:
                print(f"❌ Validation failed: {message}")
                exit_code = 1
            else:
                print("✅ Validation passed")
                
        except Exception as e:
            print(f"❌ Error processing file: {str(e)}")
            exit_code = 1
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

"""
Patch for service-screener-v2/main.py
Adds auto-discovery of frameworks from the frameworks/ directory
when --frameworks flag is not explicitly specified.

HOW TO APPLY:
  cd /tmp/service-screener-v2
  python3 patch_main_autodiscover_frameworks.py

This patches main.py in-place (creates a .bak backup first).
"""

import os
import sys
import shutil

MAIN_PY = 'main.py'

if not os.path.exists(MAIN_PY):
    print(f"ERROR: {MAIN_PY} not found. Run this from the service-screener-v2 root directory.")
    sys.exit(1)

# Read the original file
with open(MAIN_PY, 'r') as f:
    content = f.read()

# The code we're looking for (the existing framework parsing logic)
SEARCH_PATTERN = """    frameworks = []
    
    if len(_cli_options['frameworks']) > 0:
        frameworks = _cli_options['frameworks'].split(',')"""

# Alternative pattern (whitespace may vary)
SEARCH_PATTERN_ALT = """    frameworks = []
    if len(_cli_options['frameworks']) > 0:
        frameworks = _cli_options['frameworks'].split(',')"""

# The replacement code with auto-discovery
REPLACEMENT = """    frameworks = []
    
    if len(_cli_options['frameworks']) > 0:
        frameworks = _cli_options['frameworks'].split(',')
    else:
        # Auto-discover frameworks from frameworks/ directory
        import constants as _C
        _fw_dir = _C.FRAMEWORK_DIR
        if os.path.isdir(_fw_dir):
            frameworks = [
                d for d in os.listdir(_fw_dir)
                if os.path.isdir(os.path.join(_fw_dir, d))
                and os.path.exists(os.path.join(_fw_dir, d, 'map.json'))
                and not d.startswith('_')
                and not d.startswith('.')
                and d != '__pycache__'
            ]
            if frameworks:
                print(f"  Auto-discovered frameworks: {', '.join(sorted(frameworks))}")"""

# Try to find and replace
if SEARCH_PATTERN in content:
    # Create backup
    shutil.copy2(MAIN_PY, MAIN_PY + '.bak')
    
    content = content.replace(SEARCH_PATTERN, REPLACEMENT, 1)
    
    with open(MAIN_PY, 'w') as f:
        f.write(content)
    
    print("✅ main.py patched successfully!")
    print(f"   Backup saved to: {MAIN_PY}.bak")
    print("   Frameworks will now auto-discover from frameworks/ directory")
    print("   when --frameworks flag is not specified.")

elif SEARCH_PATTERN_ALT in content:
    # Create backup
    shutil.copy2(MAIN_PY, MAIN_PY + '.bak')
    
    content = content.replace(SEARCH_PATTERN_ALT, REPLACEMENT, 1)
    
    with open(MAIN_PY, 'w') as f:
        f.write(content)
    
    print("✅ main.py patched successfully!")
    print(f"   Backup saved to: {MAIN_PY}.bak")
    print("   Frameworks will now auto-discover from frameworks/ directory")
    print("   when --frameworks flag is not specified.")

else:
    # Fallback: try a more flexible search
    import re
    pattern = r'(\s+frameworks\s*=\s*\[\]\s*\n\s*if\s+len\(_cli_options\[.frameworks.\]\)\s*>\s*0\s*:\s*\n\s*frameworks\s*=\s*_cli_options\[.frameworks.\]\.split\(.,.?\))'
    match = re.search(pattern, content)
    
    if match:
        shutil.copy2(MAIN_PY, MAIN_PY + '.bak')
        content = content[:match.end()] + """
    else:
        # Auto-discover frameworks from frameworks/ directory
        import constants as _C
        _fw_dir = _C.FRAMEWORK_DIR
        if os.path.isdir(_fw_dir):
            frameworks = [
                d for d in os.listdir(_fw_dir)
                if os.path.isdir(os.path.join(_fw_dir, d))
                and os.path.exists(os.path.join(_fw_dir, d, 'map.json'))
                and not d.startswith('_')
                and not d.startswith('.')
                and d != '__pycache__'
            ]
            if frameworks:
                print(f"  Auto-discovered frameworks: {', '.join(sorted(frameworks))}")""" + content[match.end():]
        
        with open(MAIN_PY, 'w') as f:
            f.write(content)
        
        print("✅ main.py patched successfully (regex fallback)!")
        print(f"   Backup saved to: {MAIN_PY}.bak")
    else:
        print("❌ Could not find the framework parsing code in main.py.")
        print("   The file may have been modified. Please apply the patch manually.")
        print()
        print("   Find this section in main.py:")
        print("     frameworks = []")
        print("     if len(_cli_options['frameworks']) > 0:")
        print("         frameworks = _cli_options['frameworks'].split(',')")
        print()
        print("   And add this AFTER it:")
        print("     else:")
        print("         import constants as _C")
        print("         _fw_dir = _C.FRAMEWORK_DIR")
        print("         if os.path.isdir(_fw_dir):")
        print("             frameworks = [")
        print("                 d for d in os.listdir(_fw_dir)")
        print("                 if os.path.isdir(os.path.join(_fw_dir, d))")
        print("                 and os.path.exists(os.path.join(_fw_dir, d, 'map.json'))")
        print("                 and not d.startswith('_')")
        print("                 and not d.startswith('.')")
        print("                 and d != '__pycache__'")
        print("             ]")
        sys.exit(1)

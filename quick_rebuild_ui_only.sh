#!/bin/bash
# Quick UI-only rebuild script for Cloudscape UI development
# Rebuilds React app and regenerates HTML using existing data (no content enrichment fetch)

echo "🔄 Quick rebuilding Cloudscape UI (UI changes only)..."

# Step 1: Build React app
echo "📦 Building React app..."
cd cloudscape-ui
npm run build
cd ..

# Step 2: Regenerate Cloudscape HTML with existing data for all accounts
echo "🔧 Regenerating HTML with existing data..."
python3 -c "
import sys
import os
import glob
sys.path.insert(0, '.')
from utils.OutputGenerator import OutputGenerator
from utils.Config import Config

# Set up config
Config.init()

# Find all account folders
account_folders = glob.glob('adminlte/aws/[0-9]*')
if not account_folders:
    print('❌ No account folders found in adminlte/aws/')
    sys.exit(1)

success_count = 0
total_count = len(account_folders)

for folder in account_folders:
    account_id = os.path.basename(folder)
    if len(account_id) == 12 and account_id.isdigit():
        print(f'  📁 Processing account: {account_id}')
        
        generator = OutputGenerator(beta_mode=True)
        generator.html_folder = folder
        generator.account_id = account_id
        
        result = generator._generate_cloudscape()
        if result:
            success_count += 1
            print(f'  ✅ {account_id}: Cloudscape HTML regenerated!')
        else:
            print(f'  ❌ {account_id}: Failed to regenerate Cloudscape HTML')
    else:
        print(f'  ⚠️  Skipping invalid account folder: {folder}')

print(f'📊 Summary: {success_count}/{total_count} accounts processed successfully')
if success_count > 0:
    print('✅ Multi-account Cloudscape HTML regenerated!')
    # Show the first account for opening
    first_account = os.path.basename(account_folders[0])
    print(f'📂 Open: adminlte/aws/{first_account}/index.html')
else:
    print('❌ Failed to regenerate any Cloudscape HTML')
"

echo "🎉 Quick UI-only rebuild complete!"
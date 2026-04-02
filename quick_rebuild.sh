#!/bin/bash
# Quick rebuild script for Cloudscape UI development
# Rebuilds React app and regenerates HTML with fresh content enrichment data

echo "🔄 Quick rebuilding Cloudscape UI..."

# Step 1: Build React app
echo "📦 Building React app..."
cd cloudscape-ui
npm run build
cd ..

# Step 2: Generate fresh content enrichment data and regenerate HTML
echo "🔧 Regenerating HTML with fresh content enrichment data..."
python3 -c "
import sys
import os
import glob
import json
sys.path.insert(0, '.')
from utils.OutputGenerator import OutputGenerator
from utils.Config import Config
from utils.Tools import _info, _warn

# Set up config
Config.init()
Config.set('beta', True)  # Enable beta mode for content enrichment

# Generate fresh content enrichment data
print('  🔍 Generating fresh content enrichment data...')
try:
    from utils.ContentEnrichment import ContentAggregator, ContentProcessor, RelevanceEngine
    from utils.ContentEnrichment.models import UserContext
    
    # Use common detected services for quick rebuild
    detected_services = ['s3', 'ec2', 'rds', 'lambda', 'cloudfront', 'guardduty', 'iam']
    scan_findings = []
    
    user_context = UserContext(
        detected_services=detected_services,
        scan_findings=scan_findings
    )
    
    # Fetch and process content with shorter timeout for quick rebuild
    content_aggregator = ContentAggregator(timeout=10, max_retries=1)
    content_processor = ContentProcessor()
    relevance_engine = RelevanceEngine()
    
    # Fetch content from AWS sources
    raw_content = content_aggregator.fetch_aws_content()
    
    # Process and filter content
    processed_content = {}
    total_items = 0
    requested_categories = ['security-reliability', 'ai-ml-genai', 'best-practices']
    
    for category, items in raw_content.items():
        if category not in requested_categories:
            continue
            
        processed_items = []
        for item in items:
            processed_item = content_processor.process_single_item(item)
            if processed_item:
                relevance_score = relevance_engine.calculate_relevance(processed_item, user_context)
                processed_item.relevance_score = relevance_score
                processed_items.append(processed_item)
        
        # Filter and prioritize content
        filtered_items = content_aggregator.filter_by_services(processed_items, detected_services)
        prioritized_items = relevance_engine.prioritize_content(filtered_items, user_context)
        
        # Limit to top 8 items per category for quick rebuild
        processed_content[category] = prioritized_items[:8]
        total_items += len(processed_content[category])
    
    # Serialize content for HTML embedding
    enriched_content_data = content_aggregator.serialize_for_html(processed_content, detected_services)
    
    # Store in Config for OutputGenerator
    Config.set('enriched_content_data', enriched_content_data)
    Config.set('content_enrichment_enabled', True)
    
    print(f'  ✅ Content enrichment complete: {total_items} relevant items generated')
    
except Exception as e:
    print(f'  ⚠️  Content enrichment failed: {str(e)}')
    # Create empty enrichment data as fallback
    empty_data = {
        'contentData': {'security-reliability': [], 'ai-ml-genai': [], 'best-practices': []},
        'metadata': {'fetchTime': '', 'detectedServices': detected_services, 'totalItems': 0},
        'userPreferences': {'enabledCategories': requested_categories, 'maxItemsPerCategory': 8}
    }
    Config.set('enriched_content_data', json.dumps(empty_data))
    Config.set('content_enrichment_enabled', False)

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
            print(f'  ✅ {account_id}: Cloudscape HTML regenerated with content enrichment!')
        else:
            print(f'  ❌ {account_id}: Failed to regenerate Cloudscape HTML')
    else:
        print(f'  ⚠️  Skipping invalid account folder: {folder}')

print(f'📊 Summary: {success_count}/{total_count} accounts processed successfully')
if success_count > 0:
    print('✅ Multi-account Cloudscape HTML regenerated with fresh content enrichment!')
    # Show the first account for opening
    first_account = os.path.basename(account_folders[0])
    print(f'📂 Open: adminlte/aws/{first_account}/index.html')
else:
    print('❌ Failed to regenerate any Cloudscape HTML')
"

echo "🎉 Quick rebuild complete!"
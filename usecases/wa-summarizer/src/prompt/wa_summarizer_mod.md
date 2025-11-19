## Context

<service_screener_results_tree>
Results from Service Screener scan follow a directory tree like below:

```
aws
.
├── ./012345678901
│   ├── ./012345678901/all.csv
│   ├── ./012345678901/api-full.json
│   ├── ./012345678901/api-raw.json
│   ├── ./012345678901/apigateway.html
│   ├── ./012345678901/CIS.html
│   ├── ./012345678901/cloudfront.html
│   ├── ./012345678901/cloudtrail.html
│   ├── ./012345678901/cloudwatch.html
│   ├── ./012345678901/CPFindings.html
│   ├── ./012345678901/CPModernize.html
│   ├── ./012345678901/CPTA.html
│   ├── ./012345678901/dynamodb.html
│   ├── ./012345678901/ec2.html
│   ├── ./012345678901/efs.html
│   ├── ./012345678901/eks.html
│   ├── ./012345678901/elasticache.html
│   ├── ./012345678901/error.txt
│   ├── ./012345678901/FTR.html
│   ├── ./012345678901/guardduty.html
│   ├── ./012345678901/iam.html
│   ├── ./012345678901/index.html
│   ├── ./012345678901/kms.html
│   ├── ./012345678901/lambda.html
│   ├── ./012345678901/MSR.html
│   ├── ./012345678901/NIST.html
│   ├── ./012345678901/opensearch.html
│   ├── ./012345678901/RBI.html
│   ├── ./012345678901/rds.html
│   ├── ./012345678901/redshift.html
│   ├── ./012345678901/RMiT.html
│   ├── ./012345678901/s3.html
│   ├── ./012345678901/SPIP.html
│   ├── ./012345678901/sqs.html
│   ├── ./012345678901/SSB.html
│   ├── ./012345678901/WAFS.html
│   └── ./012345678901/workItem.xlsx
└── ./res (This directory contains a series of CSS, img and other files for the HTML report to render properly)
```

<service_screener_results_tree>

<navigating_service_screener_data>

The global summary report `aws/<acount_id>/index.html` contains a summary of findings based on the Service Screener check results (e.g. High, Medium, Low and Informational)

Be mindful that there is a distinct separation on the Service Screener HTML files:
   * Compliance and Framework related results: The CIS (CIS Amazon Web Services Foundations Benchmark), FTR (Foundational Technical Review), MSR (MSR baseline checks), NIST (National Institute of Standards and Technology), RBI (Reserve Bank of India (RBI) Cloud Computing Guidelines), RMIT (Bank Negara Malaysia (BNM) Risk Management in Technology (RMiT)), SPIP (AWS Security Posture Improvement Program(SPIP)), SSB (AWS Startup Security Baseline) and WAFS (AWS Well-Architected Framework - Security Pillar).
   * Service specific findings: Any of the other HTMLs, with the exception of "index.html", "CPFindings.html", "CPModernize.html" and "CPTA.html".

Use below bash command to get a summary of number of resources scanned and findings from Service Screener results:

```bash
for account in <acount_id>; do echo "=== Account $account ==="; echo "=== Global Summary ==="; echo "Overall Severity Distribution:"; HIGH=$(grep -A1 'fa-ban.*High' "$account/index.html" 2>/dev/null | grep -o 'text-align: right.*[0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); MEDIUM=$(grep -A1 'fa-exclamation-triangle.*Medium' "$account/index.html" 2>/dev/null | grep -o 'text-align: right.*[0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); LOW=$(grep -A1 'fa-eye.*Low' "$account/index.html" 2>/dev/null | grep -o 'text-align: right.*[0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); INFO=$(grep -A1 'fa-info-circle.*Informational' "$account/index.html" 2>/dev/null | grep -o 'text-align: right.*[0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); echo "  High: $HIGH"; echo "  Medium: $MEDIUM"; echo "  Low: $LOW"; echo "  Informational: $INFO"; echo "AWS Well-Architected Framework Pillars:"; SEC_BLOCK=$(grep -A30 'CPFindings.html#Security' "$account/index.html" 2>/dev/null || echo ""); SEC_TOTAL=$(echo "$SEC_BLOCK" | grep -o '<h3>[0-9]\+</h3>' | head -1 | sed 's/<[^>]*>//g' || echo "N/A"); SEC_HIGH=$(echo "$SEC_BLOCK" | grep -o '<i class="fas fa-ban"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); SEC_MED=$(echo "$SEC_BLOCK" | grep -o '<i class="fas fa-exclamation-triangle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); SEC_LOW=$(echo "$SEC_BLOCK" | grep -o '<i class="fas fa-eye"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); SEC_INFO=$(echo "$SEC_BLOCK" | grep -o '<i class="fas fa-info-circle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); echo "  Security: Total=$SEC_TOTAL (High=$SEC_HIGH, Medium=$SEC_MED, Low=$SEC_LOW, Info=$SEC_INFO)"; REL_BLOCK=$(grep -A30 'CPFindings.html#Reliability' "$account/index.html" 2>/dev/null || echo ""); REL_TOTAL=$(echo "$REL_BLOCK" | grep -o '<h3>[0-9]\+</h3>' | head -1 | sed 's/<[^>]*>//g' || echo "N/A"); REL_HIGH=$(echo "$REL_BLOCK" | grep -o '<i class="fas fa-ban"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); REL_MED=$(echo "$REL_BLOCK" | grep -o '<i class="fas fa-exclamation-triangle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); REL_LOW=$(echo "$REL_BLOCK" | grep -o '<i class="fas fa-eye"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); REL_INFO=$(echo "$REL_BLOCK" | grep -o '<i class="fas fa-info-circle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); echo "  Reliability: Total=$REL_TOTAL (High=$REL_HIGH, Medium=$REL_MED, Low=$REL_LOW, Info=$REL_INFO)"; COST_BLOCK=$(grep -A30 'CPFindings.html#Cost Optimization' "$account/index.html" 2>/dev/null || echo ""); COST_TOTAL=$(echo "$COST_BLOCK" | grep -o '<h3>[0-9]\+</h3>' | head -1 | sed 's/<[^>]*>//g' || echo "N/A"); COST_HIGH=$(echo "$COST_BLOCK" | grep -o '<i class="fas fa-ban"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); COST_MED=$(echo "$COST_BLOCK" | grep -o '<i class="fas fa-exclamation-triangle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); COST_LOW=$(echo "$COST_BLOCK" | grep -o '<i class="fas fa-eye"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); COST_INFO=$(echo "$COST_BLOCK" | grep -o '<i class="fas fa-info-circle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); echo "  Cost Optimization: Total=$COST_TOTAL (High=$COST_HIGH, Medium=$COST_MED, Low=$COST_LOW, Info=$COST_INFO)"; PERF_BLOCK=$(grep -A30 'CPFindings.html#Performance Efficiency' "$account/index.html" 2>/dev/null || echo ""); PERF_TOTAL=$(echo "$PERF_BLOCK" | grep -o '<h3>[0-9]\+</h3>' | head -1 | sed 's/<[^>]*>//g' || echo "N/A"); PERF_HIGH=$(echo "$PERF_BLOCK" | grep -o '<i class="fas fa-ban"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); PERF_MED=$(echo "$PERF_BLOCK" | grep -o '<i class="fas fa-exclamation-triangle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); PERF_LOW=$(echo "$PERF_BLOCK" | grep -o '<i class="fas fa-eye"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); PERF_INFO=$(echo "$PERF_BLOCK" | grep -o '<i class="fas fa-info-circle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); echo "  Performance Efficiency: Total=$PERF_TOTAL (High=$PERF_HIGH, Medium=$PERF_MED, Low=$PERF_LOW, Info=$PERF_INFO)"; OP_BLOCK=$(grep -A30 'CPFindings.html#Operation Excellence' "$account/index.html" 2>/dev/null || echo ""); OP_TOTAL=$(echo "$OP_BLOCK" | grep -o '<h3>[0-9]\+</h3>' | head -1 | sed 's/<[^>]*>//g' || echo "N/A"); OP_HIGH=$(echo "$OP_BLOCK" | grep -o '<i class="fas fa-ban"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); OP_MED=$(echo "$OP_BLOCK" | grep -o '<i class="fas fa-exclamation-triangle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); OP_LOW=$(echo "$OP_BLOCK" | grep -o '<i class="fas fa-eye"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); OP_INFO=$(echo "$OP_BLOCK" | grep -o '<i class="fas fa-info-circle"></i> [0-9]\+' | grep -o '[0-9]\+' || echo "N/A"); echo "  Operational Excellence: Total=$OP_TOTAL (High=$OP_HIGH, Medium=$OP_MED, Low=$OP_LOW, Info=$OP_INFO)"; echo "=== COMPLIANCE FRAMEWORKS ==="; echo "CIS (CIS Amazon Web Services Foundations Benchmark):"; grep -o "Summary: \[.*\]" "$account/CIS.html" 2>/dev/null || echo "No CIS data"; echo "FTR (Foundational Technical Review):"; grep -o "Summary: \[.*\]" "$account/FTR.html" 2>/dev/null || echo "No FTR data"; echo "MSR (MSR baseline checks):"; grep -o "Summary: \[.*\]" "$account/MSR.html" 2>/dev/null || echo "No MSR data"; echo "NIST (National Institute of Standards and Technology):"; grep -o "Summary: \[.*\]" "$account/NIST.html" 2>/dev/null || echo "No NIST data"; echo "RBI (Reserve Bank of India Cloud Computing Guidelines):"; grep -o "Summary: \[.*\]" "$account/RBI.html" 2>/dev/null || echo "No RBI data"; echo "RMiT (Bank Negara Malaysia Risk Management in Technology):"; grep -o "Summary: \[.*\]" "$account/RMiT.html" 2>/dev/null || echo "No RMiT data"; echo "SPIP (AWS Security Posture Improvement Program):"; grep -o "Summary: \[.*\]" "$account/SPIP.html" 2>/dev/null || echo "No SPIP data"; echo "SSB (AWS Startup Security Baseline):"; grep -o "Summary: \[.*\]" "$account/SSB.html" 2>/dev/null || echo "No SSB data"; echo "WAFS (AWS Well-Architected Framework - Security Pillar):"; grep -o "Summary: \[.*\]" "$account/WAFS.html" 2>/dev/null || echo "No WAFS data"; echo "=== SERVICE-SPECIFIC FINDINGS ==="; for svc in apigateway cloudfront cloudtrail cloudwatch dynamodb ec2 efs eks elasticache guardduty iam kms lambda opensearch rds redshift s3 sqs; do SVC_UPPER=$(echo $svc | tr '[:lower:]' '[:upper:]'); echo "$SVC_UPPER:"; grep -o "<h3>[0-9]*</h3>" "$account/$svc.html" 2>/dev/null | head -2 | sed 's/<[^>]*>//g' | paste - - | awk '{print "Resources: " $1 ", Findings: " $2}' || echo "No $SVC_UPPER data"; done; echo; done
```

For any of the Framework or Compliance related HTML files (E.g. aws/<account_id>/WAFS.html), you can look for summary and detailed information as per below:
   * Check on `<div class='card-header'><h3 class='card-title'>Summary:` for the summary counting.
   * For in-depth details: Check on the table (line after: `<table id='screener-framework' class='table table-bordered table-striped'> <thead><tr><th>Category</th><th>Rule ID</th><th>Compliance Status</th><th>Description</th><th>Reference</th></tr></thead>`) for list details about this particular Framework or Compliance HTML file.

For any of the service related HTML files (e.g. `aws/<account_id>/iam.html`) except for the `guardduty.html`, you can look for summary and detailed information as per below:
   * Check on line above `<p>Total Findings</p>` for the number of total findings for that particular service.
   * Check on line above `<p>Resources</p>` for the number of total service specific resources scanned.
   * For in-depth details:
     * Check and review all lines that contains `<dl><dt>Description</dt><dd class='detail-desc'>` for Service Screener check detail and flagged resources grouped by Service Screener Check.
     * Also, you can review anything from `</div><h5 class="mt-4 mb-2">Detail</h5>` until `<footer class='main-footer'>` finding grouped by flagged resources.
  
For GuardDuty related results, in file `aws/<account_id>/guardduty.html`:
   * Review anything from `<div class='card-header'><h3 class='card-title'>All findings</h3>` until `<footer class='main-footer'>` for any GuarDuty related findings.


You can use below bash script to get a full markdown-formatted table of the `aws/<account_id>/CPFindings.html` file. Useful to get resources flagged per Type (Security, Reliability, Cost Optimization, Performance Efficiency, Operation Excellence) or Severity (High, Medium, Low, and Informational):

```bash
cat <acount_id>/CPFindings.html | grep -o '<tr><td>[^<]*</td><td>[^<]*</td><td>[^<]*</td><td>[^<]*</td><td>[^<]*</td><td>[^<]*</td><td>[^<]*</td></tr>' | sed 's/<tr><td>//g; s/<\/td><td>/|/g; s/<\/td><\/tr>//g' | awk -F'|' -v type="$1" -v severity="$2" 'BEGIN {print "# AWS Service Screener Findings\n\n"; print "| Service | Region | Check | Type | ResourceID | Severity | Status |"; print "|---------|--------|-------|------|-----------|----------|--------|";} {if ((type=="" || $4==type) && (severity=="" || $6==severity)) print "| " $1 " | " $2 " | " $3 " | " $4 " | " $5 " | " $6 " | " $7 " |";}'
```

</navigating_service_screener_data>

<wa_html_summary_report>
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Service Screener Well-Architected Framework Analysis Report</title>
    <style>
        :root {
            --aws-squid-ink: #232F3E;
            --aws-orange: #FF9900;
            --aws-orange-dark: #EC7211;
            --aws-blue: #0073bb;
            --aws-blue-light: #00a1c9;
            --aws-blue-dark: #0d47a1;
            --success-green: #1D8102;
            --warning-orange: #FF9900;
            --danger-red: #D13212;
            --white: #FFFFFF;
            --gray-50: #FAFAFA;
            --gray-100: #F2F3F3;
            --gray-200: #EAEDED;
            --gray-300: #D5DBDB;
            --gray-400: #AAB7B8;
            --gray-600: #687078;
            --gray-700: #545B64;
            --gray-800: #37475A;
            --gray-900: #232F3E;
            --sidebar-width: 280px;
        }

        /* Side Navigation Styles */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: var(--sidebar-width);
            height: 100vh;
            background: var(--white);
            color: var(--gray-900);
            overflow-y: auto;
            z-index: 1000;
            transition: transform 0.3s ease;
            box-shadow: 2px 0 4px rgba(0, 0, 0, 0.1);
            border-right: 1px solid var(--gray-200);
        }

        .sidebar-header {
            padding: 20px;
            background: var(--gray-100);
            border-bottom: 2px solid var(--aws-orange);
        }

        .sidebar-header h3 {
            font-size: 1.2rem;
            margin-bottom: 5px;
            color: var(--gray-900);
            font-weight: 700;
        }

        .sidebar-header p {
            font-size: 0.85rem;
            color: var(--gray-600);
        }

        .sidebar-nav {
            padding: 20px 0;
        }

        .nav-section {
            margin-bottom: 5px;
        }

        .nav-link {
            display: block;
            padding: 10px 20px;
            color: var(--gray-900);
            text-decoration: none;
            transition: all 0.2s ease;
            border-left: 4px solid transparent;
            font-size: 0.9rem;
            font-weight: 400;
        }

        .nav-link:hover {
            background: var(--gray-100);
            border-left-color: var(--aws-orange);
            color: var(--aws-blue);
        }

        .nav-link.active {
            background: var(--gray-100);
            border-left-color: var(--aws-orange);
            color: var(--aws-blue);
            font-weight: 600;
        }

        .nav-link .nav-icon {
            margin-right: 8px;
        }

        /* Mobile Toggle Button */
        .sidebar-toggle {
            position: fixed;
            left: 20px;
            top: 20px;
            z-index: 1001;
            background: var(--aws-orange);
            color: var(--white);
            border: none;
            padding: 10px 15px;
            border-radius: 2px;
            cursor: pointer;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            display: none;
            font-size: 1.2rem;
            font-weight: 700;
        }

        .sidebar-toggle:hover {
            background: var(--aws-orange-dark);
        }
        
        /* Main Content with Sidebar */
        .page-wrapper {
            display: flex;
        }

        .content-wrapper {
            flex: 1;
            margin-left: var(--sidebar-width);
            transition: margin-left 0.3s ease;
        }

        /* Scrollbar Styling for Sidebar */
        .sidebar::-webkit-scrollbar {
            width: 6px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: var(--gray-100);
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: var(--gray-400);
            border-radius: 2px;
        }

        .sidebar::-webkit-scrollbar-thumb:hover {
            background: var(--gray-600);
        }

        /* AWS-style scrollbar for main content */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        ::-webkit-scrollbar-track {
            background: var(--gray-100);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--gray-400);
            border-radius: 2px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--gray-600);
        }

        /* AWS-style focus states */
        *:focus {
            outline: 2px solid var(--aws-blue-light);
            outline-offset: 2px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Amazon Ember', 'Helvetica Neue', Roboto, Arial, sans-serif;
            line-height: 1.6;
            color: var(--gray-900);
            background-color: var(--gray-50);
            font-size: 14px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, var(--aws-squid-ink), var(--gray-800));
            color: var(--white);
            padding: 40px 0;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
            font-family: 'Amazon Ember', sans-serif;
        }

        .header p {
            font-size: 1.1rem;
            opacity: 0.95;
        }

        .summary-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .summary-card {
            background: var(--white);
            border-radius: 2px;
            padding: 25px;
            box-shadow: 0 1px 1px 0 rgba(0, 28, 36, 0.3), 
                        1px 1px 1px 0 rgba(0, 28, 36, 0.15), 
                        -1px 1px 1px 0 rgba(0, 28, 36, 0.15);
            border-top: 4px solid var(--aws-orange);
            transition: box-shadow 0.3s ease;
        }

        .summary-card:hover {
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .summary-card h3 {
            color: var(--gray-900);
            font-size: 1.3rem;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
        }

        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding: 8px 0;
            border-bottom: 1px solid var(--gray-200);
        }

        .metric:last-child {
            border-bottom: none;
        }

        .metric-label {
            font-weight: 600;
            color: var(--gray-600);
        }

        .metric-value {
            font-weight: 700;
            font-size: 1.1rem;
        }

        .high { 
            color: var(--danger-red); 
            font-weight: 700;
        }

        .medium { 
            color: var(--warning-orange); 
            font-weight: 700;
        }

        .low { 
            color: var(--aws-blue); 
            font-weight: 700;
        }

        .info { 
            color: var(--gray-600); 
            font-weight: 700;
        }

        .compliant { 
            color: var(--success-green); 
            font-weight: 700;
        }

        .pillar-scores {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 40px;
        }

        .pillar-card {
            background: var(--white);
            border-radius: 2px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 1px 1px 0 rgba(0, 28, 36, 0.3);
            transition: transform 0.3s ease;
        }

        .pillar-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .pillar-name {
            font-weight: 700;
            color: var(--gray-900);
            margin-bottom: 10px;
            font-size: 1.1rem;
        }

        .pillar-score {
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 5px;
        }

        .pillar-total {
            color: var(--gray-600);
            font-size: 0.9rem;
        }

        .section {
            background: var(--white);
            border-radius: 2px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 1px 1px 0 rgba(0, 28, 36, 0.3);
            scroll-margin-top: 20px;
        }

        .section h2 {
            color: var(--gray-900);
            font-size: 1.8rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--aws-orange);
            font-weight: 700;
        }

        .subsection {
            margin-bottom: 30px;
        }

        .subsection h3 {
            color: var(--gray-900);
            font-size: 1.3rem;
            margin-bottom: 15px;
            font-weight: 700;
        }

        .subsection p {
            margin-bottom: 15px;
            line-height: 1.8;
        }

        .subsection ul, .subsection ol {
            margin-left: 20px;
            margin-bottom: 15px;
        }

        .subsection li {
            margin-bottom: 8px;
        }

        .issue-item {
            background: var(--white);
            border-radius: 2px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--aws-blue);
            box-shadow: 0 1px 1px 0 rgba(0, 28, 36, 0.3);
        }

        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }

        .issue-title {
            font-weight: 700;
            color: var(--gray-900);
            font-size: 1.1rem;
            flex: 1;
        }

        .issue-severity {
            padding: 4px 12px;
            border-radius: 2px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-high, .severity-critical {
            background-color: var(--danger-red);
            color: var(--white);
        }

        .severity-medium {
            background-color: var(--warning-orange);
            color: var(--white);
        }

        .severity-low {
            background-color: var(--aws-blue);
            color: var(--white);
        }

        .severity-info {
            background-color: var(--gray-600);
            color: var(--white);
        }

        .issue-description {
            color: var(--gray-600);
            margin-bottom: 15px;
            line-height: 1.6;
        }

        .affected-resources {
            background: var(--gray-50);
            border-radius: 2px;
            padding: 15px;
            margin-top: 10px;
            border: 1px solid var(--gray-200);
        }

        .affected-resources h4 {
            color: var(--gray-900);
            margin-bottom: 10px;
            font-size: 1rem;
            font-weight: 700;
        }

        .resource-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .resource-tag {
            background: var(--gray-100);
            color: var(--gray-900);
            padding: 4px 8px;
            border-radius: 2px;
            font-size: 0.85rem;
            font-family: 'Courier New', monospace;
            border: 1px solid var(--gray-300);
        }

        .recommendations {
            background: var(--success-green);
            color: var(--white);
            border-radius: 2px;
            padding: 15px;
            margin-top: 15px;
        }

        .recommendations h4 {
            margin-bottom: 10px;
            font-size: 1rem;
            font-weight: 700;
        }

        .architecture-diagram {
            background: var(--white);
            border-radius: 2px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 1px 1px 0 rgba(0, 28, 36, 0.3);
            text-align: center;
        }

        .mermaid {
            background: var(--gray-50);
            border-radius: 2px;
            padding: 20px;
            margin: 20px 0;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: var(--gray-600);
            border-top: 2px solid var(--gray-200);
            margin-top: 40px;
            background: var(--white);
            border-radius: 0;
        }

        .footer p {
            margin-bottom: 10px;
        }

        .footer a {
            color: var(--aws-blue);
        }

        .footer a:hover {
            color: var(--aws-blue-light);
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background-color: var(--gray-200);
            border-radius: 2px;
            overflow: hidden;
            margin-top: 5px;
        }

        .progress-fill {
            height: 100%;
            transition: width 0.3s ease;
        }

        .icon {
            width: 20px;
            height: 20px;
            display: inline-block;
        }

        .cost-analysis {
            display: grid;
            gap: 20px;
        }

        .cost-item {
            background: var(--white);
            border-radius: 2px;
            padding: 20px;
            border-left: 4px solid var(--aws-blue);
            box-shadow: 0 1px 1px 0 rgba(0, 28, 36, 0.3);
        }

        .cost-item h3 {
            color: var(--gray-900);
            font-weight: 700;
            margin-bottom: 15px;
        }

        .cost-details {
            margin-top: 15px;
        }

        .cost-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid var(--gray-200);
        }

        .cost-increase {
            color: var(--danger-red);
            font-weight: 600;
        }

        .cost-savings {
            color: var(--success-green);
            font-weight: 600;
        }

        .cost-total {
            font-size: 1.1rem;
            font-weight: 700;
            padding: 15px 0;
            border-top: 2px solid var(--aws-blue);
            margin-top: 10px;
        }

        .cost-positive {
            color: var(--success-green);
        }

        .roi-analysis {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .roi-metric {
            text-align: center;
            padding: 15px;
            background: var(--gray-50);
            border-radius: 2px;
        }

        .roi-label {
            font-size: 0.9rem;
            color: var(--gray-600);
            margin-bottom: 5px;
        }

        .roi-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--aws-blue);
        }

        .conclusion {
            background: var(--gray-50);
            border-radius: 2px;
            padding: 30px;
        }

        .conclusion-summary {
            margin-bottom: 30px;
        }

        .conclusion-summary h3 {
            color: var(--gray-900);
            margin-bottom: 15px;
            font-weight: 700;
        }

        .key-findings {
            margin-top: 20px;
        }

        .key-findings h4 {
            color: var(--gray-900);
            margin-bottom: 10px;
            font-weight: 700;
        }

        .key-findings ul {
            margin-left: 20px;
        }

        .conclusion-recommendations {
            margin-bottom: 30px;
        }

        .conclusion-recommendations h3 {
            color: var(--gray-900);
            margin-bottom: 15px;
            font-weight: 700;
        }

        .recommendation-item {
            margin-bottom: 20px;
            padding: 15px;
            background: var(--white);
            border-radius: 2px;
            border-left: 4px solid var(--aws-blue);
        }

        .recommendation-item h4 {
            color: var(--aws-blue);
            margin-bottom: 10px;
            font-weight: 700;
        }

        .recommendation-item ul {
            margin-left: 20px;
        }

        .conclusion-benefits {
            margin-bottom: 30px;
        }

        .conclusion-benefits h3 {
            color: var(--gray-900);
            margin-bottom: 15px;
            font-weight: 700;
        }

        .benefits-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .benefit-item {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 20px;
            background: var(--white);
            border-radius: 2px;
            box-shadow: 0 1px 1px 0 rgba(0, 28, 36, 0.3);
        }

        .benefit-icon {
            font-size: 2rem;
        }

        .benefit-content h4 {
            color: var(--aws-blue);
            margin-bottom: 5px;
            font-weight: 700;
        }

        .next-steps {
            background: var(--white);
            padding: 20px;
            border-radius: 2px;
            border-left: 4px solid var(--success-green);
        }

        .next-steps h3 {
            color: var(--success-green);
            margin-bottom: 15px;
            font-weight: 700;
        }

        .next-steps ol {
            margin-left: 20px;
        }

        .next-steps li {
            margin-bottom: 10px;
        }

        .appendix {
            background: var(--gray-50);
            padding: 20px;
            border-radius: 2px;
        }

        .appendix h3 {
            color: var(--gray-900);
            margin-bottom: 15px;
            font-weight: 700;
        }

        .appendix ul {
            margin-left: 20px;
            margin-bottom: 20px;
        }

        .appendix a {
            color: var(--aws-blue);
            text-decoration: none;
        }

        .appendix a:hover {
            text-decoration: underline;
            color: var(--aws-blue-light);
        }

        pre {
            background: var(--gray-900);
            color: var(--white);
            padding: 15px;
            border-radius: 2px;
            overflow-x: auto;
            margin: 15px 0;
            border: 1px solid var(--gray-700);
        }

        code {
            font-family: 'Courier New', Consolas, monospace;
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }

            .sidebar.open {
                transform: translateX(0);
            }

            .sidebar-toggle {
                display: block;
            }

            .content-wrapper {
                margin-left: 0;
            }

            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .summary-dashboard {
                grid-template-columns: 1fr;
            }
            
            .pillar-scores {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        /* Print Styles */
        @media print {
            .sidebar,
            .sidebar-toggle {
                display: none;
            }

            .content-wrapper {
                margin-left: 0;
            }

            .section {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="page-wrapper">
        <!-- Mobile Toggle Button -->
        <button class="sidebar-toggle" onclick="toggleSidebar()" aria-label="Toggle navigation">
            ☰
        </button>

        <!-- Side Navigation -->
        <nav class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <h3>WA Assessment Report</h3>
                <p>Navigation</p>
            </div>
            <div class="sidebar-nav">
                <div class="nav-section">
                    <a href="#overview" class="nav-link">
                        <span class="nav-icon">🏠</span>Overview
                    </a>
                </div>
                <div class="nav-section">
                    <a href="#screener-analysis" class="nav-link">
                        <span class="nav-icon">🔍</span>Screener Analysis
                    </a>
                </div>
                <div class="nav-section">
                    <a href="#pillar-analysis" class="nav-link">
                        <span class="nav-icon">🏛️</span>6 Pillars Analysis
                    </a>
                </div>
                <div class="nav-section">
                    <a href="#priorities" class="nav-link">
                        <span class="nav-icon">🎯</span>Priority Recommendations
                    </a>
                </div>
                <div class="nav-section">
                    <a href="#roadmap" class="nav-link">
                        <span class="nav-icon">🗓️</span>Implementation Roadmap
                    </a>
                </div>
                <div class="nav-section">
                    <a href="#cost-analysis" class="nav-link">
                        <span class="nav-icon">💰</span>Cost Impact Analysis
                    </a>
                </div>
                <div class="nav-section">
                    <a href="#conclusion" class="nav-link">
                        <span class="nav-icon">✅</span>Conclusion
                    </a>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <div class="content-wrapper">
            <div class="container">
                
                <!-- ==================== HEADER SECTION START ==================== -->
                <div class="header" id="overview">
                    <h1>🏗️ AWS Service Screener Well-Architected Framework Analysis Report</h1>
                    <p>Account ID: 123456789012 | Generated: July 21, 2025 07:50:41 (UTC)</p>
                </div>
                <!-- ==================== HEADER SECTION END ==================== -->

                <!-- ==================== DASHBOARD SECTION START ==================== -->
                <div class="summary-dashboard">
                    <div class="summary-card">
                        <h3>📊 Service Screener Issues Found</h3>
                        <div class="metric">
                            <span class="metric-label">High Severity</span>
                            <span class="metric-value high">433</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Medium Severity</span>
                            <span class="metric-value medium">544</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Low Severity</span>
                            <span class="metric-value low">592</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Informational</span>
                            <span class="metric-value info">125</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Total Issues</span>
                            <span class="metric-value">1,694</span>
                        </div>
                    </div>

                    <div class="summary-card">
                        <h3>🔒 Security Issues Status</h3>
                        <div class="metric">
                            <span class="metric-label">High Security Issues</span>
                            <span class="metric-value high">274</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Medium Security Issues</span>
                            <span class="metric-value medium">132</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Low Security Issues</span>
                            <span class="metric-value low">269</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Total Security Issues</span>
                            <span class="metric-value">706</span>
                        </div>
                    </div>

                    <div class="summary-card">
                        <h3>📈 Expected Improvement Impact</h3>
                        <div class="metric">
                            <span class="metric-label">Security Enhancement</span>
                            <span class="metric-value compliant">706 issues resolved</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Cost Optimization</span>
                            <span class="metric-value compliant">297 issues resolved</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Performance Improvement</span>
                            <span class="metric-value compliant">339 issues resolved</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Reliability Enhancement</span>
                            <span class="metric-value compliant">210 issues resolved</span>
                        </div>
                    </div>
                </div>
                <!-- ==================== DASHBOARD SECTION END ==================== -->

                <!-- ==================== PILLAR SCORES SECTION START ==================== -->
                <div class="pillar-scores">
                    <div class="pillar-card">
                        <div class="pillar-name">🔒 Security</div>
                        <div class="pillar-score high">706</div>
                        <div class="pillar-total">Total Issues</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 42%; background-color: var(--danger-red);"></div>
                        </div>
                    </div>
                    <div class="pillar-card">
                        <div class="pillar-name">⚡ Performance Efficiency</div>
                        <div class="pillar-score medium">339</div>
                        <div class="pillar-total">Total Issues</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 20%; background-color: var(--warning-orange);"></div>
                        </div>
                    </div>
                    <div class="pillar-card">
                        <div class="pillar-name">💰 Cost Optimization</div>
                        <div class="pillar-score medium">297</div>
                        <div class="pillar-total">Total Issues</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 18%; background-color: var(--aws-blue);"></div>
                        </div>
                    </div>
                    <div class="pillar-card">
                        <div class="pillar-name">🛡️ Reliability</div>
                        <div class="pillar-score medium">210</div>
                        <div class="pillar-total">Total Issues</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 12%; background-color: var(--success-green);"></div>
                        </div>
                    </div>
                    <div class="pillar-card">
                        <div class="pillar-name">🔧 Operational Excellence</div>
                        <div class="pillar-score low">142</div>
                        <div class="pillar-total">Total Issues</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 8%; background-color: var(--gray-600);"></div>
                        </div>
                    </div>
                </div>
                <!-- ==================== PILLAR SCORES SECTION END ==================== -->

                <!-- ==================== SCREENER ANALYSIS SECTION START ==================== -->
                <div class="section" id="screener-analysis">
                    <h2>🔍 Service Screener Results Analysis</h2>
                    
                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">EC2 Instance Security and Performance Issues</div>
                            <span class="issue-severity severity-high">HIGH</span>
                        </div>
                        <div class="issue-description">
                            Major issues found across 99 EC2 instances:
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li><strong>Missing IAM Instance Profiles:</strong> 28 instances without attached IAM profiles</li>
                                <li><strong>Public IP Assignment:</strong> 17 instances with public IP addresses</li>
                                <li><strong>Unencrypted EBS Volumes:</strong> 99 EBS volumes without encryption</li>
                                <li><strong>Missing EBS Snapshots:</strong> 99 EBS volumes without snapshots</li>
                                <li><strong>Low Utilization:</strong> 70 instances showing low CPU utilization</li>
                            </ul>
                        </div>
                        <div class="affected-resources">
                            <h4>Key Affected Resources:</h4>
                            <div class="resource-list">
                                <span class="resource-tag">i-01234abcdef56789a</span>
                                <span class="resource-tag">i-01234abcdef56789b</span>
                                <span class="resource-tag">i-01234abcdef56789c</span>
                                <span class="resource-tag">i-01234abcdef56789d</span>
                                <span class="resource-tag">... and 95 additional instances</span>
                            </div>
                        </div>
                        <div class="recommendations">
                            <h4>Recommendations:</h4>
                            <ul>
                                <li>Attach appropriate IAM roles to all EC2 instances</li>
                                <li>Remove unnecessary public IPs and use NAT Gateway</li>
                                <li>Enable EBS volume encryption</li>
                                <li>Automate regular EBS snapshot creation</li>
                                <li>Install CloudWatch agent for detailed monitoring</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">RDS Database Security and Backup Issues</div>
                            <span class="issue-severity severity-high">HIGH</span>
                        </div>
                        <div class="issue-description">
                            Critical issues found across 7 MySQL RDS instances:
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li><strong>Public Access Enabled:</strong> All 7 instances allow public access</li>
                                <li><strong>Storage Encryption Disabled:</strong> All instances have encryption disabled</li>
                                <li><strong>Backup Not Configured:</strong> 4 instances have automatic backup disabled</li>
                                <li><strong>Multi-AZ Not Applied:</strong> 4 instances without Multi-AZ deployment</li>
                                <li><strong>Outdated Versions:</strong> All instances not using latest versions</li>
                            </ul>
                        </div>
                        <div class="affected-resources">
                            <h4>Affected RDS Instances:</h4>
                            <div class="resource-list">
                                <span class="resource-tag">agent-firmware-db</span>
                                <span class="resource-tag">mydw-development-db</span>
                                <span class="resource-tag">mydw-production-db</span>
                                <span class="resource-tag">mydw-staging-db</span>
                                <span class="resource-tag">mydw-*-db-replica (3 instances)</span>
                            </div>
                        </div>
                        <div class="recommendations">
                            <h4>Recommendations:</h4>
                            <ul>
                                <li>Disable public access and restrict to VPC internal access</li>
                                <li>Enable RDS storage encryption</li>
                                <li>Enable automatic backup (minimum 7-day retention)</li>
                                <li>Apply Multi-AZ for production instances</li>
                                <li>Upgrade to latest MySQL versions</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">S3 Bucket Security and Configuration Issues</div>
                            <span class="issue-severity severity-high">HIGH</span>
                        </div>
                        <div class="issue-description">
                            Security and configuration issues found across 30 S3 buckets:
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li><strong>Public Access Allowed:</strong> 18 buckets with public access block disabled</li>
                                <li><strong>Public Read Allowed:</strong> 11 buckets allowing public read access</li>
                                <li><strong>Public Write Allowed:</strong> 3 buckets allowing public write access</li>
                                <li><strong>Versioning Disabled:</strong> All 30 buckets without versioning enabled</li>
                                <li><strong>MFA Delete Disabled:</strong> All buckets without MFA delete protection</li>
                            </ul>
                        </div>
                        <div class="affected-resources">
                            <h4>Key Affected S3 Buckets:</h4>
                            <div class="resource-list">
                                <span class="resource-tag">mydw-prod-front</span>
                                <span class="resource-tag">mydw-dev-front</span>
                                <span class="resource-tag">mydw-stag-front</span>
                                <span class="resource-tag">mydw-firmware-bucket</span>
                                <span class="resource-tag">... and 26 additional buckets</span>
                            </div>
                        </div>
                        <div class="recommendations">
                            <h4>Recommendations:</h4>
                            <ul>
                                <li>Enable public access block for all S3 buckets</li>
                                <li>Allow limited public access only when necessary</li>
                                <li>Enable versioning for all buckets</li>
                                <li>Apply MFA delete protection for critical buckets</li>
                                <li>Enforce encryption in transit for all data</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">IAM User and Permission Management Issues</div>
                            <span class="issue-severity severity-high">HIGH</span>
                        </div>
                        <div class="issue-description">
                            Critical security issues found in IAM management:
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li><strong>MFA Not Applied:</strong> 15 IAM users without MFA enabled</li>
                                <li><strong>Old Passwords:</strong> 11 users haven't changed passwords for over 365 days</li>
                                <li><strong>Access Key Not Rotated:</strong> 10 users haven't rotated access keys for over 90 days</li>
                                <li><strong>Excessive Permissions:</strong> 12 users/roles with administrator privileges</li>
                                <li><strong>Inactive Users:</strong> 4 users inactive for over 90 days</li>
                            </ul>
                        </div>
                        <div class="affected-resources">
                            <h4>Key Affected IAM Users:</h4>
                            <div class="resource-list">
                                <span class="resource-tag">root_id</span>
                                <span class="resource-tag">cvv-bucket-viewer</span>
                                <span class="resource-tag">user1</span>
                                <span class="resource-tag">user@example.com</span>
                                <span class="resource-tag">... and 11 additional users</span>
                            </div>
                        </div>
                        <div class="recommendations">
                            <h4>Recommendations:</h4>
                            <ul>
                                <li>Enforce MFA for all IAM users</li>
                                <li>Set password policy and enforce regular changes</li>
                                <li>Automate regular access key rotation</li>
                                <li>Apply principle of least privilege and limit admin access</li>
                                <li>Regularly review and remove inactive users</li>
                            </ul>
                        </div>
                    </div>
                </div>
                <!-- ==================== SCREENER ANALYSIS SECTION END ==================== -->

                <!-- ==================== PILLAR ANALYSIS SECTION START ==================== -->
                <div class="section" id="pillar-analysis">
                    <h2>🏛️ Well-Architected Framework 6 Pillars Analysis</h2>
                    
                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">🔒 Security - 706 Issues</div>
                            <span class="issue-severity severity-high">HIGH</span>
                        </div>
                        <div class="issue-description">
                            <strong>Current State:</strong> The security pillar has the highest number of issues, with critical security vulnerabilities requiring immediate attention.
                            <br><br>
                            <strong>Key Security Issues:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>IAM users without MFA (15 users)</li>
                                <li>RDS instances allowing public access (7 instances)</li>
                                <li>S3 buckets allowing public access (18 buckets)</li>
                                <li>Security groups with excessive port openings (24 security groups)</li>
                                <li>Unencrypted EBS volumes (99 volumes)</li>
                            </ul>
                        </div>
                        <div class="recommendations">
                            <h4>Security Enhancement Recommendations:</h4>
                            <ul>
                                <li><strong>Immediate Action:</strong> Enforce MFA for all IAM users</li>
                                <li><strong>Network Security:</strong> Block RDS public access and restrict to VPC internal communication</li>
                                <li><strong>Data Protection:</strong> Enable encryption for all EBS volumes and RDS instances</li>
                                <li><strong>Access Control:</strong> Enable S3 bucket public access block</li>
                                <li><strong>Monitoring:</strong> Enable CloudTrail, GuardDuty, and Config services</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">⚡ Performance Efficiency - 339 Issues</div>
                            <span class="issue-severity severity-medium">MEDIUM</span>
                        </div>
                        <div class="issue-description">
                            <strong>Current State:</strong> Many performance optimization opportunities exist, particularly in instance type selection and monitoring.
                            <br><br>
                            <strong>Key Performance Issues:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>EC2 instances with low utilization (70 instances)</li>
                                <li>Not using Graviton processors (46 instances)</li>
                                <li>CloudWatch detailed monitoring not applied (78 instances)</li>
                                <li>Lambda functions not using ARM64 architecture (8 functions)</li>
                                <li>ElastiCache not using latest instance types (12 clusters)</li>
                            </ul>
                        </div>
                        <div class="recommendations">
                            <h4>Performance Optimization Recommendations:</h4>
                            <ul>
                                <li><strong>Instance Optimization:</strong> Downsize low-utilization instances</li>
                                <li><strong>Processor Upgrade:</strong> Migrate to Graviton-based instances</li>
                                <li><strong>Enhanced Monitoring:</strong> Enable CloudWatch detailed monitoring and Performance Insights</li>
                                <li><strong>Serverless Optimization:</strong> Apply ARM64 architecture to Lambda functions</li>
                                <li><strong>Cache Optimization:</strong> Apply latest ElastiCache instance types</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">💰 Cost Optimization - 297 Issues</div>
                            <span class="issue-severity severity-medium">MEDIUM</span>
                        </div>
                        <div class="issue-description">
                            <strong>Current State:</strong> Significant cost savings opportunities exist, particularly through unused resource cleanup and storage optimization.
                            <br><br>
                            <strong>Key Cost Optimization Opportunities:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>Cost waste due to low EC2 instance utilization</li>
                                <li>Unused Elastic IP (1 instance)</li>
                                <li>S3 Intelligent Tiering not applied (26 buckets)</li>
                                <li>S3 Lifecycle policies not configured (24 buckets)</li>
                                <li>CloudWatch log retention period not set (20 log groups)</li>
                            </ul>
                        </div>
                        <div class="recommendations">
                            <h4>Cost Optimization Recommendations:</h4>
                            <ul>
                                <li><strong>Instance Optimization:</strong> Adjust instance sizing based on utilization</li>
                                <li><strong>Resource Cleanup:</strong> Remove unused Elastic IPs and EBS volumes</li>
                                <li><strong>Storage Optimization:</strong> Apply S3 Intelligent Tiering and Lifecycle policies</li>
                                <li><strong>Log Management:</strong> Set CloudWatch log retention periods</li>
                                <li><strong>Reserved Instances:</strong> Apply Reserved Instances for long-running workloads</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">🛡️ Reliability - 210 Issues</div>
                            <span class="issue-severity severity-medium">MEDIUM</span>
                        </div>
                        <div class="issue-description">
                            <strong>Current State:</strong> Basic backup and multi-availability zone configurations for system reliability are lacking, making recovery difficult in case of failures.
                            <br><br>
                            <strong>Key Reliability Issues:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>EBS snapshots not configured (99 volumes)</li>
                                <li>RDS automatic backup not configured (4 instances)</li>
                                <li>RDS Multi-AZ not applied (4 instances)</li>
                                <li>ELB Cross-Zone load balancing not applied (4 load balancers)</li>
                                <li>DynamoDB Point-in-Time Recovery not applied (5 tables)</li>
                            </ul>
                        </div>
                        <div class="recommendations">
                            <h4>Reliability Enhancement Recommendations:</h4>
                            <ul>
                                <li><strong>Backup Strategy:</strong> Configure automatic snapshots for all EBS volumes</li>
                                <li><strong>Database Protection:</strong> Enable RDS automatic backup and Multi-AZ</li>
                                <li><strong>High Availability:</strong> Enable ELB Cross-Zone load balancing</li>
                                <li><strong>NoSQL Protection:</strong> Enable DynamoDB PITR</li>
                                <li><strong>Monitoring:</strong> Set up CloudWatch alarms and SNS notifications</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">🔧 Operational Excellence - 142 Issues</div>
                            <span class="issue-severity severity-low">LOW</span>
                        </div>
                        <div class="issue-description">
                            <strong>Current State:</strong> Operational processes and monitoring systems are partially established, but improvements needed in automation and observability.
                            <br><br>
                            <strong>Key Operational Issues:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>CloudWatch log retention period not set (20 log groups)</li>
                                <li>Lambda function Enhanced Monitoring not applied (8 functions)</li>
                                <li>ElastiCache notifications not configured (12 clusters)</li>
                                <li>CloudTrail SNS notifications not configured</li>
                                <li>AWS Config service not enabled</li>
                            </ul>
                        </div>
                        <div class="recommendations">
                            <h4>Operational Excellence Enhancement Recommendations:</h4>
                            <ul>
                                <li><strong>Log Management:</strong> Centralize all service logs and set retention policies</li>
                                <li><strong>Enhanced Monitoring:</strong> Comprehensive metric collection and alarm setup</li>
                                <li><strong>Automation:</strong> Automate infrastructure deployment and management</li>
                                <li><strong>Compliance:</strong> Track resource configuration through AWS Config</li>
                                <li><strong>Incident Response:</strong> Build automated notification and response processes</li>
                            </ul>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">🌱 Sustainability</div>
                            <span class="issue-severity severity-info">INFO</span>
                        </div>
                        <div class="issue-description">
                            <strong>Current State:</strong> Optimization opportunities exist to reduce environmental impact, particularly through energy-efficient instance types and improved resource utilization.
                            <br><br>
                            <strong>Sustainability Improvement Opportunities:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>Expand use of Graviton processor-based instances</li>
                                <li>Optimize low-utilization instances</li>
                                <li>Expand serverless architecture adoption</li>
                                <li>Improve energy efficiency through storage tiering</li>
                                <li>Clean up unused resources</li>
                            </ul>
                        </div>
                        <div class="recommendations">
                            <h4>Sustainability Enhancement Recommendations:</h4>
                            <ul>
                                <li><strong>Energy Efficiency:</strong> Migrate to Graviton-based instances</li>
                                <li><strong>Resource Optimization:</strong> Utilization-based instance sizing</li>
                                <li><strong>Serverless Adoption:</strong> Utilize Lambda, Fargate and other serverless services</li>
                                <li><strong>Storage Optimization:</strong> Apply S3 Intelligent Tiering</li>
                                <li><strong>Resource Cleanup:</strong> Regular review and removal of unused resources</li>
                            </ul>
                        </div>
                    </div>
                </div>
                <!-- ==================== PILLAR ANALYSIS SECTION END ==================== -->

                <!-- ==================== PRIORITIES SECTION START ==================== -->
                <div class="section" id="priorities">
                    <h2>🎯 Priority-based Improvement Recommendations</h2>
                    
                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">🚨 Immediate Action Required (High Priority)</div>
                            <span class="issue-severity severity-high">HIGH</span>
                        </div>
                        <div class="issue-description">
                            <strong>Issues with high security risk requiring immediate resolution.</strong>
                        </div>
                        <div class="affected-resources">
                            <h4>1. Enable MFA for IAM Users</h4>
                            <p><strong>Affected Resources:</strong> 15 IAM users</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Create and attach MFA device
aws iam create-virtual-mfa-device --virtual-mfa-device-name MyMFADevice --path /
aws iam enable-mfa-device --user-name USERNAME --serial-number arn:aws:iam::ACCOUNT:mfa/MyMFADevice --authentication-code-1 CODE1 --authentication-code-2 CODE2

# Apply MFA enforcement policy
aws iam put-user-policy --user-name USERNAME --policy-name MFARequired --policy-document file://mfa-policy.json</pre>
                            <p><strong>Expected Cost:</strong> Free (AWS MFA has no additional cost)</p>
                            <p><strong>Expected Impact:</strong> 99% reduction in account takeover risk</p>
                        </div>
                        
                        <div class="affected-resources">
                            <h4>2. Block RDS Public Access</h4>
                            <p><strong>Affected Resources:</strong> 7 RDS instances</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Disable RDS public access
aws rds modify-db-instance --db-instance-identifier mydw-production-db --no-publicly-accessible
aws rds modify-db-instance --db-instance-identifier mydw-development-db --no-publicly-accessible

# Modify security group rules (allow VPC internal access only)
aws ec2 revoke-security-group-ingress --group-id sg-01234abcdef56789a --protocol tcp --port 3306 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-01234abcdef56789a --protocol tcp --port 3306 --cidr 10.0.0.0/16</pre>
                            <p><strong>Expected Cost:</strong> Free</p>
                            <p><strong>Expected Impact:</strong> Complete elimination of external database attack risk</p>
                        </div>

                        <div class="affected-resources">
                            <h4>3. S3 Bucket Public Access Block</h4>
                            <p><strong>Affected Resources:</strong> 18 S3 buckets</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Enable S3 bucket public access block
aws s3api put-public-access-block --bucket mydw-prod-front --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Account-level public access block
aws s3control put-public-access-block --account-id 123456789012 --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"</pre>
                            <p><strong>Expected Cost:</strong> Free</p>
                            <p><strong>Expected Impact:</strong> 95% reduction in data breach risk</p>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">⚠️ Short-term Improvement (Medium Priority)</div>
                            <span class="issue-severity severity-medium">MEDIUM</span>
                        </div>
                        <div class="issue-description">
                            <strong>Issues recommended for resolution within 1-2 weeks for system stability and performance improvement.</strong>
                        </div>
                        <div class="affected-resources">
                            <h4>1. Enable EBS Volume Encryption</h4>
                            <p><strong>Affected Resources:</strong> 99 EBS volumes</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Enable default EBS encryption
aws ec2 enable-ebs-encryption-by-default --region us-west-2

# Encrypt existing volumes (create snapshot then replace with encrypted volume)
aws ec2 create-snapshot --volume-id vol-01234abcdef56789a --description "Pre-encryption snapshot"
aws ec2 copy-snapshot --source-snapshot-id snap-xxx --encrypted --source-region us-west-2</pre>
                            <p><strong>Expected Cost:</strong> Free (encryption itself has no additional cost)</p>
                            <p><strong>Expected Impact:</strong> Enhanced data security, improved compliance</p>
                        </div>

                        <div class="affected-resources">
                            <h4>2. Configure RDS Automatic Backup and Multi-AZ</h4>
                            <p><strong>Affected Resources:</strong> 4 RDS instances</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Enable automatic backup (7-day retention)
aws rds modify-db-instance --db-instance-identifier mydw-production-db --backup-retention-period 7 --apply-immediately

# Enable Multi-AZ
aws rds modify-db-instance --db-instance-identifier mydw-production-db --multi-az --apply-immediately</pre>
                            <p><strong>Expected Cost:</strong> Approximately 100% cost increase due to Multi-AZ (ensures high availability)</p>
                            <p><strong>Expected Impact:</strong> 99.95% availability, minimized data loss risk</p>
                        </div>

                        <div class="affected-resources">
                            <h4>3. Enable CloudWatch Detailed Monitoring</h4>
                            <p><strong>Affected Resources:</strong> 78 EC2 instances</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Enable EC2 detailed monitoring
aws ec2 monitor-instances --instance-ids i-01234abcdef56789a i-01234abcdef56789b

# Install and configure CloudWatch agent
aws ssm send-command --document-name "AmazonCloudWatch-ManageAgent" --parameters action=configure,mode=ec2,config-content=file://cloudwatch-config.json --targets "Key=tag:Environment,Values=production"</pre>
                            <p><strong>Expected Cost:</strong> Approximately $50-100/month (metric collection costs)</p>
                            <p><strong>Expected Impact:</strong> Early detection of performance issues, 50% reduction in average resolution time</p>
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">📈 Long-term Optimization (Low Priority)</div>
                            <span class="issue-severity severity-low">LOW</span>
                        </div>
                        <div class="issue-description">
                            <strong>Issues that can be gradually improved over 1-3 months for cost optimization and performance enhancement.</strong>
                        </div>
                        <div class="affected-resources">
                            <h4>1. Graviton Processor Migration</h4>
                            <p><strong>Affected Resources:</strong> 46 EC2 instances</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Change from current instance type to Graviton-based
aws ec2 modify-instance-attribute --instance-id i-01234abcdef56789c --instance-type m6g.large

# Test application compatibility then perform staged migration
aws ec2 create-image --instance-id i-01234abcdef56789c --name "pre-graviton-migration"</pre>
                            <p><strong>Expected Cost:</strong> 20-40% cost savings</p>
                            <p><strong>Expected Impact:</strong> Performance improvement and cost reduction</p>
                        </div>

                        <div class="affected-resources">
                            <h4>2. Apply S3 Intelligent Tiering</h4>
                            <p><strong>Affected Resources:</strong> 26 S3 buckets</p>
                            <p><strong>Implementation Method:</strong></p>
                            <pre style="background: var(--gray-100); padding: 10px; border-radius: 4px; font-size: 0.9rem; color: var(--gray-900);">
# Configure S3 Intelligent Tiering
aws s3api put-bucket-intelligent-tiering-configuration --bucket mydw-prod-front --id EntireBucket --intelligent-tiering-configuration Id=EntireBucket,Status=Enabled,Filter={},Tierings=[{Days=1,AccessTier=ARCHIVE_ACCESS},{Days=90,AccessTier=DEEP_ARCHIVE_ACCESS}]

# Configure Lifecycle policy
aws s3api put-bucket-lifecycle-configuration --bucket mydw-prod-front --lifecycle-configuration file://lifecycle-policy.json</pre>
                            <p><strong>Expected Cost:</strong> 30-50% storage cost savings</p>
                            <p><strong>Expected Impact:</strong> Automatic cost optimization, reduced management burden</p>
                        </div>
                    </div>
                </div>
                <!-- ==================== PRIORITIES SECTION END ==================== -->

                <!-- ==================== ROADMAP SECTION START ==================== -->
                <div class="section" id="roadmap">
                    <h2>🗓️ Implementation Roadmap</h2>
                    
                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">Week 1: Emergency Security Measures</div>
                            <span class="issue-severity severity-high">HIGH</span>
                        </div>
                        <div class="issue-description">
                            <strong>Goal:</strong> Eliminate immediate security risks
                            <br><br>
                            <strong>Key Tasks:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>Enable MFA for all IAM users (1-2 days)</li>
                                <li>Block public access for RDS instances (1 day)</li>
                                <li>Enable public access block for S3 buckets (1 day)</li>
                                <li>Minimize security group rules (2-3 days)</li>
                                <li>Set up root account activity monitoring (1 day)</li>
                            </ul>
                            <br>
                            <strong>Required Resources:</strong> 1 Security Engineer, 1 System Administrator
                            <br>
                            <strong>Expected Cost:</strong> $0 (configuration changes only)
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">Weeks 2-4: Data Protection and Backup Enhancement</div>
                            <span class="issue-severity severity-medium">MEDIUM</span>
                        </div>
                        <div class="issue-description">
                            <strong>Goal:</strong> Strengthen data protection and disaster recovery capabilities
                            <br><br>
                            <strong>Key Tasks:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>Enable EBS volume encryption (1 week)</li>
                                <li>Configure RDS automatic backup and Multi-AZ (1 week)</li>
                                <li>Implement EBS snapshot automation (1 week)</li>
                                <li>Enable S3 versioning and MFA delete (3-5 days)</li>
                                <li>Enable DynamoDB Point-in-Time Recovery (2 days)</li>
                            </ul>
                            <br>
                            <strong>Required Resources:</strong> 1 Cloud Architect, 1 DevOps Engineer
                            <br>
                            <strong>Expected Cost:</strong> $200-500/month (Multi-AZ and backup storage)
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">Months 1-2: Monitoring and Operations Improvement</div>
                            <span class="issue-severity severity-medium">MEDIUM</span>
                        </div>
                        <div class="issue-description">
                            <strong>Goal:</strong> Build comprehensive monitoring and operational automation
                            <br><br>
                            <strong>Key Tasks:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>Configure CloudWatch detailed monitoring and alarms (2 weeks)</li>
                                <li>Enable AWS Config and CloudTrail (1 week)</li>
                                <li>Enable GuardDuty security monitoring (3 days)</li>
                                <li>Configure Lambda function Enhanced Monitoring (1 week)</li>
                                <li>Set up log centralization and retention policies (1 week)</li>
                            </ul>
                            <br>
                            <strong>Required Resources:</strong> 1 DevOps Engineer, 1 Monitoring Specialist
                            <br>
                            <strong>Expected Cost:</strong> $100-300/month (monitoring service costs)
                        </div>
                    </div>

                    <div class="issue-item">
                        <div class="issue-header">
                            <div class="issue-title">Months 2-3: Performance and Cost Optimization</div>
                            <span class="issue-severity severity-low">LOW</span>
                        </div>
                        <div class="issue-description">
                            <strong>Goal:</strong> Long-term performance improvement and cost reduction
                            <br><br>
                            <strong>Key Tasks:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                <li>Optimize EC2 instance sizing (3 weeks)</li>
                                <li>Migrate to Graviton processors (4 weeks)</li>
                                <li>Apply S3 Intelligent Tiering and Lifecycle policies (2 weeks)</li>
                                <li>Migrate Lambda functions to ARM64 architecture (2 weeks)</li>
                                <li>Upgrade ElastiCache instance types (1 week)</li>
                            </ul>
                            <br>
                            <strong>Required Resources:</strong> 1 Cloud Architect, 2 Application Developers
                            <br>
                            <strong>Expected Cost Savings:</strong> $500-1,500/month (instance optimization and storage savings)
                        </div>
                    </div>
                </div>
                <!-- ==================== ROADMAP SECTION END ==================== -->

                <!-- ==================== COST ANALYSIS SECTION START ==================== -->
                <div class="section" id="cost-analysis">
                    <h2>💰 Cost Impact Analysis</h2>
                    
                    <div class="cost-analysis">
                        <div class="cost-item">
                            <h3>🔴 Immediate Investment Required (Within 1 Month)</h3>
                            <div class="cost-details">
                                <div class="cost-row">
                                    <span>RDS Multi-AZ Activation</span>
                                    <span class="cost-increase">+$800/month</span>
                                </div>
                                <div class="cost-row">
                                    <span>CloudWatch Detailed Monitoring</span>
                                    <span class="cost-increase">+$100/month</span>
                                </div>
                                <div class="cost-row">
                                    <span>GuardDuty Security Monitoring</span>
                                    <span class="cost-increase">+$50/month</span>
                                </div>
                                <div class="cost-row">
                                    <span>Backup Storage Increase</span>
                                    <span class="cost-increase">+$150/month</span>
                                </div>
                                <div class="cost-total">
                                    <strong>Total Short-term Investment: +$1,100/month</strong>
                                </div>
                            </div>
                        </div>

                        <div class="cost-item">
                            <h3>🟢 Medium to Long-term Cost Savings (3-6 Months)</h3>
                            <div class="cost-details">
                                <div class="cost-row">
                                    <span>Graviton Instance Migration</span>
                                    <span class="cost-savings">-$600/month</span>
                                </div>
                                <div class="cost-row">
                                    <span>EC2 Instance Sizing Optimization</span>
                                    <span class="cost-savings">-$400/month</span>
                                </div>
                                <div class="cost-row">
                                    <span>S3 Intelligent Tiering</span>
                                    <span class="cost-savings">-$300/month</span>
                                </div>
                                <div class="cost-row">
                                    <span>Unused Resource Cleanup</span>
                                    <span class="cost-savings">-$200/month</span>
                                </div>
                                <div class="cost-row">
                                    <span>Reserved Instance Purchase</span>
                                    <span class="cost-savings">-$500/month</span>
                                </div>
                                <div class="cost-total cost-positive">
                                    <strong>Total Long-term Savings: -$2,000/month</strong>
                                </div>
                            </div>
                        </div>

                        <div class="cost-item">
                            <h3>📊 ROI Analysis</h3>
                            <div class="roi-analysis">
                                <div class="roi-metric">
                                    <div class="roi-label">Initial Investment Payback Period</div>
                                    <div class="roi-value">7 months</div>
                                </div>
                                <div class="roi-metric">
                                    <div class="roi-label">Annual Net Savings</div>
                                    <div class="roi-value">$10,800</div>
                                </div>
                                <div class="roi-metric">
                                    <div class="roi-label">Security Risk Reduction</div>
                                    <div class="roi-value">85%</div>
                                </div>
                                <div class="roi-metric">
                                    <div class="roi-label">Availability Improvement</div>
                                    <div class="roi-value">99.9%</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- ==================== COST ANALYSIS SECTION END ==================== -->

                <!-- ==================== CONCLUSION SECTION START ==================== -->
                <div class="section" id="conclusion">
                    <h2>🎯 Conclusion and Recommendations</h2>
                    
                    <div class="conclusion">
                        <div class="conclusion-summary">
                            <h3>📋 Current State Summary</h3>
                            <p>The Service Screener analysis of AWS account 123456789012 identified <strong>1,694 improvement opportunities</strong>. 
                            Particularly, 706 issues were found in the security domain, requiring immediate action.</p>
                            
                            <div class="key-findings">
                                <h4>🔍 Key Findings</h4>
                                <ul>
                                    <li><strong>Security Risks:</strong> 7 RDS instances and 18 S3 buckets allowing public access</li>
                                    <li><strong>Access Control:</strong> 15 IAM users without MFA configured</li>
                                    <li><strong>Data Protection:</strong> 99 unencrypted EBS volumes</li>
                                    <li><strong>Monitoring Gaps:</strong> 78 EC2 instances without detailed monitoring</li>
                                    <li><strong>Backup Issues:</strong> 4 RDS instances without automatic backup configured</li>
                                </ul>
                            </div>
                        </div>

                        <div class="conclusion-recommendations">
                            <h3>🚀 Core Recommendations</h3>
                            
                            <div class="recommendation-item">
                                <h4>1. Immediate Action (Within 1 Week)</h4>
                                <ul>
                                    <li>Enforce MFA activation for all IAM users</li>
                                    <li>Block public access for RDS instances and S3 buckets</li>
                                    <li>Minimize security group rules and block unnecessary ports</li>
                                    <li>Set up root account activity monitoring and alerts</li>
                                </ul>
                            </div>

                            <div class="recommendation-item">
                                <h4>2. Short-term Improvement (Within 1 Month)</h4>
                                <ul>
                                    <li>Enable EBS volume encryption and default encryption settings</li>
                                    <li>Enable RDS Multi-AZ deployment and automatic backup</li>
                                    <li>Configure CloudWatch detailed monitoring and alarms</li>
                                    <li>Enable AWS Config and CloudTrail</li>
                                </ul>
                            </div>

                            <div class="recommendation-item">
                                <h4>3. Medium to Long-term Optimization (3-6 Months)</h4>
                                <ul>
                                    <li>Migrate to Graviton processor-based instances</li>
                                    <li>Optimize EC2 instance sizing and purchase Reserved Instances</li>
                                    <li>Apply S3 Intelligent Tiering and Lifecycle policies</li>
                                    <li>Migrate Lambda functions to ARM64 architecture</li>
                                </ul>
                            </div>
                        </div>

                        <div class="conclusion-benefits">
                            <h3>🎁 Expected Benefits</h3>
                            <div class="benefits-grid">
                                <div class="benefit-item">
                                    <div class="benefit-icon">🔒</div>
                                    <div class="benefit-content">
                                        <h4>Security Enhancement</h4>
                                        <p>85% reduction in security risks<br>Improved compliance</p>
                                    </div>
                                </div>
                                <div class="benefit-item">
                                    <div class="benefit-icon">⚡</div>
                                    <div class="benefit-content">
                                        <h4>Performance Improvement</h4>
                                        <p>30% improvement in response time<br>99.9% availability achievement</p>
                                    </div>
                                </div>
                                <div class="benefit-item">
                                    <div class="benefit-icon">💰</div>
                                    <div class="benefit-content">
                                        <h4>Cost Savings</h4>
                                        <p>$10,800 annual savings<br>7-month ROI achievement</p>
                                    </div>
                                </div>
                                <div class="benefit-item">
                                    <div class="benefit-icon">📊</div>
                                    <div class="benefit-content">
                                        <h4>Operational Efficiency</h4>
                                        <p>Monitoring automation<br>50% reduction in management burden</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="next-steps">
                            <h3>📋 Next Steps</h3>
                            <ol>
                                <li><strong>Priority Review:</strong> Adjust recommendation priorities based on organizational business requirements</li>
                                <li><strong>Team Formation:</strong> Organize implementation team with security engineers, DevOps engineers, and cloud architects</li>
                                <li><strong>Pilot Testing:</strong> Test and validate major changes in development environment</li>
                                <li><strong>Phased Implementation:</strong> Apply to production environment starting with low-risk items</li>
                                <li><strong>Continuous Monitoring:</strong> Measure implementation effectiveness and identify additional optimization opportunities</li>
                            </ol>
                        </div>
                    </div>
                </div>
                <!-- ==================== CONCLUSION SECTION END ==================== -->

                <!-- ==================== APPENDIX SECTION START ==================== -->
                <div class="section">
                    <h2>📚 Appendix</h2>
                    
                    <div class="appendix">
                        <h3>🔗 Useful Resources</h3>
                        <ul>
                            <li><a href="https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html" target="_blank">AWS Well-Architected Framework</a></li>
                            <li><a href="https://aws.amazon.com/security/security-bulletins/" target="_blank">AWS Security Bulletins</a></li>
                            <li><a href="https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html" target="_blank">AWS Config Conformance Packs</a></li>
                            <li><a href="https://aws.amazon.com/premiumsupport/technology/trusted-advisor/" target="_blank">AWS Trusted Advisor</a></li>
                            <li><a href="https://calculator.aws/" target="_blank">AWS Pricing Calculator</a></li>
                        </ul>

                        <h3>📞 Support Contact</h3>
                        <p>For additional support, please contact the AWS Support team or schedule a consultation with an AWS Solutions Architect.</p>
                        
                        <h3>📅 Report Information</h3>
                        <ul>
                            <li><strong>Generated:</strong> July 21, 2025 07:50:41 (UTC)</li>
                            <li><strong>Analysis Target:</strong> AWS Account 123456789012</li>
                            <li><strong>Service Screener Version:</strong> Latest</li>
                            <li><strong>Report Version:</strong> v1.0</li>
                        </ul>
                    </div>
                </div>
                <!-- ==================== APPENDIX SECTION END ==================== -->

                <!-- ==================== FOOTER SECTION START ==================== -->
                <div class="footer">
                    <p><strong>AWS Service Screener Well-Architected Framework Analysis Report</strong></p>
                    <p>Generated: July 21, 2025 07:50:41 (UTC) | Account: 123456789012</p>
                    <p>This report provides a comprehensive analysis based on AWS Well-Architected Framework best practices.</p>
                    <p>For questions or additional support, please contact your AWS account team.</p>
                </div>
                <!-- ==================== FOOTER SECTION END ==================== -->
                
            </div>
        </div>
    </div>

    <script>
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            sidebar.classList.toggle('open');
        }

        // Smooth scrolling for navigation links
        document.addEventListener('DOMContentLoaded', function() {
            const navLinks = document.querySelectorAll('.nav-link');
            const sections = document.querySelectorAll('.section, .header');
            
            // Smooth scroll on link click
            navLinks.forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    const targetId = this.getAttribute('href');
                    const targetSection = document.querySelector(targetId);
                    
                    if (targetSection) {
                        targetSection.scrollIntoView({ 
                            behavior: 'smooth',
                            block: 'start'
                        });
                        
                        // Close sidebar on mobile after clicking
                        if (window.innerWidth <= 768) {
                            document.getElementById('sidebar').classList.remove('open');
                        }
                    }
                });
            });

            // Highlight active section on scroll
            function highlightActiveSection() {
                let current = '';
                
                sections.forEach(section => {
                    const sectionTop = section.offsetTop;
                    const sectionHeight = section.clientHeight;
                    
                    if (pageYOffset >= sectionTop - 100) {
                        current = section.getAttribute('id');
                    }
                });

                navLinks.forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === '#' + current) {
                        link.classList.add('active');
                    }
                });
            }

            window.addEventListener('scroll', highlightActiveSection);
            highlightActiveSection(); // Initial call

            // Close sidebar when clicking outside on mobile
            document.addEventListener('click', function(e) {
                const sidebar = document.getElementById('sidebar');
                const toggleButton = document.querySelector('.sidebar-toggle');
                
                if (window.innerWidth <= 768 && 
                    sidebar.classList.contains('open') &&
                    !sidebar.contains(e.target) && 
                    !toggleButton.contains(e.target)) {
                    sidebar.classList.remove('open');
                }
            });

            // Progress bar animation
            const progressBars = document.querySelectorAll('.progress-fill');
            progressBars.forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {
                    bar.style.width = width;
                }, 500);
            });
        });
    </script>
</body>
</html>
```
</wa_html_summary_report>

<html_structure_requirements>
**CRITICAL: Follow AWS-Themed Structure**

The generated HTML report must include:

1. **Sidebar Navigation**: Fixed left sidebar with smooth scrolling navigation
2. **AWS Color Scheme**: Use AWS orange (#FF9900) and squid ink (#232F3E)
3. **Section IDs**: All major sections must have IDs matching navigation links
4. **Responsive Design**: Mobile-friendly with collapsible sidebar
5. **AWS-Style Shadows**: Use the multi-layer shadow pattern for cards
6. **Amazon Ember Font**: Primary font family for all text
7. **Custom Scrollbars**: AWS-themed scrollbars for sidebar and main content
8. **Section Markers**: HTML comments for unambiguous section identification

**Navigation Links Required**:
- Overview (#overview)
- Screener Analysis (#screener-analysis)
- 6 Pillars Analysis (#pillar-analysis)
- Priority Recommendations (#priorities)
- Implementation Roadmap (#roadmap)
- Cost Impact Analysis (#cost-analysis)
- Conclusion (#conclusion)
</html_structure_requirements>


## Your Instructions - AWS Service Screener Well-Architected Framework Analysis

You are a cloud architecture expert and AWS Well-Architected Framework specialist. Your task is to analyze AWS Service Screener output data located at `{SERVICE_SCREENER_DIR}` and generate a comprehensive Well-Architected Framework analysis report as per the HTML format provided in the <wa_html_summary_report> section.

### Service Screener Data Structure

The AWS Service Screener data is organized as provided in the example within the <service_screener_results_tree> section above.

### Navigating and retrieving information from the AWS Service Screener output directory

Before and while generating the HTML report, follow the methods and recommendations for retrieving AWS Service Screener data as described within the <navigating_service_screener_data> section above.

### Analysis Requirements

1. **Analyze the Service Screener data** as described within the <navigating_service_screener_data> section above to identify security issues, performance optimization opportunities, and other findings across all six Well-Architected Framework pillars.

2. **Focus on the TOP 5 services with the most findings**, prioritized by severity (High, then Medium, then Low). Always include IAM findings regardless of their ranking. Used the methods as described within the <navigating_service_screener_data> section above to pull this information effectively.

3. **Extract Well-Architected Framework pillar information** from the `CPFindings.html` file by filtering for the "Type" column, which maps to the six pillars. Use the methods as described within the <navigating_service_screener_data> section above to pull this information effectively.

4. **DO NOT try to fetch information from the files**: `/<account_id>/workItem.xlsx`, `/<account_id>/all.csv`, `/<account_id>/api-full.json` and `/<account_id>/api-raw.json`, or from any file within the `/<account_id>/res/`.

5. **Assess and recommend a database modernization path to MongoDB with its benefits** based on the guidance provided in `/workshop/wa-ss-summarizer/references/migration-mongodb-atlas.md`, `/workshop/wa-ss-summarizer/references/modernization-phased-approach.md`, and findings identified in `/<account_id>/rds.html` and `/<account_id>/dynamodb.html`. This should outline data strategies using `MongoDB` as a vector database for `generative AI applications`, along with `a high-level overview of migration plans to MongoDB`.

6. **Assess and recommend an application modernization path to Amazon Elastic Container Service(ECS) including guidance on how to containerize applications currently running on Amazon EC2** based on the guidance provided in `/workshop/wa-ss-summarizer/references/ecs-bestpracticesguide.md`, `/workshop/wa-ss-summarizer/references/strategy-modernizing-applications.md`, `/workshop/wa-ss-summarizer/references/modernization-phased-approach.md`, and findings identified in `/<account_id>/ec2.html`.

7. **Assess and recommend Elastic Kubernetes Service (Amazon EKS) best practices** based on the guidance provided in `/workshop/wa-ss-summarizer/references/eks-bpg.md` and findings identified in `/<account_id>/eks.html`.


### Generate HTML Report

Based on the information you have extracted from the TOP-5 services, generate an HTML report following the guidelines below without creating or executing separate scripts (As reference, within the square brackets in each step below, you have the different section headers from the provided <wa_html_summary_report> example): 

1) ["AWS Service Screener Well-Architected Framework Analysis Report", "Service Screener Issues Found", "Security Issues Status"] Service Screener Summary Dashboard (Overall assessment and Security Issues Status score with Critical/High/Medium/Low findings count breakdown and SPIP compliance status overview).

2) ["Well-Architected Framework 6 Pillars Analysis"] Well-Architected Framework Analysis based on Service Screener findings - Operational Excellence Assessment (Monitoring and logging findings, Automation opportunities, Change management recommendations, Performance monitoring gaps), Security Assessment (Identity and access findings, Data protection recommendations, Network security gaps, Incident response improvements), Reliability Assessment (Fault tolerance findings, Backup and recovery gaps, Monitoring and alerting recommendations, Capacity planning improvements), Performance Efficiency Assessment (Resource optimization opportunities, Scaling recommendations, Technology modernization suggestions, Performance monitoring enhancements), Cost Optimization Assessment (Cost reduction opportunities, Resource rightsizing recommendations, Reserved instance optimization, Unused resource identification), Sustainability Assessment (Resource efficiency improvements, Carbon footprint reduction opportunities, Sustainable architecture patterns, Green computing recommendations)

3) ["Service Screener Results Analysis"] Detailed Findings Analysis (Service-specific recommendations with priority levels, Resource-specific improvement opportunities, Configuration optimization suggestions, Best practices alignment gaps)

4) ["Priority-based Improvement Recommendations"] Risk Assessment and Prioritization. Prioritize recommendations based on business impact and implementation complexity (High-impact findings requiring immediate attention, Medium-priority improvements for planning, Low-priority enhancements for future consideration, Business risk assessment and mitigation strategies). Provide actionable improvement steps with AWS CLI commands.

5) ["Implementation Roadmap"] Implementation Roadmap (Immediate actions 0-30 days with specific steps, Short-term improvements 1-6 months with timelines, Long-term strategic initiatives 6-24 months with milestones, Resource requirements and budget considerations)

6) ["Database and Application Modernization Pathway"] You are a cloud modernization expert and AWS Solutions Architect. Create a comprehensive modernization roadmap for database modernization with `MongoDB`, serverless and container-based transformation by analyzing actual AWS resources currently operating in the {REGION} region. Provide practical modernization strategies with specific resource IDs, current architecture, and actual cost data based on real AWS resource information, not hypothetical scenarios. Generate an English HTML report following the guidelines below without creating or executing separate scripts: 1) Modernization Summary Dashboard (Current vs Target Architecture Comparison, Number of serverless/container transformation candidates, Expected cost savings, TCO analysis, Modernization readiness score) 2) Generate current Architecture Diagram (`Mermaid` diagram showing overall system architecture, Service interactions and data flows, External integrations and dependencies, User access patterns, Multi-AZ and region setup). Network-Level Architecture (VPC and subnet configurations with actual CIDR blocks, Security groups and NACLs with specific rules, Load balancers and routing configurations, Internet gateways and NAT configurations, VPC peering and transit gateway connections). Service-Level Architecture (Detailed service configurations with resource IDs, Database relationships and connections, Storage configurations and access patterns, Compute resources and scaling configurations, Serverless functions and triggers) 3)TO-BE Architecture Proposal if it's modernized with MongoDB and ECS (Mermaid diagrams, Legacy component identification, Modernization target workload classification) 4) Serverless Transformation Analysis (EC2/Service candidates for Lambda transformation, API Gateway adoption opportunities, Serverless database transformation possibilities, Event-driven architecture design) 5) Containerization Transformation Analysis (ECS transformation candidates, Fargate applicability assessment, Microservices decomposition strategy, CI/CD pipeline modernization) 6) Phased Modernization Roadmap (Phase 1: Quick Wins 0-3 months, Phase 2: Serverless Transformation 3-6 months, Phase 3: Containerization 6-12 months, Phase 4: Complete Modernization 12+ months) 7) Cost-Benefit Analysis (Current vs Post-modernization cost comparison, ROI calculation, Operational cost reduction effects, Development productivity improvement metrics) 8) Implementation Guide (Technology-specific migration methods, Required skill sets, Risk management strategies, Success metrics).Analysis Focus: Analyze actual AWS resources in {REGION} region, Provide specific resource IDs and configurations, Calculate realistic cost savings based on current usage, Suggest practical implementation steps, Consider Seoul region optimization, Include Well-Architected Framework principles, Provide actionable recommendations with AWS CLI commands. Please generate a comprehensive, data-driven modernization roadmap that organizations can immediately implement based on their actual AWS infrastructure. If you encounter a syntax error in the `Mermaid` diagram, please correct it to ensure the architecture is properly visualized.

8) ["Conclusion and Recommendations" and "Appendix"]. Refer to the <wa_html_summary_report> section for example information.

### Example Report Structure and HTML Styling

You can refer to a full example, including HTML CSS styling within the <wa_html_summary_report> section provided above.

Use the following CSS styling for the report:

### Important Notes

1. The report should be visually appealing and easy to navigate.
2. Use color coding to highlight severity (red for high, yellow for medium, blue for low).
3. Include progress bars and visual elements to enhance readability.
4. Organize information in a logical, hierarchical structure.
5. Make the report responsive and readable on different devices.
6. Provide realistic cost estimates and timelines.

Analyze the Service Screener data thoroughly and generate a comprehensive Well-Architected Framework analysis HTML report that follows the provided guidelines and instructions. The report should be in HTML format and saved as `wa_summary_report_mod_{YYYYMMDD_HHMMSS}.html` in the current location's `{DEFAULT_OUTPUT_DIR}` folder (Timezone: UTC).

# WAFv2 Service Build Spec

Project: /Users/kuettai/Documents/project/ss-genai/service-screener-v2

Build the WAFv2 service. Create ONLY files inside `services/wafv2/` — do NOT modify any shared files (ArguParser, frameworks, info.json).

## Step 1: Research the API

- aws wafv2 list-web-acls --scope REGIONAL --region us-east-1
- aws wafv2 get-web-acl (if any exist) to see response fields
- aws wafv2 get-logging-configuration --resource-arn <acl-arn>

## Step 2: Define checks (10-12)

Focus areas:
- Security: No rules (empty ACL), no managed rule groups, no rate-based rules, rules in COUNT mode (not BLOCK)
- Operational: Logging not configured, CloudWatch metrics disabled (VisibilityConfig), sampled requests disabled
- Cost: WebACL not associated with any resource (unused)
- Reliability: Default action is ALLOW without rules (pass-through WAF)

## Step 3: Create files

1. `services/wafv2/wafv2.reporter.json` — all check definitions (same format as services/bedrock/bedrock.reporter.json)
2. `services/wafv2/Wafv2.py` — main service class. Use `wafv2` boto3 client. List both REGIONAL and CLOUDFRONT scoped WebACLs. For each: get_web_acl, get_logging_configuration, list_resources_for_web_acl.
3. `services/wafv2/drivers/Wafv2Common.py` — all checks
4. `services/wafv2/simulation/create_test_resources.sh` — create a WebACL with no rules, no logging, COUNT-only rules, etc.
5. `services/wafv2/simulation/cleanup_test_resources.sh`
6. `services/wafv2/simulation/README.md`

## Step 4: Validate

- Verify all reporter keys match _check methods
- python3 -c "import json; json.load(open('services/wafv2/wafv2.reporter.json')); print('OK')"
- python3 -c "import py_compile; py_compile.compile('services/wafv2/Wafv2.py'); py_compile.compile('services/wafv2/drivers/Wafv2Common.py'); print('compiles OK')"

## Step 5: Test

python3 main.py --regions us-east-1 --services wafv2 --beta 1 --sequential 1

## Step 6: Simulate

Run create_test_resources.sh, wait 30s, scan, verify FAILs, cleanup.

Report: check list, coverage percentage, any issues.

IMPORTANT: Do NOT modify utils/ArguParser.py, frameworks/*, info.json, or any file outside services/wafv2/

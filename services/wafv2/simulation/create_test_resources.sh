#!/bin/bash

################################################################################
# WAFv2 Service Screener - Test Resource Creation Script
#
# Creates ONE intentionally-insecure REGIONAL WebACL that triggers most of the
# 12 wafv2* checks:
#   - 0 rules                             (#1 wafv2NoRules)
#   - No managed rule groups              (#2 wafv2NoManagedRuleGroups — trivially fails via #1)
#   - No rate-based rule                  (#3 wafv2NoRateBasedRules — trivially fails via #1)
#   - No rules in COUNT (n/a — #4 PASSES) : the pass-through is proved by #5
#   - DefaultAction=Allow + no blockers   (#5 wafv2DefaultActionAllow)
#   - No logging configuration            (#6 wafv2LoggingNotConfigured)
#   - CW metrics off at ACL level         (#8 wafv2CloudWatchMetricsDisabled)
#   - Sampled requests off at ACL level   (#9 wafv2SampledRequestsDisabled)
#   - Not associated with any resource    (#11 wafv2NotAssociated)
#   - No tags                             (#12 wafv2ResourcesWithoutTags)
#
# Not directly forced (documented in README):
#   #4  wafv2RulesInCountMode   — needs a rule; adding one contradicts #1
#   #7  wafv2LoggingFilterAllDrop — needs logging on (contradicts #6)
#   #10 wafv2RuleVisibilityDisabled — needs a rule (contradicts #1)
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --help)   grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)        echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

ACL_NAME="${PREFIX}-wafv2-acl-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== WAFv2 Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}A REGIONAL WebACL with no rules, no logging, no metrics, no tags,${NC}"
echo -e "${YELLOW}not associated with anything. Base cost while it exists: ~\$5/month.${NC}"
echo ""

################################################################################
# Step 1: Create REGIONAL WebACL with:
#   - DefaultAction=Allow
#   - No rules
#   - VisibilityConfig: CloudWatchMetricsEnabled=false, SampledRequestsEnabled=false
#   - No tags
################################################################################

echo -e "${GREEN}=== Step 1: Create insecure REGIONAL WebACL ===${NC}"

CREATE_JSON=$(aws wafv2 create-web-acl \
    --name "$ACL_NAME" \
    --scope REGIONAL \
    --default-action '{"Allow":{}}' \
    --rules '[]' \
    --visibility-config "SampledRequestsEnabled=false,CloudWatchMetricsEnabled=false,MetricName=${ACL_NAME}" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ WebACL create failed${NC}"
        echo "$CREATE_JSON" | head -5
        exit 1;
    }

ACL_ID=$(echo "$CREATE_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
ACL_ARN=$(echo "$CREATE_JSON" | grep -o '"ARN": *"[^"]*"' | head -1 | sed 's/.*"ARN": *"\([^"]*\)".*/\1/')

if [ -z "${ACL_ID:-}" ] || [ -z "${ACL_ARN:-}" ]; then
    echo -e "${RED}✗ Could not parse WebACL Id/ARN from CreateWebACL response${NC}"
    echo "$CREATE_JSON" | head -20
    exit 1
fi

log "WEBACL:${ACL_NAME}|${ACL_ID}|${ACL_ARN}"
echo -e "${GREEN}✓ WebACL created${NC}"
echo "  Name: ${ACL_NAME}"
echo "  Id:   ${ACL_ID}"
echo "  ARN:  ${ACL_ARN}"

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}=== Resources Created ===${NC}"
echo -e "${GREEN}=========================================${NC}"
cat "$OUTPUT_FILE" | sed 's/^/  /'
echo ""
echo "Next:"
echo "  1. cd ../../.. && python3 main.py --regions $REGION --services wafv2 --beta 1 --sequential 1"
echo "  2. cd services/wafv2/simulation && ./cleanup_test_resources.sh"

#!/bin/bash

################################################################################
# WAFv2 Service Screener - Test Resource Creation Script (Phase 1 + Phase 2)
#
# Creates a suite of intentionally-misconfigured WAFv2 resources that trigger
# both the original 12 checks and the Phase 2 additions (25-41).
#
# Resources created (all prefixed ss-test-):
#   1. CloudWatch Log Group        aws-waf-logs-ss-test-*
#   2. Empty IPSet                 ss-test-ipset-empty-*
#   3. Empty Regex Pattern Set     ss-test-regex-empty-*
#   4. Empty custom Rule Group     ss-test-rulegroup-empty-*
#   5. WebACL "insecure"           ss-test-wafv2-acl-* (no rules, DefaultAction=Allow)
#   6. WebACL "partial"            ss-test-wafv2-acl-partial-* (managed rule group
#                                   with >50% overrides, references empty ipset/
#                                   regex/rule-group, logging w/o RedactedFields)
#   7. AppSync GraphQL API         ss-test-appsync-nowaf-*
#
# Coverage of the 17 new Phase 2 checks:
#   25. wafv2NoAccountTakeoverPrevention       — partial ACL has managed group,
#                                                 no ATP (skipped when unassociated;
#                                                 both test ACLs are unassociated
#                                                 → check will report INFO — see
#                                                 README workaround)
#   26. wafv2NoAccountCreationFraudPrevention  — same INFO-when-unassociated caveat
#   27. wafv2PaidRuleGroupWithoutScopeDown     — not triggered (paid groups skipped)
#   28. wafv2ManagedRuleGroupExcludedRulesExcessive — partial ACL overrides 8 of ~15
#                                                     CommonRuleSet rules to Count
#   29. wafv2NoKnownBadInputsRuleSet            — partial ACL has CRS only, no KBI
#   30. wafv2NoAnonymousIpList                  — partial ACL has CRS only, no AIL
#   31. wafv2RulePriorityOrdering               — not triggered (paid deps)
#   32. wafv2IpSetEmpty                         — partial ACL references empty IPSet
#   33. wafv2RegexPatternSetEmpty               — partial ACL references empty regex
#   34. wafv2RuleGroupEmpty                     — partial ACL references empty rg
#   35. wafv2LoggingMissingRedactedFields       — partial ACL logging on, no redact
#   36. wafv2ManagedRuleGroupVersionExpiring    — not simulated (depends on AWS
#                                                 version schedule)
#   37. wafv2AlbWithoutWebAcl                   — NOT SIMULATED (ALB costs $16/mo).
#                                                 Documented in README as manual.
#   38. wafv2ApiGatewayWithoutWebAcl            — typically fires naturally against
#                                                 existing account resources
#   39. wafv2CloudFrontWithoutWebAcl            — same, natural state
#   40. wafv2AppSyncWithoutWebAcl               — triggered by created AppSync API
#   41. wafv2CognitoUserPoolWithoutWebAcl       — natural state / existing pools
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--skip-appsync] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SKIP_APPSYNC=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region)        REGION="$2"; shift 2 ;;
        --skip-appsync)  SKIP_APPSYNC=true; shift ;;
        --help)          grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)               echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

ACL_INSECURE_NAME="${PREFIX}-wafv2-acl-${TIMESTAMP}"
ACL_PARTIAL_NAME="${PREFIX}-wafv2-acl-partial-${TIMESTAMP}"
LOG_GROUP_NAME="aws-waf-logs-${PREFIX}-${TIMESTAMP}"
IPSET_NAME="${PREFIX}-ipset-empty-${TIMESTAMP}"
REGEX_NAME="${PREFIX}-regex-empty-${TIMESTAMP}"
RG_NAME="${PREFIX}-rulegroup-empty-${TIMESTAMP}"
APPSYNC_NAME="${PREFIX}-appsync-nowaf-${TIMESTAMP}"

OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"
log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== WAFv2 Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}Two WebACLs (~\$10/mo base while alive) + CW log group + AppSync API${NC}"
echo -e "${YELLOW}(free until used). Clean up promptly.${NC}"
echo ""

################################################################################
# Step 1: Insecure WebACL (original — checks 1, 5, 6, 8, 9, 11, 12)
################################################################################

echo -e "${GREEN}=== Step 1: Insecure REGIONAL WebACL (no rules) ===${NC}"

CREATE_JSON=$(aws wafv2 create-web-acl \
    --name "$ACL_INSECURE_NAME" \
    --scope REGIONAL \
    --default-action '{"Allow":{}}' \
    --rules '[]' \
    --visibility-config "SampledRequestsEnabled=false,CloudWatchMetricsEnabled=false,MetricName=${ACL_INSECURE_NAME}" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Insecure WebACL create failed${NC}"
        echo "$CREATE_JSON" | head -5
        exit 1
    }

ACL1_ID=$(echo "$CREATE_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
ACL1_ARN=$(echo "$CREATE_JSON" | grep -o '"ARN": *"[^"]*"' | head -1 | sed 's/.*"ARN": *"\([^"]*\)".*/\1/')
log "WEBACL:${ACL_INSECURE_NAME}|${ACL1_ID}|${ACL1_ARN}"
echo -e "${GREEN}✓ Insecure WebACL: ${ACL_INSECURE_NAME}${NC}"

################################################################################
# Step 2: CloudWatch Log Group for WAF logging destination
################################################################################

echo -e "\n${GREEN}=== Step 2: CloudWatch Log Group ===${NC}"

aws logs create-log-group \
    --log-group-name "$LOG_GROUP_NAME" \
    --region "$REGION" > /dev/null 2>&1 \
    && { log "LOGGROUP:${LOG_GROUP_NAME}"; echo -e "${GREEN}✓ Log group: ${LOG_GROUP_NAME}${NC}"; } \
    || echo -e "${YELLOW}⚠ Log group creation failed (may already exist)${NC}"

# Resolve the log group ARN for the PutLoggingConfiguration call later
LOG_GROUP_ARN=$(aws logs describe-log-groups \
    --log-group-name-prefix "$LOG_GROUP_NAME" \
    --region "$REGION" \
    --query "logGroups[?logGroupName=='${LOG_GROUP_NAME}'].arn | [0]" \
    --output text 2>/dev/null | sed 's/:\*$//')

################################################################################
# Step 3: Empty IPSet (referenced by partial WebACL to trigger #32)
################################################################################

echo -e "\n${GREEN}=== Step 3: Empty IPSet ===${NC}"

IPSET_JSON=$(aws wafv2 create-ip-set \
    --name "$IPSET_NAME" \
    --scope REGIONAL \
    --ip-address-version IPV4 \
    --addresses '[]' \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ IPSet create failed${NC}"
        echo "$IPSET_JSON" | head -5
    }
IPSET_ID=$(echo "$IPSET_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
IPSET_ARN=$(echo "$IPSET_JSON" | grep -o '"ARN": *"[^"]*"' | head -1 | sed 's/.*"ARN": *"\([^"]*\)".*/\1/')
if [ -n "${IPSET_ID:-}" ] && [ -n "${IPSET_ARN:-}" ]; then
    log "IPSET:${IPSET_NAME}|${IPSET_ID}|${IPSET_ARN}|REGIONAL"
    echo -e "${GREEN}✓ Empty IPSet: ${IPSET_NAME}${NC}"
fi

################################################################################
# Step 4: Empty Regex Pattern Set (triggers #33)
################################################################################

echo -e "\n${GREEN}=== Step 4: Empty Regex Pattern Set ===${NC}"

# WAFv2 requires at least one entry in RegularExpressionList at create time,
# but we can attempt with the actual minimum viable set which the check will
# still see as "empty patterns" after we describe it, so try both approaches.
REGEX_JSON=$(aws wafv2 create-regex-pattern-set \
    --name "$REGEX_NAME" \
    --scope REGIONAL \
    --regular-expression-list 'RegexString=' \
    --region "$REGION" \
    --output json 2>&1) || {
        # Fallback: try empty list explicitly
        REGEX_JSON=$(aws wafv2 create-regex-pattern-set \
            --name "$REGEX_NAME" \
            --scope REGIONAL \
            --regular-expression-list '[]' \
            --region "$REGION" \
            --output json 2>&1) || {
                echo -e "${YELLOW}⚠ Empty Regex Pattern Set creation rejected (WAFv2 API validation)${NC}"
                echo "$REGEX_JSON" | head -3
                REGEX_JSON=""
        }
    }
REGEX_ID=$(echo "$REGEX_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
REGEX_ARN=$(echo "$REGEX_JSON" | grep -o '"ARN": *"[^"]*"' | head -1 | sed 's/.*"ARN": *"\([^"]*\)".*/\1/')
if [ -n "${REGEX_ID:-}" ] && [ -n "${REGEX_ARN:-}" ]; then
    log "REGEXSET:${REGEX_NAME}|${REGEX_ID}|${REGEX_ARN}|REGIONAL"
    echo -e "${GREEN}✓ Regex Pattern Set: ${REGEX_NAME}${NC}"
fi

################################################################################
# Step 5: Empty custom Rule Group (triggers #34)
################################################################################

echo -e "\n${GREEN}=== Step 5: Empty custom Rule Group ===${NC}"

RG_JSON=$(aws wafv2 create-rule-group \
    --name "$RG_NAME" \
    --scope REGIONAL \
    --capacity 2 \
    --rules '[]' \
    --visibility-config "SampledRequestsEnabled=false,CloudWatchMetricsEnabled=false,MetricName=${RG_NAME}" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${YELLOW}⚠ Empty rule group rejected — creating with one dummy rule then emptying is tricky. Skipping.${NC}"
        echo "$RG_JSON" | head -3
        RG_JSON=""
    }
RG_ID=$(echo "$RG_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
RG_ARN=$(echo "$RG_JSON" | grep -o '"ARN": *"[^"]*"' | head -1 | sed 's/.*"ARN": *"\([^"]*\)".*/\1/')
if [ -n "${RG_ID:-}" ] && [ -n "${RG_ARN:-}" ]; then
    log "RULEGROUP:${RG_NAME}|${RG_ID}|${RG_ARN}|REGIONAL"
    echo -e "${GREEN}✓ Empty Rule Group: ${RG_NAME}${NC}"
fi

################################################################################
# Step 6: Partial WebACL — managed CRS with >50% overrides + references to
#         the empty ipset/regex/rule-group we created above.
################################################################################

echo -e "\n${GREEN}=== Step 6: 'Partial' WebACL with managed group + empty refs ===${NC}"

# Build rules JSON dynamically based on which supporting resources succeeded.
PARTIAL_RULES=$(cat <<EOF
[
  {
    "Name": "CommonRuleSetPartial",
    "Priority": 10,
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesCommonRuleSet",
        "RuleActionOverrides": [
          {"Name": "NoUserAgent_HEADER",             "ActionToUse": {"Count": {}}},
          {"Name": "UserAgent_BadBots_HEADER",       "ActionToUse": {"Count": {}}},
          {"Name": "SizeRestrictions_QUERYSTRING",   "ActionToUse": {"Count": {}}},
          {"Name": "SizeRestrictions_Cookie_HEADER", "ActionToUse": {"Count": {}}},
          {"Name": "SizeRestrictions_BODY",          "ActionToUse": {"Count": {}}},
          {"Name": "SizeRestrictions_URIPATH",       "ActionToUse": {"Count": {}}},
          {"Name": "EC2MetaDataSSRF_BODY",           "ActionToUse": {"Count": {}}},
          {"Name": "EC2MetaDataSSRF_URIPATH",        "ActionToUse": {"Count": {}}},
          {"Name": "EC2MetaDataSSRF_QUERYARGUMENTS", "ActionToUse": {"Count": {}}}
        ]
      }
    },
    "OverrideAction": {"None": {}},
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "CommonRuleSetPartial"
    }
  }
EOF
)

if [ -n "${IPSET_ARN:-}" ]; then
    PARTIAL_RULES+=",
  {
    \"Name\": \"BlockFromEmptyIPSet\",
    \"Priority\": 20,
    \"Statement\": {\"IPSetReferenceStatement\": {\"ARN\": \"${IPSET_ARN}\"}},
    \"Action\": {\"Block\": {}},
    \"VisibilityConfig\": {
      \"SampledRequestsEnabled\": true,
      \"CloudWatchMetricsEnabled\": true,
      \"MetricName\": \"BlockFromEmptyIPSet\"
    }
  }"
fi

if [ -n "${REGEX_ARN:-}" ]; then
    PARTIAL_RULES+=",
  {
    \"Name\": \"BlockFromEmptyRegex\",
    \"Priority\": 30,
    \"Statement\": {
      \"RegexPatternSetReferenceStatement\": {
        \"ARN\": \"${REGEX_ARN}\",
        \"FieldToMatch\": {\"UriPath\": {}},
        \"TextTransformations\": [{\"Priority\": 0, \"Type\": \"NONE\"}]
      }
    },
    \"Action\": {\"Block\": {}},
    \"VisibilityConfig\": {
      \"SampledRequestsEnabled\": true,
      \"CloudWatchMetricsEnabled\": true,
      \"MetricName\": \"BlockFromEmptyRegex\"
    }
  }"
fi

if [ -n "${RG_ARN:-}" ]; then
    PARTIAL_RULES+=",
  {
    \"Name\": \"EmptyRuleGroupRef\",
    \"Priority\": 40,
    \"Statement\": {\"RuleGroupReferenceStatement\": {\"ARN\": \"${RG_ARN}\"}},
    \"OverrideAction\": {\"None\": {}},
    \"VisibilityConfig\": {
      \"SampledRequestsEnabled\": true,
      \"CloudWatchMetricsEnabled\": true,
      \"MetricName\": \"EmptyRuleGroupRef\"
    }
  }"
fi

PARTIAL_RULES+="
]"

echo "$PARTIAL_RULES" > /tmp/${PREFIX}-partial-rules.json

CREATE_JSON=$(aws wafv2 create-web-acl \
    --name "$ACL_PARTIAL_NAME" \
    --scope REGIONAL \
    --default-action '{"Allow":{}}' \
    --rules "file:///tmp/${PREFIX}-partial-rules.json" \
    --visibility-config "SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${ACL_PARTIAL_NAME}" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${YELLOW}⚠ Partial WebACL create failed${NC}"
        echo "$CREATE_JSON" | head -8
        CREATE_JSON=""
    }

ACL2_ID=$(echo "$CREATE_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
ACL2_ARN=$(echo "$CREATE_JSON" | grep -o '"ARN": *"[^"]*"' | head -1 | sed 's/.*"ARN": *"\([^"]*\)".*/\1/')
if [ -n "${ACL2_ID:-}" ] && [ -n "${ACL2_ARN:-}" ]; then
    log "WEBACL:${ACL_PARTIAL_NAME}|${ACL2_ID}|${ACL2_ARN}"
    echo -e "${GREEN}✓ Partial WebACL: ${ACL_PARTIAL_NAME}${NC}"

    # Attach logging config WITHOUT RedactedFields — triggers #35
    if [ -n "${LOG_GROUP_ARN:-}" ]; then
        LOG_CFG=$(cat <<JSON
{
  "ResourceArn": "${ACL2_ARN}",
  "LogDestinationConfigs": ["${LOG_GROUP_ARN}"]
}
JSON
)
        echo "$LOG_CFG" > /tmp/${PREFIX}-log-cfg.json
        aws wafv2 put-logging-configuration \
            --logging-configuration file:///tmp/${PREFIX}-log-cfg.json \
            --region "$REGION" > /dev/null 2>&1 \
            && { log "LOGCFG:${ACL2_ARN}"; echo -e "${GREEN}✓ Logging attached (no RedactedFields)${NC}"; } \
            || echo -e "${YELLOW}⚠ Logging attachment failed (log group ARN or permissions issue)${NC}"
        rm -f /tmp/${PREFIX}-log-cfg.json
    fi
fi
rm -f /tmp/${PREFIX}-partial-rules.json

################################################################################
# Step 7: AppSync GraphQL API without WAF association (triggers #40)
################################################################################

if [ "$SKIP_APPSYNC" = false ]; then
    echo -e "\n${GREEN}=== Step 7: AppSync GraphQL API (no WAF) ===${NC}"
    AS_JSON=$(aws appsync create-graphql-api \
        --name "$APPSYNC_NAME" \
        --authentication-type API_KEY \
        --region "$REGION" \
        --output json 2>&1) || {
            echo -e "${YELLOW}⚠ AppSync API creation failed (service may not be available)${NC}"
            echo "$AS_JSON" | head -3
            AS_JSON=""
        }
    AS_API_ID=$(echo "$AS_JSON" | grep -o '"apiId": *"[^"]*"' | head -1 | sed 's/.*"apiId": *"\([^"]*\)".*/\1/')
    AS_ARN=$(echo "$AS_JSON" | grep -o '"arn": *"[^"]*"' | head -1 | sed 's/.*"arn": *"\([^"]*\)".*/\1/')
    if [ -n "${AS_API_ID:-}" ] && [ -n "${AS_ARN:-}" ]; then
        log "APPSYNC:${AS_API_ID}|${AS_ARN}"
        echo -e "${GREEN}✓ AppSync API: ${APPSYNC_NAME}${NC}"
    fi
else
    echo -e "\n${YELLOW}=== Step 7: AppSync skipped (--skip-appsync) ===${NC}"
fi

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
echo ""
echo -e "${YELLOW}Cost while active: ~\$10/month base (2 WebACLs) + tiny CW logs storage.${NC}"

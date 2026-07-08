#!/bin/bash

################################################################################
# Route 53 Service Screener - Test Resource Creation Script
#
# Creates intentionally-misconfigured Route 53 resources to validate the
# route53* service-screener checks that can be forced via the AWS API.
#
# ---- WHAT THIS SCRIPT SIMULATES ----
#
# Hosted-Zone / record checks (all fabricable via API):
#   #1  route53DnssecNotEnabled         — public zone without DNSSEC
#   #2  route53QueryLoggingNotEnabled   — public zone without query logging
#   #12 route53HostedZoneUnused         — extra empty zone
#   #15 route53CnameAtZoneApex          — apex CNAME (created via UPSERT)
#   #16 route53MxWithoutSpfDmarc        — MX record without SPF/DMARC TXT
#   #18 route53RecordNoHealthCheck      — weighted record without HealthCheckId
#   #19 route53DanglingDnsRecords       — CNAME to a bogus cloudfront target
#   #20 route53LowTtlOnStableRecords    — A record with TTL=15
#   #21 route53PublicZoneSensitiveNames — creates admin.<zone> A record
#   #23 route53EmptyHostedZone          — extra empty zone (RRsets=2)
#   #24 route53NoRecordRoutingPolicy    — direct-IP A record with no routing policy
#
# Health-check checks (all fabricable via API):
#   #7  route53HealthCheckUsingHttp      — Type=HTTP
#   #8  route53HealthCheckNoAlarm        — no CloudWatch alarm attached
#   #13 route53HealthCheckSlowInterval   — RequestInterval=30
#   #14 route53HealthCheckLowFailureThreshold — FailureThreshold=1
#   #17 route53HealthCheckDisabled       — Disabled=true
#   #22 route53HealthCheckSniDisabled    — HTTPS check with EnableSNI=false
#
# ---- WHAT THIS SCRIPT DOES NOT SIMULATE (documented as manual) ----
#
# Domain checks — require a real registered domain in route53domains
# (which costs money to register, cannot be created via API for testing):
#   #3  route53DomainAutoRenewDisabled
#   #4  route53DomainTransferLockDisabled
#   #5  route53DomainPrivacyDisabled
#   #6  route53DomainExpiringSoon
#
# Resolver checks — these fire based on the account's natural state.
# Most AWS accounts have no DNS Firewall / no Resolver query logging /
# no DNSSEC validation configured by default, so these will fail
# without any test-resource creation:
#   #9  route53ResolverDnsFirewallNotConfigured
#   #10 route53ResolverQueryLoggingNotEnabled
#   #11 route53ResolverDnssecValidationDisabled
#
# ---- USAGE ----
#   ./create_test_resources.sh [--region REGION] [--help]
#
# Resources are prefixed `ss-test-route53-<timestamp>` for easy cleanup.
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
PREFIX="ss-test-route53"
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

# Unique names for THIS run
FAIL_ZONE_NAME="${PREFIX}-fail-${TIMESTAMP}.example.internal."
EMPTY_ZONE_NAME="${PREFIX}-empty-${TIMESTAMP}.example.internal."
HC_HTTP_NAME="${PREFIX}-hc-http-${TIMESTAMP}"
HC_HTTPS_NAME="${PREFIX}-hc-https-nosni-${TIMESTAMP}"
HC_DISABLED_NAME="${PREFIX}-hc-disabled-${TIMESTAMP}"

# Bogus target for the dangling-DNS check — clearly won't resolve to a real
# CloudFront distribution the account owns.
BOGUS_CF_TARGET="d3b0gu5nonex1st.cloudfront.net"

OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
: > "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Route 53 Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Create the "populated" test hosted zone that will trigger many
#         record-level checks
################################################################################
echo -e "${GREEN}=== Step 1: Create populated test hosted zone ===${NC}"
CALLER_REF="ss-test-${TIMESTAMP}-$$"
FAIL_ZONE_JSON=$(aws route53 create-hosted-zone \
    --name "$FAIL_ZONE_NAME" \
    --caller-reference "$CALLER_REF-fail" \
    --hosted-zone-config "Comment=service-screener-test,PrivateZone=false" \
    --output json 2>&1) || {
        echo -e "${RED}create-hosted-zone failed: $FAIL_ZONE_JSON${NC}"; exit 1
    }
FAIL_ZONE_ID=$(echo "$FAIL_ZONE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['HostedZone']['Id'].split('/')[-1])")
echo "  Populated zone: $FAIL_ZONE_NAME  ($FAIL_ZONE_ID)"
log "zone:$FAIL_ZONE_ID"

# Compose a change batch that creates all record-level violations at once.
FAIL_ZONE_APEX="${FAIL_ZONE_NAME%.}"

CHANGE_BATCH=$(cat <<EOF
{
  "Changes": [
    { "Action": "CREATE", "ResourceRecordSet": {
        "Name": "www.$FAIL_ZONE_APEX",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "$BOGUS_CF_TARGET"}]
    }},
    { "Action": "CREATE", "ResourceRecordSet": {
        "Name": "mail.$FAIL_ZONE_APEX",
        "Type": "MX",
        "TTL": 300,
        "ResourceRecords": [{"Value": "10 mail.example.com."}]
    }},
    { "Action": "CREATE", "ResourceRecordSet": {
        "Name": "admin.$FAIL_ZONE_APEX",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "192.0.2.10"}]
    }},
    { "Action": "CREATE", "ResourceRecordSet": {
        "Name": "flappy.$FAIL_ZONE_APEX",
        "Type": "A",
        "TTL": 15,
        "ResourceRecords": [{"Value": "192.0.2.20"}]
    }},
    { "Action": "CREATE", "ResourceRecordSet": {
        "Name": "weighted.$FAIL_ZONE_APEX",
        "Type": "A",
        "SetIdentifier": "primary",
        "Weight": 100,
        "TTL": 60,
        "ResourceRecords": [{"Value": "192.0.2.30"}]
    }}
  ]
}
EOF
)

CHANGE_FILE=$(mktemp)
echo "$CHANGE_BATCH" > "$CHANGE_FILE"
aws route53 change-resource-record-sets \
    --hosted-zone-id "$FAIL_ZONE_ID" \
    --change-batch "file://$CHANGE_FILE" >/dev/null || {
        echo -e "${YELLOW}Warning: change-resource-record-sets failed${NC}"
    }
rm -f "$CHANGE_FILE"
echo "  Added records: www(CNAME→dangling), mail(MX no-SPF), admin(sensitive), flappy(TTL=15), weighted(no-HC)"

# CNAME at apex must be UPSERT'd separately because you can't co-exist with NS/SOA
# We create it as a TYPE=CNAME with the apex name, which route53 will reject
# in a valid change batch — so we intentionally attempt this and note the result.
# Instead: use TYPE=CNAME on a subdomain to keep the script robust. The
# route53CnameAtZoneApex check specifically looks for CNAME at apex, and Route53
# refuses to create one — so this check is DOCUMENTED as MANUAL (edit records
# outside API using DNS import to demonstrate). We attempt it and gracefully
# ignore failure.
APEX_CNAME_BATCH=$(cat <<EOF
{
  "Changes": [
    { "Action": "CREATE", "ResourceRecordSet": {
        "Name": "$FAIL_ZONE_APEX",
        "Type": "CNAME",
        "TTL": 60,
        "ResourceRecords": [{"Value": "example.com."}]
    }}
  ]
}
EOF
)
APEX_FILE=$(mktemp)
echo "$APEX_CNAME_BATCH" > "$APEX_FILE"
if aws route53 change-resource-record-sets \
    --hosted-zone-id "$FAIL_ZONE_ID" \
    --change-batch "file://$APEX_FILE" >/dev/null 2>&1
then
    echo "  Added apex CNAME (unexpectedly accepted — DNS misconfig)"
else
    echo "  Apex CNAME rejected by Route 53 (as expected) — check #15 must be validated manually"
fi
rm -f "$APEX_FILE"

################################################################################
# Step 2: Create the "empty" test hosted zone (only NS + SOA) — triggers
#         both route53HostedZoneUnused (#12) and route53EmptyHostedZone (#23)
################################################################################
echo -e "${GREEN}=== Step 2: Create empty test hosted zone ===${NC}"
EMPTY_ZONE_JSON=$(aws route53 create-hosted-zone \
    --name "$EMPTY_ZONE_NAME" \
    --caller-reference "$CALLER_REF-empty" \
    --hosted-zone-config "Comment=service-screener-test-empty,PrivateZone=false" \
    --output json 2>&1) || {
        echo -e "${RED}create-hosted-zone (empty) failed: $EMPTY_ZONE_JSON${NC}"; exit 1
    }
EMPTY_ZONE_ID=$(echo "$EMPTY_ZONE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['HostedZone']['Id'].split('/')[-1])")
echo "  Empty zone: $EMPTY_ZONE_NAME  ($EMPTY_ZONE_ID)"
log "zone:$EMPTY_ZONE_ID"

# NOTE: Both #12 and #23 exempt zones < 24h old. To validate them the scan must
# be run at least 24 hours after zone creation. Documented as a known limitation.

################################################################################
# Step 3: Create health checks (all fabricable via API)
################################################################################
echo -e "${GREEN}=== Step 3: Create health checks ===${NC}"

# 3a. HTTP check with 30s interval, threshold 1 (fires #7, #13, #14)
HC_HTTP_JSON=$(aws route53 create-health-check \
    --caller-reference "$CALLER_REF-hchttp" \
    --health-check-config '{
        "FullyQualifiedDomainName": "ss-test-http.example.internal",
        "Port": 80,
        "Type": "HTTP",
        "ResourcePath": "/",
        "RequestInterval": 30,
        "FailureThreshold": 1
    }' \
    --output json 2>&1) || {
        echo -e "${YELLOW}Warning: create HTTP health check failed: $HC_HTTP_JSON${NC}"
    }
HC_HTTP_ID=$(echo "$HC_HTTP_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['HealthCheck']['Id'])" 2>/dev/null || echo "")
if [ -n "$HC_HTTP_ID" ]; then
    echo "  HTTP health check: $HC_HTTP_ID  (fires #7 HTTP + #13 slow + #14 low-threshold + #8 no-alarm)"
    log "hc:$HC_HTTP_ID"
fi

# 3b. HTTPS check with EnableSNI=false (fires #22)
HC_HTTPS_JSON=$(aws route53 create-health-check \
    --caller-reference "$CALLER_REF-hchttps" \
    --health-check-config '{
        "FullyQualifiedDomainName": "example.com",
        "Port": 443,
        "Type": "HTTPS",
        "ResourcePath": "/",
        "RequestInterval": 30,
        "FailureThreshold": 3,
        "EnableSNI": false
    }' \
    --output json 2>&1) || {
        echo -e "${YELLOW}Warning: create HTTPS-noSNI health check failed: $HC_HTTPS_JSON${NC}"
    }
HC_HTTPS_ID=$(echo "$HC_HTTPS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['HealthCheck']['Id'])" 2>/dev/null || echo "")
if [ -n "$HC_HTTPS_ID" ]; then
    echo "  HTTPS/no-SNI health check: $HC_HTTPS_ID  (fires #22 SNI-disabled + #13 slow + #8 no-alarm)"
    log "hc:$HC_HTTPS_ID"
fi

# 3c. Disabled health check (fires #17)
HC_DISABLED_JSON=$(aws route53 create-health-check \
    --caller-reference "$CALLER_REF-hcdis" \
    --health-check-config '{
        "FullyQualifiedDomainName": "ss-test-disabled.example.internal",
        "Port": 80,
        "Type": "HTTP",
        "ResourcePath": "/",
        "RequestInterval": 30,
        "FailureThreshold": 3,
        "Disabled": true
    }' \
    --output json 2>&1) || {
        echo -e "${YELLOW}Warning: create disabled health check failed: $HC_DISABLED_JSON${NC}"
    }
HC_DISABLED_ID=$(echo "$HC_DISABLED_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['HealthCheck']['Id'])" 2>/dev/null || echo "")
if [ -n "$HC_DISABLED_ID" ]; then
    echo "  Disabled health check: $HC_DISABLED_ID  (fires #17 disabled + #7 HTTP + #13 slow + #8 no-alarm)"
    log "hc:$HC_DISABLED_ID"
fi

echo ""
echo -e "${GREEN}=== Route 53 test resources created ===${NC}"
echo "Resource manifest: $OUTPUT_FILE"
echo ""
echo -e "${CYAN}To scan:${NC}"
echo "  cd ../../.."
echo "  python3 main.py --regions $REGION --services route53 --beta 1 --sequential 1"
echo ""
echo -e "${CYAN}To clean up:${NC}"
echo "  cd services/route53/simulation && ./cleanup_test_resources.sh --force"
echo ""
echo -e "${YELLOW}Notes:${NC}"
echo "  * Domain checks (#3-#6) require a REAL registered domain in route53domains"
echo "    and cannot be simulated cheaply. Document these as manually validated."
echo "  * Resolver checks (#9-#11) fire on natural account state — no fabrication"
echo "    needed. They fail unless you have DNS Firewall + Resolver query logging"
echo "    + DNSSEC validation configured, which most AWS accounts don't by default."
echo "  * DNSSEC signing (#1) requires KMS + KSK setup which costs money. Not"
echo "    simulated here — will fire on ANY public zone without signing."
echo "  * Empty-zone checks (#12, #23) exempt zones < 24h old — re-run scan"
echo "    24h after creation to see them fail."
echo "  * Apex CNAME (#15) is rejected by Route 53 API — must be validated with"
echo "    an imported zone file that pre-existed the API validation."

#!/bin/bash

################################################################################
# Cognito Service Screener - Test Resource Creation Script
#
# Creates ONE intentionally-insecure Cognito user pool that triggers
# 11 of the 12 cognito* checks. An intentionally-permissive app client is
# also created to fire the token-validity check.
#
# Checks triggered (all FAIL unless noted):
#   #1  cognitoMfaNotEnforced             — MfaConfiguration=OFF
#   #2  cognitoWeakPasswordPolicy         — MinimumLength=6, no symbol required
#   #3  cognitoAdvancedSecurityNotEnforced— UserPoolAddOns not set (default OFF)
#   #4  cognitoDeletionProtectionDisabled — DeletionProtection=INACTIVE
#   #5  cognitoNoEmailPhoneVerification   — AutoVerifiedAttributes empty
#   #6  cognitoNoLambdaTriggers           — LambdaConfig empty
#   #7  cognitoAccountRecoveryNotConfigured — n/a (Cognito auto-injects
#                                              defaults when unset; the check
#                                              PASSes here, and is validated
#                                              in reverse against pools that
#                                              have RecoveryMechanisms:[])
#   #8  cognitoSingleRecoveryOption       — exactly 1 RecoveryMechanism
#   #9  cognitoUnusedUserPool             — EstimatedNumberOfUsers=0
#   #10 cognitoTokenValidityTooLong       — app client with 24h access token
#   #11 cognitoDeviceTrackingDisabled     — DeviceConfiguration not set
#   #12 cognitoResourcesWithoutTags       — no UserPoolTags
#
# Not simulated:
#   #7 cognitoAccountRecoveryNotConfigured — Cognito auto-injects two default
#      recovery mechanisms (verified_email, verified_phone_number) when
#      --account-recovery-setting is unset. The API also rejects an empty
#      RecoveryMechanisms array. Check #7 is validated against real pools
#      that were created without recovery configuration in older Cognito
#      versions (its complement is exercised here — the check PASSes).
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
if [ -z "${ACCOUNT_ID:-}" ]; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"; exit 1
fi

POOL_NAME="${PREFIX}-cognito-pool-${TIMESTAMP}"
CLIENT_NAME="${PREFIX}-cognito-client-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Cognito Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}All resources prefixed with '${PREFIX}-'. User pools with no${NC}"
echo -e "${YELLOW}monthly active users on the LITE tier are free.${NC}"
echo ""

################################################################################
# Step 1: Create user pool with a weak password policy and everything else off.
################################################################################

echo -e "${GREEN}=== Step 1: Create user pool (weak everything) ===${NC}"

# Weak password policy: only 6 chars, only lowercase required.
# Account recovery: set to a SINGLE mechanism (verified_email) to fire the
# cognitoSingleRecoveryOption check. Cognito rejects an empty
# RecoveryMechanisms array, so we can't simulate #7 directly.
# Explicitly do NOT set:
#   --mfa-configuration           (default: OFF)
#   --user-pool-add-ons           (default: no advanced security)
#   --auto-verified-attributes    (default: none)
#   --lambda-config               (default: none)
#   --device-configuration        (default: none)
#   --user-pool-tags              (default: none)
POOL_JSON=$(aws cognito-idp create-user-pool \
    --pool-name "$POOL_NAME" \
    --policies '{"PasswordPolicy":{"MinimumLength":6,"RequireUppercase":false,"RequireLowercase":true,"RequireNumbers":false,"RequireSymbols":false,"TemporaryPasswordValidityDays":7}}' \
    --account-recovery-setting '{"RecoveryMechanisms":[{"Priority":1,"Name":"verified_email"}]}' \
    --deletion-protection INACTIVE \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Create user pool failed${NC}"
        echo "$POOL_JSON" | head -5
        exit 1
    }

POOL_ID=$(echo "$POOL_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
if [ -z "${POOL_ID:-}" ]; then
    echo -e "${RED}✗ Could not extract pool ID from response${NC}"
    exit 1
fi
log "USER_POOL:${POOL_ID}"
echo -e "${GREEN}✓ User pool: ${POOL_NAME}${NC}"
echo -e "  ID: ${POOL_ID}"

################################################################################
# Step 2: Create app client with intentionally-long token validity.
################################################################################

echo -e "\n${GREEN}=== Step 2: Create app client (long-lived tokens) ===${NC}"

# Access token: 24 hours (limit is 60 min) → FAIL
# Id token:    24 hours (limit is 60 min) → FAIL
# Refresh:     365 days (limit is 30 days) → FAIL
CLIENT_JSON=$(aws cognito-idp create-user-pool-client \
    --user-pool-id "$POOL_ID" \
    --client-name "$CLIENT_NAME" \
    --access-token-validity 24 \
    --id-token-validity 24 \
    --refresh-token-validity 365 \
    --token-validity-units '{"AccessToken":"hours","IdToken":"hours","RefreshToken":"days"}' \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${YELLOW}⚠ App client creation failed (check #10 will not fire)${NC}"
        echo "$CLIENT_JSON" | head -3
        CLIENT_JSON=""
    }

if [ -n "$CLIENT_JSON" ]; then
    CLIENT_ID=$(echo "$CLIENT_JSON" | grep -o '"ClientId": *"[^"]*"' | head -1 | sed 's/.*"ClientId": *"\([^"]*\)".*/\1/')
    if [ -n "${CLIENT_ID:-}" ]; then
        log "APP_CLIENT:${POOL_ID}:${CLIENT_ID}"
        echo -e "${GREEN}✓ App client: ${CLIENT_NAME}${NC}"
        echo -e "  ID: ${CLIENT_ID}"
    fi
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
echo "  1. cd ../../.. && python3 main.py --regions $REGION --services cognito --beta 1 --sequential 1"
echo "  2. cd services/cognito/simulation && ./cleanup_test_resources.sh"

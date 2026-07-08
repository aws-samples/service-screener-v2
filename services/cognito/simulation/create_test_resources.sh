#!/bin/bash

################################################################################
# Cognito Service Screener - Test Resource Creation Script
#
# Creates THREE intentionally-insecure Cognito user pools plus supporting
# Lambda / IAM roles that exercise every `cognito*` service-screener check
# that can be forced through the AWS API. Covers Phase 1 (checks 13-27)
# plus Phase 2 (checks 28-37).
#
#   Pool 1 ("baseline")   — Phase 1 pristine pool:
#     - MfaConfiguration=OFF, weak PW policy, no UserPoolAddOns,
#       DeletionProtection=INACTIVE, no AutoVerifiedAttributes, no
#       LambdaConfig, single recovery mechanism, no DeviceConfiguration,
#       no tags, 0 users, app client with 24h access/id + 365d refresh
#       token validity.
#     Fires Phase 1 checks 13, 14, 15, 16, 17, 18, 20, 21, 23, 24
#     (many; see README).
#
#   Pool 2 ("phase2-lite") — Phase 2 misconfig pool (same tier as Pool 1):
#     - LambdaConfig.DefineAuthChallenge=<lambda-arn> with AdvSec OFF
#         → fires #37 cognitoCustomAuthThreatProtectionDisabled
#     - Policies.PasswordPolicy.TemporaryPasswordValidityDays=30
#         → fires #30 cognitoLongTemporaryPassword
#     - Cognito group `phase2-admins` with an attached IAM role whose
#       inline policy allows Action:*, Resource:*
#         → fires #36 cognitoGroupOverlyPermissiveRole
#     - App client with AllowedOAuthScopes=[aws.cognito.signin.user.admin]
#         → fires #32 cognitoClientExcessiveScopes (INFO)
#
#   Pool 3 ("phase2-plus") — PLUS-tier pool with threat protection ON:
#     - UserPoolTier=PLUS, AdvancedSecurityMode=ENFORCED
#     - Risk config: CompromisedCredentials.EventFilter=[SIGN_IN] only
#         → fires #28 cognitoCompromisedCredentialIncompleteFilter
#     - Risk config: AccountTakeover Actions with Notify=false on High/Med
#         → fires #35 cognitoAccountTakeoverNoNotification (INFO)
#     - No LogDelivery for userAuthEvents
#         → fires #29 cognitoNoThreatProtectionLogging
#     - MFA=ON with SoftwareTokenMfa.Enabled=false and no SMS config
#         (attempt; API may refuse — check #33 fires only if accepted)
#
# Not simulated (documented in README):
#   #31 cognitoClientNoSecret — Cognito refuses to create a
#       client_credentials app client without --generate-secret, so a
#       "confidential client without a secret" state cannot be forced
#       via the current API.
#   #34 cognitoSmsOnlyMfa    — requires a fully-configured SNS role with
#       ExternalId + phone_number attribute + regional support; setup
#       and role trust are non-trivial and not free of maintenance risk.
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

POOL1_NAME="${PREFIX}-cognito-pool-${TIMESTAMP}"
POOL2_NAME="${PREFIX}-cognito-pool2-${TIMESTAMP}"
POOL3_NAME="${PREFIX}-cognito-pool3-${TIMESTAMP}"
CLIENT1_NAME="${PREFIX}-cognito-client-${TIMESTAMP}"
CLIENT2_NAME="${PREFIX}-cognito-oauth-${TIMESTAMP}"
LAMBDA_ROLE_NAME="${PREFIX}-cognito-lambda-role-${TIMESTAMP}"
LAMBDA_FN_NAME="${PREFIX}-cognito-authtrigger-${TIMESTAMP}"
GROUP_ROLE_NAME="${PREFIX}-cognito-group-role-${TIMESTAMP}"
GROUP_NAME="phase2-admins"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== Cognito Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}All resources prefixed with '${PREFIX}-'. User pools without${NC}"
echo -e "${YELLOW}monthly active users cost \$0 across all tiers.${NC}"
echo ""

################################################################################
# Step 1: Pool 1 — baseline (Phase 1 pristine)
################################################################################

echo -e "${GREEN}=== Step 1: Pool 1 — Phase 1 pristine baseline ===${NC}"

POOL1_JSON=$(aws cognito-idp create-user-pool \
    --pool-name "$POOL1_NAME" \
    --policies '{"PasswordPolicy":{"MinimumLength":6,"RequireUppercase":false,"RequireLowercase":true,"RequireNumbers":false,"RequireSymbols":false,"TemporaryPasswordValidityDays":7}}' \
    --account-recovery-setting '{"RecoveryMechanisms":[{"Priority":1,"Name":"verified_email"}]}' \
    --deletion-protection INACTIVE \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Create Pool 1 failed${NC}"; echo "$POOL1_JSON" | head -5; exit 1;
    }
POOL1_ID=$(echo "$POOL1_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
log "USER_POOL:${POOL1_ID}"
echo -e "${GREEN}✓ Pool 1: ${POOL1_NAME} (${POOL1_ID})${NC}"

CLIENT1_JSON=$(aws cognito-idp create-user-pool-client \
    --user-pool-id "$POOL1_ID" \
    --client-name "$CLIENT1_NAME" \
    --access-token-validity 24 \
    --id-token-validity 24 \
    --refresh-token-validity 365 \
    --token-validity-units '{"AccessToken":"hours","IdToken":"hours","RefreshToken":"days"}' \
    --region "$REGION" \
    --output json 2>&1) || echo -e "${YELLOW}⚠ App client on Pool 1 failed${NC}"

CLIENT1_ID=$(echo "$CLIENT1_JSON" | grep -o '"ClientId": *"[^"]*"' | head -1 | sed 's/.*"ClientId": *"\([^"]*\)".*/\1/')
if [ -n "${CLIENT1_ID:-}" ]; then
    log "APP_CLIENT:${POOL1_ID}:${CLIENT1_ID}"
    echo -e "${GREEN}✓ Pool 1 app client: ${CLIENT1_NAME} (${CLIENT1_ID})${NC}"
fi

################################################################################
# Step 2: IAM role + Lambda function for Pool 2 custom-auth trigger
################################################################################

echo -e "\n${GREEN}=== Step 2: Lambda IAM role + function (Pool 2 custom-auth trigger) ===${NC}"

cat > /tmp/${PREFIX}-cognito-lambda-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
    --role-name "$LAMBDA_ROLE_NAME" \
    --assume-role-policy-document file:///tmp/${PREFIX}-cognito-lambda-trust.json \
    --description "SS simulation - Lambda execution for Cognito custom auth" \
    > /dev/null
aws iam attach-role-policy \
    --role-name "$LAMBDA_ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
LAMBDA_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${LAMBDA_ROLE_NAME}"
log "IAM_ROLE:${LAMBDA_ROLE_NAME}"
echo -e "${GREEN}✓ Lambda role: ${LAMBDA_ROLE_NAME}${NC}"

echo -e "${YELLOW}Sleeping 15s for IAM role propagation...${NC}"
sleep 15

# Minimal Lambda handler
cat > /tmp/${PREFIX}-cognito-lambda-src.py <<'EOF'
def handler(event, context):
    # SS simulation stub — never invoked because Cognito flows aren't exercised.
    return event
EOF

# Zip in a subdirectory to keep the archive minimal
LAMBDA_ZIP=/tmp/${PREFIX}-cognito-lambda.zip
(cd /tmp && cp ${PREFIX}-cognito-lambda-src.py index.py && zip -q "$LAMBDA_ZIP" index.py && rm -f index.py)

LAMBDA_JSON=$(aws lambda create-function \
    --function-name "$LAMBDA_FN_NAME" \
    --runtime python3.11 \
    --role "$LAMBDA_ROLE_ARN" \
    --handler index.handler \
    --zip-file "fileb://${LAMBDA_ZIP}" \
    --timeout 5 \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Create Lambda failed${NC}"; echo "$LAMBDA_JSON" | head -5
        LAMBDA_JSON=""
    }

if [ -n "$LAMBDA_JSON" ]; then
    LAMBDA_ARN=$(echo "$LAMBDA_JSON" | grep -o '"FunctionArn": *"[^"]*"' | head -1 | sed 's/.*"FunctionArn": *"\([^"]*\)".*/\1/')
    log "LAMBDA:${LAMBDA_FN_NAME}"
    echo -e "${GREEN}✓ Lambda: ${LAMBDA_FN_NAME}${NC}"
else
    LAMBDA_ARN=""
fi

################################################################################
# Step 3: IAM role for Cognito group (overly permissive)
################################################################################

echo -e "\n${GREEN}=== Step 3: Cognito-group IAM role (Action:*/Resource:*) ===${NC}"

cat > /tmp/${PREFIX}-cognito-group-wild.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF

cat > /tmp/${PREFIX}-cognito-group-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "cognito-identity.amazonaws.com:aud": "us-east-1:ss-test-simulation-placeholder"
      },
      "ForAnyValue:StringLike": {
        "cognito-identity.amazonaws.com:amr": "authenticated"
      }
    }
  }]
}
EOF

aws iam create-role \
    --role-name "$GROUP_ROLE_NAME" \
    --assume-role-policy-document file:///tmp/${PREFIX}-cognito-group-trust.json \
    --description "SS simulation - intentionally overprivileged group role" \
    > /dev/null 2>&1
if ! aws iam get-role --role-name "$GROUP_ROLE_NAME" > /dev/null 2>&1; then
    echo -e "${RED}✗ Group role create failed${NC}"
    GROUP_ROLE_ARN=""
else
    aws iam put-role-policy \
        --role-name "$GROUP_ROLE_NAME" \
        --policy-name "${PREFIX}-cognito-group-wildcard" \
        --policy-document file:///tmp/${PREFIX}-cognito-group-wild.json
    GROUP_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${GROUP_ROLE_NAME}"
    log "IAM_ROLE:${GROUP_ROLE_NAME}"
    echo -e "${GREEN}✓ Group role: ${GROUP_ROLE_NAME}${NC}"
fi

################################################################################
# Step 4: Pool 2 — Phase 2 misconfig pool
################################################################################

echo -e "\n${GREEN}=== Step 4: Pool 2 — Phase 2 misconfig ===${NC}"

# TemporaryPasswordValidityDays=30 → fires check 30
POLICIES_P2='{"PasswordPolicy":{"MinimumLength":6,"RequireUppercase":false,"RequireLowercase":true,"RequireNumbers":false,"RequireSymbols":false,"TemporaryPasswordValidityDays":30}}'

# LambdaConfig with custom-auth trigger (if Lambda was created)
if [ -n "${LAMBDA_ARN:-}" ]; then
    LAMBDA_CFG_JSON="{\"DefineAuthChallenge\":\"${LAMBDA_ARN}\"}"
    LAMBDA_CFG_ARGS=(--lambda-config "$LAMBDA_CFG_JSON")
else
    LAMBDA_CFG_ARGS=()
fi

POOL2_JSON=$(aws cognito-idp create-user-pool \
    --pool-name "$POOL2_NAME" \
    --policies "$POLICIES_P2" \
    --account-recovery-setting '{"RecoveryMechanisms":[{"Priority":1,"Name":"verified_email"}]}' \
    --deletion-protection INACTIVE \
    "${LAMBDA_CFG_ARGS[@]}" \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${YELLOW}⚠ Create Pool 2 with LambdaConfig failed — retry without${NC}"
        echo "$POOL2_JSON" | head -3
        POOL2_JSON=$(aws cognito-idp create-user-pool \
            --pool-name "$POOL2_NAME" \
            --policies "$POLICIES_P2" \
            --account-recovery-setting '{"RecoveryMechanisms":[{"Priority":1,"Name":"verified_email"}]}' \
            --deletion-protection INACTIVE \
            --region "$REGION" \
            --output json 2>&1) || {
                echo -e "${RED}✗ Create Pool 2 failed${NC}"; echo "$POOL2_JSON" | head -3;
                POOL2_JSON=""
            }
        LAMBDA_ATTACHED_LATER=true
    }

POOL2_ID=""
if [ -n "$POOL2_JSON" ]; then
    POOL2_ID=$(echo "$POOL2_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
    if [ -n "$POOL2_ID" ]; then
        log "USER_POOL:${POOL2_ID}"
        echo -e "${GREEN}✓ Pool 2: ${POOL2_NAME} (${POOL2_ID})${NC}"
    fi
fi

################################################################################
# Step 5: Grant Cognito permission to invoke the Lambda; attach if needed
################################################################################

if [ -n "${LAMBDA_ARN:-}" ] && [ -n "${POOL2_ID:-}" ]; then
    echo -e "\n${GREEN}=== Step 5: Grant Cognito lambda:InvokeFunction on Pool 2 ===${NC}"
    aws lambda add-permission \
        --function-name "$LAMBDA_FN_NAME" \
        --statement-id "AllowCognitoInvoke${TIMESTAMP}" \
        --action lambda:InvokeFunction \
        --principal cognito-idp.amazonaws.com \
        --source-arn "arn:aws:cognito-idp:${REGION}:${ACCOUNT_ID}:userpool/${POOL2_ID}" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}✓ Lambda invoke permission granted${NC}" \
        || echo -e "${YELLOW}⚠ add-permission may have been rejected (idempotency or pool-mismatch)${NC}"

    # If Pool 2 was created without LambdaConfig, attach it now
    if [ "${LAMBDA_ATTACHED_LATER:-false}" = "true" ]; then
        # UpdateUserPool requires re-supplying key fields; use as few as
        # necessary. AutoVerifiedAttributes: not set on Pool 2 → still not set.
        aws cognito-idp update-user-pool \
            --user-pool-id "$POOL2_ID" \
            --lambda-config "{\"DefineAuthChallenge\":\"${LAMBDA_ARN}\"}" \
            --region "$REGION" > /dev/null 2>&1 \
            && echo -e "${GREEN}✓ LambdaConfig attached to Pool 2 post-create${NC}" \
            || echo -e "${YELLOW}⚠ Could not attach LambdaConfig post-create${NC}"
    fi
fi

################################################################################
# Step 6: Cognito group on Pool 2 with overly-permissive role
################################################################################

if [ -n "${POOL2_ID:-}" ] && [ -n "${GROUP_ROLE_ARN:-}" ]; then
    echo -e "\n${GREEN}=== Step 6: Create Cognito group with overprivileged role ===${NC}"
    echo -e "${YELLOW}Sleeping 10s for group role propagation...${NC}"
    sleep 10
    aws cognito-idp create-group \
        --group-name "$GROUP_NAME" \
        --user-pool-id "$POOL2_ID" \
        --role-arn "$GROUP_ROLE_ARN" \
        --description "SS simulation - Phase 2 #36 group with wildcard IAM role" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}✓ Group ${GROUP_NAME} on Pool 2 (fires Phase 2 #36)${NC}" \
        || echo -e "${YELLOW}⚠ create-group failed (role may need more propagation time)${NC}"
fi

################################################################################
# Step 7: App client on Pool 2 with excessive OAuth scopes
################################################################################

if [ -n "${POOL2_ID:-}" ]; then
    echo -e "\n${GREEN}=== Step 7: Pool 2 app client with excessive scopes ===${NC}"
    CLIENT2_JSON=$(aws cognito-idp create-user-pool-client \
        --user-pool-id "$POOL2_ID" \
        --client-name "$CLIENT2_NAME" \
        --allowed-o-auth-flows code \
        --allowed-o-auth-flows-user-pool-client \
        --allowed-o-auth-scopes aws.cognito.signin.user.admin openid \
        --callback-urls "https://example.com/callback" \
        --supported-identity-providers COGNITO \
        --region "$REGION" \
        --output json 2>&1) || echo -e "${YELLOW}⚠ create OAuth client failed${NC}"

    CLIENT2_ID=$(echo "$CLIENT2_JSON" | grep -o '"ClientId": *"[^"]*"' | head -1 | sed 's/.*"ClientId": *"\([^"]*\)".*/\1/')
    if [ -n "${CLIENT2_ID:-}" ]; then
        log "APP_CLIENT:${POOL2_ID}:${CLIENT2_ID}"
        echo -e "${GREEN}✓ OAuth app client: ${CLIENT2_NAME} (fires Phase 2 #32)${NC}"
    fi
fi

################################################################################
# Step 8: Pool 3 — PLUS tier + AdvSec ENFORCED
################################################################################

echo -e "\n${GREEN}=== Step 8: Pool 3 — PLUS tier + Advanced Security ENFORCED ===${NC}"

POOL3_JSON=$(aws cognito-idp create-user-pool \
    --pool-name "$POOL3_NAME" \
    --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":false,"TemporaryPasswordValidityDays":7}}' \
    --account-recovery-setting '{"RecoveryMechanisms":[{"Priority":1,"Name":"verified_email"}]}' \
    --user-pool-add-ons '{"AdvancedSecurityMode":"ENFORCED"}' \
    --user-pool-tier PLUS \
    --deletion-protection INACTIVE \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${YELLOW}⚠ Pool 3 (PLUS tier) creation failed — falling back to ESSENTIALS${NC}"
        echo "$POOL3_JSON" | head -3
        POOL3_JSON=$(aws cognito-idp create-user-pool \
            --pool-name "$POOL3_NAME" \
            --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":false,"TemporaryPasswordValidityDays":7}}' \
            --account-recovery-setting '{"RecoveryMechanisms":[{"Priority":1,"Name":"verified_email"}]}' \
            --user-pool-add-ons '{"AdvancedSecurityMode":"ENFORCED"}' \
            --deletion-protection INACTIVE \
            --region "$REGION" \
            --output json 2>&1) || {
                echo -e "${RED}✗ Pool 3 fallback also failed${NC}"; echo "$POOL3_JSON" | head -3;
                POOL3_JSON=""
            }
    }

POOL3_ID=""
if [ -n "$POOL3_JSON" ]; then
    POOL3_ID=$(echo "$POOL3_JSON" | grep -o '"Id": *"[^"]*"' | head -1 | sed 's/.*"Id": *"\([^"]*\)".*/\1/')
    if [ -n "$POOL3_ID" ]; then
        log "USER_POOL:${POOL3_ID}"
        echo -e "${GREEN}✓ Pool 3: ${POOL3_NAME} (${POOL3_ID})${NC}"
    fi
fi

################################################################################
# Step 9: Risk configuration on Pool 3 (Phase 2 #28 + #35)
################################################################################

if [ -n "${POOL3_ID:-}" ]; then
    echo -e "\n${GREEN}=== Step 9: Risk configuration on Pool 3 ===${NC}"

    # CompromisedCredentials with EventFilter = [SIGN_IN] only (missing
    # SIGN_UP and PASSWORD_CHANGE) → fires Phase 2 #28.
    CC_CFG='{"Actions":{"EventAction":"BLOCK"},"EventFilter":["SIGN_IN"]}'

    # AccountTakeover with Notify=false everywhere → fires Phase 2 #35.
    ATO_CFG='{"Actions":{"LowAction":{"Notify":false,"EventAction":"NO_ACTION"},"MediumAction":{"Notify":false,"EventAction":"MFA_IF_CONFIGURED"},"HighAction":{"Notify":false,"EventAction":"BLOCK"}}}'

    aws cognito-idp set-risk-configuration \
        --user-pool-id "$POOL3_ID" \
        --compromised-credentials-risk-configuration "$CC_CFG" \
        --account-takeover-risk-configuration "$ATO_CFG" \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}✓ Risk config set (fires Phase 2 #28, #35)${NC}" \
        || echo -e "${YELLOW}⚠ set-risk-configuration failed (may need PLUS tier or ATO NotifyConfiguration)${NC}"
fi

################################################################################
# Step 10: MFA=ON with no methods enabled on Pool 3 (Phase 2 #33)
################################################################################

if [ -n "${POOL3_ID:-}" ]; then
    echo -e "\n${GREEN}=== Step 10: MFA=ON with no methods on Pool 3 ===${NC}"

    aws cognito-idp set-user-pool-mfa-config \
        --user-pool-id "$POOL3_ID" \
        --mfa-configuration ON \
        --software-token-mfa-configuration Enabled=false \
        --region "$REGION" > /dev/null 2>&1 \
        && echo -e "${GREEN}✓ MFA=ON with TOTP disabled (fires Phase 2 #33 if Cognito accepts)${NC}" \
        || echo -e "${YELLOW}⚠ set-user-pool-mfa-config refused MFA=ON without methods (expected on some accounts)${NC}"
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
echo "  1. sleep 30   # eventual consistency for IAM + Cognito"
echo "  2. cd ../../.. && python3 main.py --regions $REGION --services cognito --beta 1 --sequential 1"
echo "  3. cd services/cognito/simulation && ./cleanup_test_resources.sh"

rm -f /tmp/${PREFIX}-cognito-lambda-trust.json /tmp/${PREFIX}-cognito-lambda-src.py \
      /tmp/${PREFIX}-cognito-group-trust.json /tmp/${PREFIX}-cognito-group-wild.json \
      "$LAMBDA_ZIP"

#!/bin/bash

# API Gateway Test Resources Creation Script
# This script creates test API Gateway resources to validate the new Tier 1 checks
# 
# Prerequisites:
# - AWS CLI configured with appropriate credentials
# - Permissions to create API Gateway resources, VPC endpoints, custom domains, etc.
# - jq installed for JSON parsing

set -e

# Configuration
REGION="${AWS_REGION:-us-east-1}"
API_NAME_PREFIX="ss-test-api"
TIMESTAMP=$(date +%s)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}API Gateway Test Resources Creation${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Region: $REGION"
echo "Timestamp: $TIMESTAMP"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Store created resource IDs
RESOURCE_IDS_FILE="simulation/test_resources_${TIMESTAMP}.json"

# Initialize JSON file
echo "{" > "$RESOURCE_IDS_FILE"
echo "  \"timestamp\": \"$TIMESTAMP\"," >> "$RESOURCE_IDS_FILE"
echo "  \"region\": \"$REGION\"," >> "$RESOURCE_IDS_FILE"
echo "  \"resources\": {" >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 1: API with Resource Policy (PASS)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 1: API with Resource Policy (PASS)${NC}"

API1_NAME="${API_NAME_PREFIX}-with-policy-${TIMESTAMP}"
API1_ID=$(sleep 5
aws apigateway create-rest-api \
    --name "$API1_NAME" \
    --description "Test API with resource policy - should PASS ResourcePolicy check" \
    --endpoint-configuration types=REGIONAL \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created API: $API1_NAME (ID: $API1_ID)"

# Add resource policy
POLICY1='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}'

POLICY1_ESCAPED=$(echo "$POLICY1" | jq -c . | jq -Rs .)
aws apigateway update-rest-api \
    --rest-api-id "$API1_ID" \
    --patch-operations "[{\"op\":\"replace\",\"path\":\"/policy\",\"value\":$(echo $POLICY1 | jq -c . | jq -Rs .)}]" \
    --region "$REGION" > /dev/null

print_status "Added resource policy to $API1_NAME"

echo "    \"api_with_policy\": \"$API1_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 2: API without Resource Policy (FAIL)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 2: API without Resource Policy (FAIL)${NC}"

API2_NAME="${API_NAME_PREFIX}-no-policy-${TIMESTAMP}"
API2_ID=$(sleep 5
aws apigateway create-rest-api \
    --name "$API2_NAME" \
    --description "Test API without resource policy - should FAIL ResourcePolicy check" \
    --endpoint-configuration types=REGIONAL \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created API: $API2_NAME (ID: $API2_ID)"
echo "    \"api_without_policy\": \"$API2_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 3: API with IAM Authentication (PASS)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 3: API with IAM Authentication (PASS)${NC}"

API3_NAME="${API_NAME_PREFIX}-iam-auth-${TIMESTAMP}"
API3_ID=$(sleep 5
aws apigateway create-rest-api \
    --name "$API3_NAME" \
    --description "Test API with IAM authentication - should PASS IAMAuthentication check" \
    --endpoint-configuration types=REGIONAL \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created API: $API3_NAME (ID: $API3_ID)"

# Get root resource
ROOT_RESOURCE_ID=$(aws apigateway get-resources \
    --rest-api-id "$API3_ID" \
    --region "$REGION" \
    --query 'items[0].id' \
    --output text)

# Create /users resource
USERS_RESOURCE_ID=$(aws apigateway create-resource \
    --rest-api-id "$API3_ID" \
    --parent-id "$ROOT_RESOURCE_ID" \
    --path-part "users" \
    --region "$REGION" \
    --query 'id' \
    --output text)

# Add GET method with IAM authentication
aws apigateway put-method \
    --rest-api-id "$API3_ID" \
    --resource-id "$USERS_RESOURCE_ID" \
    --http-method GET \
    --authorization-type AWS_IAM \
    --region "$REGION" > /dev/null

# Add mock integration
aws apigateway put-integration \
    --rest-api-id "$API3_ID" \
    --resource-id "$USERS_RESOURCE_ID" \
    --http-method GET \
    --type MOCK \
    --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
    --region "$REGION" > /dev/null

print_status "Added GET /users with IAM authentication"
echo "    \"api_with_iam_auth\": \"$API3_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 4: API with NONE Authentication (FAIL)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 4: API with NONE Authentication (FAIL)${NC}"

API4_NAME="${API_NAME_PREFIX}-no-auth-${TIMESTAMP}"
API4_ID=$(sleep 5
aws apigateway create-rest-api \
    --name "$API4_NAME" \
    --description "Test API with NONE authentication - should FAIL IAMAuthentication check" \
    --endpoint-configuration types=REGIONAL \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created API: $API4_NAME (ID: $API4_ID)"

# Get root resource
ROOT_RESOURCE_ID=$(aws apigateway get-resources \
    --rest-api-id "$API4_ID" \
    --region "$REGION" \
    --query 'items[0].id' \
    --output text)

# Create /public resource
PUBLIC_RESOURCE_ID=$(aws apigateway create-resource \
    --rest-api-id "$API4_ID" \
    --parent-id "$ROOT_RESOURCE_ID" \
    --path-part "public" \
    --region "$REGION" \
    --query 'id' \
    --output text)

# Add GET method with NONE authentication
aws apigateway put-method \
    --rest-api-id "$API4_ID" \
    --resource-id "$PUBLIC_RESOURCE_ID" \
    --http-method GET \
    --authorization-type NONE \
    --region "$REGION" > /dev/null

# Add mock integration
aws apigateway put-integration \
    --rest-api-id "$API4_ID" \
    --resource-id "$PUBLIC_RESOURCE_ID" \
    --http-method GET \
    --type MOCK \
    --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
    --region "$REGION" > /dev/null

print_status "Added GET /public with NONE authentication"
echo "    \"api_without_auth\": \"$API4_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 5: API with Throttling (PASS)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 5: API with Throttling (PASS)${NC}"

API5_NAME="${API_NAME_PREFIX}-with-throttling-${TIMESTAMP}"
API5_ID=$(sleep 5
aws apigateway create-rest-api \
    --name "$API5_NAME" \
    --description "Test API with throttling - should PASS RequestThrottling check" \
    --endpoint-configuration types=REGIONAL \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created API: $API5_NAME (ID: $API5_ID)"

# Add a method so deployment works
API5_ROOT=$(aws apigateway get-resources --rest-api-id "$API5_ID" --region "$REGION" --query 'items[0].id' --output text)
aws apigateway put-method --rest-api-id "$API5_ID" --resource-id "$API5_ROOT" --http-method GET --authorization-type NONE --region "$REGION" > /dev/null
aws apigateway put-integration --rest-api-id "$API5_ID" --resource-id "$API5_ROOT" --http-method GET --type MOCK --request-templates '{"application/json":"{\"statusCode\":200}"}' --region "$REGION" > /dev/null

# Create deployment
DEPLOYMENT_ID=$(aws apigateway create-deployment \
    --rest-api-id "$API5_ID" \
    --stage-name prod \
    --stage-description "Production stage with throttling" \
    --region "$REGION" \
    --query 'id' \
    --output text)

# Update stage with throttling settings
aws apigateway update-stage \
    --rest-api-id "$API5_ID" \
    --stage-name prod \
    --patch-operations \
        "op=replace,path=/*/*/throttling/burstLimit,value=5000" \
        "op=replace,path=/*/*/throttling/rateLimit,value=10000" \
    --region "$REGION" > /dev/null

print_status "Created stage 'prod' with throttling (burst: 5000, rate: 10000)"
echo "    \"api_with_throttling\": \"$API5_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 6: API without Throttling (FAIL)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 6: API without Throttling (FAIL)${NC}"

API6_NAME="${API_NAME_PREFIX}-no-throttling-${TIMESTAMP}"
API6_ID=$(sleep 5
aws apigateway create-rest-api \
    --name "$API6_NAME" \
    --description "Test API without throttling - should FAIL RequestThrottling check" \
    --endpoint-configuration types=REGIONAL \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created API: $API6_NAME (ID: $API6_ID)"

# Add a method so deployment works
API6_ROOT=$(aws apigateway get-resources --rest-api-id "$API6_ID" --region "$REGION" --query 'items[0].id' --output text)
aws apigateway put-method --rest-api-id "$API6_ID" --resource-id "$API6_ROOT" --http-method GET --authorization-type NONE --region "$REGION" > /dev/null
aws apigateway put-integration --rest-api-id "$API6_ID" --resource-id "$API6_ROOT" --http-method GET --type MOCK --request-templates '{"application/json":"{\"statusCode\":200}"}' --region "$REGION" > /dev/null

# Create deployment without throttling
aws apigateway create-deployment \
    --rest-api-id "$API6_ID" \
    --stage-name dev \
    --stage-description "Development stage without throttling" \
    --region "$REGION" > /dev/null

print_status "Created stage 'dev' without throttling"
echo "    \"api_without_throttling\": \"$API6_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 7: Private API with VPC Endpoints (PASS)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 7: Private API with VPC Endpoints${NC}"
print_warning "Note: Creating VPC endpoints requires VPC setup. Skipping for basic simulation."
print_warning "To test PrivateAPI check, manually create a private API with VPC endpoints."

# ========================================
# Test Case 10: API with Lambda Authorizer (PASS)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 10: API with Lambda Authorizer${NC}"
print_warning "Note: Lambda authorizer requires Lambda function. Skipping for basic simulation."
print_warning "To test LambdaAuthorizer check, manually create an API with Lambda authorizer."

# ========================================
# Test Case 11: API with API Key Anti-pattern (FAIL)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 11: API with API Key Anti-pattern (FAIL)${NC}"

API7_NAME="${API_NAME_PREFIX}-apikey-antipattern-${TIMESTAMP}"
API7_ID=$(sleep 5
aws apigateway create-rest-api \
    --name "$API7_NAME" \
    --description "Test API with API key but no auth - should FAIL APIKeyAntiPattern check" \
    --endpoint-configuration types=REGIONAL \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created API: $API7_NAME (ID: $API7_ID)"

# Get root resource
ROOT_RESOURCE_ID=$(aws apigateway get-resources \
    --rest-api-id "$API7_ID" \
    --region "$REGION" \
    --query 'items[0].id' \
    --output text)

# Create /data resource
DATA_RESOURCE_ID=$(aws apigateway create-resource \
    --rest-api-id "$API7_ID" \
    --parent-id "$ROOT_RESOURCE_ID" \
    --path-part "data" \
    --region "$REGION" \
    --query 'id' \
    --output text)

# Add GET method with API key required but NONE authorization (anti-pattern)
aws apigateway put-method \
    --rest-api-id "$API7_ID" \
    --resource-id "$DATA_RESOURCE_ID" \
    --http-method GET \
    --authorization-type NONE \
    --api-key-required \
    --region "$REGION" > /dev/null

# Add mock integration
aws apigateway put-integration \
    --rest-api-id "$API7_ID" \
    --resource-id "$DATA_RESOURCE_ID" \
    --http-method GET \
    --type MOCK \
    --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
    --region "$REGION" > /dev/null

print_status "Added GET /data with API key required but NONE authorization"
echo "    \"api_with_apikey_antipattern\": \"$API7_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 12: CloudWatch Alarms (Manual)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 12: CloudWatch Alarms${NC}"
print_warning "Note: CloudWatch alarms should be created manually for specific APIs."
print_warning "To test CloudWatchAlarms check, create alarms for 4XXError, 5XXError, Latency metrics."

# ========================================
# Test Case 13: CloudTrail Logging (Manual)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 13: CloudTrail Logging${NC}"
print_warning "Note: CloudTrail should be configured at account level."
print_warning "To test CloudTrailLogging check, ensure CloudTrail trail with management events is enabled."

# ========================================
# Test Case 8: Usage Plan with Throttling (PASS)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 8: Usage Plan with Throttling (PASS)${NC}"

USAGE_PLAN_NAME="${API_NAME_PREFIX}-plan-with-limits-${TIMESTAMP}"
USAGE_PLAN_ID=$(aws apigateway create-usage-plan \
    --name "$USAGE_PLAN_NAME" \
    --description "Usage plan with throttling and quota" \
    --throttle burstLimit=1000,rateLimit=500 \
    --quota limit=10000,period=DAY \
    --api-stages apiId="$API5_ID",stage=prod \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created usage plan: $USAGE_PLAN_NAME (ID: $USAGE_PLAN_ID)"
echo "    \"usage_plan_with_limits\": \"$USAGE_PLAN_ID\"," >> "$RESOURCE_IDS_FILE"

# ========================================
# Test Case 9: Usage Plan without Limits (FAIL)
# ========================================
echo -e "\n${YELLOW}Creating Test Case 9: Usage Plan without Limits (FAIL)${NC}"

USAGE_PLAN2_NAME="${API_NAME_PREFIX}-plan-no-limits-${TIMESTAMP}"
USAGE_PLAN2_ID=$(aws apigateway create-usage-plan \
    --name "$USAGE_PLAN2_NAME" \
    --description "Usage plan without throttling or quota" \
    --api-stages apiId="$API6_ID",stage=dev \
    --region "$REGION" \
    --query 'id' \
    --output text)

print_status "Created usage plan: $USAGE_PLAN2_NAME (ID: $USAGE_PLAN2_ID)"
echo "    \"usage_plan_without_limits\": \"$USAGE_PLAN2_ID\"" >> "$RESOURCE_IDS_FILE"

# Close JSON file
echo "  }" >> "$RESOURCE_IDS_FILE"
echo "}" >> "$RESOURCE_IDS_FILE"

# ========================================
# Summary
# ========================================
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Resource Creation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Created resources saved to: $RESOURCE_IDS_FILE"
echo ""
echo "Test Cases Created:"
echo "  1. API with Resource Policy (PASS) - $API1_ID"
echo "  2. API without Resource Policy (FAIL) - $API2_ID"
echo "  3. API with IAM Authentication (PASS) - $API3_ID"
echo "  4. API with NONE Authentication (FAIL) - $API4_ID"
echo "  5. API with Throttling (PASS) - $API5_ID"
echo "  6. API without Throttling (FAIL) - $API6_ID"
echo "  7. Usage Plan with Limits (PASS) - $USAGE_PLAN_ID"
echo "  8. Usage Plan without Limits (FAIL) - $USAGE_PLAN2_ID"
echo "  9. API with API Key Anti-pattern (FAIL) - $API7_ID"
echo ""
echo -e "${YELLOW}Manual Test Cases (Tier 2):${NC}"
echo "  10. Lambda Authorizer - Requires Lambda function setup"
echo "  11. CloudWatch Alarms - Create alarms for API metrics"
echo "  12. CloudTrail Logging - Enable CloudTrail with management events"
echo "  13. VPC Access Restrictions - Create private API with VPC conditions"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Run Service Screener against these APIs"
echo "  2. Verify expected check results"
echo "  3. Run cleanup script when done: ./cleanup_test_resources.sh $TIMESTAMP"
echo ""

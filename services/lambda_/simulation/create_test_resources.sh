#!/bin/bash

# Lambda Service - Test Resource Creation Script
# This script creates Lambda functions and related resources to test new checks
# Usage: ./create_test_resources.sh [region]

set -e

REGION=${1:-us-east-1}
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%s)
PREFIX="ss-lambda-test-${TIMESTAMP}"

echo "Creating test resources in region: $REGION"
echo "Account ID: $ACCOUNT_ID"
echo "Resource prefix: $PREFIX"
echo ""

# Create IAM role for Lambda
echo "1. Creating IAM execution role..."
ROLE_NAME="${PREFIX}-role"
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document "$TRUST_POLICY" \
  --description "Test role for Lambda Service Screener checks" \
  > /dev/null

aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" \
  > /dev/null

aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole" \
  > /dev/null

aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaKinesisExecutionRole" \
  > /dev/null

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo "   Created role: $ROLE_ARN"

# Wait for role to be available
echo "   Waiting for IAM role to propagate..."
sleep 10

# Create Lambda function code
echo ""
echo "2. Creating Lambda function deployment package..."
TEMP_DIR=$(mktemp -d)
cat > "$TEMP_DIR/index.py" << 'EOF'
def lambda_handler(event, context):
    return {
        'statusCode': 200,
        'body': 'Test function for Service Screener'
    }
EOF

cd "$TEMP_DIR"
zip -q function.zip index.py
FUNCTION_ZIP="$TEMP_DIR/function.zip"
echo "   Created deployment package: $FUNCTION_ZIP"

# Create SQS queue for testing SQS visibility timeout check
echo ""
echo "3. Creating SQS queue with low visibility timeout..."
QUEUE_NAME="${PREFIX}-queue"
QUEUE_URL=$(aws sqs create-queue \
  --queue-name "$QUEUE_NAME" \
  --region "$REGION" \
  --attributes VisibilityTimeout=30 \
  --query QueueUrl --output text)
echo "   Created queue: $QUEUE_URL"

QUEUE_ARN=$(aws sqs get-queue-attributes \
  --queue-url "$QUEUE_URL" \
  --region "$REGION" \
  --attribute-names QueueArn \
  --query 'Attributes.QueueArn' --output text)

# Create Lambda function with SQS trigger (FAIL: visibility timeout too low)
echo ""
echo "4. Creating Lambda function with SQS trigger (visibility timeout issue)..."
FUNCTION_NAME_1="${PREFIX}-sqs-fail"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_1" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 5 \
  --region "$REGION" \
  > /dev/null

# Add SQS event source mapping with short timeout first
aws lambda create-event-source-mapping \
  --function-name "$FUNCTION_NAME_1" \
  --event-source-arn "$QUEUE_ARN" \
  --region "$REGION" \
  > /dev/null

# Now update function timeout to 60s to create the mismatch
aws lambda update-function-configuration \
  --function-name "$FUNCTION_NAME_1" \
  --timeout 60 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_1 (FAIL: SQS visibility timeout < 6x function timeout)"

# Create Lambda function without async retry config (FAIL)
echo ""
echo "5. Creating Lambda function without async retry configuration..."
FUNCTION_NAME_2="${PREFIX}-no-async-config"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_2" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 30 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_2 (FAIL: No async retry configuration)"

# Create Lambda function without CloudWatch alarms (FAIL)
echo ""
echo "6. Creating Lambda function without CloudWatch alarms..."
FUNCTION_NAME_3="${PREFIX}-no-alarms"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_3" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 30 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_3 (FAIL: No CloudWatch alarms)"

# Create Kinesis stream for testing stream-related checks
echo ""
echo "7. Creating Kinesis stream..."
STREAM_NAME="${PREFIX}-stream"
aws kinesis create-stream \
  --stream-name "$STREAM_NAME" \
  --shard-count 1 \
  --region "$REGION" \
  > /dev/null

echo "   Waiting for stream to become active..."
aws kinesis wait stream-exists \
  --stream-name "$STREAM_NAME" \
  --region "$REGION"

STREAM_ARN=$(aws kinesis describe-stream \
  --stream-name "$STREAM_NAME" \
  --region "$REGION" \
  --query 'StreamDescription.StreamARN' --output text)
echo "   Created stream: $STREAM_ARN"

# Create Lambda function with Kinesis trigger without partial batch response (FAIL)
echo ""
echo "8. Creating Lambda function with Kinesis trigger (no partial batch response)..."
FUNCTION_NAME_4="${PREFIX}-kinesis-fail"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_4" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 30 \
  --region "$REGION" \
  > /dev/null

# Add Kinesis event source mapping without partial batch response
aws lambda create-event-source-mapping \
  --function-name "$FUNCTION_NAME_4" \
  --event-source-arn "$STREAM_ARN" \
  --starting-position LATEST \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_4 (FAIL: No partial batch response)"

# Create Lambda function with Kinesis trigger without batching window (FAIL)
echo ""
echo "9. Creating Lambda function with Kinesis trigger (no batching window)..."
FUNCTION_NAME_5="${PREFIX}-no-batching"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_5" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 30 \
  --region "$REGION" \
  > /dev/null

# Add Kinesis event source mapping without batching window
aws lambda create-event-source-mapping \
  --function-name "$FUNCTION_NAME_5" \
  --event-source-arn "$STREAM_ARN" \
  --starting-position LATEST \
  --maximum-batching-window-in-seconds 0 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_5 (FAIL: No batching window)"

# Create Lambda function without environment variables (FAIL - Tier 2)
echo ""
echo "10. Creating Lambda function without environment variables..."
FUNCTION_NAME_6="${PREFIX}-no-env-vars"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_6" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 30 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_6 (FAIL: No environment variables)"

# Create Lambda function with over-provisioned memory (FAIL - Tier 2)
echo ""
echo "11. Creating Lambda function with over-provisioned memory..."
FUNCTION_NAME_7="${PREFIX}-memory-over"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_7" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --memory-size 3008 \
  --timeout 30 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_7 (FAIL: Over-provisioned memory - requires invocations to detect)"

# Create Lambda function with timeout too close to execution time (FAIL - Tier 2)
echo ""
echo "12. Creating Lambda function with low timeout..."
FUNCTION_NAME_8="${PREFIX}-timeout-low"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_8" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 3 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_8 (FAIL: Low timeout - requires invocations to detect)"

# Create IAM role with wildcard permissions for testing (FAIL - Tier 2)
echo ""
echo "13. Creating IAM role with wildcard permissions..."
PERMISSIVE_ROLE_NAME="${PREFIX}-permissive-role"
PERMISSIVE_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}'

aws iam create-role \
  --role-name "$PERMISSIVE_ROLE_NAME" \
  --assume-role-policy-document "$TRUST_POLICY" \
  --description "Test role with wildcard permissions" \
  > /dev/null

aws iam put-role-policy \
  --role-name "$PERMISSIVE_ROLE_NAME" \
  --policy-name "WildcardPolicy" \
  --policy-document "$PERMISSIVE_POLICY" \
  > /dev/null

PERMISSIVE_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${PERMISSIVE_ROLE_NAME}"
echo "   Created role: $PERMISSIVE_ROLE_ARN"

# Wait for role to propagate
sleep 10

# Create Lambda function with permissive role (FAIL - Tier 2)
echo ""
echo "14. Creating Lambda function with permissive IAM role..."
FUNCTION_NAME_9="${PREFIX}-permissive-role"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_9" \
  --runtime python3.11 \
  --role "$PERMISSIVE_ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 30 \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_9 (FAIL: Permissive IAM role)"

# Create Lambda function with proper configuration (PASS)
echo ""
echo "15. Creating Lambda function with proper configuration (PASS scenarios)..."
FUNCTION_NAME_10="${PREFIX}-pass"
aws lambda create-function \
  --function-name "$FUNCTION_NAME_10" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler index.lambda_handler \
  --zip-file "fileb://$FUNCTION_ZIP" \
  --timeout 30 \
  --memory-size 512 \
  --environment "Variables={ENV=production,LOG_LEVEL=info}" \
  --region "$REGION" \
  > /dev/null

# Configure async retry
aws lambda put-function-event-invoke-config \
  --function-name "$FUNCTION_NAME_10" \
  --maximum-retry-attempts 1 \
  --maximum-event-age-in-seconds 3600 \
  --region "$REGION" \
  > /dev/null

# Create CloudWatch alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "${FUNCTION_NAME_10}-errors" \
  --alarm-description "Test alarm for Lambda errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value="$FUNCTION_NAME_10" \
  --region "$REGION" \
  > /dev/null

echo "   Created function: $FUNCTION_NAME_10 (PASS: Proper configuration)"

# Cleanup temp directory
rm -rf "$TEMP_DIR"

# Save resource information
echo ""
echo "16. Saving resource information..."
RESOURCE_FILE="test_resources_${TIMESTAMP}.txt"
cat > "$RESOURCE_FILE" << EOF
# Lambda Service Screener Test Resources
# Created: $(date)
# Region: $REGION
# Prefix: $PREFIX

ROLE_NAME=$ROLE_NAME
PERMISSIVE_ROLE_NAME=$PERMISSIVE_ROLE_NAME
QUEUE_NAME=$QUEUE_NAME
STREAM_NAME=$STREAM_NAME
FUNCTION_NAME_1=$FUNCTION_NAME_1
FUNCTION_NAME_2=$FUNCTION_NAME_2
FUNCTION_NAME_3=$FUNCTION_NAME_3
FUNCTION_NAME_4=$FUNCTION_NAME_4
FUNCTION_NAME_5=$FUNCTION_NAME_5
FUNCTION_NAME_6=$FUNCTION_NAME_6
FUNCTION_NAME_7=$FUNCTION_NAME_7
FUNCTION_NAME_8=$FUNCTION_NAME_8
FUNCTION_NAME_9=$FUNCTION_NAME_9
FUNCTION_NAME_10=$FUNCTION_NAME_10
REGION=$REGION
EOF

echo "   Resource information saved to: $RESOURCE_FILE"

echo ""
echo "=========================================="
echo "Test resources created successfully!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - IAM Roles: 2 ($ROLE_NAME, $PERMISSIVE_ROLE_NAME)"
echo "  - SQS Queue: $QUEUE_NAME"
echo "  - Kinesis Stream: $STREAM_NAME"
echo "  - Lambda Functions: 10"
echo ""
echo "Expected Check Results (Tier 1):"
echo "  - $FUNCTION_NAME_1: FAIL (SQS visibility timeout)"
echo "  - $FUNCTION_NAME_2: FAIL (No async retry config)"
echo "  - $FUNCTION_NAME_3: FAIL (No CloudWatch alarms)"
echo "  - $FUNCTION_NAME_4: FAIL (No partial batch response)"
echo "  - $FUNCTION_NAME_5: FAIL (No batching window)"
echo ""
echo "Expected Check Results (Tier 2):"
echo "  - $FUNCTION_NAME_6: FAIL (No environment variables)"
echo "  - $FUNCTION_NAME_7: FAIL (Over-provisioned memory - needs invocations)"
echo "  - $FUNCTION_NAME_8: FAIL (Low timeout - needs invocations)"
echo "  - $FUNCTION_NAME_9: FAIL (Permissive IAM role)"
echo ""
echo "Expected Check Results (PASS):"
echo "  - $FUNCTION_NAME_10: PASS (Proper configuration)"
echo ""
echo "Note: Memory and timeout optimization checks require function invocations"
echo "      and CloudWatch Logs/Metrics data to detect issues."
echo ""
echo "To cleanup resources, run:"
echo "  ./cleanup_test_resources.sh $RESOURCE_FILE"
echo ""

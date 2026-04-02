#!/bin/bash

# Lambda Service - Test Resource Cleanup Script
# This script deletes all test resources created by create_test_resources.sh
# Usage: ./cleanup_test_resources.sh [resource_file]

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <resource_file>"
    echo "Example: $0 test_resources_1234567890.txt"
    exit 1
fi

RESOURCE_FILE="$1"

if [ ! -f "$RESOURCE_FILE" ]; then
    echo "Error: Resource file not found: $RESOURCE_FILE"
    exit 1
fi

echo "Loading resource information from: $RESOURCE_FILE"
source "$RESOURCE_FILE"

echo "Cleaning up test resources..."
echo "Region: $REGION"
echo ""

# Delete Lambda functions
echo "1. Deleting Lambda functions..."
for FUNC in "$FUNCTION_NAME_1" "$FUNCTION_NAME_2" "$FUNCTION_NAME_3" "$FUNCTION_NAME_4" "$FUNCTION_NAME_5" "$FUNCTION_NAME_6" "$FUNCTION_NAME_7" "$FUNCTION_NAME_8" "$FUNCTION_NAME_9" "$FUNCTION_NAME_10"; do
    if [ -n "$FUNC" ]; then
        echo "   Deleting function: $FUNC"
        
        # Delete event source mappings first
        MAPPINGS=$(aws lambda list-event-source-mappings \
          --function-name "$FUNC" \
          --region "$REGION" \
          --query 'EventSourceMappings[].UUID' \
          --output text 2>/dev/null || echo "")
        
        for UUID in $MAPPINGS; do
            if [ -n "$UUID" ]; then
                echo "     Deleting event source mapping: $UUID"
                aws lambda delete-event-source-mapping \
                  --uuid "$UUID" \
                  --region "$REGION" \
                  > /dev/null 2>&1 || true
            fi
        done
        
        # Delete function
        aws lambda delete-function \
          --function-name "$FUNC" \
          --region "$REGION" \
          > /dev/null 2>&1 || echo "     Function not found or already deleted"
    fi
done

# Delete CloudWatch alarms
echo ""
echo "2. Deleting CloudWatch alarms..."
if [ -n "$FUNCTION_NAME_10" ]; then
    ALARM_NAME="${FUNCTION_NAME_10}-errors"
    echo "   Deleting alarm: $ALARM_NAME"
    aws cloudwatch delete-alarms \
      --alarm-names "$ALARM_NAME" \
      --region "$REGION" \
      > /dev/null 2>&1 || echo "     Alarm not found or already deleted"
fi

# Delete Kinesis stream
echo ""
echo "3. Deleting Kinesis stream..."
if [ -n "$STREAM_NAME" ]; then
    echo "   Deleting stream: $STREAM_NAME"
    aws kinesis delete-stream \
      --stream-name "$STREAM_NAME" \
      --region "$REGION" \
      > /dev/null 2>&1 || echo "     Stream not found or already deleted"
fi

# Delete SQS queue
echo ""
echo "4. Deleting SQS queue..."
if [ -n "$QUEUE_NAME" ]; then
    echo "   Deleting queue: $QUEUE_NAME"
    QUEUE_URL=$(aws sqs get-queue-url \
      --queue-name "$QUEUE_NAME" \
      --region "$REGION" \
      --query QueueUrl --output text 2>/dev/null || echo "")
    
    if [ -n "$QUEUE_URL" ]; then
        aws sqs delete-queue \
          --queue-url "$QUEUE_URL" \
          --region "$REGION" \
          > /dev/null 2>&1 || echo "     Queue not found or already deleted"
    else
        echo "     Queue not found or already deleted"
    fi
fi

# Delete IAM roles
echo ""
echo "5. Deleting IAM roles..."

# Delete permissive role
if [ -n "$PERMISSIVE_ROLE_NAME" ]; then
    echo "   Processing role: $PERMISSIVE_ROLE_NAME"
    
    # Detach managed policies
    POLICIES=$(aws iam list-attached-role-policies \
      --role-name "$PERMISSIVE_ROLE_NAME" \
      --query 'AttachedPolicies[].PolicyArn' \
      --output text 2>/dev/null || echo "")
    
    for POLICY_ARN in $POLICIES; do
        if [ -n "$POLICY_ARN" ]; then
            echo "     Detaching policy: $POLICY_ARN"
            aws iam detach-role-policy \
              --role-name "$PERMISSIVE_ROLE_NAME" \
              --policy-arn "$POLICY_ARN" \
              > /dev/null 2>&1 || true
        fi
    done
    
    # Delete inline policies
    INLINE_POLICIES=$(aws iam list-role-policies \
      --role-name "$PERMISSIVE_ROLE_NAME" \
      --query 'PolicyNames' \
      --output text 2>/dev/null || echo "")
    
    for POLICY_NAME in $INLINE_POLICIES; do
        if [ -n "$POLICY_NAME" ]; then
            echo "     Deleting inline policy: $POLICY_NAME"
            aws iam delete-role-policy \
              --role-name "$PERMISSIVE_ROLE_NAME" \
              --policy-name "$POLICY_NAME" \
              > /dev/null 2>&1 || true
        fi
    done
    
    echo "   Deleting role: $PERMISSIVE_ROLE_NAME"
    aws iam delete-role \
      --role-name "$PERMISSIVE_ROLE_NAME" \
      > /dev/null 2>&1 || echo "     Role not found or already deleted"
fi

# Delete main role
if [ -n "$ROLE_NAME" ]; then
    echo "   Processing role: $ROLE_NAME"
    
    # Detach managed policies
    POLICIES=$(aws iam list-attached-role-policies \
      --role-name "$ROLE_NAME" \
      --query 'AttachedPolicies[].PolicyArn' \
      --output text 2>/dev/null || echo "")
    
    for POLICY_ARN in $POLICIES; do
        if [ -n "$POLICY_ARN" ]; then
            echo "     Detaching policy: $POLICY_ARN"
            aws iam detach-role-policy \
              --role-name "$ROLE_NAME" \
              --policy-arn "$POLICY_ARN" \
              > /dev/null 2>&1 || true
        fi
    done
    
    # Delete inline policies
    INLINE_POLICIES=$(aws iam list-role-policies \
      --role-name "$ROLE_NAME" \
      --query 'PolicyNames' \
      --output text 2>/dev/null || echo "")
    
    for POLICY_NAME in $INLINE_POLICIES; do
        if [ -n "$POLICY_NAME" ]; then
            echo "     Deleting inline policy: $POLICY_NAME"
            aws iam delete-role-policy \
              --role-name "$ROLE_NAME" \
              --policy-name "$POLICY_NAME" \
              > /dev/null 2>&1 || true
        fi
    done
    
    echo "   Deleting role: $ROLE_NAME"
    aws iam delete-role \
      --role-name "$ROLE_NAME" \
      > /dev/null 2>&1 || echo "     Role not found or already deleted"
fi

echo ""
echo "=========================================="
echo "Cleanup completed!"
echo "=========================================="
echo ""
echo "All test resources have been deleted."
echo "Resource file: $RESOURCE_FILE (you can delete this manually)"
echo ""

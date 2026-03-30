#!/bin/bash

# KMS Test Resources Creation Script
# This script creates KMS keys with various configurations to test new checks

set -e

REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TAG_KEY="ServiceScreenerTest"
TAG_VALUE="kms-test-${TIMESTAMP}"

echo "=========================================="
echo "KMS Test Resources Creation"
echo "=========================================="
echo "Region: $REGION"
echo "Account: $ACCOUNT_ID"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="

# Function to create a key with tags
create_key() {
    local description=$1
    >&2 echo "Creating key: $description"
    
    KEY_ID=$(aws kms create-key \
        --region $REGION \
        --description "$description" \
        --tags TagKey=$TAG_KEY,TagValue=$TAG_VALUE \
        --query 'KeyMetadata.KeyId' \
        --output text)
    
    >&2 echo "Created key: $KEY_ID"
    echo "$KEY_ID"
}

# Function to create an alias
create_alias() {
    local key_id=$1
    local alias_name=$2
    
    echo "Creating alias: $alias_name for key $key_id"
    aws kms create-alias \
        --region $REGION \
        --alias-name "alias/$alias_name" \
        --target-key-id "$key_id"
}

echo ""
echo "1. Creating key with rotation disabled (should fail KeyRotationEnabled)"
KEY_NO_ROTATION=$(create_key "Test key without rotation - $TIMESTAMP")
create_alias "$KEY_NO_ROTATION" "test-no-rotation-$TIMESTAMP"

echo ""
echo "2. Creating key with rotation enabled (should pass KeyRotationEnabled)"
KEY_WITH_ROTATION=$(create_key "Test key with rotation - $TIMESTAMP")
create_alias "$KEY_WITH_ROTATION" "test-with-rotation-$TIMESTAMP"
aws kms enable-key-rotation --region $REGION --key-id "$KEY_WITH_ROTATION"

echo ""
echo "3. Creating key with overly permissive grant"
KEY_PERMISSIVE_GRANT=$(create_key "Test key with permissive grant - $TIMESTAMP")
create_alias "$KEY_PERMISSIVE_GRANT" "test-permissive-grant-$TIMESTAMP"

# Get current user ARN
USER_ARN=$(aws sts get-caller-identity --query Arn --output text)

# Create grant with many operations
GRANT_ID=$(aws kms create-grant \
    --region $REGION \
    --key-id "$KEY_PERMISSIVE_GRANT" \
    --grantee-principal "$USER_ARN" \
    --operations Encrypt Decrypt GenerateDataKey CreateGrant RetireGrant DescribeKey \
    --query 'GrantId' \
    --output text)

echo "Created overly permissive grant: $GRANT_ID"

echo ""
echo "4. Creating key with duplicate grants"
KEY_DUPLICATE_GRANTS=$(create_key "Test key with duplicate grants - $TIMESTAMP")
create_alias "$KEY_DUPLICATE_GRANTS" "test-duplicate-grants-$TIMESTAMP"

# Create two identical grants
GRANT1=$(aws kms create-grant \
    --region $REGION \
    --key-id "$KEY_DUPLICATE_GRANTS" \
    --grantee-principal "$USER_ARN" \
    --operations Encrypt Decrypt \
    --query 'GrantId' \
    --output text)

GRANT2=$(aws kms create-grant \
    --region $REGION \
    --key-id "$KEY_DUPLICATE_GRANTS" \
    --grantee-principal "$USER_ARN" \
    --operations Encrypt Decrypt \
    --query 'GrantId' \
    --output text)

echo "Created duplicate grants: $GRANT1, $GRANT2"

echo ""
echo "5. Creating key with wildcard action in policy"
KEY_WILDCARD_ACTION=$(create_key "Test key with wildcard action - $TIMESTAMP")
create_alias "$KEY_WILDCARD_ACTION" "test-wildcard-action-$TIMESTAMP"

# Create policy with wildcard action
POLICY_WILDCARD_ACTION=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow wildcard actions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "$USER_ARN"
      },
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
)

aws kms put-key-policy \
    --region $REGION \
    --key-id "$KEY_WILDCARD_ACTION" \
    --policy-name default \
    --policy "$POLICY_WILDCARD_ACTION"

echo "Applied policy with wildcard action"

echo ""
echo "6. Creating key without root access in policy"
KEY_NO_ROOT=$(create_key "Test key without root access - $TIMESTAMP")
create_alias "$KEY_NO_ROOT" "test-no-root-$TIMESTAMP"

# Create policy without root access
POLICY_NO_ROOT=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow specific user only",
      "Effect": "Allow",
      "Principal": {
        "AWS": "$USER_ARN"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
EOF
)

aws kms put-key-policy \
    --region $REGION \
    --key-id "$KEY_NO_ROOT" \
    --policy-name default \
    --policy "$POLICY_NO_ROOT"

echo "Applied policy without root access"

echo ""
echo "7. Creating key with grant missing encryption context (Tier 2)"
KEY_NO_ENCRYPTION_CONTEXT=$(create_key "Test key with grant missing encryption context - $TIMESTAMP")
create_alias "$KEY_NO_ENCRYPTION_CONTEXT" "test-no-encryption-context-$TIMESTAMP"

# Create grant without encryption context constraints
GRANT_NO_CONTEXT=$(aws kms create-grant \
    --region $REGION \
    --key-id "$KEY_NO_ENCRYPTION_CONTEXT" \
    --grantee-principal "$USER_ARN" \
    --operations Encrypt Decrypt \
    --query 'GrantId' \
    --output text)

echo "Created grant without encryption context: $GRANT_NO_CONTEXT"

echo ""
echo "8. Creating key with policy missing sensitive actions (Tier 2)"
KEY_NO_SENSITIVE_ACTIONS=$(create_key "Test key with policy missing sensitive actions - $TIMESTAMP")
create_alias "$KEY_NO_SENSITIVE_ACTIONS" "test-no-sensitive-actions-$TIMESTAMP"

# Create policy without PutKeyPolicy or ScheduleKeyDeletion
POLICY_NO_SENSITIVE=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:PutKeyPolicy",
        "kms:GetKeyPolicy"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)

aws kms put-key-policy \
    --region $REGION \
    --key-id "$KEY_NO_SENSITIVE_ACTIONS" \
    --policy-name default \
    --policy "$POLICY_NO_SENSITIVE"

echo "Applied policy without sensitive actions"

echo ""
echo "9. Creating key with policy statements without conditions (Tier 2)"
KEY_NO_CONDITIONS=$(create_key "Test key with policy without conditions - $TIMESTAMP")
create_alias "$KEY_NO_CONDITIONS" "test-no-conditions-$TIMESTAMP"

# Create policy with statements lacking conditions
POLICY_NO_CONDITIONS=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow user without conditions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "$USER_ARN"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)

aws kms put-key-policy \
    --region $REGION \
    --key-id "$KEY_NO_CONDITIONS" \
    --policy-name default \
    --policy "$POLICY_NO_CONDITIONS"

echo "Applied policy without conditions on user statement"

echo ""
echo "10. Creating disabled key for unused check (Tier 2)"
KEY_UNUSED=$(create_key "Test unused key - $TIMESTAMP")
create_alias "$KEY_UNUSED" "test-unused-$TIMESTAMP"

# Disable the key to simulate unused state
aws kms disable-key --region $REGION --key-id "$KEY_UNUSED"

echo "Disabled key to simulate unused state"

echo ""
echo "=========================================="
echo "Test Resources Created Successfully"
echo "=========================================="
echo ""
echo "Summary of created resources:"
echo "Tier 1 Checks:"
echo "1. Key without rotation: $KEY_NO_ROTATION"
echo "2. Key with rotation: $KEY_WITH_ROTATION"
echo "3. Key with permissive grant: $KEY_PERMISSIVE_GRANT"
echo "4. Key with duplicate grants: $KEY_DUPLICATE_GRANTS"
echo "5. Key with wildcard action: $KEY_WILDCARD_ACTION"
echo "6. Key without root access: $KEY_NO_ROOT"
echo ""
echo "Tier 2 Checks:"
echo "7. Key with grant missing encryption context: $KEY_NO_ENCRYPTION_CONTEXT"
echo "8. Key with policy missing sensitive actions: $KEY_NO_SENSITIVE_ACTIONS"
echo "9. Key with policy without conditions: $KEY_NO_CONDITIONS"
echo "10. Disabled/unused key: $KEY_UNUSED"
echo ""
echo "Note: GrantOldAge check requires grants >180 days old (cannot simulate)"
echo "Note: KeyCentralizedManagement check requires multi-account setup (cannot simulate)"
echo ""
echo "All keys are tagged with: $TAG_KEY=$TAG_VALUE"
echo ""
echo "To run Service Screener on these keys:"
echo "  python3 main.py --regions $REGION --services kms --tags $TAG_KEY=$TAG_VALUE"
echo ""
echo "To cleanup these resources:"
echo "  ./cleanup_test_resources.sh $TAG_VALUE"
echo ""

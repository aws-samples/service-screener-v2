#!/bin/bash

# CloudTrail Test Resources Cleanup Script
# Deletes all test resources created by create_test_resources.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test-cloudtrail"

echo -e "${GREEN}Cleaning up CloudTrail test resources in region: ${REGION}${NC}"
echo "Prefix: ${PREFIX}"
echo ""

# Check if timestamp file exists
if [ -f .last_test_timestamp ]; then
    TIMESTAMP=$(cat .last_test_timestamp)
    echo "Found timestamp from last run: ${TIMESTAMP}"
    echo ""
else
    echo -e "${YELLOW}No timestamp file found. Will search for all resources with prefix: ${PREFIX}${NC}"
    echo ""
    TIMESTAMP=""
fi

# Get AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Account ID: ${ACCOUNT_ID}"
echo ""

echo "=== Cleaning up CloudTrail Trails ===${NC}"
echo ""

# List and delete trails
TRAILS=$(aws cloudtrail list-trails --region "${REGION}" --query "Trails[?contains(Name, '${PREFIX}')].Name" --output text)

if [ -n "$TRAILS" ]; then
    for trail in $TRAILS; do
        echo -e "${YELLOW}Deleting trail: ${trail}${NC}"
        aws cloudtrail stop-logging --name "${trail}" --region "${REGION}" 2>/dev/null || true
        aws cloudtrail delete-trail --name "${trail}" --region "${REGION}"
        echo "Deleted: ${trail}"
    done
else
    echo "No trails found with prefix: ${PREFIX}"
fi
echo ""

echo "=== Cleaning up CloudWatch Alarms ===${NC}"
echo ""

# List and delete alarms
ALARMS=$(aws cloudwatch describe-alarms --region "${REGION}" --query "MetricAlarms[?contains(AlarmName, '${PREFIX}')].AlarmName" --output text)

if [ -n "$ALARMS" ]; then
    for alarm in $ALARMS; do
        echo -e "${YELLOW}Deleting alarm: ${alarm}${NC}"
        aws cloudwatch delete-alarms --alarm-names "${alarm}" --region "${REGION}"
        echo "Deleted: ${alarm}"
    done
else
    echo "No alarms found with prefix: ${PREFIX}"
fi
echo ""

echo "=== Cleaning up CloudWatch Metric Filters ===${NC}"
echo ""

# List log groups and delete metric filters
LOG_GROUPS=$(aws logs describe-log-groups --region "${REGION}" --query "logGroups[?contains(logGroupName, '${PREFIX}')].logGroupName" --output text)

if [ -n "$LOG_GROUPS" ]; then
    for log_group in $LOG_GROUPS; do
        echo -e "${YELLOW}Checking metric filters for log group: ${log_group}${NC}"
        FILTERS=$(aws logs describe-metric-filters --log-group-name "${log_group}" --region "${REGION}" --query "metricFilters[?contains(filterName, '${PREFIX}')].filterName" --output text)
        
        if [ -n "$FILTERS" ]; then
            for filter in $FILTERS; do
                echo -e "${YELLOW}Deleting metric filter: ${filter}${NC}"
                aws logs delete-metric-filter --log-group-name "${log_group}" --filter-name "${filter}" --region "${REGION}"
                echo "Deleted: ${filter}"
            done
        fi
    done
fi
echo ""

echo "=== Cleaning up CloudWatch Logs Log Groups ===${NC}"
echo ""

if [ -n "$LOG_GROUPS" ]; then
    for log_group in $LOG_GROUPS; do
        echo -e "${YELLOW}Deleting log group: ${log_group}${NC}"
        aws logs delete-log-group --log-group-name "${log_group}" --region "${REGION}"
        echo "Deleted: ${log_group}"
    done
else
    echo "No log groups found with prefix: ${PREFIX}"
fi
echo ""

echo "=== Cleaning up IAM Test User ===${NC}"
echo ""

# List and delete test users
USERS=$(aws iam list-users --query "Users[?contains(UserName, '${PREFIX}')].UserName" --output text)

if [ -n "$USERS" ]; then
    for user in $USERS; do
        echo -e "${YELLOW}Detaching policies from user: ${user}${NC}"
        
        # Detach managed policies
        ATTACHED_POLICIES=$(aws iam list-attached-user-policies --user-name "${user}" --query "AttachedPolicies[].PolicyArn" --output text)
        if [ -n "$ATTACHED_POLICIES" ]; then
            for policy_arn in $ATTACHED_POLICIES; do
                echo "Detaching policy: ${policy_arn}"
                aws iam detach-user-policy --user-name "${user}" --policy-arn "${policy_arn}"
            done
        fi
        
        # Delete inline policies
        INLINE_POLICIES=$(aws iam list-user-policies --user-name "${user}" --query "PolicyNames[]" --output text)
        if [ -n "$INLINE_POLICIES" ]; then
            for policy_name in $INLINE_POLICIES; do
                echo "Deleting inline policy: ${policy_name}"
                aws iam delete-user-policy --user-name "${user}" --policy-name "${policy_name}"
            done
        fi
        
        echo -e "${YELLOW}Deleting user: ${user}${NC}"
        aws iam delete-user --user-name "${user}"
        echo "Deleted: ${user}"
    done
else
    echo "No test users found with prefix: ${PREFIX}"
fi
echo ""

echo "=== Cleaning up IAM Roles ===${NC}"
echo ""

# List and delete IAM roles
ROLES=$(aws iam list-roles --query "Roles[?contains(RoleName, '${PREFIX}')].RoleName" --output text)

if [ -n "$ROLES" ]; then
    for role in $ROLES; do
        echo -e "${YELLOW}Cleaning up role: ${role}${NC}"
        
        # Detach managed policies
        ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name "${role}" --query "AttachedPolicies[].PolicyArn" --output text)
        if [ -n "$ATTACHED_POLICIES" ]; then
            for policy_arn in $ATTACHED_POLICIES; do
                echo "Detaching policy: ${policy_arn}"
                aws iam detach-role-policy --role-name "${role}" --policy-arn "${policy_arn}"
            done
        fi
        
        # Delete inline policies
        INLINE_POLICIES=$(aws iam list-role-policies --role-name "${role}" --query "PolicyNames[]" --output text)
        if [ -n "$INLINE_POLICIES" ]; then
            for policy_name in $INLINE_POLICIES; do
                echo "Deleting inline policy: ${policy_name}"
                aws iam delete-role-policy --role-name "${role}" --policy-name "${policy_name}"
            done
        fi
        
        echo -e "${YELLOW}Deleting role: ${role}${NC}"
        aws iam delete-role --role-name "${role}"
        echo "Deleted: ${role}"
    done
else
    echo "No roles found with prefix: ${PREFIX}"
fi
echo ""

echo "=== Cleaning up KMS Keys ===${NC}"
echo ""

# List and schedule deletion of KMS keys
KMS_ALIASES=$(aws kms list-aliases --region "${REGION}" --query "Aliases[?contains(AliasName, '${PREFIX}')].TargetKeyId" --output text)

if [ -n "$KMS_ALIASES" ]; then
    for key_id in $KMS_ALIASES; do
        if [ -n "$key_id" ] && [ "$key_id" != "None" ]; then
            echo -e "${YELLOW}Scheduling deletion for KMS key: ${key_id}${NC}"
            aws kms schedule-key-deletion \
                --key-id "${key_id}" \
                --pending-window-in-days 7 \
                --region "${REGION}" 2>/dev/null || echo "Key may already be scheduled for deletion"
            echo "Scheduled for deletion (7 days): ${key_id}"
        fi
    done
else
    echo "No KMS keys found with prefix: ${PREFIX}"
fi
echo ""

echo "=== Cleaning up S3 Buckets ===${NC}"
echo ""

# List and delete S3 buckets
BUCKETS=$(aws s3api list-buckets --query "Buckets[?contains(Name, '${PREFIX}')].Name" --output text)

if [ -n "$BUCKETS" ]; then
    for bucket in $BUCKETS; do
        echo -e "${YELLOW}Emptying and deleting bucket: ${bucket}${NC}"
        
        # Empty bucket first
        echo "Emptying bucket..."
        aws s3 rm "s3://${bucket}" --recursive 2>/dev/null || true
        
        # Delete bucket
        echo "Deleting bucket..."
        aws s3api delete-bucket --bucket "${bucket}" --region "${REGION}" 2>/dev/null || echo "Bucket may not be empty or may not exist"
        echo "Deleted: ${bucket}"
    done
else
    echo "No buckets found with prefix: ${PREFIX}"
fi
echo ""

# Clean up timestamp file
if [ -f .last_test_timestamp ]; then
    rm .last_test_timestamp
    echo "Removed timestamp file"
fi

echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "All test resources with prefix '${PREFIX}' have been deleted or scheduled for deletion."
echo ""
echo -e "${YELLOW}Note: KMS keys are scheduled for deletion with a 7-day waiting period.${NC}"
echo "You can cancel the deletion within 7 days if needed using:"
echo "  aws kms cancel-key-deletion --key-id <key-id> --region ${REGION}"
echo ""
echo -e "${YELLOW}Manual cleanup may be required for:${NC}"
echo "- GuardDuty detectors (if enabled during testing)"
echo "- Security Hub (if enabled during testing)"
echo "- Organization trails (if created during testing)"
echo ""

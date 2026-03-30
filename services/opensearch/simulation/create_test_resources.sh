#!/bin/bash

################################################################################
# OpenSearch Service Review - Test Resource Creation Script
#
# Creates a single minimal OpenSearch domain with intentionally weak config
# to trigger as many checks as possible from OpensearchCommon.py.
#
# Resources Created:
#   1. Security Group
#   2. OpenSearch domain (t3.small.search, single-node, minimal security)
#
# Checks expected to FAIL:
#   DedicatedMasterNodes (none), DataNodes (<3), AvailabilityZones (single),
#   EngineVersion (older), TSeriesForProduction (t3), SearchSlowLogs,
#   ApplicationLogs, AuditLogs, AutoTune, UltrawarmEnabled, ColdStorage,
#   CloudWatchAlarms (none configured)
#
# Checks expected to PASS:
#   DomainWithinVPC (VPC deployed), EncyptionAtRest, NodeToNodeEncryption,
#   TLSEnforced, FineGrainedAccessControl
#
# Usage:
#   ./create_test_resources.sh [OPTIONS]
#
# Options:
#   --region REGION    AWS region (default: ap-southeast-1)
#   --help             Show this help message
#
################################################################################

set -e
set -u

REGION="${AWS_REGION:-ap-southeast-1}"
PREFIX="os-sim"
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

# OpenSearch domain names: lowercase, 3-28 chars, start with letter
DOMAIN_NAME="${PREFIX}-${TIMESTAMP}"
SG_NAME="${PREFIX}-sg-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

echo -e "${GREEN}=== OpenSearch Test Resource Creation ===${NC}"
echo "Region: $REGION | Timestamp: $TIMESTAMP"
echo -e "${YELLOW}WARNING: OpenSearch domain costs ~\$0.04/hour (t3.small.search). Clean up promptly!${NC}"
echo ""

################################################################################
# Step 0: Detect VPC and Subnet
################################################################################

echo -e "${CYAN}--- Detecting VPC and subnet ---${NC}"

VPC_ID=$(aws ec2 describe-vpcs \
    --filters Name=isDefault,Values=true \
    --query 'Vpcs[0].VpcId' --output text \
    --region "$REGION")

if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
    echo -e "${RED}Error: No default VPC found.${NC}"
    exit 1
fi

SUBNET_ID=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=default-for-az,Values=true" \
    --query 'Subnets[0].SubnetId' --output text \
    --region "$REGION")

echo "VPC: $VPC_ID | Subnet: $SUBNET_ID"

################################################################################
# Step 1: Create Security Group
################################################################################

echo -e "\n${GREEN}=== Step 1: Creating Security Group ===${NC}"

SG_ID=$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "OpenSearch simulation SG" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text \
    --region "$REGION")

log_resource "SECURITY_GROUP:$SG_ID"
echo -e "${GREEN}✓ Security Group created: $SG_ID${NC}"

################################################################################
# Step 2: Create OpenSearch Domain (intentionally weak config)
# - Single t3.small.search node (triggers DataNodes, TSeriesForProduction)
# - No dedicated masters (triggers DedicatedMasterNodes)
# - Single AZ (triggers AvailabilityZones)
# - Older engine version (triggers EngineVersion)
# - No logs configured (triggers SearchSlowLogs, ApplicationLogs, AuditLogs)
# - AutoTune disabled
# - No Ultrawarm/ColdStorage
# - Encryption enabled (required for VPC + fine-grained access)
################################################################################

echo -e "\n${GREEN}=== Step 2: Creating OpenSearch Domain ===${NC}"
echo "This will take 10-20 minutes..."

aws opensearch create-domain \
    --domain-name "$DOMAIN_NAME" \
    --engine-version "OpenSearch_2.11" \
    --cluster-config \
        "InstanceType=t3.small.search,InstanceCount=1,DedicatedMasterEnabled=false,ZoneAwarenessEnabled=false,WarmEnabled=false,ColdStorageOptions={Enabled=false}" \
    --ebs-options "EBSEnabled=true,VolumeType=gp3,VolumeSize=10" \
    --vpc-options "SubnetIds=$SUBNET_ID,SecurityGroupIds=$SG_ID" \
    --encryption-at-rest-options "Enabled=true" \
    --node-to-node-encryption-options "Enabled=true" \
    --domain-endpoint-options "EnforceHTTPS=true,TLSSecurityPolicy=Policy-Min-TLS-1-2-2019-07" \
    --advanced-security-options "Enabled=true,InternalUserDatabaseEnabled=true,MasterUserOptions={MasterUserName=admin,MasterUserPassword=Admin1234!}" \
    --access-policies "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::${ACCOUNT_ID}:root\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:${REGION}:${ACCOUNT_ID}:domain/${DOMAIN_NAME}/*\"}]}" \
    --region "$REGION" > /dev/null

log_resource "DOMAIN:$DOMAIN_NAME"
echo -e "${GREEN}✓ Domain creation initiated: $DOMAIN_NAME${NC}"

################################################################################
# Wait for domain
################################################################################

echo -e "\n${YELLOW}=== Waiting for domain to become available ===${NC}"

# opensearch doesn't have a built-in waiter in all CLI versions, poll manually
while true; do
    STATUS=$(aws opensearch describe-domain \
        --domain-name "$DOMAIN_NAME" \
        --query 'DomainStatus.Processing' --output text \
        --region "$REGION" 2>/dev/null || echo "true")
    if [ "$STATUS" = "False" ]; then
        break
    fi
    echo "  Still creating... (checking again in 30s)"
    sleep 30
done

echo -e "${GREEN}✓ Domain is available${NC}"

################################################################################
# Summary
################################################################################

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}=== All Resources Created ===${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Resources saved to: $OUTPUT_FILE"
echo ""
echo "Created:"
echo "  ✓ Security Group:  $SG_ID"
echo "  ✓ Domain:          $DOMAIN_NAME"
echo ""
echo "Next steps:"
echo "  1. Run screener:"
echo "     cd /Users/kuettai/Documents/project/ssvsprowler/service-screener-v2"
echo "     python main.py --services opensearch --regions $REGION --sequential 1 --beta 1"
echo ""
echo "  2. Cleanup when done:"
echo "     ./cleanup_test_resources.sh $OUTPUT_FILE --region $REGION"
echo ""
echo -e "${RED}IMPORTANT: ~\$0.04/hour while running. Clean up promptly!${NC}"

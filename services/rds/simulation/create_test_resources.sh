#!/bin/bash

################################################################################
# RDS Service Review - Comprehensive Test Resource Creation Script
#
# Purpose: Create RDS test resources to trigger as many checks as possible
#          from the RDS service review.
#
# Resources Created:
#   1. Custom MySQL Parameter Group (with suboptimal parameter values)
#   2. Custom PostgreSQL Parameter Group (with suboptimal parameter values)
#   3. DB Subnet Group (with 2 AZs only, triggers Subnets3Az)
#   4. Security Group with public CIDR (triggers SecurityGroupIPRangeNotPrivateCidr)
#   5. RDS MySQL instance (triggers ~15 checks via bad config)
#   6. RDS PostgreSQL instance (triggers ~15 checks via bad config)
#   7. SNS Topic (for optional event subscription testing)
#   8. No event subscription (triggers EventSubscriptionNotConfigured)
#
# Checks NOT covered (require days of data, Aurora, MSSQL, or special setup):
#   - FreeStorage20pct, FreeMemory*, RightSizing*, RdsIsIdle7days
#   - AuroraStorageType*, Aurora__ClusterSize, AuroraStorage64TBLimit
#   - MSSQL__* (require MSSQL license)
#   - MYSQLA__* (require Aurora MySQL)
#   - ManualSnapshotTooOld, ManualSnapshotTooMany
#   - CACertExpiringIn365days, CrossRegionBackupNotEnabled
#   - EngineVersionMajor/Minor, LatestInstanceGeneration
#   - SnapshotRDSIsPublic (security risk)
#   - Secret__NoRotation, Secret__NotUsed7days
#   - DBwithoutSecretManager, DBwithSomeSecretsManagerOnly
#
# Prerequisites:
#   - AWS CLI v2 installed and configured
#   - IAM permissions for RDS, EC2, SNS
#   - A VPC with at least 2 subnets in different AZs
#
# Usage:
#   ./create_test_resources.sh [OPTIONS]
#
# Options:
#   --region REGION          AWS region (default: us-east-1)
#   --prefix PREFIX          Resource name prefix (default: rds-sim)
#   --vpc-id VPC_ID          VPC ID (default: auto-detect default VPC)
#   --help                   Show this help message
#
################################################################################

set -e
set -u

# Default values
REGION="us-east-1"
PREFIX="rds-sim"
VPC_ID=""
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region)  REGION="$2"; shift 2 ;;
        --prefix)  PREFIX="$2"; shift 2 ;;
        --vpc-id)  VPC_ID="$2"; shift 2 ;;
        --help)    grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)         echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

# Resource names
MYSQL_PG_NAME="${PREFIX}-mysql-params-${TIMESTAMP}"
PG_PG_NAME="${PREFIX}-pg-params-${TIMESTAMP}"
SUBNET_GROUP_NAME="${PREFIX}-subnet-2az-${TIMESTAMP}"
SG_NAME="${PREFIX}-public-sg-${TIMESTAMP}"
MYSQL_INSTANCE_ID="${PREFIX}-mysql-${TIMESTAMP}"
PG_INSTANCE_ID="${PREFIX}-pg-${TIMESTAMP}"
SNS_TOPIC_NAME="${PREFIX}-events-${TIMESTAMP}"

OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"

log_resource() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== RDS Comprehensive Test Resource Creation ===${NC}"
echo "Region: $REGION | Prefix: $PREFIX | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 0: Detect VPC and Subnets
################################################################################

echo -e "${CYAN}--- Detecting VPC and subnets ---${NC}"

if [ -z "$VPC_ID" ]; then
    VPC_ID=$(aws ec2 describe-vpcs \
        --filters Name=isDefault,Values=true \
        --query 'Vpcs[0].VpcId' --output text \
        --region "$REGION")
    echo "Auto-detected default VPC: $VPC_ID"
fi

if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
    echo -e "${RED}Error: No default VPC found. Use --vpc-id to specify one.${NC}"
    exit 1
fi

# Get all subnets, pick 2 from different AZs (for Subnets3Az trigger)
ALL_SUBNETS=$(aws ec2 describe-subnets \
    --filters Name=vpc-id,Values="$VPC_ID" \
    --query 'Subnets[*].[SubnetId,AvailabilityZone]' --output text \
    --region "$REGION")

SUBNET_1=$(echo "$ALL_SUBNETS" | head -1 | awk '{print $1}')
AZ_1=$(echo "$ALL_SUBNETS" | head -1 | awk '{print $2}')
SUBNET_2=$(echo "$ALL_SUBNETS" | awk -v az="$AZ_1" '$2 != az {print $1; exit}')

if [ -z "$SUBNET_2" ]; then
    echo -e "${YELLOW}Warning: Only 1 AZ available. Subnets3Az check may not trigger as expected.${NC}"
    SUBNET_2="$SUBNET_1"
fi

echo "Using subnets: $SUBNET_1, $SUBNET_2"

################################################################################
# Step 1: Create Security Group with public CIDR rule
# Triggers: SecurityGroupIPRangeNotPrivateCidr
################################################################################

echo -e "\n${GREEN}=== Step 1: Creating Security Group with public CIDR ===${NC}"

SG_ID=$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "RDS simulation - public CIDR test" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text \
    --region "$REGION")

log_resource "SECURITY_GROUP:$SG_ID"

# Add inbound rule with public IP range (triggers SecurityGroupIPRangeNotPrivateCidr)
aws ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" \
    --protocol tcp \
    --port 3306 \
    --cidr "8.8.8.0/24" \
    --region "$REGION"

# Add another rule for PostgreSQL port
aws ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" \
    --protocol tcp \
    --port 5432 \
    --cidr "1.1.1.0/24" \
    --region "$REGION"

echo -e "${GREEN}✓ Security Group created: $SG_ID (public CIDRs added)${NC}"

################################################################################
# Step 2: Create DB Subnet Group with only 2 AZs
# Triggers: Subnets3Az (< 3 AZs)
################################################################################

echo -e "\n${GREEN}=== Step 2: Creating DB Subnet Group (2 AZs only) ===${NC}"

aws rds create-db-subnet-group \
    --db-subnet-group-name "$SUBNET_GROUP_NAME" \
    --db-subnet-group-description "RDS simulation - 2 AZ subnet group" \
    --subnet-ids "$SUBNET_1" "$SUBNET_2" \
    --tags Key=Purpose,Value=RdsSimulation \
    --region "$REGION"

log_resource "DB_SUBNET_GROUP:$SUBNET_GROUP_NAME"
echo -e "${GREEN}✓ DB Subnet Group created: $SUBNET_GROUP_NAME${NC}"

################################################################################
# Step 3: Create MySQL Custom Parameter Group with suboptimal values
# Triggers: MYSQL__param_syncBinLog, MYSQL__param_innodbFlushTrxCommit,
#           MYSQL__PerfSchema, MYSQL__parammAutoCommit,
#           MYSQL__parammInnodbStatsPersistent, MYSQL__LogsGeneral,
#           MYSQL__innodb_change_buffering, MYSQL__innodb_open_files
# Also: NOT using default param group avoids DefaultParams trigger for MySQL
#        (we want DefaultParams to trigger on PG instance instead)
################################################################################

echo -e "\n${GREEN}=== Step 3: Creating MySQL Parameter Group ===${NC}"

aws rds create-db-parameter-group \
    --db-parameter-group-name "$MYSQL_PG_NAME" \
    --db-parameter-group-family mysql8.0 \
    --description "RDS simulation - suboptimal MySQL params" \
    --tags Key=Purpose,Value=RdsSimulation \
    --region "$REGION"

log_resource "DB_PARAM_GROUP:$MYSQL_PG_NAME"

# Set suboptimal parameter values
echo "Setting MySQL parameters..."

aws rds modify-db-parameter-group \
    --db-parameter-group-name "$MYSQL_PG_NAME" \
    --parameters \
        "ParameterName=performance_schema,ParameterValue=0,ApplyMethod=pending-reboot" \
        "ParameterName=autocommit,ParameterValue=0,ApplyMethod=pending-reboot" \
        "ParameterName=innodb_stats_persistent,ParameterValue=0,ApplyMethod=pending-reboot" \
        "ParameterName=innodb_flush_log_at_trx_commit,ParameterValue=0,ApplyMethod=immediate" \
        "ParameterName=sync_binlog,ParameterValue=0,ApplyMethod=immediate" \
        "ParameterName=general_log,ParameterValue=1,ApplyMethod=immediate" \
        "ParameterName=innodb_change_buffering,ParameterValue=inserts,ApplyMethod=immediate" \
        "ParameterName=innodb_open_files,ParameterValue=50,ApplyMethod=pending-reboot" \
    --region "$REGION"

echo -e "${GREEN}✓ MySQL Parameter Group created with suboptimal values${NC}"

################################################################################
# Step 4: Create PostgreSQL Custom Parameter Group with suboptimal values
# Triggers: PG__param_idleTransTimeout, PG__param_statementTimeout,
#           PG__param_logTempFiles, PG__param_tempFileLimit,
#           PG__param_rdsAutoVacuumLevel, PG__param_autoVacDuration,
#           PG__param_trackIoTime, PG__param_logStatement,
#           PG__param_synchronousCommit, MSSQLorPG__TransportEncrpytionDisabled
################################################################################

echo -e "\n${GREEN}=== Step 4: Creating PostgreSQL Parameter Group ===${NC}"

aws rds create-db-parameter-group \
    --db-parameter-group-name "$PG_PG_NAME" \
    --db-parameter-group-family postgres16 \
    --description "RDS simulation - suboptimal PG params" \
    --tags Key=Purpose,Value=RdsSimulation \
    --region "$REGION"

log_resource "DB_PARAM_GROUP:$PG_PG_NAME"

echo "Setting PostgreSQL parameters..."

aws rds modify-db-parameter-group \
    --db-parameter-group-name "$PG_PG_NAME" \
    --parameters \
        "ParameterName=idle_in_transaction_session_timeout,ParameterValue=0,ApplyMethod=immediate" \
        "ParameterName=statement_timeout,ParameterValue=0,ApplyMethod=immediate" \
        "ParameterName=log_temp_files,ParameterValue=-1,ApplyMethod=immediate" \
        "ParameterName=temp_file_limit,ParameterValue=-1,ApplyMethod=immediate" \
        "ParameterName=rds.force_autovacuum_logging_level,ParameterValue=disabled,ApplyMethod=immediate" \
        "ParameterName=log_autovacuum_min_duration,ParameterValue=-1,ApplyMethod=immediate" \
        "ParameterName=track_io_timing,ParameterValue=0,ApplyMethod=immediate" \
        "ParameterName=log_statement,ParameterValue=all,ApplyMethod=immediate" \
        "ParameterName=synchronous_commit,ParameterValue=off,ApplyMethod=immediate" \
        "ParameterName=rds.force_ssl,ParameterValue=0,ApplyMethod=immediate" \
    --region "$REGION"

echo -e "${GREEN}✓ PostgreSQL Parameter Group created with suboptimal values${NC}"

################################################################################
# Step 5: Create MySQL RDS Instance
# Triggers: MultiAZ, Backup, AutoMinorVersionUpgrade, StorageEncrypted,
#           PerformanceInsightsEnabled, EnhancedMonitor, MonitoringIntervalTooLow,
#           DeleteProtection, PubliclyAccessible, BurstableInstance,
#           DefaultMasterAdmin, EnableStorageAutoscaling, Subnets3Az,
#           ConsiderAurora, MoveToGraviton, DBInstanceWithoutTags
################################################################################

echo -e "\n${GREEN}=== Step 5: Creating MySQL RDS Instance ===${NC}"

aws rds create-db-instance \
    --db-instance-identifier "$MYSQL_INSTANCE_ID" \
    --db-instance-class db.t3.micro \
    --engine mysql \
    --engine-version "8.0" \
    --master-username admin \
    --master-user-password "SimTest1234!" \
    --allocated-storage 20 \
    --db-parameter-group-name "$MYSQL_PG_NAME" \
    --db-subnet-group-name "$SUBNET_GROUP_NAME" \
    --vpc-security-group-ids "$SG_ID" \
    --no-multi-az \
    --backup-retention-period 0 \
    --no-auto-minor-version-upgrade \
    --monitoring-interval 0 \
    --no-deletion-protection \
    --publicly-accessible \
    --no-enable-performance-insights \
    --region "$REGION"

log_resource "RDS_INSTANCE:$MYSQL_INSTANCE_ID"
echo -e "${GREEN}✓ MySQL instance creation initiated: $MYSQL_INSTANCE_ID${NC}"

################################################################################
# Step 6: Create PostgreSQL RDS Instance
# Triggers: MultiAZ, BackupTooLow, AutoMinorVersionUpgrade, StorageEncrypted,
#           PerformanceInsightsEnabled, EnhancedMonitor, MonitoringIntervalTooLow,
#           DeleteProtection, DefaultMasterAdmin, EnableStorageAutoscaling,
#           Subnets3Az, ConsiderAurora, MoveToGraviton, BurstableInstance,
#           MSSQLorPG__TransportEncrpytionDisabled, PG param checks
################################################################################

echo -e "\n${GREEN}=== Step 6: Creating PostgreSQL RDS Instance ===${NC}"

aws rds create-db-instance \
    --db-instance-identifier "$PG_INSTANCE_ID" \
    --db-instance-class db.t3.micro \
    --engine postgres \
    --engine-version "16" \
    --master-username postgres \
    --master-user-password "SimTest1234!" \
    --allocated-storage 20 \
    --db-parameter-group-name "$PG_PG_NAME" \
    --db-subnet-group-name "$SUBNET_GROUP_NAME" \
    --vpc-security-group-ids "$SG_ID" \
    --no-multi-az \
    --backup-retention-period 3 \
    --no-auto-minor-version-upgrade \
    --monitoring-interval 0 \
    --no-deletion-protection \
    --no-enable-performance-insights \
    --region "$REGION"

log_resource "RDS_INSTANCE:$PG_INSTANCE_ID"
echo -e "${GREEN}✓ PostgreSQL instance creation initiated: $PG_INSTANCE_ID${NC}"

################################################################################
# Step 7: Create SNS Topic (no event subscription)
# Triggers: EventSubscriptionNotConfigured (by NOT creating a subscription)
################################################################################

echo -e "\n${GREEN}=== Step 7: Creating SNS Topic (no event subscription) ===${NC}"

SNS_TOPIC_ARN=$(aws sns create-topic \
    --name "$SNS_TOPIC_NAME" \
    --tags Key=Purpose,Value=RdsSimulation \
    --query 'TopicArn' --output text \
    --region "$REGION")

log_resource "SNS_TOPIC:$SNS_TOPIC_ARN"
echo -e "${GREEN}✓ SNS Topic created: $SNS_TOPIC_ARN${NC}"
echo -e "${YELLOW}  (No event subscription created — triggers EventSubscriptionNotConfigured)${NC}"

################################################################################
# Wait for instances to become available
################################################################################

echo -e "\n${YELLOW}=== Waiting for RDS instances to become available ===${NC}"
echo "This may take 5-15 minutes..."

echo "Waiting for MySQL instance: $MYSQL_INSTANCE_ID"
aws rds wait db-instance-available \
    --db-instance-identifier "$MYSQL_INSTANCE_ID" \
    --region "$REGION"
echo -e "${GREEN}✓ MySQL instance is available${NC}"

echo "Waiting for PostgreSQL instance: $PG_INSTANCE_ID"
aws rds wait db-instance-available \
    --db-instance-identifier "$PG_INSTANCE_ID" \
    --region "$REGION"
echo -e "${GREEN}✓ PostgreSQL instance is available${NC}"

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
echo "  ✓ Security Group:       $SG_ID"
echo "  ✓ DB Subnet Group:      $SUBNET_GROUP_NAME"
echo "  ✓ MySQL Param Group:    $MYSQL_PG_NAME"
echo "  ✓ PG Param Group:       $PG_PG_NAME"
echo "  ✓ MySQL Instance:       $MYSQL_INSTANCE_ID"
echo "  ✓ PostgreSQL Instance:  $PG_INSTANCE_ID"
echo "  ✓ SNS Topic:            $SNS_TOPIC_ARN"
echo ""
echo "Next steps:"
echo "  1. Run screener:"
echo "     cd /Users/kuettai/Documents/project/ssvsprowler/service-screener-v2"
echo "     python main.py --services rds --regions $REGION --sequential 1 --beta 1"
echo ""
echo "  2. Cleanup when done:"
echo "     ./cleanup_test_resources.sh $OUTPUT_FILE --region $REGION"

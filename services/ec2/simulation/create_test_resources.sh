#!/bin/bash
###############################################################################
# EC2 Service Screener - Simulation Resource Creator
#
# Creates AWS resources that trigger both PASS and FAIL scenarios for the
# 12 Tier 1 EC2 checks implemented in Service Screener v2.
#
# Prerequisites:
#   - AWS CLI v2 configured with appropriate permissions
#   - jq installed
#   - Sufficient IAM permissions (EC2, ELB, AutoScaling, Service Quotas)
#
# Usage:
#   ./create_test_resources.sh [--region <region>]
#
# All resources are tagged with ServiceScreenerTest=ec2-simulation
###############################################################################

set -euo pipefail

# --- Configuration ---
TAG_KEY="ServiceScreenerTest"
TAG_VALUE="ec2-simulation"
TAG_SPEC="ResourceType=__TYPE__,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}}]"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/simulation.log"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Helper Functions ---
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
err() { log "ERROR: $*" >&2; }

aws_ec2()  { aws ec2 "$@" --region "$REGION"; }
aws_elb()  { aws elbv2 "$@" --region "$REGION"; }
aws_asg()  { aws autoscaling "$@" --region "$REGION"; }

tag_spec() {
    local rtype="$1"
    echo "ResourceType=${rtype},Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}}]"
}

# Store created resource IDs for reference
RESOURCES_FILE="${SCRIPT_DIR}/resources.env"

save_resource() {
    local key="$1" val="$2"
    echo "${key}=${val}" >> "${SCRIPT_DIR}/resources.env"
    log "Created ${key}: ${val}"
}

# --- Safety Check ---
echo "============================================="
echo " EC2 Simulation Resource Creator"
echo "============================================="
echo ""
echo "Region: ${REGION}"
echo "Tag:    ${TAG_KEY}=${TAG_VALUE}"
echo ""
echo "This script will create AWS resources that incur costs."
echo "Run cleanup_test_resources.sh when done to remove them."
echo ""
read -rp "Continue? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

# Clear previous resource file
> "${SCRIPT_DIR}/resources.env"
log "=== Starting simulation resource creation in ${REGION} ==="

###############################################################################
# 0. Discover VPC / Subnet / AZ info
###############################################################################
log "--- Discovering default VPC and AZs ---"

DEFAULT_VPC_ID=$(aws_ec2 describe-vpcs \
    --filters "Name=isDefault,Values=true" \
    --query 'Vpcs[0].VpcId' --output text)

if [[ "$DEFAULT_VPC_ID" == "None" || -z "$DEFAULT_VPC_ID" ]]; then
    err "No default VPC found in ${REGION}. Creating a VPC..."
    DEFAULT_VPC_ID=$(aws_ec2 create-default-vpc --query 'Vpc.VpcId' --output text 2>/dev/null || true)
    if [[ -z "$DEFAULT_VPC_ID" ]]; then
        err "Cannot create default VPC. Please ensure a VPC exists."
        exit 1
    fi
fi
save_resource "DEFAULT_VPC_ID" "$DEFAULT_VPC_ID"

# Get two AZs for multi-AZ tests
AZS=($(aws_ec2 describe-availability-zones \
    --filters "Name=state,Values=available" \
    --query 'AvailabilityZones[].ZoneName' --output text | tr '\t' '\n' | head -2))

if [[ ${#AZS[@]} -lt 2 ]]; then
    err "Need at least 2 AZs. Found: ${#AZS[@]}"
    exit 1
fi
AZ1="${AZS[0]}"
AZ2="${AZS[1]}"
log "Using AZs: ${AZ1}, ${AZ2}"

# Get subnets in each AZ
SUBNET_AZ1=$(aws_ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${DEFAULT_VPC_ID}" "Name=availability-zone,Values=${AZ1}" \
    --query 'Subnets[0].SubnetId' --output text)
SUBNET_AZ2=$(aws_ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${DEFAULT_VPC_ID}" "Name=availability-zone,Values=${AZ2}" \
    --query 'Subnets[0].SubnetId' --output text)

save_resource "SUBNET_AZ1" "$SUBNET_AZ1"
save_resource "SUBNET_AZ2" "$SUBNET_AZ2"

# Get latest Amazon Linux 2023 AMI
AMI_ID=$(aws_ec2 describe-images \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023*-x86_64" "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)
save_resource "AMI_ID" "$AMI_ID"
log "Using AMI: ${AMI_ID}"

###############################################################################
# 1. EBSEncryptionByDefault (Regional check)
#    PASS: Encryption enabled by default
#    FAIL: Encryption NOT enabled by default (default AWS state)
#    NOTE: We log the current state. Toggling is destructive so we skip it.
###############################################################################
log "--- Check 1: EBSEncryptionByDefault ---"
EBS_ENC_DEFAULT=$(aws_ec2 get-ebs-encryption-by-default \
    --query 'EbsEncryptionByDefault' --output text)
log "Current EBS encryption by default: ${EBS_ENC_DEFAULT}"
log "If 'False', the check will FAIL (expected for simulation)."
log "To test PASS: aws ec2 enable-ebs-encryption-by-default --region ${REGION}"

###############################################################################
# 2. EBSVolumeDataClassification
#    FAIL: Volume without data classification tags
#    PASS: Volume with DataClassification tag
###############################################################################
log "--- Check 2: EBSVolumeDataClassification ---"

# FAIL scenario: volume with no classification tag
VOL_NO_CLASS=$(aws_ec2 create-volume \
    --availability-zone "$AZ1" \
    --size 1 \
    --volume-type gp3 \
    --tag-specifications "$(tag_spec volume)" \
    --query 'VolumeId' --output text)
save_resource "VOL_NO_CLASSIFICATION" "$VOL_NO_CLASS"

# PASS scenario: volume with DataClassification tag
VOL_WITH_CLASS=$(aws_ec2 create-volume \
    --availability-zone "$AZ1" \
    --size 1 \
    --volume-type gp3 \
    --tag-specifications "ResourceType=volume,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}},{Key=DataClassification,Value=Confidential}]" \
    --query 'VolumeId' --output text)
save_resource "VOL_WITH_CLASSIFICATION" "$VOL_WITH_CLASS"

###############################################################################
# 3. EBSSnapshotFirstArchived & 7. EBSSnapshotLatestArchived
#    These checks look at snapshot tier status (standard vs archive).
#    Archiving requires 72+ hours, so we create standard-tier snapshots
#    which will PASS both checks (first/latest NOT archived = good).
#    To test FAIL: manually archive a snapshot after 72h.
###############################################################################
log "--- Check 3 & 7: EBSSnapshotFirstArchived / EBSSnapshotLatestArchived ---"

# Wait for volume to be available
aws ec2 wait volume-available --volume-ids "$VOL_NO_CLASS" --region "$REGION"

# Create a snapshot (standard tier - will PASS both checks)
SNAP_STANDARD=$(aws_ec2 create-snapshot \
    --volume-id "$VOL_NO_CLASS" \
    --description "ServiceScreener simulation - standard tier snapshot" \
    --tag-specifications "$(tag_spec snapshot)" \
    --query 'SnapshotId' --output text)
save_resource "SNAP_STANDARD" "$SNAP_STANDARD"
log "Standard tier snapshot created. Both FirstArchived and LatestArchived checks will PASS."
log "To test FAIL: archive this snapshot after 72h with:"
log "  aws ec2 modify-snapshot-tier --snapshot-id ${SNAP_STANDARD} --storage-tier archive --region ${REGION}"

###############################################################################
# 4. EBSSnapshotComplianceArchive
#    FAIL: Old compliance-tagged snapshot NOT archived (standard tier)
#    We create a snapshot with a 'compliance' tag. The check flags snapshots
#    older than 90 days, so this won't trigger immediately. For immediate
#    testing, adjust the threshold in the driver or wait 90 days.
###############################################################################
log "--- Check 4: EBSSnapshotComplianceArchive ---"

sleep 5

SNAP_COMPLIANCE=$(aws_ec2 create-snapshot \
    --volume-id "$VOL_WITH_CLASS" \
    --description "ServiceScreener simulation - compliance snapshot" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}},{Key=compliance,Value=retention-required}]" \
    --query 'SnapshotId' --output text)
save_resource "SNAP_COMPLIANCE" "$SNAP_COMPLIANCE"
log "Compliance snapshot created. Will trigger FAIL after 90 days if not archived."

###############################################################################
# 5. EC2EbsOptimized
#    FAIL: Instance type supports EBS optimization but it's not enabled
#    PASS: Instance with EBS optimization enabled (default for most modern types)
#    Note: Most current-gen instances (t3, m5, etc.) are EBS-optimized by default.
#    We use t2.micro which supports but doesn't default to EBS-optimized.
###############################################################################
log "--- Check 5: EC2EbsOptimized ---"

# Create a security group for our test instances
SG_ID=$(aws_ec2 create-security-group \
    --group-name "ss-ec2-sim-sg" \
    --description "Service Screener EC2 simulation SG" \
    --vpc-id "$DEFAULT_VPC_ID" \
    --tag-specifications "$(tag_spec security-group)" \
    --query 'GroupId' --output text)
save_resource "SG_ID" "$SG_ID"

# FAIL scenario: t2.micro without explicit EBS optimization
# t2.micro supports EBS optimization but doesn't enable it by default
INSTANCE_NO_EBS_OPT=$(aws_ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type t2.micro \
    --subnet-id "$SUBNET_AZ1" \
    --security-group-ids "$SG_ID" \
    --no-ebs-optimized \
    --tag-specifications "$(tag_spec instance)" \
    --query 'Instances[0].InstanceId' --output text)
save_resource "INSTANCE_NO_EBS_OPT" "$INSTANCE_NO_EBS_OPT"

# PASS scenario: t3.micro is EBS-optimized by default
INSTANCE_EBS_OPT=$(aws_ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type t3.micro \
    --subnet-id "$SUBNET_AZ1" \
    --security-group-ids "$SG_ID" \
    --tag-specifications "$(tag_spec instance)" \
    --query 'Instances[0].InstanceId' --output text)
save_resource "INSTANCE_EBS_OPT" "$INSTANCE_EBS_OPT"

###############################################################################
# 6. EC2RootVolumeImplications
#    FAIL: Root volume has DeleteOnTermination=true and no recent snapshots
#    PASS: Root volume has DeleteOnTermination=true WITH a recent snapshot
#    The instances created above will FAIL this check (no snapshots).
#    Let's create a snapshot for the PASS instance's root volume.
###############################################################################
log "--- Check 6: EC2RootVolumeImplications ---"

# Wait for instances to be running
aws ec2 wait instance-running --instance-ids "$INSTANCE_EBS_OPT" --region "$REGION"

# Get root volume of the PASS instance
ROOT_VOL_PASS=$(aws_ec2 describe-instances \
    --instance-ids "$INSTANCE_EBS_OPT" \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==`/dev/xvda`].Ebs.VolumeId | [0]' \
    --output text)

# If /dev/xvda didn't match, try the RootDeviceName
if [[ "$ROOT_VOL_PASS" == "None" || -z "$ROOT_VOL_PASS" ]]; then
    ROOT_DEV_NAME=$(aws_ec2 describe-instances \
        --instance-ids "$INSTANCE_EBS_OPT" \
        --query 'Reservations[0].Instances[0].RootDeviceName' --output text)
    ROOT_VOL_PASS=$(aws_ec2 describe-instances \
        --instance-ids "$INSTANCE_EBS_OPT" \
        --query "Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==\`${ROOT_DEV_NAME}\`].Ebs.VolumeId | [0]" \
        --output text)
fi

if [[ "$ROOT_VOL_PASS" != "None" && -n "$ROOT_VOL_PASS" ]]; then
    SNAP_ROOT=$(aws_ec2 create-snapshot \
        --volume-id "$ROOT_VOL_PASS" \
        --description "ServiceScreener simulation - root volume snapshot" \
        --tag-specifications "$(tag_spec snapshot)" \
        --query 'SnapshotId' --output text)
    save_resource "SNAP_ROOT_VOL" "$SNAP_ROOT"
    log "Root volume snapshot created for PASS scenario: ${SNAP_ROOT}"
else
    log "WARNING: Could not find root volume for instance ${INSTANCE_EBS_OPT}"
fi

log "Instance ${INSTANCE_NO_EBS_OPT} will FAIL (no root vol snapshot)."
log "Instance ${INSTANCE_EBS_OPT} will PASS (has recent root vol snapshot)."

###############################################################################
# 8. VPCMultiAZ
#    FAIL: VPC with subnets in only 1 AZ
#    PASS: Default VPC already has subnets in multiple AZs
###############################################################################
log "--- Check 8: VPCMultiAZ ---"

# FAIL scenario: Create a VPC with a subnet in only one AZ
VPC_SINGLE_AZ=$(aws_ec2 create-vpc \
    --cidr-block "10.99.0.0/16" \
    --tag-specifications "$(tag_spec vpc)" \
    --query 'Vpc.VpcId' --output text)
save_resource "VPC_SINGLE_AZ" "$VPC_SINGLE_AZ"

SUBNET_SINGLE_AZ=$(aws_ec2 create-subnet \
    --vpc-id "$VPC_SINGLE_AZ" \
    --cidr-block "10.99.1.0/24" \
    --availability-zone "$AZ1" \
    --tag-specifications "$(tag_spec subnet)" \
    --query 'Subnet.SubnetId' --output text)
save_resource "SUBNET_SINGLE_AZ" "$SUBNET_SINGLE_AZ"

log "VPC ${VPC_SINGLE_AZ} with single-AZ subnet will FAIL VPCMultiAZ."
log "Default VPC ${DEFAULT_VPC_ID} with multi-AZ subnets will PASS."

###############################################################################
# 9. ELBMultiAZ
#    FAIL: ALB in a single AZ
#    PASS: ALB in multiple AZs
###############################################################################
log "--- Check 9: ELBMultiAZ ---"

# FAIL scenario: ALB in single AZ (need at least 2 subnets, but we use 2 subnets in same AZ concept)
# Actually ALB requires 2 subnets minimum, so we create one with 2 AZs (PASS) only.
# For FAIL, we create an NLB in a single subnet.

# PASS scenario: ALB across 2 AZs
ALB_MULTI_AZ=$(aws_elb create-load-balancer \
    --name "ss-sim-alb-multi-az" \
    --type application \
    --subnets "$SUBNET_AZ1" "$SUBNET_AZ2" \
    --security-groups "$SG_ID" \
    --tags "Key=${TAG_KEY},Value=${TAG_VALUE}" \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)
save_resource "ALB_MULTI_AZ" "$ALB_MULTI_AZ"

# FAIL scenario: NLB in single AZ
NLB_SINGLE_AZ=$(aws_elb create-load-balancer \
    --name "ss-sim-nlb-single-az" \
    --type network \
    --subnets "$SUBNET_AZ1" \
    --tags "Key=${TAG_KEY},Value=${TAG_VALUE}" \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)
save_resource "NLB_SINGLE_AZ" "$NLB_SINGLE_AZ"

log "ALB ${ALB_MULTI_AZ} in 2 AZs will PASS ELBMultiAZ."
log "NLB ${NLB_SINGLE_AZ} in 1 AZ will FAIL ELBMultiAZ."

###############################################################################
# 10. ASGMultiAZ
#     FAIL: ASG in single AZ
#     PASS: ASG in multiple AZs
# 11. ASGTargetTrackingPolicy
#     FAIL: ASG without target tracking policy
#     PASS: ASG with target tracking policy
###############################################################################
log "--- Check 10 & 11: ASGMultiAZ / ASGTargetTrackingPolicy ---"

# Create a launch template for ASGs
LT_ID=$(aws_ec2 create-launch-template \
    --launch-template-name "ss-sim-lt" \
    --launch-template-data "{\"ImageId\":\"${AMI_ID}\",\"InstanceType\":\"t3.micro\"}" \
    --tag-specifications "$(tag_spec launch-template)" \
    --query 'LaunchTemplate.LaunchTemplateId' --output text)
save_resource "LAUNCH_TEMPLATE_ID" "$LT_ID"

# FAIL scenario (both checks): ASG in single AZ, no target tracking policy
aws_asg create-auto-scaling-group \
    --auto-scaling-group-name "ss-sim-asg-single-az" \
    --launch-template "LaunchTemplateId=${LT_ID},Version=\$Latest" \
    --min-size 0 \
    --max-size 0 \
    --desired-capacity 0 \
    --availability-zones "$AZ1" \
    --tags "Key=${TAG_KEY},Value=${TAG_VALUE},PropagateAtLaunch=true"
save_resource "ASG_SINGLE_AZ" "ss-sim-asg-single-az"

# PASS scenario (both checks): ASG in multiple AZs with target tracking policy
aws_asg create-auto-scaling-group \
    --auto-scaling-group-name "ss-sim-asg-multi-az" \
    --launch-template "LaunchTemplateId=${LT_ID},Version=\$Latest" \
    --min-size 0 \
    --max-size 2 \
    --desired-capacity 0 \
    --availability-zones "$AZ1" "$AZ2" \
    --tags "Key=${TAG_KEY},Value=${TAG_VALUE},PropagateAtLaunch=true"
save_resource "ASG_MULTI_AZ" "ss-sim-asg-multi-az"

# Add target tracking policy to the multi-AZ ASG
aws_asg put-scaling-policy \
    --auto-scaling-group-name "ss-sim-asg-multi-az" \
    --policy-name "ss-sim-target-tracking" \
    --policy-type TargetTrackingScaling \
    --target-tracking-configuration '{
        "PredefinedMetricSpecification": {
            "PredefinedMetricType": "ASGAverageCPUUtilization"
        },
        "TargetValue": 50.0
    }' > /dev/null
log "Target tracking policy added to ss-sim-asg-multi-az."

log "ASG ss-sim-asg-single-az: FAIL ASGMultiAZ + FAIL ASGTargetTrackingPolicy"
log "ASG ss-sim-asg-multi-az:  PASS ASGMultiAZ + PASS ASGTargetTrackingPolicy"

###############################################################################
# 12. EC2ServiceQuotas
#     This check monitors quota utilization (>80%). It depends on actual
#     account usage and cannot be easily simulated with test resources.
#     The check will PASS if usage is below 80% of limits.
###############################################################################
log "--- Check 12: EC2ServiceQuotas ---"
log "EC2ServiceQuotas depends on actual account resource counts vs limits."
log "Current resource counts will be evaluated against account quotas."
log "No specific resources created for this check."

###############################################################################
# 13. ASGScalingCooldowns (Tier 2)
#     FAIL: ASG with DefaultCooldown < 60 seconds
#     PASS: ASG with DefaultCooldown >= 60 seconds (default is 300)
#     The ss-sim-asg-multi-az already has default cooldown (300s) → PASS
#     We update ss-sim-asg-single-az to have 0s cooldown → FAIL
###############################################################################
log "--- Check 13: ASGScalingCooldowns (Tier 2) ---"

aws_asg update-auto-scaling-group \
    --auto-scaling-group-name "ss-sim-asg-single-az" \
    --default-cooldown 0
log "ASG ss-sim-asg-single-az: cooldown set to 0s → FAIL ASGScalingCooldowns"
log "ASG ss-sim-asg-multi-az: cooldown is 300s (default) → PASS ASGScalingCooldowns"

###############################################################################
# 14. ComputeOptimizerEnhancedMetrics (Tier 2)
#     This check queries Compute Optimizer for enhanced infrastructure metrics.
#     FAIL: Enhanced metrics not enabled (default state for most accounts)
#     PASS: Enhanced metrics enabled via Compute Optimizer preferences
#     NOTE: Cannot be simulated with resource creation. Depends on account-level
#     Compute Optimizer enrollment and preference settings.
###############################################################################
log "--- Check 14: ComputeOptimizerEnhancedMetrics (Tier 2) ---"
log "ComputeOptimizerEnhancedMetrics depends on Compute Optimizer enrollment."
log "If Compute Optimizer is active but enhanced metrics are not enabled → FAIL."
log "To test PASS: enable enhanced infrastructure metrics in Compute Optimizer console."

###############################################################################
# 15. EC2SeparateOSDataVolumes (Tier 3)
#     FAIL: Instance with only 1 block device (root volume only)
#     PASS: Instance with 2+ block devices (root + data volumes)
#     The t2.micro instance (INSTANCE_NO_EBS_OPT) has only root → FAIL
#     We attach an extra volume to the t3.micro instance → PASS
###############################################################################
log "--- Check 15: EC2SeparateOSDataVolumes (Tier 3) ---"

# Create a data volume and attach to the PASS instance
DATA_VOL=$(aws_ec2 create-volume \
    --availability-zone "$AZ1" \
    --size 1 \
    --volume-type gp3 \
    --tag-specifications "$(tag_spec volume)" \
    --query 'VolumeId' --output text)
save_resource "DATA_VOL_SEPARATE" "$DATA_VOL"

aws ec2 wait volume-available --volume-ids "$DATA_VOL" --region "$REGION"
aws_ec2 attach-volume \
    --volume-id "$DATA_VOL" \
    --instance-id "$INSTANCE_EBS_OPT" \
    --device "/dev/sdf" > /dev/null
log "Attached data volume ${DATA_VOL} to ${INSTANCE_EBS_OPT} → PASS EC2SeparateOSDataVolumes"
log "Instance ${INSTANCE_NO_EBS_OPT} has only root volume → FAIL EC2SeparateOSDataVolumes"

###############################################################################
# 16. EC2InstanceStoreUsage (Tier 3)
#     FAIL: Instance type supports instance store but no ephemeral mappings
#     PASS: Instance type has no instance store (nothing to check) or
#           instance has ephemeral mappings
#     NOTE: t2.micro and t3.micro do NOT have instance store, so they won't
#     trigger this check. To fully test, launch an instance type with instance
#     store (e.g., m5d.large, c5d.large). This is expensive, so we log
#     instructions instead.
###############################################################################
log "--- Check 16: EC2InstanceStoreUsage (Tier 3) ---"
log "EC2InstanceStoreUsage requires instance types with instance store (e.g., m5d.large)."
log "t2.micro and t3.micro do not have instance store, so this check is skipped for them."
log "To test FAIL: launch m5d.large without ephemeral volume mappings."
log "To test PASS: launch m5d.large with ephemeral volumes mapped, or use types without instance store."

###############################################################################
# 17. ComputeOptimizerRightsizingPrefs (Tier 3)
#     FAIL: Rightsizing preferences use default lookBackPeriod (DAYS_14)
#     PASS: Rightsizing preferences have customized lookBackPeriod
#     NOTE: Account-level Compute Optimizer setting, cannot be simulated
#     with resource creation.
###############################################################################
log "--- Check 17: ComputeOptimizerRightsizingPrefs (Tier 3) ---"
log "ComputeOptimizerRightsizingPrefs depends on Compute Optimizer enrollment."
log "If lookBackPeriod is default (DAYS_14) → FAIL."
log "To test PASS: customize rightsizing preferences in Compute Optimizer console."

###############################################################################
# 18. ComputeOptimizerExportRecommendations (Tier 3)
#     FAIL: No recommendation export jobs configured
#     PASS: At least one export job exists
#     NOTE: Account-level Compute Optimizer setting, cannot be simulated
#     with resource creation.
###############################################################################
log "--- Check 18: ComputeOptimizerExportRecommendations (Tier 3) ---"
log "ComputeOptimizerExportRecommendations depends on Compute Optimizer enrollment."
log "If no export jobs exist → FAIL."
log "To test PASS: configure recommendation export to S3 in Compute Optimizer console."

###############################################################################
# Summary
###############################################################################
log ""
log "============================================="
log " Simulation Resources Created Successfully"
log "============================================="
log ""
log "Resource IDs saved to: ${SCRIPT_DIR}/resources.env"
log ""
log "Check Coverage Summary:"
log "  --- Tier 1 ---"
log "  1.  EBSEncryptionByDefault         - Regional setting (current: ${EBS_ENC_DEFAULT})"
log "  2.  EBSVolumeDataClassification    - FAIL: ${VOL_NO_CLASS}, PASS: ${VOL_WITH_CLASS}"
log "  3.  EBSSnapshotFirstArchived       - PASS: ${SNAP_STANDARD} (standard tier)"
log "  4.  EBSSnapshotComplianceArchive   - Created: ${SNAP_COMPLIANCE} (triggers after 90d)"
log "  5.  EC2EbsOptimized                - FAIL: ${INSTANCE_NO_EBS_OPT}, PASS: ${INSTANCE_EBS_OPT}"
log "  6.  EC2RootVolumeImplications      - FAIL: ${INSTANCE_NO_EBS_OPT}, PASS: ${INSTANCE_EBS_OPT}"
log "  7.  EBSSnapshotLatestArchived      - PASS: ${SNAP_STANDARD} (standard tier)"
log "  8.  VPCMultiAZ                     - FAIL: ${VPC_SINGLE_AZ}, PASS: ${DEFAULT_VPC_ID}"
log "  9.  ELBMultiAZ                     - FAIL: ${NLB_SINGLE_AZ}, PASS: ${ALB_MULTI_AZ}"
log "  10. ASGMultiAZ                     - FAIL: ss-sim-asg-single-az, PASS: ss-sim-asg-multi-az"
log "  11. ASGTargetTrackingPolicy        - FAIL: ss-sim-asg-single-az, PASS: ss-sim-asg-multi-az"
log "  12. EC2ServiceQuotas               - Depends on account usage (no resources created)"
log "  --- Tier 2 ---"
log "  13. ASGScalingCooldowns            - FAIL: ss-sim-asg-single-az (0s), PASS: ss-sim-asg-multi-az (300s)"
log "  14. ComputeOptimizerEnhancedMetrics - Account-level setting (see instructions above)"
log "  --- Tier 3 ---"
log "  15. EC2SeparateOSDataVolumes       - FAIL: ${INSTANCE_NO_EBS_OPT}, PASS: ${INSTANCE_EBS_OPT}"
log "  16. EC2InstanceStoreUsage          - Requires instance store types (see instructions above)"
log "  17. ComputeOptimizerRightsizingPrefs - Account-level setting (see instructions above)"
log "  18. ComputeOptimizerExportRecommendations - Account-level setting (see instructions above)"
log ""
log "Run cleanup_test_resources.sh to remove all simulation resources."

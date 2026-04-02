#!/bin/bash
###############################################################################
# EC2 Service Screener - Simulation Resource Cleanup
#
# Removes ALL resources created by create_test_resources.sh.
# Uses the ServiceScreenerTest=ec2-simulation tag to find resources,
# and also reads resources.env as a fallback.
#
# Usage:
#   ./cleanup_test_resources.sh [--region <region>]
###############################################################################

set -uo pipefail

# --- Configuration ---
TAG_KEY="ServiceScreenerTest"
TAG_VALUE="ec2-simulation"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/cleanup.log"
ERRORS=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Helper Functions ---
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
err() { log "ERROR: $*" >&2; ((ERRORS++)) || true; }

aws_ec2()  { aws ec2 "$@" --region "$REGION" --output json 2>/dev/null; }
aws_elb()  { aws elbv2 "$@" --region "$REGION" --output json 2>/dev/null; }
aws_asg()  { aws autoscaling "$@" --region "$REGION" --output json 2>/dev/null; }

safe_delete() {
    local desc="$1"
    shift
    log "Deleting ${desc}..."
    if "$@" 2>/dev/null; then
        log "  Deleted ${desc}"
    else
        err "  Failed to delete ${desc} (may already be deleted)"
    fi
}

# --- Safety Check ---
echo "============================================="
echo " EC2 Simulation Resource Cleanup"
echo "============================================="
echo ""
echo "Region: ${REGION}"
echo "Tag:    ${TAG_KEY}=${TAG_VALUE}"
echo ""
echo "This will DELETE all resources tagged with ${TAG_KEY}=${TAG_VALUE}"
echo ""
read -rp "Continue? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

> "$LOG_FILE"
log "=== Starting cleanup in ${REGION} ==="

###############################################################################
# 1. Delete Auto Scaling Groups (must be first - they manage instances)
###############################################################################
log "--- Cleaning up Auto Scaling Groups ---"

for asg_name in "ss-sim-asg-single-az" "ss-sim-asg-multi-az"; do
    # Remove scaling policies first
    POLICIES=$(aws_asg describe-policies \
        --auto-scaling-group-name "$asg_name" \
        --query 'ScalingPolicies[].PolicyName' --output text 2>/dev/null || echo "")
    for policy in $POLICIES; do
        safe_delete "scaling policy ${policy}" \
            aws autoscaling delete-policy \
                --auto-scaling-group-name "$asg_name" \
                --policy-name "$policy" \
                --region "$REGION"
    done

    safe_delete "ASG ${asg_name}" \
        aws autoscaling delete-auto-scaling-group \
            --auto-scaling-group-name "$asg_name" \
            --force-delete \
            --region "$REGION"
done

# Wait a moment for ASG deletion to propagate
sleep 5

###############################################################################
# 2. Delete Load Balancers
###############################################################################
log "--- Cleaning up Load Balancers ---"

# Find tagged load balancers
LB_ARNS=$(aws_elb describe-load-balancers \
    --query 'LoadBalancers[].LoadBalancerArn' --output text 2>/dev/null || echo "")

for arn in $LB_ARNS; do
    # Check if this LB has our tag
    TAGS=$(aws_elb describe-tags --resource-arns "$arn" \
        --query "TagDescriptions[0].Tags[?Key=='${TAG_KEY}' && Value=='${TAG_VALUE}'].Key" \
        --output text 2>/dev/null || echo "")
    if [[ -n "$TAGS" ]]; then
        # Delete listeners first
        LISTENER_ARNS=$(aws_elb describe-listeners \
            --load-balancer-arn "$arn" \
            --query 'Listeners[].ListenerArn' --output text 2>/dev/null || echo "")
        for listener_arn in $LISTENER_ARNS; do
            safe_delete "listener ${listener_arn}" \
                aws elbv2 delete-listener --listener-arn "$listener_arn" --region "$REGION"
        done

        safe_delete "load balancer ${arn}" \
            aws elbv2 delete-load-balancer --load-balancer-arn "$arn" --region "$REGION"
    fi
done

# Wait for LBs to finish deleting
log "Waiting for load balancers to be deleted..."
sleep 15

###############################################################################
# 3. Detach and note extra EBS volumes (attached as data volumes)
###############################################################################
log "--- Detaching extra EBS volumes from instances ---"

# Find tagged instances that are still running and detach non-root volumes
RUNNING_IDS=$(aws_ec2 describe-instances \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || echo "")

for inst_id in $RUNNING_IDS; do
    # Get root device name
    ROOT_DEV=$(aws_ec2 describe-instances \
        --instance-ids "$inst_id" \
        --query 'Reservations[0].Instances[0].RootDeviceName' --output text 2>/dev/null || echo "")

    # Get all attached volume IDs that are NOT the root device
    EXTRA_VOLS=$(aws_ec2 describe-instances \
        --instance-ids "$inst_id" \
        --query "Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName!=\`${ROOT_DEV}\`].Ebs.VolumeId" \
        --output text 2>/dev/null || echo "")

    for vol_id in $EXTRA_VOLS; do
        safe_delete "detach volume ${vol_id} from ${inst_id}" \
            aws ec2 detach-volume --volume-id "$vol_id" --instance-id "$inst_id" --force --region "$REGION"
    done
done

# Brief wait for detach operations
sleep 3

###############################################################################
# 4. Delete EC2 Instances
###############################################################################
log "--- Cleaning up EC2 Instances ---"

INSTANCE_IDS=$(aws_ec2 describe-instances \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || echo "")

if [[ -n "$INSTANCE_IDS" ]]; then
    log "Terminating instances: ${INSTANCE_IDS}"
    aws ec2 terminate-instances --instance-ids $INSTANCE_IDS --region "$REGION" > /dev/null 2>&1 || true

    log "Waiting for instances to terminate..."
    aws ec2 wait instance-terminated --instance-ids $INSTANCE_IDS --region "$REGION" 2>/dev/null || true
    log "Instances terminated."
fi

###############################################################################
# 5. Delete Launch Templates
###############################################################################
log "--- Cleaning up Launch Templates ---"

LT_IDS=$(aws_ec2 describe-launch-templates \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
    --query 'LaunchTemplates[].LaunchTemplateId' --output text 2>/dev/null || echo "")

for lt_id in $LT_IDS; do
    safe_delete "launch template ${lt_id}" \
        aws ec2 delete-launch-template --launch-template-id "$lt_id" --region "$REGION"
done

###############################################################################
# 6. Delete EBS Snapshots
###############################################################################
log "--- Cleaning up EBS Snapshots ---"

SNAP_IDS=$(aws_ec2 describe-snapshots \
    --owner-ids self \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
    --query 'Snapshots[].SnapshotId' --output text 2>/dev/null || echo "")

for snap_id in $SNAP_IDS; do
    safe_delete "snapshot ${snap_id}" \
        aws ec2 delete-snapshot --snapshot-id "$snap_id" --region "$REGION"
done

###############################################################################
# 7. Delete EBS Volumes
###############################################################################
log "--- Cleaning up EBS Volumes ---"

VOL_IDS=$(aws_ec2 describe-volumes \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
    --query 'Volumes[].VolumeId' --output text 2>/dev/null || echo "")

for vol_id in $VOL_IDS; do
    # Wait for volume to be available (not in-use)
    aws ec2 wait volume-available --volume-ids "$vol_id" --region "$REGION" 2>/dev/null || true
    safe_delete "volume ${vol_id}" \
        aws ec2 delete-volume --volume-id "$vol_id" --region "$REGION"
done

###############################################################################
# 8. Delete Security Groups (after instances are terminated)
###############################################################################
log "--- Cleaning up Security Groups ---"

SG_IDS=$(aws_ec2 describe-security-groups \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
    --query 'SecurityGroups[].GroupId' --output text 2>/dev/null || echo "")

for sg_id in $SG_IDS; do
    safe_delete "security group ${sg_id}" \
        aws ec2 delete-security-group --group-id "$sg_id" --region "$REGION"
done

###############################################################################
# 9. Delete Subnets and VPCs (created for single-AZ test)
###############################################################################
log "--- Cleaning up VPCs and Subnets ---"

# Delete tagged subnets first
SUBNET_IDS=$(aws_ec2 describe-subnets \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
    --query 'Subnets[].SubnetId' --output text 2>/dev/null || echo "")

for subnet_id in $SUBNET_IDS; do
    safe_delete "subnet ${subnet_id}" \
        aws ec2 delete-subnet --subnet-id "$subnet_id" --region "$REGION"
done

# Delete tagged VPCs (non-default only)
VPC_IDS=$(aws_ec2 describe-vpcs \
    --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" "Name=isDefault,Values=false" \
    --query 'Vpcs[].VpcId' --output text 2>/dev/null || echo "")

for vpc_id in $VPC_IDS; do
    # Delete any remaining network interfaces
    ENI_IDS=$(aws_ec2 describe-network-interfaces \
        --filters "Name=vpc-id,Values=${vpc_id}" \
        --query 'NetworkInterfaces[].NetworkInterfaceId' --output text 2>/dev/null || echo "")
    for eni_id in $ENI_IDS; do
        safe_delete "network interface ${eni_id}" \
            aws ec2 delete-network-interface --network-interface-id "$eni_id" --region "$REGION"
    done

    # Delete any remaining security groups (non-default)
    VPC_SGS=$(aws_ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=${vpc_id}" \
        --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text 2>/dev/null || echo "")
    for sg_id in $VPC_SGS; do
        safe_delete "VPC security group ${sg_id}" \
            aws ec2 delete-security-group --group-id "$sg_id" --region "$REGION"
    done

    safe_delete "VPC ${vpc_id}" \
        aws ec2 delete-vpc --vpc-id "$vpc_id" --region "$REGION"
done

###############################################################################
# 10. Clean up local files
###############################################################################
log "--- Cleaning up local files ---"
rm -f "${SCRIPT_DIR}/resources.env"
log "Removed resources.env"

###############################################################################
# Summary
###############################################################################
log ""
log "============================================="
log " Cleanup Complete"
log "============================================="
if [[ $ERRORS -gt 0 ]]; then
    log "Completed with ${ERRORS} error(s). Check log for details."
    log "Some resources may need manual cleanup."
else
    log "All simulation resources removed successfully."
fi
log "Log saved to: ${LOG_FILE}"

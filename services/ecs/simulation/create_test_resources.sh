#!/bin/bash

################################################################################
# ECS Service Screener - Test Resource Creation Script
#
# Creates a Fargate ECS cluster + task definition + service with intentional
# misconfigurations that exercise the majority of the 42 ECS checks:
#
# CLUSTER (ss-test-ecs-cluster-{TS}):
#   No containerInsights           -> FAIL #1  (ecsClusterContainerInsightsEnabled)
#   No managedStorageConfiguration -> FAIL #4  (ecsClusterManagedStorageEncryption)
#   No capacity providers          -> FAIL #5  (ecsClusterDefaultCapacityProviderStrategy)
#   No tags                        -> FAIL #7  (ecsClusterTagging)
#
# TASK DEFINITION (ss-test-ecs-td-{TS}) — Fargate, single container:
#   nginx:latest image             -> FAIL #32 (ecsTaskDefinitionNoLatestTag)
#                                  -> FAIL #33 (ecsTaskDefinitionEcrImageSource)
#   user unset (root)              -> FAIL #20 (ecsTaskDefinitionNonRootUser)
#   readonlyRootFilesystem=false   -> FAIL #22 (ecsTaskDefinitionReadonlyRootFilesystem)
#   env: DB_PASSWORD=secret        -> FAIL #24 (ecsTaskDefinitionNoSecretsInEnvVars)
#   env: FAKE_AWS_KEY=AKIA...      -> FAIL #24 (AWS access key value pattern)
#   No healthCheck                 -> FAIL #27 (ecsTaskDefinitionHealthCheckDefined)
#   taskRoleArn == executionRoleArn-> FAIL #26 (ecsTaskDefinitionSeparateTaskAndExecutionRoles)
#   ephemeralStorage.sizeInGiB=30  -> FAIL #42 (ecsTaskDefinitionEphemeralStorageEncryption)
#   awslogs driver (log group)     -> PASS #23, #34
#
#   NOTE: Linux capabilities check #31 cannot be simulated on Fargate — the
#   RegisterTaskDefinition API rejects capabilities.add=[SYS_ADMIN|NET_RAW] etc.
#   on Fargate. Reproduce on EC2 launch type if needed.
#
# SERVICE (ss-test-ecs-svc-{TS}) — Fargate, desiredCount=0:
#   assignPublicIp=ENABLED         -> FAIL #8  (ecsServicePublicIpDisabled)
#   circuit breaker disabled       -> FAIL #9  (ecsServiceDeploymentCircuitBreakerEnabled)
#   platformVersion=1.4.0          -> PASS #11 (current LATEST equivalent)
#   No Application Auto Scaling    -> FAIL #12 (ecsServiceAutoScalingConfigured)
#   desiredCount=0, ACTIVE         -> FAIL #13 (ecsServiceDesiredCountZero)
#   minimumHealthyPercent=0        -> FAIL #16 (ecsServiceMinimumHealthyPercent)
#   Task def networkMode=awsvpc    -> PASS #17
#   propagateTags=NONE             -> FAIL #19
#   launchType=FARGATE, no SPOT    -> FAIL #37
#   No LB / registry / SC          -> FAIL #38
#
# SUPPORTING RESOURCES:
#   1 IAM role with wildcard Action:*/Resource:* (execution+task role reused).
#   1 CloudWatch log group.
#   Default VPC + 2 default subnets discovered dynamically.
#
# Total: ~19 FAIL findings across the 27 checks that apply to the created
# resources (host-mode/PID/IPC checks fire only for EC2 launch type; capability
# checks require adding dangerous caps to a container; Fargate rejects
# privileged=true; task sets require EXTERNAL deployment controller).
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--help]
################################################################################

set -u

REGION="${AWS_REGION:-us-east-1}"
PREFIX="ss-test-ecs"
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

ROLE_NAME="${PREFIX}-role-${TIMESTAMP}"
LOG_GROUP_NAME="/ecs/${PREFIX}-${TIMESTAMP}"
CLUSTER_NAME="${PREFIX}-cluster-${TIMESTAMP}"
TD_FAMILY="${PREFIX}-td-${TIMESTAMP}"
SVC_NAME="${PREFIX}-svc-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== ECS Test Resource Creation ===${NC}"
echo "Region:    $REGION"
echo "Account:   $ACCOUNT_ID"
echo "Timestamp: $TIMESTAMP"
echo -e "${YELLOW}All resources prefixed with '${PREFIX}-'. Service is created with"
echo -e "desiredCount=0 so NO Fargate tasks are launched (zero runtime cost).${NC}"
echo ""

################################################################################
# Step 1: Discover default VPC + subnets (Fargate awsvpc needs them)
################################################################################

echo -e "${GREEN}=== Step 1: Discovering default VPC and subnets ===${NC}"

VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=isDefault,Values=true" \
    --query 'Vpcs[0].VpcId' --output text --region "$REGION" 2>/dev/null || echo "None")

if [ -z "${VPC_ID:-}" ] || [ "$VPC_ID" = "None" ]; then
    echo -e "${RED}✗ No default VPC found in region $REGION${NC}"
    echo -e "${YELLOW}   Create a default VPC or pass --region with a region that has one${NC}"
    exit 1
fi

SUBNET_IDS=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=default-for-az,Values=true" \
    --query 'Subnets[*].SubnetId' --output text --region "$REGION" 2>/dev/null | tr '\t' ',')

if [ -z "${SUBNET_IDS:-}" ]; then
    echo -e "${RED}✗ No default subnets found in VPC $VPC_ID${NC}"; exit 1
fi

echo -e "${GREEN}✓ VPC: $VPC_ID${NC}"
echo -e "${GREEN}✓ Subnets: $SUBNET_IDS${NC}"

DEFAULT_SG=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=default" \
    --query 'SecurityGroups[0].GroupId' --output text --region "$REGION" 2>/dev/null || echo "None")

if [ -z "${DEFAULT_SG:-}" ] || [ "$DEFAULT_SG" = "None" ]; then
    echo -e "${RED}✗ Could not find default security group in VPC $VPC_ID${NC}"; exit 1
fi
echo -e "${GREEN}✓ Default SG: $DEFAULT_SG${NC}"

################################################################################
# Step 2: IAM role (shared execution + task role → intentionally wrong)
################################################################################

echo -e "\n${GREEN}=== Step 2: IAM role (wildcard, execution=task) ===${NC}"

cat > /tmp/${PREFIX}-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

cat > /tmp/${PREFIX}-wild.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF

aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document file:///tmp/${PREFIX}-trust.json \
    --description "SS simulation - intentionally wildcard, reused as execution+task role" \
    --region "$REGION" > /dev/null

aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "${PREFIX}-wildcard" \
    --policy-document file:///tmp/${PREFIX}-wild.json > /dev/null

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
log "IAM_ROLE:${ROLE_NAME}"
echo -e "${GREEN}✓ IAM role: ${ROLE_NAME}${NC}"
echo -e "${YELLOW}   Fires: #26 (execution==task role)${NC}"

echo -e "${YELLOW}Sleeping 15s for IAM role propagation...${NC}"
sleep 15

################################################################################
# Step 3: CloudWatch log group
################################################################################

echo -e "\n${GREEN}=== Step 3: CloudWatch log group ===${NC}"

aws logs create-log-group \
    --log-group-name "$LOG_GROUP_NAME" \
    --region "$REGION" 2>&1 | head -3 || true
log "LOG_GROUP:${LOG_GROUP_NAME}"
echo -e "${GREEN}✓ Log group: ${LOG_GROUP_NAME}${NC}"

################################################################################
# Step 4: Cluster (no Container Insights, no capacity providers, no CMK, no tags)
################################################################################

echo -e "\n${GREEN}=== Step 4: ECS cluster (minimal misconfigured) ===${NC}"

aws ecs create-cluster \
    --cluster-name "$CLUSTER_NAME" \
    --region "$REGION" > /dev/null || {
        echo -e "${RED}✗ Cluster create failed${NC}"; exit 1
    }
log "CLUSTER:${CLUSTER_NAME}"
echo -e "${GREEN}✓ Cluster: ${CLUSTER_NAME}${NC}"
echo -e "${YELLOW}   Fires: #1 (containerInsights off), #4 (no CMK), #5 (no cap providers), #7 (no tags)${NC}"

################################################################################
# Step 5: Task definition (Fargate, insecure container)
################################################################################

echo -e "\n${GREEN}=== Step 5: Task definition (insecure container) ===${NC}"

cat > /tmp/${PREFIX}-td.json <<EOF
{
  "family": "${TD_FAMILY}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "${ROLE_ARN}",
  "taskRoleArn": "${ROLE_ARN}",
  "ephemeralStorage": {"sizeInGiB": 30},
  "containerDefinitions": [
    {
      "name": "bad-app",
      "image": "nginx:latest",
      "essential": true,
      "readonlyRootFilesystem": false,
      "environment": [
        {"name": "DB_PASSWORD", "value": "supersecret123"},
        {"name": "API_KEY", "value": "abc123-fake-api-key"},
        {"name": "FAKE_AWS_ACCESS_KEY_ID", "value": "AKIAIOSFODNN7EXAMPLE"}
      ],
      "linuxParameters": {
        "initProcessEnabled": true
      },
      "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "${LOG_GROUP_NAME}",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "bad-app"
        }
      }
    }
  ]
}
EOF

TD_JSON=$(aws ecs register-task-definition \
    --cli-input-json file:///tmp/${PREFIX}-td.json \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Task-definition register failed${NC}"
        echo "$TD_JSON" | head -5
        exit 1
    }
TD_ARN=$(echo "$TD_JSON" | grep -o '"taskDefinitionArn": *"[^"]*"' | head -1 | sed 's/.*"taskDefinitionArn": *"\([^"]*\)".*/\1/')
log "TASK_DEF:${TD_ARN}"
echo -e "${GREEN}✓ Task def: ${TD_ARN}${NC}"
echo -e "${YELLOW}   Fires: #20 (root user), #22 (writable rootfs), #24 (secrets in env),${NC}"
echo -e "${YELLOW}          #26 (same role), #27 (no healthCheck),${NC}"
echo -e "${YELLOW}          #32 (:latest), #33 (non-ECR image), #42 (30GiB no CMK)${NC}"

################################################################################
# Step 6: Service (public IP, no auto-scaling, desired=0, weak deployment)
################################################################################

echo -e "\n${GREEN}=== Step 6: ECS service (public IP, no auto-scaling) ===${NC}"

# JSON array format for subnets and security groups
FIRST_SUBNET=$(echo "$SUBNET_IDS" | cut -d, -f1)
NET_CFG=$(cat <<EOF
{
  "awsvpcConfiguration": {
    "subnets": ["${FIRST_SUBNET}"],
    "securityGroups": ["${DEFAULT_SG}"],
    "assignPublicIp": "ENABLED"
  }
}
EOF
)

DEPLOY_CFG='{"deploymentCircuitBreaker":{"enable":false,"rollback":false},"minimumHealthyPercent":0,"maximumPercent":200}'

SVC_JSON=$(aws ecs create-service \
    --cluster "$CLUSTER_NAME" \
    --service-name "$SVC_NAME" \
    --task-definition "$TD_ARN" \
    --launch-type FARGATE \
    --platform-version LATEST \
    --desired-count 0 \
    --network-configuration "$NET_CFG" \
    --deployment-configuration "$DEPLOY_CFG" \
    --scheduling-strategy REPLICA \
    --propagate-tags NONE \
    --region "$REGION" \
    --output json 2>&1) || {
        echo -e "${RED}✗ Service create failed${NC}"
        echo "$SVC_JSON" | head -5
        SVC_JSON=""
    }
if [ -n "$SVC_JSON" ]; then
    SVC_ARN=$(echo "$SVC_JSON" | grep -o '"serviceArn": *"[^"]*"' | head -1 | sed 's/.*"serviceArn": *"\([^"]*\)".*/\1/')
    if [ -n "${SVC_ARN:-}" ]; then
        log "SERVICE:${CLUSTER_NAME}:${SVC_NAME}"
        echo -e "${GREEN}✓ Service: ${SVC_NAME} (desiredCount=0 — no tasks launch)${NC}"
        echo -e "${YELLOW}   Fires: #8 (public IP), #9 (no circuit breaker), #12 (no autoscaling),${NC}"
        echo -e "${YELLOW}          #13 (desired=0), #16 (mhp=0), #19 (propagateTags=NONE),${NC}"
        echo -e "${YELLOW}          #37 (no FARGATE_SPOT), #38 (no service discovery)${NC}"
    fi
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
echo "Next steps:"
echo "  1. sleep 30   # IAM propagation, cluster stabilise"
echo "  2. cd ../../.. && python3 main.py --regions $REGION --services ecs --beta 1 --sequential 1"
echo "  3. cd services/ecs/simulation && ./cleanup_test_resources.sh"
echo ""
echo -e "${CYAN}Manifest saved to: ${OUTPUT_FILE}${NC}"

rm -f /tmp/${PREFIX}-trust.json /tmp/${PREFIX}-wild.json /tmp/${PREFIX}-td.json

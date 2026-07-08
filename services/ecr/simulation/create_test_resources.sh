#!/bin/bash

################################################################################
# ECR Service Screener - Test Resource Creation Script
#
# Creates two intentionally-insecure ECR repositories that exercise most of
# the `ecr*` service-screener checks. Also pushes lightweight test images
# built from a Debian 8 (Jessie) base which surfaces known CVEs — this is
# what drives the ecrCriticalVulnerabilities / ecrHighVulnerabilities /
# ecrImageNeverScanned findings once the scan completes.
#
# Repos created (all prefixed with `ss-test-ecr-`):
#
#   Repo #1 (STANDARD) — Broad set of TIER 1/2 failures:
#     - scanOnPush=false                    → #1 ecrScanOnPush
#     - imageTagMutability=MUTABLE          → #2 ecrTagImmutability
#     - encryptionType=AES256               → #4 ecrEncryptionKms
#     - No lifecycle policy attached        → #3 ecrLifecyclePolicy, #19
#     - Public-Principal repository policy  → #9 ecrRepoPublicAccess
#     - No tags applied                     → #17 ecrPublicRepoTagging
#     - Vulnerable image pushed (debian:8)  → #5 #6 (CVEs) once scanned
#     - Additional untagged image           → #11 ecrUntaggedImages
#
#   Repo #2 (HARDENED) — Baseline for pass/fail contrast:
#     - scanOnPush=true                     → #1 passes
#     - imageTagMutability=IMMUTABLE        → #2 passes
#     - Lifecycle policy present but only   → #19 ecrLifecyclePolicyEffectiveness
#       tag-count rule (no untagged/age)      fires
#     - Tags applied                        → #17 passes
#
# Registry-level checks (#7 ecrEnhancedScanning, #8 ecrScanFrequency,
# #14 ecrReplicationNotConfigured, #15 ecrPullThroughCache) are NOT modified
# by this script — they reflect the account/region baseline. If the account
# is on BASIC scanning with no rules / no replication / no pull-through
# cache (the default), all four fire on the first repo scanned.
#
# Usage:
#   ./create_test_resources.sh [--region REGION] [--skip-push] [--help]
#
# By default we push a tiny image built FROM debian:8 (with a benign
# noop /entrypoint.sh) to Repo #1. This produces real CVE findings once
# ECR completes the async scan (usually within 1-2 minutes). Pass
# --skip-push to skip the Docker interaction entirely.
################################################################################

set -u

REGION="${AWS_REGION:-ap-southeast-1}"
PREFIX="ss-test-ecr"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SKIP_PUSH=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --region)     REGION="$2"; shift 2 ;;
        --skip-push)  SKIP_PUSH=true; shift ;;
        --help)       grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'; exit 0 ;;
        *)            echo -e "${RED}Error: Unknown option $1${NC}"; exit 1 ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)
[ -z "${ACCOUNT_ID:-}" ] && { echo -e "${RED}No AWS credentials${NC}"; exit 1; }

STANDARD_REPO="${PREFIX}-standard-${TIMESTAMP}"
HARDENED_REPO="${PREFIX}-hardened-${TIMESTAMP}"
OUTPUT_FILE="created_resources_${TIMESTAMP}.txt"
> "$OUTPUT_FILE"

log() { echo "$1" >> "$OUTPUT_FILE"; }

echo -e "${GREEN}=== ECR Test Resource Creation ===${NC}"
echo "Region: $REGION | Account: $ACCOUNT_ID | Timestamp: $TIMESTAMP"
echo ""

################################################################################
# Step 1: Create the STANDARD (insecure) repo
################################################################################

echo -e "${GREEN}=== Step 1: Create STANDARD repo (insecure defaults) ===${NC}"

STANDARD_ARN=$(aws ecr create-repository \
    --repository-name "$STANDARD_REPO" \
    --image-tag-mutability MUTABLE \
    --image-scanning-configuration scanOnPush=false \
    --region "$REGION" \
    --query 'repository.repositoryArn' \
    --output text 2>&1) || {
        echo -e "${RED}✗ Create failed${NC}"; echo "$STANDARD_ARN" | head -3; exit 1;
    }
log "REPO:${STANDARD_REPO}"
echo -e "${GREEN}✓ Standard repo: ${STANDARD_REPO}${NC}"

################################################################################
# Step 2: Attach a wildcard-Principal repo policy (no Condition)
################################################################################

echo -e "\n${GREEN}=== Step 2: Set wildcard-Principal repo policy ===${NC}"

cat > /tmp/${PREFIX}-repo-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicPullNoCondition",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ]
    }
  ]
}
EOF

aws ecr set-repository-policy \
    --repository-name "$STANDARD_REPO" \
    --policy-text file:///tmp/${PREFIX}-repo-policy.json \
    --region "$REGION" > /dev/null \
    && echo -e "${GREEN}✓ Public-Principal repo policy attached${NC}" \
    || echo -e "${YELLOW}⚠ Policy attach failed (permissions?)${NC}"

################################################################################
# Step 3: Optionally push a vulnerable image + create an untagged sibling
################################################################################

if [ "$SKIP_PUSH" = false ]; then
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}⚠ docker not found, skipping image push${NC}"
        SKIP_PUSH=true
    elif ! docker info &> /dev/null; then
        echo -e "${YELLOW}⚠ Docker daemon not running, skipping image push${NC}"
        SKIP_PUSH=true
    fi
fi

if [ "$SKIP_PUSH" = false ]; then
    echo -e "\n${GREEN}=== Step 3: Push a debian:8-based image (CVE bait) ===${NC}"

    REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
    IMAGE_URI="${REGISTRY}/${STANDARD_REPO}"

    BUILD_DIR=$(mktemp -d)
    cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM debian:8
# End-of-life base — surfaces many known CVEs when scanned by ECR.
CMD ["/bin/true"]
EOF

    echo "Building image..."
    aws ecr get-login-password --region "$REGION" 2>/dev/null | \
        docker login --username AWS --password-stdin "$REGISTRY" > /dev/null 2>&1 \
        || echo -e "${YELLOW}⚠ ECR login failed${NC}"

    if docker build --quiet -t "${IMAGE_URI}:v1" "$BUILD_DIR" > /tmp/${PREFIX}-build.log 2>&1; then
        docker push "${IMAGE_URI}:v1" > /tmp/${PREFIX}-push.log 2>&1 \
            && echo -e "${GREEN}✓ Pushed ${IMAGE_URI}:v1 (CVE bait)${NC}" \
            || echo -e "${YELLOW}⚠ Push failed — see /tmp/${PREFIX}-push.log${NC}"

        # Second tag on the SAME digest, then delete the second tag →
        # produces an untagged image layer (the digest stays but with no tag).
        docker tag "${IMAGE_URI}:v1" "${IMAGE_URI}:v2" > /dev/null 2>&1
        docker push "${IMAGE_URI}:v2" > /dev/null 2>&1

        # Delete the v2 tag but not the manifest — this leaves an untagged image.
        aws ecr batch-delete-image \
            --repository-name "$STANDARD_REPO" \
            --image-ids imageTag=v2 \
            --region "$REGION" > /dev/null 2>&1 \
            && echo -e "${GREEN}✓ Untagged image sibling produced${NC}"
    else
        echo -e "${YELLOW}⚠ Docker build failed — see /tmp/${PREFIX}-build.log${NC}"
    fi

    rm -rf "$BUILD_DIR"
else
    echo -e "\n${YELLOW}=== Step 3: skipped (no docker or --skip-push) ===${NC}"
fi

################################################################################
# Step 4: Create the HARDENED contrast repo
################################################################################

echo -e "\n${GREEN}=== Step 4: Create HARDENED repo (baseline for pass/fail contrast) ===${NC}"

HARDENED_ARN=$(aws ecr create-repository \
    --repository-name "$HARDENED_REPO" \
    --image-tag-mutability IMMUTABLE \
    --image-scanning-configuration scanOnPush=true \
    --tags Key=owner,Value=service-screener-test Key=environment,Value=simulation \
    --region "$REGION" \
    --query 'repository.repositoryArn' \
    --output text 2>&1) || {
        echo -e "${YELLOW}⚠ Hardened repo create failed${NC}"
    }
log "REPO:${HARDENED_REPO}"
echo -e "${GREEN}✓ Hardened repo: ${HARDENED_REPO}${NC}"

# Lifecycle policy WITH only a tag-count rule (no untagged, no age-based) —
# this trips #19 ecrLifecyclePolicyEffectiveness while passing #3.
cat > /tmp/${PREFIX}-lifecycle.json <<EOF
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Keep last 10 tagged images",
      "selection": {
        "tagStatus": "tagged",
        "tagPrefixList": ["v"],
        "countType": "imageCountMoreThan",
        "countNumber": 10
      },
      "action": {"type": "expire"}
    }
  ]
}
EOF

aws ecr put-lifecycle-policy \
    --repository-name "$HARDENED_REPO" \
    --lifecycle-policy-text file:///tmp/${PREFIX}-lifecycle.json \
    --region "$REGION" > /dev/null \
    && echo -e "${GREEN}✓ Lifecycle policy attached to hardened repo (intentionally missing untagged + age rules)${NC}"

################################################################################
# Summary
################################################################################

echo ""
echo -e "${GREEN}=== Complete ===${NC}"
echo "Resources logged to: ${OUTPUT_FILE}"
echo ""
echo "Wait 1-3 minutes for ECR to complete the async image scan, then run:"
echo ""
echo -e "  ${CYAN}python3 main.py --regions ${REGION} --services ecr --beta 1 --sequential 1${NC}"
echo ""
echo "Expected FAIL findings on the STANDARD repo:"
echo "  - ecrScanOnPush, ecrTagImmutability, ecrEncryptionKms,"
echo "  - ecrLifecyclePolicy, ecrRepoPublicAccess,"
echo "  - ecrPublicRepoTagging (no tags),"
echo "  - ecrUntaggedImages (when Step 3 succeeded),"
echo "  - ecrCriticalVulnerabilities/ecrHighVulnerabilities (once scan completes)"
echo ""
echo "Expected FAIL findings on the HARDENED repo:"
echo "  - ecrLifecyclePolicyEffectiveness (missing untagged + age rules)"
echo ""
echo "Expected registry-level FAILs (first repo in the region):"
echo "  - ecrEnhancedScanning (BASIC scanning)"
echo "  - ecrScanFrequency (no CONTINUOUS_SCAN rule)"
echo "  - ecrReplicationNotConfigured, ecrPullThroughCache"
echo ""
echo "To clean up: ./cleanup_test_resources.sh ${OUTPUT_FILE}"

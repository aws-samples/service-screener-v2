#!/bin/bash

# ACM Test Resources Creation Script
# Creates ACM certificates in various states to exercise the 13 ACM checks.
#
# NOTE: ACM does NOT let us:
#   - Backdate a certificate's NotAfter to force EXPIRED / <30d / <90d states
#   - Force RenewalStatus=FAILED (that requires DNS/CAA misconfiguration)
#   - Force Status=REVOKED (only Private CA revocation)
#   - Force RSA_1024 issuance (ACM no longer issues 1024; only via import of a
#     pre-existing 1024-bit cert, which itself has to be generated with openssl)
#
# What we CAN reliably simulate is documented below. Checks marked "not
# simulated" require production certificates that already exhibit the state.

set -e

REGION="${AWS_REGION:-ap-southeast-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TAG_KEY="ServiceScreenerTest"
TAG_VALUE="acm-test-${TIMESTAMP}"

echo "=========================================="
echo "ACM Test Resources Creation"
echo "=========================================="
echo "Region:    $REGION"
echo "Account:   $ACCOUNT_ID"
echo "Timestamp: $TIMESTAMP"
echo "Tag:       $TAG_KEY=$TAG_VALUE"
echo "=========================================="
echo ""

# Working directory for temporary PEM files (cleaned up at end)
WORKDIR=$(mktemp -d -t acm-sim-XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

TEST_ROOT_DOMAIN="ss-test-${TIMESTAMP}.example.internal"

# ------------------------------------------------------------------
# Helper: request an ACM-managed certificate (stays PENDING_VALIDATION
# forever because we never publish the DNS validation records).
# ------------------------------------------------------------------
request_cert() {
    local domain="$1"
    local subject_alt="$2"          # optional, may be empty
    local extra_options="$3"        # optional, e.g. "Options={CertificateTransparencyLoggingPreference=DISABLED}"

    local cmd="aws acm request-certificate --region $REGION"
    cmd+=" --domain-name $domain"
    cmd+=" --validation-method DNS"
    cmd+=" --tags Key=$TAG_KEY,Value=$TAG_VALUE"
    if [ -n "$subject_alt" ]; then
        cmd+=" --subject-alternative-names $subject_alt"
    fi
    if [ -n "$extra_options" ]; then
        cmd+=" --options $extra_options"
    fi

    eval "$cmd" --query 'CertificateArn' --output text
}

# ------------------------------------------------------------------
# 1. Wildcard certificate — triggers acmWildcardCert (+ acmCertNoTags
#    if you drop the tag flag; we leave tags on to exercise happy path)
# ------------------------------------------------------------------
echo "1. Requesting wildcard certificate (*.wildcard.$TEST_ROOT_DOMAIN)"
WILDCARD_ARN=$(request_cert "*.wildcard.$TEST_ROOT_DOMAIN" "" "")
echo "   $WILDCARD_ARN"

# ------------------------------------------------------------------
# 2. Certificate with CT logging DISABLED — triggers
#    acmCertTransparencyDisabled once validation completes; while in
#    PENDING_VALIDATION it will trigger acmCertPendingValidation after
#    ~72h. In both cases the option is set on the cert.
# ------------------------------------------------------------------
echo "2. Requesting certificate with Certificate Transparency DISABLED"
CT_DISABLED_ARN=$(request_cert \
    "ct-disabled.$TEST_ROOT_DOMAIN" \
    "" \
    "CertificateTransparencyLoggingPreference=DISABLED")
echo "   $CT_DISABLED_ARN"

# ------------------------------------------------------------------
# 3. Untagged certificate — triggers acmCertNoTags
#    (create WITHOUT --tags then intentionally leave it bare)
# ------------------------------------------------------------------
echo "3. Requesting UNTAGGED certificate (marker via description only)"
UNTAGGED_ARN=$(aws acm request-certificate \
    --region "$REGION" \
    --domain-name "untagged.$TEST_ROOT_DOMAIN" \
    --validation-method DNS \
    --query 'CertificateArn' --output text)
echo "   $UNTAGGED_ARN"
# Track it separately for cleanup because it has no ServiceScreenerTest tag
echo "$UNTAGGED_ARN" > "$WORKDIR/untagged-arn.txt"

# ------------------------------------------------------------------
# 4. Standard certificate that will sit in PENDING_VALIDATION and
#    eventually acmCertPendingValidation (>72h old).
# ------------------------------------------------------------------
echo "4. Requesting standard certificate (will stay in PENDING_VALIDATION)"
PENDING_ARN=$(request_cert "pending.$TEST_ROOT_DOMAIN" "" "")
echo "   $PENDING_ARN"

# ------------------------------------------------------------------
# 5. Imported self-signed certificate — triggers acmCertNoTags AND
#    (depending on expiry we set) acmImportedCertNoAutoRenewal and
#    acmCertExpiry30Days / acmCertExpiry90Days / acmCertExpired.
#    We generate a 60-day cert so it hits acmCertExpiry90Days AND
#    acmImportedCertNoAutoRenewal.
# ------------------------------------------------------------------
echo "5. Generating self-signed 60-day cert and importing to ACM"
openssl req -x509 -newkey rsa:2048 -sha256 \
    -keyout "$WORKDIR/imported.key" \
    -out "$WORKDIR/imported.crt" \
    -days 60 -nodes \
    -subj "/CN=imported.$TEST_ROOT_DOMAIN" >/dev/null 2>&1

IMPORTED_ARN=$(aws acm import-certificate \
    --region "$REGION" \
    --certificate "fileb://$WORKDIR/imported.crt" \
    --private-key "fileb://$WORKDIR/imported.key" \
    --tags Key=$TAG_KEY,Value=$TAG_VALUE \
    --query 'CertificateArn' --output text)
echo "   $IMPORTED_ARN"

# ------------------------------------------------------------------
# 6. Imported ALREADY-EXPIRED certificate — triggers acmCertExpired.
#    We generate a cert with a start date in the past and a 1-day
#    validity that has already lapsed.
# ------------------------------------------------------------------
echo "6. Generating self-signed EXPIRED cert (expired 5 days ago) and importing"
# openssl req -x509 doesn't accept -startdate directly; use faketime-free
# approach: create a CA-less cert with -not_before / -not_after via
# openssl x509 -req signing on a CSR. Simpler: use openssl req plus
# -not_before / -not_after (OpenSSL 3+). Fall back with -days if not
# supported.
if openssl req -help 2>&1 | grep -q -- '-not_before'; then
    NOT_BEFORE=$(date -u -v-30d +%Y%m%d%H%M%SZ 2>/dev/null \
                 || date -u -d '30 days ago' +%Y%m%d%H%M%SZ)
    NOT_AFTER=$(date -u -v-5d +%Y%m%d%H%M%SZ 2>/dev/null \
                 || date -u -d '5 days ago' +%Y%m%d%H%M%SZ)
    openssl req -x509 -newkey rsa:2048 -sha256 \
        -keyout "$WORKDIR/expired.key" \
        -out "$WORKDIR/expired.crt" \
        -not_before "$NOT_BEFORE" \
        -not_after "$NOT_AFTER" \
        -nodes \
        -subj "/CN=expired.$TEST_ROOT_DOMAIN" >/dev/null 2>&1
else
    # OpenSSL < 3.2 fallback: create a fresh CA and sign with custom dates
    openssl req -x509 -newkey rsa:2048 -sha256 -days -5 \
        -keyout "$WORKDIR/expired.key" \
        -out "$WORKDIR/expired.crt" \
        -nodes \
        -subj "/CN=expired.$TEST_ROOT_DOMAIN" >/dev/null 2>&1 || {
            echo "   ⚠ Skipping expired-cert import: openssl cannot backdate on this system"
            EXPIRED_ARN=""
        }
fi

if [ -f "$WORKDIR/expired.crt" ] && [ -z "${EXPIRED_ARN+x}" ]; then
    EXPIRED_ARN=$(aws acm import-certificate \
        --region "$REGION" \
        --certificate "fileb://$WORKDIR/expired.crt" \
        --private-key "fileb://$WORKDIR/expired.key" \
        --tags Key=$TAG_KEY,Value=$TAG_VALUE \
        --query 'CertificateArn' --output text 2>/dev/null || echo "")
    if [ -n "$EXPIRED_ARN" ]; then
        echo "   $EXPIRED_ARN"
    else
        echo "   ⚠ ACM rejected the expired cert import (region policy). Skipping."
    fi
fi

# ------------------------------------------------------------------
# 7. Imported RSA-1024 certificate — triggers acmRSAKeyLength.
#    Some regions reject weak keys at import time; the script tries
#    and records the outcome.
# ------------------------------------------------------------------
echo "7. Generating RSA-1024 self-signed cert and attempting import"
openssl req -x509 -newkey rsa:1024 -sha1 \
    -keyout "$WORKDIR/weak.key" \
    -out "$WORKDIR/weak.crt" \
    -days 365 -nodes \
    -subj "/CN=weak-rsa.$TEST_ROOT_DOMAIN" >/dev/null 2>&1 || {
        echo "   ⚠ Local OpenSSL refused RSA-1024 (system crypto policy). Skipping."
        WEAK_ARN=""
    }

if [ -f "$WORKDIR/weak.crt" ] && [ -z "${WEAK_ARN+x}" ]; then
    WEAK_ARN=$(aws acm import-certificate \
        --region "$REGION" \
        --certificate "fileb://$WORKDIR/weak.crt" \
        --private-key "fileb://$WORKDIR/weak.key" \
        --tags Key=$TAG_KEY,Value=$TAG_VALUE \
        --query 'CertificateArn' --output text 2>/dev/null || echo "")
    if [ -n "$WEAK_ARN" ]; then
        echo "   $WEAK_ARN"
    else
        echo "   ⚠ ACM rejected the RSA-1024 import (expected in most regions)."
    fi
fi

echo ""
echo "=========================================="
echo "Test Resources Created"
echo "=========================================="
echo ""
echo "Certificates created (tagged $TAG_KEY=$TAG_VALUE):"
echo "  1. Wildcard:           $WILDCARD_ARN"
echo "  2. CT-disabled:        $CT_DISABLED_ARN"
echo "  3. Untagged:           $UNTAGGED_ARN   (NO tag — cleanup uses arn file)"
echo "  4. Pending validation: $PENDING_ARN"
echo "  5. Imported 60-day:    $IMPORTED_ARN"
[ -n "${EXPIRED_ARN:-}" ] && echo "  6. Imported expired:   $EXPIRED_ARN"
[ -n "${WEAK_ARN:-}"    ] && echo "  7. Imported RSA-1024:  $WEAK_ARN"
echo ""
echo "Checks expected to trigger against these resources:"
echo "  acmWildcardCert                 -> cert 1"
echo "  acmCertTransparencyDisabled     -> cert 2  (once ISSUED)"
echo "  acmCertNoTags                   -> cert 3"
echo "  acmCertPendingValidation        -> certs 2 & 4  (after 72h)"
echo "  acmImportedCertNoAutoRenewal    -> cert 5  (60-day imported)"
echo "  acmCertExpiry90Days             -> cert 5  (60-day imported)"
echo "  acmCertExpired                  -> cert 6  (if import succeeded)"
echo "  acmRSAKeyLength                 -> cert 7  (if import succeeded)"
echo ""
echo "Checks NOT simulated (require production state):"
echo "  acmCertExpiry30Days             — needs cert within 30d of expiry"
echo "  acmCertRenewalFailed            — needs a real failed managed renewal"
echo "  acmCertRevoked                  — requires Private CA revocation"
echo "  acmCertNotInUse                 — needs an ISSUED cert not attached"
echo "  acmCertRenewalIneligible        — needs an email-validated ACM cert"
echo ""
echo "Persist ARNs for cleanup:"
echo "  echo '$UNTAGGED_ARN' > .acm-untagged-arn"
echo "$UNTAGGED_ARN" > "$(dirname "$0")/.acm-untagged-arn"
echo ""
echo "Run Service Screener:"
echo "  python3 main.py --regions $REGION --services acm --beta 1 --sequential 1"
echo ""
echo "Cleanup:"
echo "  ./cleanup_test_resources.sh $TAG_VALUE"

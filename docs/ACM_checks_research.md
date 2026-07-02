# AWS Certificate Manager (ACM) — Service Screener v2 Checks Research

## Service Overview

**Boto3 client**: `acm`  
**Primary API calls**:
- `list_certificates()` — enumerate all certs (⚠️ default returns only RSA_2048; must pass ALL keyTypes)
- `describe_certificate(CertificateArn=...)` — full cert metadata
- `list_tags_for_certificate(CertificateArn=...)` — tags

**Important `list_certificates` gotcha**: By default only returns `RSA_2048` certs. Must include ALL key types:
```python
Includes={'keyTypes': ['RSA_1024','RSA_2048','RSA_3072','RSA_4096','EC_prime256v1','EC_secp384r1','EC_secp521r1']}
```

---

## Check Inventory (13 Checks)

### Tier 1 — Critical / Security Hub Aligned (5 checks)

| # | Check Name | Pillar | Severity | Security Hub | API | FAIL Condition | Usefulness |
|---|-----------|--------|----------|--------------|-----|---------------|------------|
| 1 | `acmCertExpiry30Days` | S | H | ACM.1 | `describe_certificate` → `NotAfter` | `NotAfter` is within 30 days from now | ⭐⭐⭐⭐⭐ |
| 2 | `acmCertExpired` | S | H | ACM.1 | `describe_certificate` → `Status` / `NotAfter` | `Status == 'EXPIRED'` or `NotAfter < now` | ⭐⭐⭐⭐⭐ |
| 3 | `acmRSAKeyLength` | S | H | ACM.2 | `describe_certificate` → `KeyAlgorithm` | `KeyAlgorithm == 'RSA_1024'` | ⭐⭐⭐⭐⭐ |
| 4 | `acmCertRenewalFailed` | R | H | — | `describe_certificate` → `RenewalSummary.RenewalStatus` | `RenewalStatus == 'FAILED'` | ⭐⭐⭐⭐⭐ |
| 5 | `acmCertRevoked` | S | H | — | `describe_certificate` → `Status` | `Status == 'REVOKED'` | ⭐⭐⭐⭐ |

### Tier 2 — Operational Best Practice (5 checks)

| # | Check Name | Pillar | Severity | API | FAIL Condition | Usefulness |
|---|-----------|--------|----------|-----|---------------|------------|
| 6 | `acmCertExpiry90Days` | O | M | `describe_certificate` → `NotAfter` | `NotAfter` is within 90 days from now (but >30 days) | ⭐⭐⭐⭐ |
| 7 | `acmCertNotInUse` | O | M | `describe_certificate` → `InUseBy` | `InUseBy` is empty list AND `Status == 'ISSUED'` | ⭐⭐⭐⭐ |
| 8 | `acmCertPendingValidation` | O | M | `describe_certificate` → `Status`, `CreatedAt` | `Status == 'PENDING_VALIDATION'` AND cert is >72 hours old | ⭐⭐⭐⭐ |
| 9 | `acmCertRenewalIneligible` | O | M | `describe_certificate` → `RenewalEligibility` | `RenewalEligibility == 'INELIGIBLE'` AND `Type == 'AMAZON_ISSUED'` | ⭐⭐⭐⭐ |
| 10 | `acmCertNoTags` | O | L | `list_tags_for_certificate` | Tags list is empty | ⭐⭐⭐ |

### Tier 3 — Advisory / Informational (3 checks)

| # | Check Name | Pillar | Severity | API | FAIL Condition | Usefulness |
|---|-----------|--------|----------|-----|---------------|------------|
| 11 | `acmWildcardCert` | S | L | `describe_certificate` → `DomainName`, `SubjectAlternativeNames` | DomainName starts with `*.` or any SAN starts with `*.` | ⭐⭐⭐ |
| 12 | `acmCertTransparencyDisabled` | S | M | `describe_certificate` → `Options.CertificateTransparencyLoggingPreference` | Value is `'DISABLED'` AND `Type == 'AMAZON_ISSUED'` | ⭐⭐⭐ |
| 13 | `acmImportedCertNoAutoRenewal` | O | L | `describe_certificate` → `Type`, `NotAfter` | `Type == 'IMPORTED'` AND `NotAfter` within 90 days (manual renewal required) | ⭐⭐⭐ |

---

## Detailed Check Specifications

---

### 1. `acmCertExpiry30Days`

**Category**: Security (S)  
**Criticality**: High (H)  
**Security Hub**: ACM.1 (default 30-day threshold)  
**Well-Architected Pillar**: Security — Data Protection — Encryption in transit

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
not_after = cert['NotAfter']  # datetime
```

**FAIL Condition**:
```python
from datetime import datetime, timezone, timedelta

now = datetime.now(timezone.utc)
days_to_expiry = (not_after - now).days
if 0 < days_to_expiry <= 30:
    FAIL  # Certificate expiring within 30 days
```

**Rationale**: Expired TLS certificates cause service outages and security warnings. The 30-day threshold matches Security Hub ACM.1 default and gives teams time to act.

**References**:
- [ACM.1 Security Hub Control](https://docs.aws.amazon.com/securityhub/latest/userguide/acm-controls.html)
- [Check certificate renewal status](https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-renewal-status.html)

---

### 2. `acmCertExpired`

**Category**: Security (S)  
**Criticality**: High (H)  
**Security Hub**: ACM.1 (subset)  
**Well-Architected Pillar**: Security + Reliability

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
status = cert['Status']
not_after = cert.get('NotAfter')
```

**FAIL Condition**:
```python
if status == 'EXPIRED':
    FAIL
# Fallback: NotAfter in the past
elif not_after and not_after < datetime.now(timezone.utc):
    FAIL
```

**Rationale**: An expired certificate should be immediately remediated — it's already causing failures if attached to a resource, or represents dead inventory if not.

---

### 3. `acmRSAKeyLength`

**Category**: Security (S)  
**Criticality**: High (H)  
**Security Hub**: ACM.2  
**Well-Architected Pillar**: Security — Infrastructure Protection

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
key_algo = cert['KeyAlgorithm']
```

**FAIL Condition**:
```python
if key_algo == 'RSA_1024':
    FAIL  # Deprecated, inadequate key strength
```

**Rationale**: RSA-1024 is deprecated and considered cryptographically weak by NIST. ACM no longer issues RSA-1024 certs, but imported certificates may still use them. PCI DSS v4.0.1/4.2.1 requires adequate key strength.

**Note**: ECDSA keys (EC_prime256v1, EC_secp384r1, EC_secp521r1) are all acceptable and generally preferred over RSA for performance.

---

### 4. `acmCertRenewalFailed`

**Category**: Reliability (R)  
**Criticality**: High (H)  
**Well-Architected Pillar**: Reliability — Failure Management

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
renewal = cert.get('RenewalSummary', {})
```

**FAIL Condition**:
```python
if renewal.get('RenewalStatus') == 'FAILED':
    FAIL
    # Additional context: renewal.get('RenewalStatusReason')
```

**Rationale**: A failed renewal means ACM attempted auto-renewal but couldn't complete it (e.g., DNS validation record removed, CAA record blocking, email not responded to). Without intervention, the certificate will expire.

**Status Reasons include**: `NO_AVAILABLE_CONTACTS`, `ADDITIONAL_VERIFICATION_REQUIRED`, `DOMAIN_NOT_ALLOWED`, `DOMAIN_VALIDATION_DENIED`, `CAA_ERROR`, `PCA_*` errors, etc.

---

### 5. `acmCertRevoked`

**Category**: Security (S)  
**Criticality**: High (H)  
**Well-Architected Pillar**: Security — Incident Response

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
status = cert['Status']
revocation_reason = cert.get('RevocationReason', '')
```

**FAIL Condition**:
```python
if status == 'REVOKED':
    FAIL
    # Context: RevocationReason could be KEY_COMPROMISE, CA_COMPROMISE, etc.
```

**Rationale**: A revoked certificate indicates a potential security incident (key compromise, CA compromise, etc.). It should be immediately replaced and investigated.

---

### 6. `acmCertExpiry90Days`

**Category**: Operations (O)  
**Criticality**: Medium (M)  
**Well-Architected Pillar**: Operational Excellence — Prepare

**API Call**: Same as check 1.

**FAIL Condition**:
```python
days_to_expiry = (not_after - now).days
if 30 < days_to_expiry <= 90:
    FAIL  # Early warning — certificate expiring within 90 days
```

**Rationale**: Early warning for certificates that will need attention soon. Particularly important for imported certificates that require manual renewal and have longer lead times.

**Note**: This is advisory/informational for Amazon-issued DNS-validated certs (auto-renewed at 60 days), but critical for imported certs and email-validated certs.

---

### 7. `acmCertNotInUse`

**Category**: Operations (O)  
**Criticality**: Medium (M)  
**Well-Architected Pillar**: Operational Excellence — Organization / Cost Optimization

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
in_use_by = cert.get('InUseBy', [])
status = cert['Status']
```

**FAIL Condition**:
```python
if status == 'ISSUED' and len(in_use_by) == 0:
    FAIL  # Valid certificate not associated with any AWS resource
```

**Rationale**: Unused certificates create operational noise (renewal notifications, audit confusion) and may indicate misconfiguration (cert was issued but never deployed) or orphaned resources. While public ACM certs are free, unused certs from Private CA incur cost.

**Note**: `InUseBy` lists ARNs of resources (ALB, CloudFront, API Gateway, etc.) using the cert. Also available via `list_certificates` → `InUse` (boolean) for optimization.

---

### 8. `acmCertPendingValidation`

**Category**: Operations (O)  
**Criticality**: Medium (M)  
**Well-Architected Pillar**: Operational Excellence — Operate

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
status = cert['Status']
created_at = cert['CreatedAt']
```

**FAIL Condition**:
```python
if status == 'PENDING_VALIDATION':
    hours_since_creation = (now - created_at).total_seconds() / 3600
    if hours_since_creation > 72:
        FAIL  # Stuck in pending validation (ACM times out at 72h)
```

**Rationale**: ACM attempts validation for 72 hours before timing out. A certificate stuck in PENDING_VALIDATION for >72h indicates the DNS CNAME was never created or email was never responded to. This is likely a forgotten/abandoned request.

**Also flag**: `Status == 'VALIDATION_TIMED_OUT'` or `Status == 'FAILED'` (with `FailureReason`).

---

### 9. `acmCertRenewalIneligible`

**Category**: Operations (O)  
**Criticality**: Medium (M)  
**Well-Architected Pillar**: Reliability — Change Management

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
renewal_eligibility = cert.get('RenewalEligibility')
cert_type = cert['Type']
validation_method = cert.get('DomainValidationOptions', [{}])[0].get('ValidationMethod', '')
```

**FAIL Condition**:
```python
if cert_type == 'AMAZON_ISSUED' and renewal_eligibility == 'INELIGIBLE':
    FAIL
    # Additional context: email-validated certs require manual response
```

**Rationale**: An ACM-issued certificate marked INELIGIBLE for renewal will eventually expire without manual intervention. This typically happens when:
- Email validation is used (can't auto-renew without human response)
- The certificate was issued before ACM renewal support was added
- Domain validation records were removed

**Recommendation**: Migrate to DNS validation for automatic renewal eligibility.

---

### 10. `acmCertNoTags`

**Category**: Operations (O)  
**Criticality**: Low (L)  
**Security Hub**: ACM.3  
**Well-Architected Pillar**: Operational Excellence — Organization

**API Call**:
```python
tags_resp = client.list_tags_for_certificate(CertificateArn=arn)
tags = tags_resp.get('Tags', [])
```

**FAIL Condition**:
```python
if len(tags) == 0:
    FAIL  # No tags on certificate
```

**Rationale**: Tags enable cost attribution, ownership tracking, automation, and ABAC policies. Untagged certificates are harder to manage, audit, and associate with teams/applications.

---

### 11. `acmWildcardCert`

**Category**: Security (S)  
**Criticality**: Low (L)  
**Well-Architected Pillar**: Security — Infrastructure Protection

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
domain_name = cert['DomainName']
sans = cert.get('SubjectAlternativeNames', [])
```

**FAIL Condition**:
```python
has_wildcard = domain_name.startswith('*.')
if not has_wildcard:
    has_wildcard = any(san.startswith('*.') for san in sans)
if has_wildcard:
    FAIL  # Advisory: Wildcard certificate detected
```

**Rationale**: Wildcard certificates (`*.example.com`) cover all subdomains, which:
- Increases blast radius if the private key is compromised
- Can mask unauthorized subdomains
- Makes certificate pinning impractical
- May not meet compliance requirements (PCI DSS recommends specific certs)

**Note**: This is informational/advisory — wildcards are legitimate in many architectures. Flag for awareness, not necessarily for remediation.

---

### 12. `acmCertTransparencyDisabled`

**Category**: Security (S)  
**Criticality**: Medium (M)  
**Well-Architected Pillar**: Security — Detection

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
ct_pref = cert.get('Options', {}).get('CertificateTransparencyLoggingPreference')
cert_type = cert['Type']
```

**FAIL Condition**:
```python
if cert_type == 'AMAZON_ISSUED' and ct_pref == 'DISABLED':
    FAIL  # CT logging deliberately disabled
```

**Rationale**: Certificate Transparency (CT) allows domain owners to detect mis-issued certificates. Disabling CT logging:
- Prevents detection of unauthorized certificate issuance
- May cause browser warnings (Chrome requires CT for all public certs)
- Reduces security posture

**Note (2026 update)**: As of June 15, 2026, ACM enforces CT logging for all new public certificates (the `CertificateTransparencyLoggingPreference` option is deprecated for new issuances). This check remains relevant for older certificates that were issued with CT disabled.

---

### 13. `acmImportedCertNoAutoRenewal`

**Category**: Operations (O)  
**Criticality**: Low (L)  
**Well-Architected Pillar**: Reliability — Failure Management

**API Call**:
```python
cert = client.describe_certificate(CertificateArn=arn)['Certificate']
cert_type = cert['Type']
not_after = cert.get('NotAfter')
```

**FAIL Condition**:
```python
if cert_type == 'IMPORTED' and not_after:
    days_to_expiry = (not_after - now).days
    if 0 < days_to_expiry <= 90:
        FAIL  # Imported cert approaching expiry — no auto-renewal possible
```

**Rationale**: Imported certificates CANNOT be auto-renewed by ACM. They must be manually re-imported before expiry. This check provides early warning for imported certs specifically, since they have no automated safety net.

**Recommendation**: Where possible, replace imported certificates with ACM-issued certificates using DNS validation for automatic renewal.

---

## Implementation Architecture

### Main Service Class: `Acm.py`

```python
import botocore
from datetime import datetime, timezone, timedelta

from utils.Config import Config
from utils.Tools import _pr, _pi
from services.Service import Service
from services.acm.drivers.AcmCommon import AcmCommon


class Acm(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.acmClient = ssBoto.client('acm', config=self.bConfig)
        self.acmCertificates = []
    
    def getResources(self):
        """List ALL certificates (must specify all key types)"""
        paginator = self.acmClient.get_paginator('list_certificates')
        
        # IMPORTANT: Default only returns RSA_2048!
        # Must include all key types to get full inventory
        page_iterator = paginator.paginate(
            Includes={
                'keyTypes': [
                    'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096',
                    'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1'
                ]
            },
            CertificateStatuses=[
                'PENDING_VALIDATION', 'ISSUED', 'INACTIVE',
                'EXPIRED', 'VALIDATION_TIMED_OUT', 'REVOKED', 'FAILED'
            ]
        )
        
        for page in page_iterator:
            for cert_summary in page.get('CertificateSummaryList', []):
                arn = cert_summary['CertificateArn']
                
                # Get full certificate details
                try:
                    detail = self.acmClient.describe_certificate(
                        CertificateArn=arn
                    )['Certificate']
                except botocore.exceptions.ClientError:
                    continue
                
                # Get tags
                try:
                    tags_resp = self.acmClient.list_tags_for_certificate(
                        CertificateArn=arn
                    )
                    detail['_Tags'] = tags_resp.get('Tags', [])
                except botocore.exceptions.ClientError:
                    detail['_Tags'] = []
                
                # Tag filtering
                if self.tags:
                    nTags = self.convertTagKeyTagValueIntoKeyValue(detail['_Tags'])
                    if self.resourceHasTags(nTags) == False:
                        continue
                
                self.acmCertificates.append(detail)
    
    def advise(self):
        objs = {}
        self.getResources()
        
        for cert in self.acmCertificates:
            identifier = cert.get('DomainName', cert['CertificateArn'])
            _pi('ACM', identifier + ' (' + cert['CertificateArn'] + ')')
            
            obj = AcmCommon(cert, self.acmClient)
            obj.run(self.__class__)
            
            objs[cert['CertificateArn']] = obj.getInfo()
            del obj
        
        return objs
```

### Driver Class: `AcmCommon.py`

```python
from datetime import datetime, timezone, timedelta
from services.Evaluator import Evaluator


class AcmCommon(Evaluator):
    def __init__(self, cert, acmClient):
        self.results = {}
        self.cert = cert
        self.acmClient = acmClient
        self._resourceName = cert['CertificateArn']
        self.init()

    def _checkCertExpiry(self):
        """Checks 1, 2, 6: Certificate expiry states"""
        not_after = self.cert.get('NotAfter')
        status = self.cert.get('Status')
        
        if not not_after:
            return
        
        now = datetime.now(timezone.utc)
        days_to_expiry = (not_after - now).days
        
        # Check 2: Already expired
        if status == 'EXPIRED' or days_to_expiry < 0:
            self.results['acmCertExpired'] = [-1, f"Expired {abs(days_to_expiry)} days ago"]
            return  # Don't double-flag
        
        # Check 1: Expiring within 30 days
        if days_to_expiry <= 30:
            self.results['acmCertExpiry30Days'] = [-1, f"Expires in {days_to_expiry} days ({not_after.strftime('%Y-%m-%d')})"]
        # Check 6: Expiring within 90 days
        elif days_to_expiry <= 90:
            self.results['acmCertExpiry90Days'] = [-1, f"Expires in {days_to_expiry} days ({not_after.strftime('%Y-%m-%d')})"]

    def _checkKeyAlgorithm(self):
        """Check 3: RSA key length"""
        key_algo = self.cert.get('KeyAlgorithm', '')
        
        if key_algo == 'RSA_1024':
            self.results['acmRSAKeyLength'] = [-1, f"Key algorithm: {key_algo} (deprecated, minimum RSA_2048 required)"]

    def _checkRenewalStatus(self):
        """Check 4: Renewal failed"""
        renewal = self.cert.get('RenewalSummary', {})
        
        if renewal.get('RenewalStatus') == 'FAILED':
            reason = renewal.get('RenewalStatusReason', 'Unknown')
            self.results['acmCertRenewalFailed'] = [-1, f"Renewal failed: {reason}"]

    def _checkRevoked(self):
        """Check 5: Certificate revoked"""
        if self.cert.get('Status') == 'REVOKED':
            reason = self.cert.get('RevocationReason', 'UNSPECIFIED')
            revoked_at = self.cert.get('RevokedAt', '')
            self.results['acmCertRevoked'] = [-1, f"Revoked: {reason} at {revoked_at}"]

    def _checkInUse(self):
        """Check 7: Certificate not in use"""
        in_use_by = self.cert.get('InUseBy', [])
        status = self.cert.get('Status')
        
        if status == 'ISSUED' and len(in_use_by) == 0:
            cert_type = self.cert.get('Type', 'Unknown')
            self.results['acmCertNotInUse'] = [-1, f"Issued {cert_type} certificate not associated with any resource"]

    def _checkPendingValidation(self):
        """Check 8: Stuck in pending validation"""
        status = self.cert.get('Status')
        
        if status in ('PENDING_VALIDATION', 'VALIDATION_TIMED_OUT', 'FAILED'):
            created_at = self.cert.get('CreatedAt')
            now = datetime.now(timezone.utc)
            
            if status == 'PENDING_VALIDATION' and created_at:
                hours_old = (now - created_at).total_seconds() / 3600
                if hours_old > 72:
                    self.results['acmCertPendingValidation'] = [-1, f"Pending validation for {int(hours_old)}h (>72h timeout)"]
            elif status == 'VALIDATION_TIMED_OUT':
                self.results['acmCertPendingValidation'] = [-1, "Validation timed out — DNS/email validation never completed"]
            elif status == 'FAILED':
                reason = self.cert.get('FailureReason', 'Unknown')
                self.results['acmCertPendingValidation'] = [-1, f"Certificate request failed: {reason}"]

    def _checkRenewalEligibility(self):
        """Check 9: Renewal ineligible for ACM-issued certs"""
        cert_type = self.cert.get('Type')
        eligibility = self.cert.get('RenewalEligibility')
        
        if cert_type == 'AMAZON_ISSUED' and eligibility == 'INELIGIBLE':
            # Check validation method
            validation_methods = set()
            for dvo in self.cert.get('DomainValidationOptions', []):
                vm = dvo.get('ValidationMethod', '')
                if vm:
                    validation_methods.add(vm)
            
            method_str = ', '.join(validation_methods) if validation_methods else 'Unknown'
            self.results['acmCertRenewalIneligible'] = [-1, f"Not eligible for auto-renewal (validation: {method_str})"]

    def _checkTags(self):
        """Check 10: No tags"""
        tags = self.cert.get('_Tags', [])
        
        if len(tags) == 0:
            self.results['acmCertNoTags'] = [-1, "Certificate has no tags"]

    def _checkWildcard(self):
        """Check 11: Wildcard certificate"""
        domain_name = self.cert.get('DomainName', '')
        sans = self.cert.get('SubjectAlternativeNames', [])
        
        wildcards = []
        if domain_name.startswith('*.'):
            wildcards.append(domain_name)
        for san in sans:
            if san.startswith('*.') and san not in wildcards:
                wildcards.append(san)
        
        if wildcards:
            self.results['acmWildcardCert'] = [-1, f"Wildcard domain(s): {', '.join(wildcards)}"]

    def _checkTransparencyLogging(self):
        """Check 12: CT logging disabled"""
        cert_type = self.cert.get('Type')
        ct_pref = self.cert.get('Options', {}).get('CertificateTransparencyLoggingPreference')
        
        if cert_type == 'AMAZON_ISSUED' and ct_pref == 'DISABLED':
            self.results['acmCertTransparencyDisabled'] = [-1, "Certificate Transparency logging is disabled"]

    def _checkImportedCertRenewal(self):
        """Check 13: Imported cert approaching expiry (no auto-renewal)"""
        cert_type = self.cert.get('Type')
        not_after = self.cert.get('NotAfter')
        
        if cert_type != 'IMPORTED' or not not_after:
            return
        
        now = datetime.now(timezone.utc)
        days_to_expiry = (not_after - now).days
        
        if 0 < days_to_expiry <= 90:
            self.results['acmImportedCertNoAutoRenewal'] = [-1, 
                f"Imported cert expires in {days_to_expiry} days — manual renewal required"]
```

---

## Reporter JSON: `acm.reporter.json`

```json
{
  "acmCertExpiry30Days": {
    "category": "S",
    "^description": "You have {$COUNT} ACM certificate(s) expiring within 30 days. Certificates must be renewed before expiry to avoid service disruptions. For imported certificates, manually re-import the renewed certificate. For ACM-issued certificates, verify that DNS validation records are in place or respond to email validation requests.",
    "downtime": 1,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "H",
    "shortDesc": "Certificate expiring within 30 days",
    "ref": [
      "[ACM.1 Security Hub Control]<https://docs.aws.amazon.com/securityhub/latest/userguide/acm-controls.html>",
      "[Check certificate renewal status]<https://docs.aws.amazon.com/acm/latest/userguide/check-certificate-renewal-status.html>"
    ]
  },
  "acmCertExpired": {
    "category": "S",
    "^description": "[Critical] You have {$COUNT} expired ACM certificate(s). Expired certificates cannot secure connections and will cause service failures if still associated with resources. Replace immediately with a valid certificate.",
    "downtime": 1,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "H",
    "shortDesc": "Certificate has expired",
    "ref": [
      "[ACM Certificate Lifecycle]<https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html>",
      "[Troubleshoot certificate renewal]<https://docs.aws.amazon.com/acm/latest/userguide/troubleshooting-renewal.html>"
    ]
  },
  "acmRSAKeyLength": {
    "category": "S",
    "^description": "You have {$COUNT} ACM certificate(s) using RSA-1024 key algorithm, which is cryptographically deprecated. RSA keys must be at least 2048 bits. ECDSA (EC_prime256v1, EC_secp384r1) is preferred for better security and performance.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 1,
    "criticality": "H",
    "shortDesc": "RSA key too short (< 2048 bits)",
    "ref": [
      "[ACM.2 Security Hub Control]<https://docs.aws.amazon.com/securityhub/latest/userguide/acm-controls.html>",
      "[ACM Supported Key Algorithms]<https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html>"
    ]
  },
  "acmCertRenewalFailed": {
    "category": "R",
    "^description": "[Action Required] You have {$COUNT} ACM certificate(s) with failed renewal. ACM attempted auto-renewal but could not complete validation. Check DNS CNAME records, CAA records, or respond to email validation. Without intervention, the certificate will expire.",
    "downtime": 1,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "H",
    "shortDesc": "Certificate renewal failed",
    "ref": [
      "[Troubleshooting managed certificate renewal]<https://docs.aws.amazon.com/acm/latest/userguide/troubleshooting-renewal.html>",
      "[Managed renewal for ACM certificates]<https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html>"
    ]
  },
  "acmCertRevoked": {
    "category": "S",
    "^description": "[Critical] You have {$COUNT} revoked ACM certificate(s). A revoked certificate may indicate a security incident (key compromise, CA compromise). Investigate the revocation reason, replace the certificate immediately, and rotate any potentially compromised credentials.",
    "downtime": 1,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "H",
    "shortDesc": "Certificate has been revoked",
    "ref": [
      "[ACM Certificate Revocation]<https://docs.aws.amazon.com/acm/latest/userguide/revocation-reasons.html>"
    ]
  },
  "acmCertExpiry90Days": {
    "category": "O",
    "^description": "You have {$COUNT} ACM certificate(s) expiring within 90 days. Plan renewal activities. For ACM-issued certificates with DNS validation, renewal should happen automatically at 60 days. For imported or email-validated certificates, manual action is required.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "M",
    "shortDesc": "Certificate expiring within 90 days",
    "ref": [
      "[Managed renewal]<https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html>"
    ]
  },
  "acmCertNotInUse": {
    "category": "O",
    "^description": "You have {$COUNT} issued ACM certificate(s) not associated with any AWS resource. These may be orphaned certificates from decommissioned services. Review and delete if no longer needed. Private CA certificates incur cost even when unused.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "M",
    "shortDesc": "Certificate not associated with any resource",
    "ref": [
      "[Delete certificates]<https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-delete.html>"
    ]
  },
  "acmCertPendingValidation": {
    "category": "O",
    "^description": "You have {$COUNT} ACM certificate(s) stuck in pending validation, timed out, or failed state. These represent incomplete certificate requests that should be cleaned up. Delete the request and re-create if still needed, ensuring DNS/email validation is properly configured.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "M",
    "shortDesc": "Certificate validation stuck or failed",
    "ref": [
      "[Troubleshoot validation]<https://docs.aws.amazon.com/acm/latest/userguide/troubleshooting-validation.html>"
    ]
  },
  "acmCertRenewalIneligible": {
    "category": "O",
    "^description": "You have {$COUNT} ACM-issued certificate(s) not eligible for automatic renewal. This typically means the certificate uses email validation. Migrate to DNS validation to enable automatic renewal and eliminate manual intervention risk.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "M",
    "shortDesc": "Certificate not eligible for auto-renewal",
    "ref": [
      "[DNS validation]<https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html>",
      "[Renewal eligibility]<https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html>"
    ]
  },
  "acmCertNoTags": {
    "category": "O",
    "^description": "You have {$COUNT} ACM certificate(s) without any tags. Tags are essential for cost allocation, ownership identification, automation, and attribute-based access control (ABAC). Add tags for environment, owner, application, and cost center at minimum.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "L",
    "shortDesc": "Certificate has no tags",
    "ref": [
      "[ACM.3 Security Hub Control]<https://docs.aws.amazon.com/securityhub/latest/userguide/acm-controls.html>",
      "[Tagging ACM Certificates]<https://docs.aws.amazon.com/acm/latest/userguide/tags.html>"
    ]
  },
  "acmWildcardCert": {
    "category": "S",
    "^description": "[Informational] You have {$COUNT} wildcard ACM certificate(s). Wildcard certificates increase blast radius if compromised, can mask unauthorized subdomains, and may not meet compliance requirements (e.g., PCI DSS). Consider using specific domain certificates where feasible.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "L",
    "shortDesc": "Wildcard certificate detected",
    "ref": [
      "[ACM Best Practices]<https://docs.aws.amazon.com/acm/latest/userguide/acm-bestpractices.html>"
    ]
  },
  "acmCertTransparencyDisabled": {
    "category": "S",
    "^description": "You have {$COUNT} ACM certificate(s) with Certificate Transparency (CT) logging disabled. CT enables detection of mis-issued certificates. Browsers may show warnings for certificates not logged to CT. Enable CT logging unless there is a specific business reason to keep domain names private.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "M",
    "shortDesc": "Certificate Transparency logging disabled",
    "ref": [
      "[Opting out of CT logging]<https://docs.aws.amazon.com/acm/latest/userguide/acm-bestpractices.html#best-practices-transparency>",
      "[Certificate Transparency]<https://certificate.transparency.dev/>"
    ]
  },
  "acmImportedCertNoAutoRenewal": {
    "category": "O",
    "^description": "You have {$COUNT} imported ACM certificate(s) approaching expiry that require manual renewal. ACM cannot auto-renew imported certificates. Plan to obtain a renewed certificate from your CA and re-import it before expiry. Consider replacing with ACM-issued certificates where possible.",
    "downtime": 0,
    "slowness": 0,
    "additionalCost": 0,
    "needFullTest": 0,
    "criticality": "L",
    "shortDesc": "Imported certificate requires manual renewal",
    "ref": [
      "[Reimport a certificate]<https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html>",
      "[Monitor imported certificate expiration]<https://aws.amazon.com/blogs/security/how-to-monitor-expirations-of-imported-certificates-in-aws-certificate-manager-acm/>"
    ]
  }
}
```

---

## API Call Summary

| API Call | Purpose | Rate Limit Consideration |
|---------|---------|-------------------------|
| `list_certificates` (paginated) | Enumerate all certs | 1 call per page (default 20/page) |
| `describe_certificate` | Full cert details | 1 per certificate |
| `list_tags_for_certificate` | Tag compliance | 1 per certificate |

**Total API calls per scan**: `1 + (2 × N)` where N = number of certificates  
(1 paginated list + describe + tags per cert)

**Optimization**: `list_certificates` summary already includes `Status`, `KeyAlgorithm`, `Type`, `InUse`, `NotAfter`, `RenewalEligibility`. Use summary for initial filtering, only call `describe_certificate` for detailed checks (renewal info, CT options, SANs, InUseBy ARNs).

---

## Fields Available from `list_certificates` Summary (no additional API call)

These fields on `CertificateSummaryList` items can be used for quick filtering:

| Field | Available Checks |
|-------|-----------------|
| `Status` | Expired, Revoked, Pending, Failed |
| `KeyAlgorithm` | RSA_1024 detection |
| `Type` | IMPORTED vs AMAZON_ISSUED vs PRIVATE |
| `InUse` (boolean) | Not-in-use detection |
| `NotAfter` | Expiry calculations |
| `RenewalEligibility` | Auto-renewal eligibility |

---

## Checks NOT Included (Considered & Rejected)

| Potential Check | Reason Excluded |
|----------------|-----------------|
| Signature algorithm check (SHA-1) | ACM doesn't expose raw signature algo reliably; all ACM-issued certs use SHA-256. Only relevant for very old imports — too rare. |
| Private CA vs Public policy | Organization-specific policy, not universally applicable as a security check |
| Certificate pinning detection | Not detectable via ACM API |
| SAN count too high | Legitimate use case; no universal threshold |
| Cross-account certificate sharing | Not directly detectable from ACM API (InUseBy may show cross-account ARNs but this is informational) |

---

## File Structure for Implementation

```
services/
└── acm/
    ├── Acm.py                    # Main service class
    ├── acm.reporter.json         # Reporter definitions
    ├── drivers/
    │   └── AcmCommon.py          # Check implementations
    └── simulation/
        ├── README.md
        └── create_test_resources.sh
```

---

## Pillar/Category Mapping

- **S** = Security
- **R** = Reliability  
- **O** = Operational Excellence
- **C** = Cost Optimization

## Criticality Mapping

- **H** = High (must fix)
- **M** = Medium (should fix)
- **L** = Low (nice to fix / informational)
- **I** = Informational (awareness only)

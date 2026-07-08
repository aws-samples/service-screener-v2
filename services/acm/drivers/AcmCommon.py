from datetime import datetime, timezone

from services.Evaluator import Evaluator


class AcmCommon(Evaluator):
    """
    Per-certificate evaluator for AWS Certificate Manager.

    Implements all 13 checks (Tier 1 critical, Tier 2 operational, Tier 3
    advisory) documented in docs/ACM_checks_research.md. Each _check* method
    is auto-discovered and executed by services/Evaluator.py.
    """

    def __init__(self, cert, acmClient):
        super().__init__()
        self.cert = cert
        self.acmClient = acmClient
        self._resourceName = cert.get('CertificateArn', 'unknown')
        self.init()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _now():
        return datetime.now(timezone.utc)

    def _daysToExpiry(self):
        not_after = self.cert.get('NotAfter')
        if not not_after:
            return None
        return (not_after - self._now()).days

    # ------------------------------------------------------------------ #
    # Tier 1 — Critical / Security Hub aligned
    # ------------------------------------------------------------------ #
    def _checkCertExpired(self):
        """Check 2: Certificate is already expired (Status EXPIRED or NotAfter in the past)."""
        status = self.cert.get('Status')
        not_after = self.cert.get('NotAfter')
        days = self._daysToExpiry()

        if status == 'EXPIRED' or (days is not None and days < 0):
            reason = f"Status: {status}"
            if days is not None:
                reason += f", expired {abs(days)} day(s) ago"
            if not_after:
                reason += f" (NotAfter: {not_after.strftime('%Y-%m-%d')})"
            self.results['acmCertExpired'] = [-1, reason]

    def _checkCertExpiry30Days(self):
        """Check 1: Certificate expires within 30 days (and is not already expired)."""
        status = self.cert.get('Status')
        if status == 'EXPIRED':
            return  # covered by acmCertExpired

        days = self._daysToExpiry()
        if days is None or days < 0:
            return

        if days <= 30:
            not_after = self.cert.get('NotAfter')
            date_str = not_after.strftime('%Y-%m-%d') if not_after else 'unknown'
            self.results['acmCertExpiry30Days'] = [
                -1, f"Expires in {days} day(s) ({date_str})"
            ]

    def _checkRSAKeyLength(self):
        """Check 3: RSA-1024 keys are deprecated (Security Hub ACM.2)."""
        key_algo = self.cert.get('KeyAlgorithm', '')
        if key_algo == 'RSA_1024':
            self.results['acmRSAKeyLength'] = [
                -1, f"Key algorithm: {key_algo} (deprecated; use RSA_2048+ or ECDSA)"
            ]

    def _checkCertRenewalFailed(self):
        """Check 4: RenewalSummary.RenewalStatus == 'FAILED'."""
        renewal = self.cert.get('RenewalSummary') or {}
        if renewal.get('RenewalStatus') == 'FAILED':
            reason = renewal.get('RenewalStatusReason', 'Unknown')
            self.results['acmCertRenewalFailed'] = [
                -1, f"Renewal failed: {reason}"
            ]

    def _checkCertRevoked(self):
        """Check 5: Status == 'REVOKED'."""
        if self.cert.get('Status') == 'REVOKED':
            reason = self.cert.get('RevocationReason', 'UNSPECIFIED')
            revoked_at = self.cert.get('RevokedAt')
            when = revoked_at.strftime('%Y-%m-%d') if revoked_at else 'unknown'
            self.results['acmCertRevoked'] = [
                -1, f"Revoked: {reason} at {when}"
            ]

    # ------------------------------------------------------------------ #
    # Tier 2 — Operational best practice
    # ------------------------------------------------------------------ #
    def _checkCertExpiry90Days(self):
        """Check 6: Certificate expires within 31-90 days."""
        status = self.cert.get('Status')
        if status == 'EXPIRED':
            return

        days = self._daysToExpiry()
        if days is None:
            return

        if 30 < days <= 90:
            not_after = self.cert.get('NotAfter')
            date_str = not_after.strftime('%Y-%m-%d') if not_after else 'unknown'
            self.results['acmCertExpiry90Days'] = [
                -1, f"Expires in {days} day(s) ({date_str})"
            ]

    def _checkCertNotInUse(self):
        """Check 7: Issued certificate not associated with any AWS resource."""
        status = self.cert.get('Status')
        in_use_by = self.cert.get('InUseBy', []) or []

        if status == 'ISSUED' and len(in_use_by) == 0:
            cert_type = self.cert.get('Type', 'Unknown')
            self.results['acmCertNotInUse'] = [
                -1, f"Issued {cert_type} certificate not associated with any resource"
            ]

    def _checkCertPendingValidation(self):
        """Check 8: PENDING_VALIDATION >72h, VALIDATION_TIMED_OUT, or FAILED requests."""
        status = self.cert.get('Status')

        if status == 'PENDING_VALIDATION':
            created_at = self.cert.get('CreatedAt')
            if created_at:
                hours_old = (self._now() - created_at).total_seconds() / 3600
                if hours_old > 72:
                    self.results['acmCertPendingValidation'] = [
                        -1,
                        f"PENDING_VALIDATION for {int(hours_old)}h (ACM times out at 72h)"
                    ]
        elif status == 'VALIDATION_TIMED_OUT':
            self.results['acmCertPendingValidation'] = [
                -1, "VALIDATION_TIMED_OUT — DNS/email validation never completed"
            ]
        elif status == 'FAILED':
            reason = self.cert.get('FailureReason', 'Unknown')
            self.results['acmCertPendingValidation'] = [
                -1, f"FAILED: {reason}"
            ]

    def _checkCertRenewalIneligible(self):
        """Check 9: AMAZON_ISSUED certificate not eligible for auto-renewal."""
        cert_type = self.cert.get('Type')
        eligibility = self.cert.get('RenewalEligibility')

        if cert_type == 'AMAZON_ISSUED' and eligibility == 'INELIGIBLE':
            methods = set()
            for dvo in self.cert.get('DomainValidationOptions', []) or []:
                vm = dvo.get('ValidationMethod')
                if vm:
                    methods.add(vm)
            method_str = ', '.join(sorted(methods)) if methods else 'Unknown'
            self.results['acmCertRenewalIneligible'] = [
                -1, f"Not eligible for auto-renewal (validation: {method_str})"
            ]

    def _checkCertNoTags(self):
        """Check 10: Certificate has no tags (Security Hub ACM.3)."""
        tags = self.cert.get('_Tags', []) or []
        if len(tags) == 0:
            self.results['acmCertNoTags'] = [-1, "Certificate has no tags"]

    # ------------------------------------------------------------------ #
    # Tier 3 — Advisory / informational
    # ------------------------------------------------------------------ #
    def _checkWildcardCert(self):
        """Check 11: DomainName or any SAN is a wildcard (*.example.com)."""
        domain_name = self.cert.get('DomainName', '') or ''
        sans = self.cert.get('SubjectAlternativeNames', []) or []

        wildcards = []
        if domain_name.startswith('*.'):
            wildcards.append(domain_name)
        for san in sans:
            if san.startswith('*.') and san not in wildcards:
                wildcards.append(san)

        if wildcards:
            self.results['acmWildcardCert'] = [
                -1, f"Wildcard domain(s): {', '.join(wildcards)}"
            ]

    def _checkCertTransparencyDisabled(self):
        """Check 12: CT logging disabled on an AMAZON_ISSUED certificate."""
        cert_type = self.cert.get('Type')
        ct_pref = (self.cert.get('Options') or {}).get(
            'CertificateTransparencyLoggingPreference'
        )
        if cert_type == 'AMAZON_ISSUED' and ct_pref == 'DISABLED':
            self.results['acmCertTransparencyDisabled'] = [
                -1, "Certificate Transparency logging is disabled"
            ]

    def _checkImportedCertNoAutoRenewal(self):
        """Check 13: Imported cert within 90 days of expiry — no auto-renewal possible."""
        cert_type = self.cert.get('Type')
        if cert_type != 'IMPORTED':
            return

        days = self._daysToExpiry()
        if days is None:
            return

        if 0 < days <= 90:
            not_after = self.cert.get('NotAfter')
            date_str = not_after.strftime('%Y-%m-%d') if not_after else 'unknown'
            self.results['acmImportedCertNoAutoRenewal'] = [
                -1,
                f"Imported cert expires in {days} day(s) ({date_str}) — manual re-import required"
            ]

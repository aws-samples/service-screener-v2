from datetime import datetime, timezone

from services.Evaluator import Evaluator


class AcmPcaCa(Evaluator):
    """
    Per-certificate-authority evaluator for AWS Private CA (acm-pca).

    `ca` is the CertificateAuthority structure returned by
    acm-pca.describe_certificate_authority (read-only).
    """

    # Minimum remaining CA-certificate validity before we flag it. A root CA
    # rotation (new root distributed to every trust store) takes far longer
    # than a subordinate re-issue, hence the larger window for ROOT.
    MIN_DAYS = {'ROOT': 365, 'SUBORDINATE': 90}

    def __init__(self, ca, pcaClient):
        super().__init__()
        self.ca = ca
        self.pcaClient = pcaClient
        self._resourceName = ca.get('Arn', 'unknown')
        self.init()

    @staticmethod
    def _now():
        return datetime.now(timezone.utc)

    def _checkPcaCaCertExpiringOrFailed(self):
        key = 'pcaCaCertExpiringOrFailed'
        status = self.ca.get('Status')
        caType = self.ca.get('Type', 'UNKNOWN')

        if status in ('FAILED', 'EXPIRED'):
            msg = f"{caType} CA status is {status}"
            if self.ca.get('FailureReason'):
                msg += f" (FailureReason: {self.ca['FailureReason']})"
            self.results[key] = [-1, msg]
            return

        if status != 'ACTIVE':
            ## CREATING / PENDING_CERTIFICATE (no CA certificate installed yet),
            ## DISABLED (not issuing) or DELETED (pending deletion).
            self.results[key] = [0, f"Not applicable (CA status {status})"]
            return

        notAfter = self.ca.get('NotAfter')
        if not notAfter:
            self.results[key] = [0, 'Unable to evaluate (NotAfter not returned)']
            return

        days = (notAfter - self._now()).days
        threshold = self.MIN_DAYS.get(caType, self.MIN_DAYS['SUBORDINATE'])
        dateStr = notAfter.strftime('%Y-%m-%d')
        if days < 0:
            self.results[key] = [-1, f"{caType} CA certificate expired {abs(days)} day(s) ago ({dateStr})"]
        elif days < threshold:
            self.results[key] = [-1, f"{caType} CA certificate expires in {days} day(s) ({dateStr}); threshold {threshold} days"]
        else:
            self.results[key] = [1, f"{caType} CA certificate valid for {days} more day(s) ({dateStr})"]

    def _checkPcaRevocationNotConfigured(self):
        key = 'pcaRevocationNotConfigured'
        status = self.ca.get('Status')
        if status != 'ACTIVE':
            self.results[key] = [0, f"Not applicable (CA status {status})"]
            return

        if self.ca.get('UsageMode') == 'SHORT_LIVED_CERTIFICATE':
            ## Short-lived certificate mode (validity <= 7 days) is designed to
            ## operate without CRL/OCSP; revocation is not expected.
            self.results[key] = [1, 'Short-lived certificate mode CA; revocation not required']
            return

        rev = self.ca.get('RevocationConfiguration')
        if rev is None:
            self.results[key] = [0, 'Unable to evaluate (RevocationConfiguration not returned)']
            return

        crl = bool((rev.get('CrlConfiguration') or {}).get('Enabled'))
        ocsp = bool((rev.get('OcspConfiguration') or {}).get('Enabled'))
        if not crl and not ocsp:
            self.results[key] = [-1, 'Neither CRL nor OCSP revocation is enabled']
        else:
            enabled = [n for n, v in (('CRL', crl), ('OCSP', ocsp)) if v]
            self.results[key] = [1, f"Revocation enabled: {', '.join(enabled)}"]

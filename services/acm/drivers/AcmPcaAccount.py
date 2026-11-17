from services.Evaluator import Evaluator


class AcmPcaAccount(Evaluator):
    """
    Account/region-level AWS Private CA posture evaluator (run once per region).

    Heuristic (tier 3): a root CA should live in a dedicated, tightly
    restricted PKI account, not alongside workloads. We treat the account as a
    workload account when ACM reports at least one certificate that is in use
    by an AWS resource (InUse=True from acm.list_certificates) in the same
    region that hosts an ACTIVE or DISABLED root CA.

    Inputs:
      cas         - list of CertificateAuthority dicts (owned by this account),
                    or None if acm-pca.list_certificate_authorities failed
      pcaError    - error code string when cas is None
      inUseCerts  - number of ACM certificates with InUse=True,
                    or None if acm.list_certificates failed
      acmError    - error code string when inUseCerts is None
    """

    def __init__(self, cas, pcaError, inUseCerts, acmError, region):
        super().__init__()
        self.cas = cas
        self.pcaError = pcaError
        self.inUseCerts = inUseCerts
        self.acmError = acmError
        self._resourceName = f'PrivateCA::Account::{region}'
        self.init()

    def _checkPcaRootCaInWorkloadAccount(self):
        key = 'pcaRootCaInWorkloadAccount'
        if self.cas is None:
            self.results[key] = [0, f"Unable to evaluate ({self.pcaError})"]
            return

        roots = [c for c in self.cas
                 if c.get('Type') == 'ROOT' and c.get('Status') in ('ACTIVE', 'DISABLED')]
        if not roots:
            self.results[key] = [1, 'No active root CA in this account/region']
            return

        if self.inUseCerts is None:
            self.results[key] = [0, f"Unable to evaluate ({self.acmError})"]
            return

        if self.inUseCerts > 0:
            names = ', '.join(c.get('Arn', '?').split('/')[-1] for c in roots[:5])
            self.results[key] = [-1, f"{len(roots)} root CA(s) ({names}) in an account with {self.inUseCerts} in-use ACM certificate(s)"]
        else:
            self.results[key] = [1, f"{len(roots)} root CA(s) present; no in-use ACM certificates suggest a dedicated PKI account"]

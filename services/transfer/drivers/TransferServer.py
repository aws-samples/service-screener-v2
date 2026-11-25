from services.Evaluator import Evaluator


class TransferServer(Evaluator):
    """
    Per-server AWS Transfer Family checks.

    Input: describe_server()['Server'] merged with '_error' (the error code
    when describe_server could not be read, else None).

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ## Security policies that still offer SHA-1 / legacy algorithms (or are
    ## deprecated) and have newer replacements (TransferSecurityPolicy-2024-01 /
    ## 2025-03 and the FIPS-2024-01 / FIPS-2025-03 equivalents). The Restricted-*
    ## variants are identical to their base policy minus chacha20-poly1305, so they
    ## keep the same weaknesses (Restricted-2018-11 still offers
    ## diffie-hellman-group14-sha1 and hmac-sha1). The PQ-SSH-*Experimental-2023-04
    ## policies are deprecated by AWS.
    ## Source: https://docs.aws.amazon.com/transfer/latest/userguide/security-policies.html
    OUTDATED_POLICIES = (
        'TransferSecurityPolicy-2018-11',
        'TransferSecurityPolicy-Restricted-2018-11',
        'TransferSecurityPolicy-2020-06',
        'TransferSecurityPolicy-Restricted-2020-06',
        'TransferSecurityPolicy-FIPS-2020-06',
        'TransferSecurityPolicy-PQ-SSH-Experimental-2023-04',
        'TransferSecurityPolicy-PQ-SSH-FIPS-Experimental-2023-04',
    )

    ## Server security policies with no SHA-1 KEX/MAC and no deprecation notice.
    ## Any name in neither list is reported as INFO (not evaluable), never PASS.
    CURRENT_POLICIES = (
        'TransferSecurityPolicy-2022-03',
        'TransferSecurityPolicy-2023-05',
        'TransferSecurityPolicy-FIPS-2023-05',
        'TransferSecurityPolicy-2024-01',
        'TransferSecurityPolicy-FIPS-2024-01',
        'TransferSecurityPolicy-FIPS-2024-05',
        'TransferSecurityPolicy-2025-03',
        'TransferSecurityPolicy-FIPS-2025-03',
        'TransferSecurityPolicy-SshAuditCompliant-2025-02',
        'TransferSecurityPolicy-AS2Restricted-2025-07',
    )

    def __init__(self, server, transferClient):
        super().__init__()
        self.server = server
        self.transferClient = transferClient
        self._resourceName = server.get('ServerId')

        self.addII('endpointType', server.get('EndpointType', 'N/A'))
        self.addII('protocols', ', '.join(server.get('Protocols') or []) or 'N/A')
        self.addII('securityPolicyName', server.get('SecurityPolicyName', 'N/A'))
        return

    def _checkTransferFamilyInsecure(self):
        key = 'transferFamilyInsecure'
        err = self.server.get('_error')
        if err:
            self.results[key] = [0, f'Unable to evaluate ({err})']
            return

        protocols = [str(p).upper() for p in (self.server.get('Protocols') or [])]
        policy = self.server.get('SecurityPolicyName')

        issues = []
        if 'FTP' in protocols:
            issues.append('FTP (unencrypted; credentials and data are sent in plaintext) is enabled')
        if policy in self.OUTDATED_POLICIES:
            issues.append(f'outdated security policy {policy} is attached')

        if issues:
            self.results[key] = [-1, '; '.join(issues)]
            return
        if not policy:
            self.results[key] = [0, 'Unable to evaluate (SecurityPolicyName not returned)']
            return
        if policy not in self.CURRENT_POLICIES:
            self.results[key] = [0, f'Unable to evaluate (unrecognised security policy {policy})']
            return
        self.results[key] = [1, f"Protocols {', '.join(protocols) or 'N/A'}; security policy {policy}"]

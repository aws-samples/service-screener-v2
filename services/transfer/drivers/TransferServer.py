from services.Evaluator import Evaluator


class TransferServer(Evaluator):
    """
    Per-server AWS Transfer Family checks.

    Input: describe_server()['Server'] merged with '_error' (the error code
    when describe_server could not be read, else None).

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ## Security policies that still offer SHA-1 / CBC / older algorithms and
    ## have newer replacements (TransferSecurityPolicy-2024-01 / 2025-03 and the
    ## FIPS-2024-01 / FIPS-2025-03 equivalents).
    OUTDATED_POLICIES = (
        'TransferSecurityPolicy-2018-11',
        'TransferSecurityPolicy-2020-06',
        'TransferSecurityPolicy-FIPS-2020-06',
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
        self.results[key] = [1, f"Protocols {', '.join(protocols) or 'N/A'}; security policy {policy}"]

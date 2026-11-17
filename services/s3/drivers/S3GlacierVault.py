import botocore

from utils import PolicyPrincipal
from services.Evaluator import Evaluator


class S3GlacierVault(Evaluator):
    """One S3 Glacier (vault API) vault in the current Region.

    When listing vaults failed, the driver is created with listError=<code>
    and records an INFO result instead of silently passing."""

    def __init__(self, vaultName, glacierClient, listError=None):
        super().__init__()
        self.vaultName = vaultName
        self.glacierClient = glacierClient
        self.listError = listError

        self._resourceName = vaultName

        self.init()

    def _checkVaultPolicyPublic(self):
        key = 'glacierVaultPolicyPublic'
        if self.listError:
            self.results[key] = [0, f'Unable to evaluate ({self.listError})']
            return
        try:
            resp = self.glacierClient.get_vault_access_policy(vaultName=self.vaultName)
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                self.results[key] = [1, 'No vault access policy']
            else:
                self.results[key] = [0, f'Unable to evaluate ({code})']
            return

        doc = (resp.get('policy', {}) or {}).get('Policy')
        if not doc:
            self.results[key] = [1, 'No vault access policy']
            return
        if PolicyPrincipal.parsePolicy(doc) is None:
            self.results[key] = [0, 'Unable to evaluate (vault access policy not parseable)']
            return
        if PolicyPrincipal.policyIsPublic(doc):
            self.results[key] = [-1, 'Vault access policy allows a wildcard principal without a scoping condition']
        else:
            self.results[key] = [1, 'Vault access policy is not public']

import json

from services.Evaluator import Evaluator


class VerifiedpermissionsPolicyStore(Evaluator):
    """
    Per-policy-store Amazon Verified Permissions checks.

    Input:
      store -- a list_policy_stores entry plus '_region', '_store'
               (get_policy_store response or None), '_storeError' (error code),
               '_schema' (get_schema response or None) and '_schemaError'
               (error code; ResourceNotFoundException means no schema).

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    def __init__(self, store, avpClient):
        super().__init__()
        self.store = store
        self.avpClient = avpClient

        self.psid = store.get('policyStoreId', 'unknown')
        self._resourceName = self.psid

        self.detail = store.get('_store') or {}
        self.storeError = store.get('_storeError')
        self.schema = store.get('_schema')
        self.schemaError = store.get('_schemaError')

        self.addII('region', store.get('_region', 'N/A'))
        self.addII('arn', store.get('arn', 'N/A'))
        if store.get('description'):
            self.addII('description', store.get('description'))

    def _schemaState(self):
        """Return 'present', 'absent' or 'unknown'."""
        if self.schemaError == 'ResourceNotFoundException':
            return 'absent'
        if self.schema is None:
            return 'unknown'
        raw = self.schema.get('schema')
        if self.schema.get('namespaces'):
            return 'present'
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            return 'present' if raw else 'absent'
        return 'present' if parsed else 'absent'

    # Validation mode OFF: policies are not validated against the schema
    def _checkAvpPolicyStoreValidationOff(self):
        key = 'avpPolicyStoreValidationOff'
        if self.storeError:
            self.results[key] = [0, f'Unable to evaluate ({self.storeError})']
            return
        mode = (self.detail.get('validationSettings') or {}).get('mode')
        if not mode:
            self.results[key] = [0, 'Unable to evaluate (validationSettings not returned)']
            return

        schema = self._schemaState()
        if mode == 'OFF':
            if schema == 'present':
                extra = ('a schema is defined but is not enforced, so policies that '
                         'reference misspelt entity types, actions or attributes are '
                         'accepted and silently never match (or match unexpectedly)')
            elif schema == 'absent':
                extra = ('no schema is defined either, so nothing checks that policies '
                         'refer to real entity types, actions or attributes')
            else:
                extra = ('policies are not checked against the schema')
            self.results[key] = [-1, f'Policy validation mode is OFF; {extra}']
            return

        if mode == 'STRICT':
            if schema == 'absent':
                self.results[key] = [
                    1,
                    'Policy validation mode is STRICT. No schema is defined, so '
                    'Verified Permissions rejects new static policies and templates '
                    'until one is added'
                ]
            else:
                self.results[key] = [1, 'Policy validation mode is STRICT']
            return

        self.results[key] = [0, f'Unable to evaluate (unknown validation mode {mode})']

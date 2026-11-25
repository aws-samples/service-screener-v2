import re

import botocore

from utils.Config import Config
from services.Evaluator import Evaluator


class KmsAccount(Evaluator):
    """
    Region-scoped KMS checks, evaluated once per region.

      CustomKeyStoreUnhealthy -- a CloudHSM / external key store is FAILED, or
                                 DISCONNECTED while it still holds keys.
      SingleKeyBroadUse       -- one customer managed key protects data in
                                 many different AWS data-store services.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not evaluable. Only -1 surfaces as a finding.

    All API calls are read-only (describe / list).
    """

    ## SingleKeyBroadUse: a key referenced by at least this many distinct
    ## services is reported.
    BROAD_USE_MIN_SERVICES = 3

    ## Errors meaning "this service is not available here", not "access denied".
    _NOT_AVAILABLE = ('UnsupportedOperation', 'InvalidAction', 'OptInRequired',
                      'UnrecognizedClientException', 'SubscriptionRequiredException')

    def __init__(self, kmsClient, clientFactory, keyMetadata=None):
        super().__init__()
        self.kmsClient = kmsClient
        self.clientFactory = clientFactory
        ## Optional {keyId: KeyMetadata or None} of every key in the region, as
        ## already listed / described by the service class (None = not
        ## described). When given, list_keys and describe_key are not repeated.
        self.keyMetadata = keyMetadata
        self._resourceName = 'Account'

    def _describeKey(self, keyId):
        """KeyMetadata for keyId: from the service class when known, otherwise
        one describe_key per key for this driver (both checks may ask)."""
        if self.keyMetadata and self.keyMetadata.get(keyId) is not None:
            return dict(self.keyMetadata[keyId])
        return self._memo(('describe_key', keyId),
                          lambda: self.kmsClient.describe_key(KeyId=keyId)).get('KeyMetadata', {})

    def _listKeyIds(self):
        if self.keyMetadata is not None:
            return list(self.keyMetadata)
        keyIds = []
        paginator = self.kmsClient.get_paginator('list_keys')
        for page in paginator.paginate():
            keyIds.extend(k['KeyId'] for k in page.get('Keys', []) or [])
        return keyIds

    @staticmethod
    def _errorCode(e):
        return e.response.get('Error', {}).get('Code', 'ClientError')

    # ------------------------------------------------------------------ #
    # Custom key store health
    # ------------------------------------------------------------------ #
    def _checkCustomKeyStoreUnhealthy(self):
        stores = []
        try:
            paginator = self.kmsClient.get_paginator('describe_custom_key_stores')
            for page in paginator.paginate():
                stores.extend(page.get('CustomKeyStores', []) or [])
        except botocore.exceptions.ClientError as e:
            self.results['CustomKeyStoreUnhealthy'] = [0, f'Unable to evaluate ({self._errorCode(e)})']
            return

        if not stores:
            return

        failed = []
        info = []
        disconnected = {}
        for st in stores:
            sid = st.get('CustomKeyStoreId', 'unknown')
            label = f"{st.get('CustomKeyStoreName', sid)} ({sid}, {st.get('CustomKeyStoreType', 'AWS_CLOUDHSM')})"
            state = st.get('ConnectionState')
            if state == 'FAILED':
                failed.append(f"{label}: FAILED ({st.get('ConnectionErrorCode', 'unknown error')})")
            elif state == 'DISCONNECTED':
                disconnected[sid] = label
            elif state != 'CONNECTED':
                info.append(f"{label}: {state}")

        ## A disconnected store may be intentional (maintenance, or not yet in
        ## use). It is only a finding when it still holds keys that are not
        ## being deleted: those keys are Unavailable and their data cannot be
        ## decrypted.
        if disconnected:
            keyCounts, err = self._keysPerCustomKeyStore(set(disconnected))
            for sid, label in disconnected.items():
                if err:
                    info.append(f"{label}: DISCONNECTED (keys not checked: {err})")
                elif keyCounts.get(sid):
                    failed.append(f"{label}: DISCONNECTED with {keyCounts[sid]} key(s) unavailable")
                else:
                    info.append(f"{label}: DISCONNECTED, holds no active keys")

        if failed:
            self.results['CustomKeyStoreUnhealthy'] = [-1, "<br>".join(failed + info)]
        elif info:
            self.results['CustomKeyStoreUnhealthy'] = [0, "<br>".join(info)]
        else:
            self.results['CustomKeyStoreUnhealthy'] = [1, f"{len(stores)} custom key store(s) CONNECTED"]

    def _keysPerCustomKeyStore(self, storeIds):
        """{storeId: count of keys not pending deletion} for the given stores."""
        counts = {}
        try:
            for keyId in self._listKeyIds():
                md = self._describeKey(keyId)
                sid = md.get('CustomKeyStoreId')
                if sid in storeIds and md.get('KeyState') not in ('PendingDeletion',):
                    counts[sid] = counts.get(sid, 0) + 1
        except botocore.exceptions.ClientError as e:
            return {}, self._errorCode(e)
        return counts, None

    # ------------------------------------------------------------------ #
    # One customer managed key used across many data-store services
    # ------------------------------------------------------------------ #
    ## (label, client, paginated operation, list key, key-id field)
    KEY_REFERENCE_SOURCES = (
        ('EBS volumes', 'ec2', 'describe_volumes', 'Volumes', 'KmsKeyId'),
        ('RDS instances', 'rds', 'describe_db_instances', 'DBInstances', 'KmsKeyId'),
        ('RDS/Aurora clusters', 'rds', 'describe_db_clusters', 'DBClusters', 'KmsKeyId'),
        ('EFS file systems', 'efs', 'describe_file_systems', 'FileSystems', 'KmsKeyId'),
        ('Secrets Manager secrets', 'secretsmanager', 'list_secrets', 'SecretList', 'KmsKeyId'),
        ('SSM parameters', 'ssm', 'describe_parameters', 'Parameters', 'KeyId'),
        ('CloudWatch log groups', 'logs', 'describe_log_groups', 'logGroups', 'kmsKeyId'),
    )

    ## Labels that belong to the same service when counting distinct services.
    _SERVICE_OF = {'RDS instances': 'RDS', 'RDS/Aurora clusters': 'RDS'}

    _KEY_ARN_RE = re.compile(r'^arn:aws[a-z-]*:kms:[^:]*:(\d{12}):key/(.+)$')
    _ALIAS_ARN_RE = re.compile(r'^arn:aws[a-z-]*:kms:[^:]*:(\d{12}):(alias/.+)$')

    def _aliasTargets(self):
        aliases = {}
        paginator = self.kmsClient.get_paginator('list_aliases')
        for page in paginator.paginate():
            for a in page.get('Aliases', []) or []:
                if a.get('AliasName') and a.get('TargetKeyId'):
                    aliases[a['AliasName']] = a['TargetKeyId']
        return aliases

    def _resolveKeyId(self, ref, aliases, account):
        """Key ID for a key reference (key ARN, alias ARN, alias name or key
        ID) owned by this account; None for other accounts / unresolvable."""
        if not isinstance(ref, str) or not ref:
            return None
        m = self._KEY_ARN_RE.match(ref)
        if m:
            return m.group(2) if (not account or m.group(1) == account) else None
        m = self._ALIAS_ARN_RE.match(ref)
        if m:
            if account and m.group(1) != account:
                return None
            return aliases.get(m.group(2))
        if ref.startswith('alias/'):
            return aliases.get(ref)
        return ref

    def _checkSingleKeyBroadUse(self):
        account = (Config.get('stsInfo', {}) or {}).get('Account')
        try:
            aliases = self._aliasTargets()
        except botocore.exceptions.ClientError as e:
            self.results['SingleKeyBroadUse'] = [0, f'Unable to evaluate ({self._errorCode(e)})']
            return

        usage = {}      # keyId -> {label: count}
        errors = []
        unreadServices = set()
        evaluated = 0
        clients = {}
        for label, svc, op, listKey, field in self.KEY_REFERENCE_SOURCES:
            try:
                client = clients.get(svc) or clients.setdefault(svc, self.clientFactory(svc))
                paginator = client.get_paginator(op)
                for page in paginator.paginate():
                    for item in page.get(listKey, []) or []:
                        keyId = self._resolveKeyId(item.get(field), aliases, account)
                        if keyId:
                            usage.setdefault(keyId, {})
                            usage[keyId][label] = usage[keyId].get(label, 0) + 1
                evaluated += 1
            except botocore.exceptions.ClientError as e:
                code = self._errorCode(e)
                if code not in self._NOT_AVAILABLE:
                    errors.append(f"{label}: {code}")
                    unreadServices.add(self._SERVICE_OF.get(label, label))
            except botocore.exceptions.EndpointConnectionError:
                pass

        if evaluated == 0:
            self.results['SingleKeyBroadUse'] = [0, 'Unable to evaluate (' + ('; '.join(errors) or 'no data source available') + ')']
            return

        flagged = []
        ## Could an unread source have pushed some key over the threshold?
        ## (A key may also be referenced only by unread sources.)
        couldReach = len(unreadServices) >= self.BROAD_USE_MIN_SERVICES
        for keyId, perLabel in usage.items():
            services = {self._SERVICE_OF.get(l, l) for l in perLabel}
            if len(services) < self.BROAD_USE_MIN_SERVICES:
                if len(services | unreadServices) >= self.BROAD_USE_MIN_SERVICES:
                    couldReach = True
                continue
            try:
                md = self._describeKey(keyId)
            except botocore.exceptions.ClientError:
                continue
            ## AWS managed keys are already one-per-service; only customer
            ## managed keys are a design choice.
            if md.get('KeyManager') != 'CUSTOMER':
                continue
            detail = ', '.join(f"{l} ({n})" for l, n in sorted(perLabel.items()))
            flagged.append(f"{md.get('Arn', keyId)}: used by {len(services)} services - {detail}")

        note = ('<br>Not checked: ' + '; '.join(errors)) if errors else ''
        if flagged:
            self.results['SingleKeyBroadUse'] = [-1, "<br>".join(flagged) + note]
        elif couldReach:
            ## Not a PASS: the unreadable sources could hold the references
            ## that put a key at the threshold.
            self.results['SingleKeyBroadUse'] = [0, 'Unable to evaluate (' + '; '.join(errors) + ')']
        else:
            self.results['SingleKeyBroadUse'] = [1, f"No customer managed key is used by {self.BROAD_USE_MIN_SERVICES} or more data-store services" + note]

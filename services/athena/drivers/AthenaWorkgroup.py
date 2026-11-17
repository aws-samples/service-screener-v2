import re

import botocore

from services.Evaluator import Evaluator


class AthenaWorkgroup(Evaluator):
    """
    Per-workgroup Amazon Athena checks (9).

    Input:
      workgroup -- a get_work_group WorkGroup dict plus '_name', '_tags',
                   '_region', from services/athena/Athena.py.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    Dropped from the original spec after review:
      athenaRequesterPaysDisabled -- requester-pays is a billing-model choice,
        not a finding; it is off on almost every workgroup by design.
    """

    ## Minimum Athena engine major version considered current.
    MIN_ENGINE_VERSION = 3

    ## Parses the trailing integer out of "Athena engine version 3". Comparing
    ## the whole string (as the original spec proposed) breaks the moment AWS
    ## renames or bumps the label.
    ENGINE_VERSION_PATTERN = re.compile(r'(\d+)\s*$')

    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, workgroup, athenaClient, s3Client):
        super().__init__()
        self.workgroup = workgroup
        self.athenaClient = athenaClient
        self.s3Client = s3Client

        self.name = workgroup.get('_name', 'unknown')
        self._resourceName = self.name

        self.config = workgroup.get('Configuration') or {}
        self.resultConfig = self.config.get('ResultConfiguration') or {}
        self.encryptionConfig = self.resultConfig.get(
            'EncryptionConfiguration') or {}
        ## Managed query results: Athena stores and always encrypts the results
        ## itself. The API rejects ResultConfiguration on such a workgroup, so
        ## the settings above are always empty for it.
        self.managedConfig = self.config.get(
            'ManagedQueryResultsConfiguration') or {}
        self.usesManagedQueryResults = self.managedConfig.get('Enabled') is True
        ## Customer KMS key for managed query results; None = AWS owned key.
        self.managedKmsKey = (self.managedConfig.get('EncryptionConfiguration')
                              or {}).get('KmsKey')
        self.tags = workgroup.get('_tags') or []
        self.state = workgroup.get('State')

        self.addII('workgroupName', self.name)
        self.addII('region', workgroup.get('_region', 'N/A'))
        self.addII('state', self.state or 'N/A')
        self.addII('outputLocation',
                   self.resultConfig.get('OutputLocation', 'None'))
        self.addII('managedQueryResults', str(self.usesManagedQueryResults))
        self.addII('encryptionOption', self._encryptionOption())
        self.addII('enforceWorkGroupConfiguration',
                   str(self.config.get('EnforceWorkGroupConfiguration', 'N/A')))
        self.addII('engineVersion', self._effectiveEngineVersion() or 'N/A')
        self.addII('bytesScannedCutoffPerQuery',
                   str(self.config.get('BytesScannedCutoffPerQuery', 'unlimited')))
        self.addII('tagCount', str(len(self.tags)))

    # ------------------------------------------------------------------ #
    # 1. Query results not encrypted
    # ------------------------------------------------------------------ #
    def _checkAthenaWorkgroupNotEncrypted(self):
        """
        Athena writes every query result to the results location. Without an
        EncryptionConfiguration on the workgroup, the result set -- which is a materialised extract of
        whatever the query touched -- lands unencrypted at the Athena layer.

        Managed query results are always encrypted, so they pass.
        """
        if self.usesManagedQueryResults:
            keyDescription = (f"KMS key {self.managedKmsKey}"
                              if self.managedKmsKey else "an AWS owned key")
            self.results['athenaWorkgroupNotEncrypted'] = [
                1,
                f"Workgroup '{self.name}' uses managed query results, "
                f"encrypted with {keyDescription}"
            ]
        elif self.encryptionConfig.get('EncryptionOption'):
            self.results['athenaWorkgroupNotEncrypted'] = [
                1,
                "Workgroup '{}' encrypts query results with {}".format(
                    self.name, self.encryptionConfig['EncryptionOption'])
            ]
        else:
            self.results['athenaWorkgroupNotEncrypted'] = [
                -1,
                f"Workgroup '{self.name}' has no result EncryptionConfiguration — "
                "query results are written to S3 without Athena-level encryption, "
                "and a result set is a materialised copy of whatever the query "
                "selected"
            ]

    # ------------------------------------------------------------------ #
    # 2. Workgroup configuration not enforced
    # ------------------------------------------------------------------ #
    def _checkAthenaWorkgroupNoEnforcement(self):
        """
        With EnforceWorkGroupConfiguration false, a client can override the
        workgroup's result location and encryption settings per query — so every
        other setting on this workgroup becomes a default rather than a control.
        """
        if self.config.get('EnforceWorkGroupConfiguration') is True:
            self.results['athenaWorkgroupNoEnforcement'] = [
                1, f"Workgroup '{self.name}' enforces its configuration"
            ]
        else:
            self.results['athenaWorkgroupNoEnforcement'] = [
                -1,
                f"Workgroup '{self.name}' has EnforceWorkGroupConfiguration=false "
                "— a client can override the result location and encryption "
                "settings per query, which makes the workgroup's encryption "
                "setting advisory rather than enforced"
            ]

    # ------------------------------------------------------------------ #
    # 3. Minimum encryption not enforced
    # ------------------------------------------------------------------ #
    def _checkAthenaMinimumEncryptionDisabled(self):
        """
        EnableMinimumEncryptionConfiguration forces a floor on the encryption
        clients may select, so a client cannot downgrade to a weaker option.
        Complements athenaWorkgroupNoEnforcement.

        Not applicable to managed query results: the setting only covers results
        written to Amazon S3, and the API rejects it on such a workgroup.
        """
        if self.usesManagedQueryResults:
            self.results['athenaMinimumEncryptionDisabled'] = [
                0,
                f"Workgroup '{self.name}' uses managed query results — minimum "
                "encryption applies only to a customer results location"
            ]
            return

        if not self.encryptionConfig.get('EncryptionOption'):
            self.results['athenaMinimumEncryptionDisabled'] = [
                0,
                f"Workgroup '{self.name}' has no encryption configured — see "
                "athenaWorkgroupNotEncrypted"
            ]
            return

        if self.config.get('EnableMinimumEncryptionConfiguration') is True:
            self.results['athenaMinimumEncryptionDisabled'] = [
                1, f"Workgroup '{self.name}' enforces a minimum encryption level"
            ]
        else:
            self.results['athenaMinimumEncryptionDisabled'] = [
                -1,
                f"Workgroup '{self.name}' has "
                "EnableMinimumEncryptionConfiguration=false — clients may select a "
                "weaker encryption option than the workgroup specifies"
            ]

    # ------------------------------------------------------------------ #
    # 4. Output location is a bucket root
    # ------------------------------------------------------------------ #
    def _checkAthenaWorkgroupS3OutputNoPrefix(self):
        if self.usesManagedQueryResults:
            self.results['athenaWorkgroupS3OutputNoPrefix'] = [
                0, self._managedNoResultsLocationMessage()
            ]
            return

        location = self.resultConfig.get('OutputLocation') or ''
        if not location:
            self.results['athenaWorkgroupS3OutputNoPrefix'] = [
                0, f"Workgroup '{self.name}' defines no output location"
            ]
            return

        ## s3://bucket/ or s3://bucket -> no prefix. Anything after the bucket
        ## segment counts as a prefix.
        remainder = location[5:] if location.startswith('s3://') else location
        prefix = remainder.split('/', 1)[1] if '/' in remainder else ''

        if prefix.strip('/'):
            self.results['athenaWorkgroupS3OutputNoPrefix'] = [
                1, f"Workgroup '{self.name}' writes results under {location}"
            ]
        else:
            self.results['athenaWorkgroupS3OutputNoPrefix'] = [
                -1,
                f"Workgroup '{self.name}' writes query results to the bucket root "
                f"({location}) — results mix with any other bucket content, so a "
                "lifecycle rule or bucket policy scoped to results cannot be "
                "written without affecting everything else"
            ]

    # ------------------------------------------------------------------ #
    # 5. Output bucket not encrypted (cross-service check)
    # ------------------------------------------------------------------ #
    def _checkAthenaS3OutputNotEncrypted(self):
        """
        Resolves the output location's bucket and reads its default encryption.
        This overlaps s3.ServerSideEncrypted, but is reported here because the
        Athena workgroup is what chose the destination -- a reader of the Athena
        section should not have to cross-reference the S3 section to learn that
        its results land unencrypted.
        """
        if self.usesManagedQueryResults:
            self.results['athenaS3OutputNotEncrypted'] = [
                0, self._managedNoResultsLocationMessage()
            ]
            return

        location = self.resultConfig.get('OutputLocation') or ''
        if not location.startswith('s3://'):
            self.results['athenaS3OutputNotEncrypted'] = [
                0, f"Workgroup '{self.name}' has no S3 output location to check"
            ]
            return

        bucket = location[5:].split('/', 1)[0]
        if not bucket:
            self.results['athenaS3OutputNotEncrypted'] = [
                0, f"Could not parse a bucket name from {location}"
            ]
            return

        try:
            resp = self.s3Client.get_bucket_encryption(Bucket=bucket)
            rules = (resp.get('ServerSideEncryptionConfiguration') or {}).get(
                'Rules', []) or []
            if rules:
                algo = (rules[0].get('ApplyServerSideEncryptionByDefault')
                        or {}).get('SSEAlgorithm', 'unknown')
                self.results['athenaS3OutputNotEncrypted'] = [
                    1,
                    f"Output bucket {bucket} has default encryption ({algo})"
                ]
            else:
                self.results['athenaS3OutputNotEncrypted'] = [
                    -1,
                    f"Output bucket {bucket} reports no default encryption rule"
                ]
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'ServerSideEncryptionConfigurationNotFoundError':
                self.results['athenaS3OutputNotEncrypted'] = [
                    -1,
                    f"Workgroup '{self.name}' writes results to s3://{bucket}, "
                    "which has no default encryption configured"
                ]
            elif code in ('AccessDenied', 'AccessDeniedException'):
                ## The bucket may belong to another account, or the scanner may
                ## lack s3:GetEncryptionConfiguration. Not evidence either way.
                self.results['athenaS3OutputNotEncrypted'] = [
                    0,
                    f"Encryption of output bucket {bucket} could not be read "
                    "(access denied — the bucket may be in another account)"
                ]
            elif code in ('NoSuchBucket',):
                self.results['athenaS3OutputNotEncrypted'] = [
                    -1,
                    f"Workgroup '{self.name}' points at s3://{bucket}, which does "
                    "not exist — queries writing results will fail"
                ]
            else:
                self.results['athenaS3OutputNotEncrypted'] = [
                    0, f"Could not read encryption for {bucket}: {code}"
                ]

    # ------------------------------------------------------------------ #
    # 6. CloudWatch metrics not published
    # ------------------------------------------------------------------ #
    def _checkAthenaPublishMetricsDisabled(self):
        if self.config.get('PublishCloudWatchMetricsEnabled') is True:
            self.results['athenaPublishMetricsDisabled'] = [
                1, f"Workgroup '{self.name}' publishes CloudWatch metrics"
            ]
        else:
            self.results['athenaPublishMetricsDisabled'] = [
                -1,
                f"Workgroup '{self.name}' does not publish CloudWatch metrics — "
                "query volume, data scanned and failure rates are not observable, "
                "so neither cost spikes nor a broken consumer can be alarmed on"
            ]

    # ------------------------------------------------------------------ #
    # 7. No per-query data scanned limit
    # ------------------------------------------------------------------ #
    def _checkAthenaBytesScannedNoLimit(self):
        """
        Athena bills per byte scanned. Without a cutoff, a single unpartitioned
        SELECT * can scan an entire data lake and produce a very large bill from
        one query.
        """
        cutoff = self.config.get('BytesScannedCutoffPerQuery')
        if cutoff:
            gib = cutoff / (1024 ** 3)
            self.results['athenaBytesScannedNoLimit'] = [
                1,
                f"Workgroup '{self.name}' caps each query at {gib:.2f} GiB scanned"
            ]
        else:
            self.results['athenaBytesScannedNoLimit'] = [
                -1,
                f"Workgroup '{self.name}' has no BytesScannedCutoffPerQuery — one "
                "unpartitioned query can scan the entire dataset, and Athena "
                "bills per byte scanned"
            ]

    # ------------------------------------------------------------------ #
    # 8. Outdated engine version
    # ------------------------------------------------------------------ #
    def _checkAthenaEngineVersionOutdated(self):
        """
        Reads EffectiveEngineVersion, not SelectedEngineVersion: a workgroup set
        to AUTO reports SelectedEngineVersion='AUTO' (verified live) while the
        effective version is the real one. Parses the trailing integer rather
        than string-comparing the label.
        """
        effective = self._effectiveEngineVersion()
        if not effective:
            self.results['athenaEngineVersionOutdated'] = [
                0, f"Workgroup '{self.name}' reports no engine version"
            ]
            return

        match = self.ENGINE_VERSION_PATTERN.search(effective)
        if not match:
            self.results['athenaEngineVersionOutdated'] = [
                0,
                f"Workgroup '{self.name}' engine version '{effective}' could not "
                "be parsed"
            ]
            return

        version = int(match.group(1))
        if version >= self.MIN_ENGINE_VERSION:
            self.results['athenaEngineVersionOutdated'] = [
                1, f"Workgroup '{self.name}' runs {effective}"
            ]
        else:
            self.results['athenaEngineVersionOutdated'] = [
                -1,
                f"Workgroup '{self.name}' runs {effective} — engine version "
                f"{self.MIN_ENGINE_VERSION} or later brings performance "
                "improvements and security fixes that older engines do not receive"
            ]

    # ------------------------------------------------------------------ #
    # 9. Workgroup disabled
    # ------------------------------------------------------------------ #
    def _checkAthenaWorkgroupDisabled(self):
        if self.state == 'ENABLED':
            self.results['athenaWorkgroupDisabled'] = [
                1, f"Workgroup '{self.name}' is ENABLED"
            ]
        elif self.state == 'DISABLED':
            self.results['athenaWorkgroupDisabled'] = [
                -1,
                f"Workgroup '{self.name}' is DISABLED — every query submitted to "
                "it fails. Either re-enable it or delete it so the configuration "
                "reflects what is actually in use"
            ]
        else:
            self.results['athenaWorkgroupDisabled'] = [
                0, f"Workgroup '{self.name}' reports state {self.state}"
            ]

    # ------------------------------------------------------------------ #
    # 10. No tags
    # ------------------------------------------------------------------ #
    def _checkAthenaNoTags(self):
        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['athenaNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['athenaNoTags'] = [
                -1,
                f"Workgroup '{self.name}' has no tags — Athena cost is attributed "
                "per workgroup, so an untagged workgroup makes query spend "
                "impossible to charge back to the team generating it"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _encryptionOption(self):
        """
        Inventory value for encryptionOption. For a customer results location
        this is the API's EncryptionOption (SSE_S3, SSE_KMS, CSE_KMS). Managed
        query results have no such field, so two Service Screener values are
        used instead: AWS_OWNED_KEY or CUSTOMER_KMS_KEY.
        """
        if self.usesManagedQueryResults:
            return 'CUSTOMER_KMS_KEY' if self.managedKmsKey else 'AWS_OWNED_KEY'
        return self.encryptionConfig.get('EncryptionOption', 'None')

    def _managedNoResultsLocationMessage(self):
        return (f"Workgroup '{self.name}' uses managed query results — no "
                "customer results location to check")

    def _effectiveEngineVersion(self):
        ev = self.config.get('EngineVersion') or {}
        return ev.get('EffectiveEngineVersion') or ev.get(
            'SelectedEngineVersion')

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown

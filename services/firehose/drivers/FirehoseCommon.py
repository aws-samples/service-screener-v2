from services.Evaluator import Evaluator


class FirehoseCommon(Evaluator):
    """
    All 8 Amazon Data Firehose checks.

    Input:
      stream -- dict produced by Firehose.py._describeStream:
        '_name'        -- DeliveryStreamName
        '_arn'         -- DeliveryStreamARN
        '_description' -- raw DescribeDeliveryStream.DeliveryStreamDescription body
        '_tags'        -- list of {'Key','Value'} tag dicts
      firehoseClient -- boto3 firehose client (kept for future extension).

    Check catalogue (matches docs/kinesis-service-screener-checks.md #14-21):
      1. firehoseSSEDisabled                (S, HIGH)
      2. firehoseSSEDefaultKey              (S, MEDIUM)
      3. firehoseS3DestinationNoEncryption  (S, MEDIUM)
      4. firehoseLoggingDisabled            (O, MEDIUM)
      5. firehoseS3BackupDisabled           (R, LOW)
      6. firehoseBufferingSuboptimal        (P, LOW)
      7. firehoseNoTags                     (O, LOW)
      8. firehoseStreamNotActive            (R, HIGH)
    """

    # Firehose default buffering for S3 destinations is 300s / 5MB.
    # Values below these thresholds create many tiny objects in S3.
    MIN_BUFFER_INTERVAL_SECONDS = 60
    MIN_BUFFER_SIZE_MB = 1

    # Terminal / failed states surface as HIGH severity.
    FAILED_STATES = ('CREATING_FAILED', 'DELETING_FAILED', 'SUSPENDED')

    def __init__(self, stream, firehoseClient):
        super().__init__()
        self.stream = stream
        self.firehoseClient = firehoseClient

        self._resourceName = stream.get('_name', 'unknown')
        self.desc = stream.get('_description') or {}
        self.destinations = self.desc.get('Destinations', []) or []

        self.addII('deliveryStreamName', self._resourceName)
        self.addII('deliveryStreamArn', stream.get('_arn', 'N/A'))
        self.addII('deliveryStreamStatus', self.desc.get('DeliveryStreamStatus', 'UNKNOWN'))
        self.addII('deliveryStreamType', self.desc.get('DeliveryStreamType', 'UNKNOWN'))

        enc = self.desc.get('DeliveryStreamEncryptionConfiguration') or {}
        self.addII('encryptionStatus', enc.get('Status', 'DISABLED'))
        self.addII('encryptionKeyType', enc.get('KeyType', 'N/A'))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _s3DestinationDescriptions(self):
        """Yield S3-flavoured destination descriptors from each destination.

        Firehose exposes S3 configuration through one of:
          - ExtendedS3DestinationDescription (preferred; superset of S3)
          - S3DestinationDescription         (legacy fallback)

        Non-S3 destinations (Redshift, OpenSearch, Splunk, HTTP endpoints,
        etc.) still carry an inner `S3DestinationDescription` for the
        "S3 backup" side-channel — those are yielded too so backup-related
        checks still work.
        """
        for dest in self.destinations:
            if not isinstance(dest, dict):
                continue
            # Prefer the extended description when present.
            ext = dest.get('ExtendedS3DestinationDescription')
            if isinstance(ext, dict):
                yield ext
                continue
            legacy = dest.get('S3DestinationDescription')
            if isinstance(legacy, dict):
                yield legacy

    def _allS3ContainingDescriptions(self):
        """Return every dict on a destination that could contain S3 config.

        Some checks (encryption, logging) must consider S3 backup buckets
        attached to non-S3 primary destinations too.
        """
        out = []
        for dest in self.destinations:
            if not isinstance(dest, dict):
                continue
            for key in (
                'ExtendedS3DestinationDescription',
                'S3DestinationDescription',
                'RedshiftDestinationDescription',
                'ElasticsearchDestinationDescription',
                'AmazonopensearchserviceDestinationDescription',
                'AmazonOpenSearchServerlessDestinationDescription',
                'SplunkDestinationDescription',
                'HttpEndpointDestinationDescription',
                'SnowflakeDestinationDescription',
                'IcebergDestinationDescription',
            ):
                block = dest.get(key)
                if isinstance(block, dict):
                    out.append(block)
        return out

    # ------------------------------------------------------------------ #
    # 1. firehoseSSEDisabled (research doc #14)
    # ------------------------------------------------------------------ #
    def _checkFirehoseSSEDisabled(self):
        enc = self.desc.get('DeliveryStreamEncryptionConfiguration') or {}
        status = enc.get('Status', 'DISABLED')
        if status == 'ENABLED':
            self.results['firehoseSSEDisabled'] = [
                1, f"Server-side encryption ENABLED ({enc.get('KeyType', 'unknown')})"
            ]
        elif status in ('ENABLING', 'DISABLING'):
            # Transient — surface as advisory rather than fail.
            self.results['firehoseSSEDisabled'] = [
                0, f"Encryption in transient state: {status}"
            ]
        else:
            # DISABLED, ENABLING_FAILED, DISABLING_FAILED, or absent.
            reason = status if status else 'not configured'
            self.results['firehoseSSEDisabled'] = [
                -1, f"Server-side encryption is not enabled ({reason})"
            ]

    # ------------------------------------------------------------------ #
    # 2. firehoseSSEDefaultKey (research doc #15)
    # ------------------------------------------------------------------ #
    def _checkFirehoseSSEDefaultKey(self):
        enc = self.desc.get('DeliveryStreamEncryptionConfiguration') or {}
        if enc.get('Status') != 'ENABLED':
            # If encryption is off, this check is not applicable — the
            # firehoseSSEDisabled check surfaces the primary finding.
            self.results['firehoseSSEDefaultKey'] = [
                0, "Encryption disabled — see firehoseSSEDisabled"
            ]
            return

        key_type = enc.get('KeyType', '')
        if key_type == 'AWS_OWNED_CMK':
            self.results['firehoseSSEDefaultKey'] = [
                -1, "Using AWS-owned CMK; customer-managed CMK preferred"
            ]
        elif key_type == 'CUSTOMER_MANAGED_CMK':
            self.results['firehoseSSEDefaultKey'] = [
                1, "Customer-managed CMK in use"
            ]
        else:
            # Unknown key type — informational.
            self.results['firehoseSSEDefaultKey'] = [
                0, f"Unknown encryption KeyType: {key_type!r}"
            ]

    # ------------------------------------------------------------------ #
    # 3. firehoseS3DestinationNoEncryption (research doc #16)
    # ------------------------------------------------------------------ #
    def _checkFirehoseS3DestinationNoEncryption(self):
        s3_blocks = list(self._s3DestinationDescriptions())
        if not s3_blocks:
            self.results['firehoseS3DestinationNoEncryption'] = [
                0, "No S3 destination on this delivery stream"
            ]
            return

        offenders = []
        for block in s3_blocks:
            enc_config = block.get('EncryptionConfiguration') or {}
            kms_config = enc_config.get('KMSEncryptionConfig')
            no_enc = enc_config.get('NoEncryptionConfig')
            bucket = block.get('BucketARN', '<unknown>')
            # If KMSEncryptionConfig has an AWSKMSKeyARN, encryption is on.
            if isinstance(kms_config, dict) and kms_config.get('AWSKMSKeyARN'):
                continue
            # Explicit NoEncryption OR both fields missing → offender.
            if no_enc == 'NoEncryption' or not kms_config:
                offenders.append(bucket.split(':::')[-1] or bucket)

        if offenders:
            self.results['firehoseS3DestinationNoEncryption'] = [
                -1,
                "S3 destination(s) without KMS encryption: "
                + ", ".join(offenders[:5])
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['firehoseS3DestinationNoEncryption'] = [
                1, f"All {len(s3_blocks)} S3 destination block(s) have KMS encryption"
            ]

    # ------------------------------------------------------------------ #
    # 4. firehoseLoggingDisabled (research doc #17)
    # ------------------------------------------------------------------ #
    def _checkFirehoseLoggingDisabled(self):
        blocks = self._allS3ContainingDescriptions()
        if not blocks:
            self.results['firehoseLoggingDisabled'] = [
                0, "No destinations to inspect"
            ]
            return

        disabled = []
        enabled_count = 0
        for block in blocks:
            logging = block.get('CloudWatchLoggingOptions') or {}
            if logging.get('Enabled') is True:
                enabled_count += 1
                continue
            # Best-effort label to identify which destination is missing logs.
            label = (
                block.get('BucketARN')
                or block.get('ClusterJDBCURL')
                or block.get('DomainARN')
                or block.get('EndpointConfiguration', {}).get('Url')
                or 'destination'
            )
            disabled.append(str(label).split(':::')[-1] or str(label))

        if disabled:
            self.results['firehoseLoggingDisabled'] = [
                -1,
                "CloudWatch logging disabled on: "
                + ", ".join(disabled[:5])
                + (f" (+{len(disabled)-5} more)" if len(disabled) > 5 else "")
            ]
        else:
            self.results['firehoseLoggingDisabled'] = [
                1, f"CloudWatch logging enabled on all {enabled_count} destination block(s)"
            ]

    # ------------------------------------------------------------------ #
    # 5. firehoseS3BackupDisabled (research doc #18)
    # ------------------------------------------------------------------ #
    def _checkFirehoseS3BackupDisabled(self):
        s3_blocks = list(self._s3DestinationDescriptions())
        if not s3_blocks:
            self.results['firehoseS3BackupDisabled'] = [
                0, "No S3 destination on this delivery stream"
            ]
            return

        # Only meaningful when data transformation (ProcessingConfiguration)
        # is enabled — without processing there is no "original" record to
        # back up separately.
        offenders = []
        processing_enabled_count = 0
        for block in s3_blocks:
            processing = block.get('ProcessingConfiguration') or {}
            if not processing.get('Enabled'):
                continue
            processing_enabled_count += 1
            backup_mode = block.get('S3BackupMode', 'Disabled')
            if backup_mode == 'Disabled':
                bucket = block.get('BucketARN', '<unknown>')
                offenders.append(bucket.split(':::')[-1] or bucket)

        if processing_enabled_count == 0:
            self.results['firehoseS3BackupDisabled'] = [
                0, "Data transformation not enabled — S3 backup not applicable"
            ]
        elif offenders:
            self.results['firehoseS3BackupDisabled'] = [
                -1,
                "Data transformation on but S3 backup disabled: "
                + ", ".join(offenders[:5])
            ]
        else:
            self.results['firehoseS3BackupDisabled'] = [
                1, f"S3 backup enabled on all {processing_enabled_count} transforming destination(s)"
            ]

    # ------------------------------------------------------------------ #
    # 6. firehoseBufferingSuboptimal (research doc #19)
    # ------------------------------------------------------------------ #
    def _checkFirehoseBufferingSuboptimal(self):
        s3_blocks = list(self._s3DestinationDescriptions())
        if not s3_blocks:
            self.results['firehoseBufferingSuboptimal'] = [
                0, "No S3 destination on this delivery stream"
            ]
            return

        offenders = []
        for block in s3_blocks:
            hints = block.get('BufferingHints') or {}
            interval = hints.get('IntervalInSeconds')
            size = hints.get('SizeInMBs')
            bucket = block.get('BucketARN', '<unknown>')
            bucket_short = bucket.split(':::')[-1] or bucket
            issues = []
            if isinstance(interval, int) and interval < self.MIN_BUFFER_INTERVAL_SECONDS:
                issues.append(f"IntervalInSeconds={interval}")
            if isinstance(size, (int, float)) and size < self.MIN_BUFFER_SIZE_MB:
                issues.append(f"SizeInMBs={size}")
            if issues:
                offenders.append(f"{bucket_short} ({', '.join(issues)})")

        if offenders:
            self.results['firehoseBufferingSuboptimal'] = [
                -1,
                "Buffering below recommended threshold on: "
                + "; ".join(offenders[:5])
            ]
        else:
            self.results['firehoseBufferingSuboptimal'] = [
                1, f"Buffering within recommended range on all {len(s3_blocks)} destination(s)"
            ]

    # ------------------------------------------------------------------ #
    # 7. firehoseNoTags (research doc #20)
    # ------------------------------------------------------------------ #
    def _checkFirehoseNoTags(self):
        tags = self.stream.get('_tags') or []
        # Filter AWS-system tags (aws:* prefix) so managed tags don't hide
        # the fact that the resource has no user-defined tags.
        user_tags = [t for t in tags if not str(t.get('Key', '')).startswith('aws:')]
        if not user_tags:
            self.results['firehoseNoTags'] = [-1, "No user-defined tags applied"]
        else:
            keys = [t.get('Key') for t in user_tags if t.get('Key')]
            self.results['firehoseNoTags'] = [
                1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
            ]

    # ------------------------------------------------------------------ #
    # 8. firehoseStreamNotActive (research doc #21)
    # ------------------------------------------------------------------ #
    def _checkFirehoseStreamNotActive(self):
        status = self.desc.get('DeliveryStreamStatus', 'UNKNOWN')
        if status == 'ACTIVE':
            self.results['firehoseStreamNotActive'] = [1, "DeliveryStreamStatus=ACTIVE"]
        elif status in self.FAILED_STATES:
            # Terminal / halted state — needs operator attention.
            # SUSPENDED typically means a KMS key became unavailable and
            # Firehose has paused delivery; CREATING_FAILED / DELETING_FAILED
            # mean the create / delete call itself hit an unrecoverable error.
            failure_desc = self.desc.get('FailureDescription') or {}
            details = failure_desc.get('Details') or failure_desc.get('Type') or ''
            msg = f"Delivery stream in non-active state: {status}"
            if details:
                msg += f" ({str(details)[:120]})"
            self.results['firehoseStreamNotActive'] = [-1, msg]
        else:
            # CREATING / DELETING — transient.
            self.results['firehoseStreamNotActive'] = [
                0, f"Delivery stream is in transient state: {status}"
            ]

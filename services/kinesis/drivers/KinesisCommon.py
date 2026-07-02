from datetime import datetime, timezone

from services.Evaluator import Evaluator


class KinesisCommon(Evaluator):
    """
    All 14 Amazon Kinesis Data Streams checks.

    Input:
      stream -- dict produced by Kinesis.py.getResources with keys:
        '_name', '_arn', '_summary' (raw StreamDescriptionSummary),
        '_tags' (list of {'Key','Value'}), '_consumers' (list of EFO consumers),
        '_kmsRotation' ('enabled'|'disabled'|'unknown'|'not_applicable'),
        '_hasCloudWatchAlarms' (True|False|None),
        '_shardLimit' (int), '_totalOpenShards' (int).
      kinesisClient -- boto3 kinesis client (kept for future per-check calls).
    """

    AWS_MANAGED_KMS_ALIAS = 'alias/aws/kinesis'

    # Security Hub Kinesis.3 default
    MINIMUM_RETENTION_HOURS = 24
    RECOMMENDED_RETENTION_HOURS = 168

    # Shard utilisation threshold — matches spec §9 (80%)
    SHARD_UTILISATION_THRESHOLD = 0.80

    # Age thresholds
    NO_CONSUMER_MIN_AGE_DAYS = 7
    ON_DEMAND_ADVISORY_AGE_DAYS = 30
    CONSUMER_STUCK_MINUTES = 10

    # Critical shard-level metrics that check #12 looks for
    CRITICAL_SHARD_METRICS = [
        'IteratorAgeMilliseconds',
        'WriteProvisionedThroughputExceeded',
        'ReadProvisionedThroughputExceeded',
    ]

    def __init__(self, stream, kinesisClient):
        super().__init__()
        self.stream = stream
        self.kinesisClient = kinesisClient

        self.summary = stream.get('_summary') or {}
        self.tags = stream.get('_tags') or []
        self.consumers = stream.get('_consumers') or []

        self._resourceName = stream.get('_name', 'unknown')

        # Inventory info surfaced in the UI
        self.addII('streamName', self._resourceName)
        self.addII('streamArn', stream.get('_arn', 'N/A'))
        self.addII('streamStatus', self.summary.get('StreamStatus', 'N/A'))
        self.addII('streamMode', (self.summary.get('StreamModeDetails') or {})
                   .get('StreamMode', 'N/A'))
        self.addII('encryptionType', self.summary.get('EncryptionType', 'NONE'))
        self.addII('keyId', self.summary.get('KeyId', 'N/A'))
        self.addII('retentionPeriodHours',
                   self.summary.get('RetentionPeriodHours', 'N/A'))
        self.addII('openShardCount', self.summary.get('OpenShardCount', 'N/A'))
        self.addII('consumerCount', self.summary.get('ConsumerCount', 0))

    # ------------------------------------------------------------------ #
    # 1. Server-side encryption not enabled
    # ------------------------------------------------------------------ #
    def _checkKinesisSSEDisabled(self):
        encType = self.summary.get('EncryptionType', 'NONE')
        if encType == 'NONE' or not encType:
            self.results['kinesisSSEDisabled'] = [
                -1, "Server-side encryption is not enabled (EncryptionType=NONE)"
            ]
        else:
            self.results['kinesisSSEDisabled'] = [
                1, f"Encryption enabled (EncryptionType={encType})"
            ]

    # ------------------------------------------------------------------ #
    # 2. Encryption uses AWS-managed key instead of CMK
    # ------------------------------------------------------------------ #
    def _checkKinesisSSEDefaultKey(self):
        encType = self.summary.get('EncryptionType', 'NONE')
        if encType != 'KMS':
            # Unencrypted stream is already flagged by check #1; not applicable here.
            self.results['kinesisSSEDefaultKey'] = [
                0, "Stream is unencrypted — see kinesisSSEDisabled"
            ]
            return

        keyId = self.summary.get('KeyId') or ''
        if self.AWS_MANAGED_KMS_ALIAS in keyId:
            self.results['kinesisSSEDefaultKey'] = [
                -1, f"Using AWS-managed key ({keyId}); customer-managed CMK preferred"
            ]
        else:
            self.results['kinesisSSEDefaultKey'] = [
                1, f"Customer-managed key: {keyId}"
            ]

    # ------------------------------------------------------------------ #
    # 3. KMS key rotation disabled (CMK only)
    # ------------------------------------------------------------------ #
    def _checkKinesisKMSKeyRotationDisabled(self):
        rotation = self.stream.get('_kmsRotation', 'not_applicable')

        if rotation == 'not_applicable':
            self.results['kinesisKMSKeyRotationDisabled'] = [
                0, "Not applicable (unencrypted or using AWS-managed key)"
            ]
        elif rotation == 'enabled':
            self.results['kinesisKMSKeyRotationDisabled'] = [
                1, "CMK key rotation is enabled"
            ]
        elif rotation == 'disabled':
            self.results['kinesisKMSKeyRotationDisabled'] = [
                -1, "CMK key rotation is not enabled"
            ]
        else:  # unknown
            self.results['kinesisKMSKeyRotationDisabled'] = [
                0, "Could not determine key rotation status "
                   "(AccessDenied or unsupported key type)"
            ]

    # ------------------------------------------------------------------ #
    # 4. Retention at minimum (24h)
    # ------------------------------------------------------------------ #
    def _checkKinesisRetentionPeriodMinimum(self):
        retention = self.summary.get('RetentionPeriodHours')
        if retention is None:
            self.results['kinesisRetentionPeriodMinimum'] = [
                0, "RetentionPeriodHours not present in describe_stream_summary"
            ]
            return

        try:
            retention = int(retention)
        except (TypeError, ValueError):
            self.results['kinesisRetentionPeriodMinimum'] = [
                0, f"RetentionPeriodHours has non-numeric value: {retention}"
            ]
            return

        if retention <= self.MINIMUM_RETENTION_HOURS:
            self.results['kinesisRetentionPeriodMinimum'] = [
                -1, f"Retention at minimum {retention}h — Security Hub "
                    f"Kinesis.3 recommends >= {self.RECOMMENDED_RETENTION_HOURS}h"
            ]
        elif retention < self.RECOMMENDED_RETENTION_HOURS:
            self.results['kinesisRetentionPeriodMinimum'] = [
                -1, f"Retention {retention}h below recommended "
                    f"{self.RECOMMENDED_RETENTION_HOURS}h (Security Hub Kinesis.3)"
            ]
        else:
            self.results['kinesisRetentionPeriodMinimum'] = [
                1, f"Retention {retention}h meets recommended threshold"
            ]

    # ------------------------------------------------------------------ #
    # 5. Stream has no user tags
    # ------------------------------------------------------------------ #
    def _checkKinesisNoTags(self):
        user_tags = [t for t in self.tags
                     if not (t.get('Key') or '').startswith('aws:')]
        if not user_tags:
            self.results['kinesisNoTags'] = [
                -1, "Stream has no user-defined tags"
            ]
        else:
            self.results['kinesisNoTags'] = [
                1, f"Stream has {len(user_tags)} user-defined tag(s)"
            ]

    # ------------------------------------------------------------------ #
    # 6. Enhanced (shard-level) monitoring disabled
    # ------------------------------------------------------------------ #
    def _checkKinesisEnhancedMonitoringDisabled(self):
        enhanced = self.summary.get('EnhancedMonitoring', []) or []
        for entry in enhanced:
            metrics = entry.get('ShardLevelMetrics') or []
            if metrics:
                self.results['kinesisEnhancedMonitoringDisabled'] = [
                    1, f"Shard-level metrics enabled: {len(metrics)} metric(s)"
                ]
                return
        self.results['kinesisEnhancedMonitoringDisabled'] = [
            -1, "Enhanced (shard-level) monitoring is not enabled"
        ]

    # ------------------------------------------------------------------ #
    # 7. Stream in non-ACTIVE state
    # ------------------------------------------------------------------ #
    def _checkKinesisStreamNotActive(self):
        status = self.summary.get('StreamStatus', 'UNKNOWN')
        if status == 'ACTIVE':
            self.results['kinesisStreamNotActive'] = [
                1, "Stream is ACTIVE"
            ]
        else:
            self.results['kinesisStreamNotActive'] = [
                -1, f"Stream is in '{status}' state "
                    "(CREATING/UPDATING should be transient; DELETING may indicate stuck cleanup)"
            ]

    # ------------------------------------------------------------------ #
    # 8. Provisioned mode advisory
    # ------------------------------------------------------------------ #
    def _checkKinesisProvisionedModeNoAutoScaling(self):
        mode = (self.summary.get('StreamModeDetails') or {}).get('StreamMode')
        if mode == 'PROVISIONED':
            self.results['kinesisProvisionedModeNoAutoScaling'] = [
                -1, "Stream uses PROVISIONED mode — ensure Application Auto "
                    "Scaling is configured or workload is predictable"
            ]
        else:
            self.results['kinesisProvisionedModeNoAutoScaling'] = [
                1, f"StreamMode={mode or 'ON_DEMAND'}"
            ]

    # ------------------------------------------------------------------ #
    # 9. Account-wide shard utilisation approaching limit
    # ------------------------------------------------------------------ #
    def _checkKinesisShardUtilizationHigh(self):
        limit = self.stream.get('_shardLimit') or 0
        total = self.stream.get('_totalOpenShards') or 0

        if limit <= 0:
            self.results['kinesisShardUtilizationHigh'] = [
                0, "Shard limit could not be determined"
            ]
            return

        utilisation = total / limit
        pct = int(round(utilisation * 100))
        if utilisation > self.SHARD_UTILISATION_THRESHOLD:
            self.results['kinesisShardUtilizationHigh'] = [
                -1, f"Account open-shard utilisation at {pct}% "
                    f"({total}/{limit}) — risk of hitting service quota"
            ]
        else:
            self.results['kinesisShardUtilizationHigh'] = [
                1, f"Account open-shard utilisation at {pct}% ({total}/{limit})"
            ]

    # ------------------------------------------------------------------ #
    # 10. No enhanced fan-out consumers
    # ------------------------------------------------------------------ #
    def _checkKinesisNoConsumers(self):
        consumer_count = self.summary.get('ConsumerCount', 0) or 0
        status = self.summary.get('StreamStatus', 'UNKNOWN')

        if consumer_count > 0:
            self.results['kinesisNoConsumers'] = [
                1, f"{consumer_count} enhanced fan-out consumer(s) registered"
            ]
            return

        if status != 'ACTIVE':
            self.results['kinesisNoConsumers'] = [
                0, "Stream not ACTIVE — consumer check deferred"
            ]
            return

        age_days = self._streamAgeDays()
        if age_days is None or age_days < self.NO_CONSUMER_MIN_AGE_DAYS:
            self.results['kinesisNoConsumers'] = [
                0, "Stream too young to evaluate consumer usage "
                   f"(< {self.NO_CONSUMER_MIN_AGE_DAYS} days)"
            ]
            return

        # NOTE: this only counts EFO consumers — KCL, Lambda triggers, and
        # Firehose sources do NOT register here. Advisory only.
        self.results['kinesisNoConsumers'] = [
            -1, "No enhanced fan-out consumers registered — verify stream is "
                "actively consumed (KCL/Lambda consumers do not appear here)"
        ]

    # ------------------------------------------------------------------ #
    # 11. On-demand mode advisory for long-running streams
    # ------------------------------------------------------------------ #
    def _checkKinesisOnDemandPredictableWorkload(self):
        mode = (self.summary.get('StreamModeDetails') or {}).get('StreamMode')
        if mode != 'ON_DEMAND':
            self.results['kinesisOnDemandPredictableWorkload'] = [
                0, f"Not applicable (StreamMode={mode or 'PROVISIONED'})"
            ]
            return

        age_days = self._streamAgeDays()
        if age_days is None or age_days < self.ON_DEMAND_ADVISORY_AGE_DAYS:
            self.results['kinesisOnDemandPredictableWorkload'] = [
                1, f"On-demand stream is < {self.ON_DEMAND_ADVISORY_AGE_DAYS} "
                   "days old — review after workload stabilises"
            ]
            return

        self.results['kinesisOnDemandPredictableWorkload'] = [
            -1, f"On-demand stream active for {age_days} days — review whether "
                "provisioned mode would be more cost-effective for predictable workloads"
        ]

    # ------------------------------------------------------------------ #
    # 12. Enhanced monitoring partially enabled (missing critical metrics)
    # ------------------------------------------------------------------ #
    def _checkKinesisEnhancedMonitoringPartial(self):
        enhanced = self.summary.get('EnhancedMonitoring', []) or []
        enabled = set()
        for entry in enhanced:
            for m in entry.get('ShardLevelMetrics') or []:
                enabled.add(m)

        if not enabled:
            # Fully off — check #6 already reports this. Skip partial evaluation.
            self.results['kinesisEnhancedMonitoringPartial'] = [
                0, "No shard-level metrics enabled — see kinesisEnhancedMonitoringDisabled"
            ]
            return

        if 'ALL' in enabled:
            self.results['kinesisEnhancedMonitoringPartial'] = [
                1, "All shard-level metrics enabled (ALL)"
            ]
            return

        missing = [m for m in self.CRITICAL_SHARD_METRICS if m not in enabled]
        if missing:
            self.results['kinesisEnhancedMonitoringPartial'] = [
                -1, f"Critical shard-level metric(s) not enabled: {', '.join(missing)}"
            ]
        else:
            self.results['kinesisEnhancedMonitoringPartial'] = [
                1, "All critical shard-level metrics enabled"
            ]

    # ------------------------------------------------------------------ #
    # 13. Enhanced fan-out consumer stuck in non-ACTIVE state
    # ------------------------------------------------------------------ #
    def _checkKinesisConsumerStuck(self):
        if not self.consumers:
            self.results['kinesisConsumerStuck'] = [
                0, "No enhanced fan-out consumers to evaluate"
            ]
            return

        now = datetime.now(tz=timezone.utc)
        stuck = []
        for c in self.consumers:
            status = c.get('ConsumerStatus') or ''
            if status == 'ACTIVE':
                continue
            created = c.get('ConsumerCreationTimestamp')
            if not isinstance(created, datetime):
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_minutes = (now - created).total_seconds() / 60.0
            if age_minutes > self.CONSUMER_STUCK_MINUTES:
                stuck.append(f"{c.get('ConsumerName', '<unnamed>')}:{status}")

        if stuck:
            self.results['kinesisConsumerStuck'] = [
                -1, f"Consumer(s) stuck > {self.CONSUMER_STUCK_MINUTES} min "
                    f"in non-ACTIVE state: {', '.join(stuck[:5])}"
                    + (f" (+{len(stuck)-5} more)" if len(stuck) > 5 else "")
            ]
        else:
            self.results['kinesisConsumerStuck'] = [
                1, f"All {len(self.consumers)} consumer(s) ACTIVE or transitioning normally"
            ]

    # ------------------------------------------------------------------ #
    # 14 (spec #22). No CloudWatch alarms configured
    # ------------------------------------------------------------------ #
    def _checkKinesisNoCloudWatchAlarms(self):
        has_alarms = self.stream.get('_hasCloudWatchAlarms')
        if has_alarms is None:
            self.results['kinesisNoCloudWatchAlarms'] = [
                0, "Could not determine alarm coverage (AccessDenied on CloudWatch)"
            ]
        elif has_alarms is True:
            self.results['kinesisNoCloudWatchAlarms'] = [
                1, "CloudWatch alarm(s) configured on critical stream metrics"
            ]
        else:
            self.results['kinesisNoCloudWatchAlarms'] = [
                -1, "No CloudWatch alarms on IteratorAge / "
                    "WriteProvisionedThroughputExceeded / ReadProvisionedThroughputExceeded"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _streamAgeDays(self):
        """Return age in days, or None if the timestamp is missing/unparseable."""
        ts = self.summary.get('StreamCreationTimestamp')
        if not isinstance(ts, datetime):
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(tz=timezone.utc) - ts).days

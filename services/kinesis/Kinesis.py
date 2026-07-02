import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

from services.kinesis.drivers.KinesisCommon import KinesisCommon


class Kinesis(Service):
    """
    Amazon Kinesis Data Streams service scanner.

    Discovers every stream in the region via list_streams and hydrates each with:
      - describe_stream_summary        (encryption, retention, mode, shards, monitoring)
      - list_tags_for_stream           (tag governance)
      - list_stream_consumers          (enhanced fan-out consumers)
      - kms.get_key_rotation_status    (only for customer-managed CMKs)
      - cloudwatch.describe_alarms_for_metric (per stream, for alarm coverage)

    Account-level metadata fetched once per scan and shared across streams:
      - describe_limits                (account-wide shard limit)
    """

    # Account default shard limit if describe_limits is unavailable
    DEFAULT_SHARD_LIMIT = 200

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.kinesisClient = ssBoto.client('kinesis', config=self.bConfig)
        self.kmsClient = ssBoto.client('kms', config=self.bConfig)
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)

        # Cache: KMS keyId → rotation status ('enabled' | 'disabled' | 'unknown' | 'not_applicable')
        self._kmsRotationCache = {}
        # Account-level shard limit (fetched once per region)
        self._shardLimit = None
        # Total open shards across all streams in this region (computed after all
        # streams are discovered so utilisation check has correct denominator)
        self._totalOpenShards = 0

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        streams = []
        try:
            # list_streams supports pagination via ExclusiveStartStreamName
            names = self._listAllStreamNames()
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_streams', e)
            return []
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Kinesis not available in region {self.region}: {e}")
            return []

        # Account-level shard limit (once)
        self._shardLimit = self._fetchShardLimit()

        for name in names:
            summary = self._describeStreamSummary(name)
            if summary is None:
                continue

            arn = summary.get('StreamARN', '')
            tags = self._listTags(arn, name)
            if self.tags and not self.resourceHasTags(tags):
                continue

            detail = {
                '_name': name,
                '_arn': arn,
                '_summary': summary,
                '_tags': tags,
                '_consumers': self._listConsumers(arn),
                '_kmsRotation': self._kmsRotationFor(summary),
                '_hasCloudWatchAlarms': self._hasCloudWatchAlarms(name),
                '_shardLimit': self._shardLimit,
                # _totalOpenShards is filled in below after all streams are known.
                '_totalOpenShards': 0,
            }
            self._totalOpenShards += int(summary.get('OpenShardCount', 0) or 0)

            _pi('Kinesis', f"Stream: {name}")
            streams.append(detail)

        # Inject account-wide total open shards into every stream detail so
        # the shard-utilisation check has the correct denominator.
        for d in streams:
            d['_totalOpenShards'] = self._totalOpenShards

        return streams

    def _listAllStreamNames(self):
        names = []
        exclusiveStart = None
        while True:
            kwargs = {'Limit': 100}
            if exclusiveStart:
                kwargs['ExclusiveStartStreamName'] = exclusiveStart
            resp = self.kinesisClient.list_streams(**kwargs)
            for n in resp.get('StreamNames', []) or []:
                names.append(n)
            if not resp.get('HasMoreStreams'):
                break
            if not names:
                break
            exclusiveStart = names[-1]
        return names

    def _describeStreamSummary(self, streamName):
        try:
            resp = self.kinesisClient.describe_stream_summary(StreamName=streamName)
            return resp.get('StreamDescriptionSummary') or {}
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_stream_summary({streamName})', e)
            return None

    def _listTags(self, arn, streamName):
        """list_tags_for_stream paginates via ExclusiveStartTagKey + HasMoreTags."""
        tags = []
        exclusiveStart = None
        try:
            while True:
                kwargs = {'StreamName': streamName, 'Limit': 50}
                if exclusiveStart:
                    kwargs['ExclusiveStartTagKey'] = exclusiveStart
                resp = self.kinesisClient.list_tags_for_stream(**kwargs)
                batch = resp.get('Tags', []) or []
                tags.extend(batch)
                if not resp.get('HasMoreTags') or not batch:
                    break
                exclusiveStart = batch[-1].get('Key')
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_stream({streamName})', e)
        return tags

    def _listConsumers(self, streamArn):
        """list_stream_consumers returns Enhanced Fan-Out consumers only."""
        if not streamArn:
            return []
        consumers = []
        try:
            token = None
            while True:
                kwargs = {'StreamARN': streamArn, 'MaxResults': 100}
                if token:
                    kwargs['NextToken'] = token
                resp = self.kinesisClient.list_stream_consumers(**kwargs)
                for c in resp.get('Consumers', []) or []:
                    consumers.append(c)
                token = resp.get('NextToken')
                if not token:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_stream_consumers({streamArn})', e)
        return consumers

    def _fetchShardLimit(self):
        """
        Account-level open-shard limit. Falls back to DEFAULT_SHARD_LIMIT (200)
        if the API is unavailable or access-denied.
        """
        try:
            resp = self.kinesisClient.describe_limits()
            limit = resp.get('ShardLimit')
            if isinstance(limit, int) and limit > 0:
                return limit
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_limits', e)
        return self.DEFAULT_SHARD_LIMIT

    def _kmsRotationFor(self, summary):
        """
        Determine rotation state for the stream's KMS key.

        Returns one of:
          'not_applicable' — stream unencrypted or uses AWS-managed alias/aws/kinesis
          'enabled'        — CMK rotation is on
          'disabled'       — CMK rotation is off
          'unknown'        — lookup failed (AccessDenied, cross-account, etc.)
        """
        if summary.get('EncryptionType') != 'KMS':
            return 'not_applicable'

        keyId = summary.get('KeyId') or ''
        # AWS-managed key: no customer control over rotation.
        if 'alias/aws/kinesis' in keyId:
            return 'not_applicable'

        # Cache by keyId to avoid duplicate KMS calls when streams share a CMK
        if keyId in self._kmsRotationCache:
            return self._kmsRotationCache[keyId]

        result = self._probeKeyRotation(keyId)
        self._kmsRotationCache[keyId] = result
        return result

    def _probeKeyRotation(self, keyId):
        try:
            resp = self.kmsClient.get_key_rotation_status(KeyId=keyId)
            return 'enabled' if resp.get('KeyRotationEnabled') else 'disabled'
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # Asymmetric keys, external key stores, cross-account keys, or
            # missing permission → we can't determine rotation.
            if code in ('AccessDenied', 'AccessDeniedException',
                        'UnsupportedOperationException',
                        'NotFoundException', 'KMSInvalidStateException'):
                return 'unknown'
            self._logClientError(f'kms.get_key_rotation_status({keyId})', e)
            return 'unknown'

    def _hasCloudWatchAlarms(self, streamName):
        """
        Return True if any CloudWatch alarm targets one of the key stream-health
        metrics for this stream. Falls back to None ('unknown') on AccessDenied
        so the driver can degrade the check to INFO.
        """
        critical_metrics = [
            'GetRecords.IteratorAgeMilliseconds',
            'WriteProvisionedThroughputExceeded',
            'ReadProvisionedThroughputExceeded',
        ]
        for metric in critical_metrics:
            try:
                resp = self.cwClient.describe_alarms_for_metric(
                    MetricName=metric,
                    Namespace='AWS/Kinesis',
                    Dimensions=[{'Name': 'StreamName', 'Value': streamName}],
                )
                if resp.get('MetricAlarms') or resp.get('CompositeAlarms'):
                    return True
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', '')
                if code in ('AccessDenied', 'AccessDeniedException'):
                    return None
                self._logClientError(
                    f'cloudwatch.describe_alarms_for_metric({metric})', e
                )
        return False

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        streams = self.getResources()

        for stream in streams:
            try:
                name = stream.get('_name', 'unknown')
                _pi('Kinesis', f"Analyzing: {name}")
                obj = KinesisCommon(stream, self.kinesisClient)
                obj.run(self.__class__)
                objs[f"Kinesis::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Kinesis stream {stream.get('_arn')}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Kinesis {where}: {code} - {msg}")

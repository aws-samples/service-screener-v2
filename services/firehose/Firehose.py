import botocore

from utils.Tools import _pi
from services.Service import Service

from services.firehose.drivers.FirehoseCommon import FirehoseCommon


class Firehose(Service):
    """
    Amazon Data Firehose service scanner.

    Discovers every delivery stream in the region via list_delivery_streams,
    hydrates each with:
      - describe_delivery_stream (encryption config, destinations, status)
      - list_tags_for_delivery_stream
    """

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.firehoseClient = ssBoto.client('firehose', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        streams = []
        try:
            names = self._listDeliveryStreamNames()
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Firehose not available in region {self.region}: {e}")
            return streams
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_delivery_streams', e)
            return streams

        for name in names:
            detail = self._describeStream(name)
            if detail is None:
                continue
            _pi('Firehose', f"DeliveryStream: {detail.get('_name', name)}")
            streams.append(detail)
        return streams

    def _listDeliveryStreamNames(self):
        """list_delivery_streams uses ExclusiveStartDeliveryStreamName pagination
        rather than the standard NextToken model, so we hand-roll it."""
        names = []
        exclusive_start = None
        while True:
            kwargs = {'Limit': 100}
            if exclusive_start:
                kwargs['ExclusiveStartDeliveryStreamName'] = exclusive_start
            resp = self.firehoseClient.list_delivery_streams(**kwargs)
            batch = resp.get('DeliveryStreamNames', []) or []
            names.extend(batch)
            if not resp.get('HasMoreDeliveryStreams'):
                break
            if not batch:
                # Defensive: no more names but flag says more -> abort loop.
                break
            exclusive_start = batch[-1]
        return names

    def _describeStream(self, name):
        try:
            resp = self.firehoseClient.describe_delivery_stream(DeliveryStreamName=name)
            desc = resp.get('DeliveryStreamDescription', {}) or {}
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_delivery_stream({name})', e)
            return None

        tags = self._listTags(name)
        if self.tags and not self.resourceHasTags(tags):
            return None

        return {
            '_name': name,
            '_arn': desc.get('DeliveryStreamARN', ''),
            '_description': desc,
            '_tags': tags,
        }

    def _listTags(self, name):
        """list_tags_for_delivery_stream uses ExclusiveStartTagKey pagination."""
        tags = []
        exclusive_start = None
        try:
            while True:
                kwargs = {'DeliveryStreamName': name, 'Limit': 50}
                if exclusive_start:
                    kwargs['ExclusiveStartTagKey'] = exclusive_start
                resp = self.firehoseClient.list_tags_for_delivery_stream(**kwargs)
                batch = resp.get('Tags', []) or []
                tags.extend(batch)
                if not resp.get('HasMoreTags'):
                    break
                if not batch:
                    break
                exclusive_start = batch[-1].get('Key')
                if not exclusive_start:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_delivery_stream({name})', e)
        return tags

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        streams = self.getResources()

        for stream in streams:
            try:
                name = stream.get('_name', 'unknown')
                _pi('Firehose', f"Analyzing: {name}")
                obj = FirehoseCommon(stream, self.firehoseClient)
                obj.run(self.__class__)
                objs[f"Firehose::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Firehose delivery stream {stream.get('_name')}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Firehose {where}: {code} - {msg}")

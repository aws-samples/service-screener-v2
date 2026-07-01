import botocore

from utils.Tools import _pi
from services.Service import Service

from services.sns.drivers.SnsCommon import SnsCommon


class Sns(Service):
    """
    Amazon SNS service scanner.

    Discovers every topic in the region via list_topics, hydrates each with:
      - get_topic_attributes  (encryption, policy, tracing, sig version, sub counts,
                               delivery-status feedback roles)
      - list_tags_for_resource
      - list_subscriptions_by_topic (paginated)
      - get_subscription_attributes for every DLQ-eligible subscription
    """

    # Protocols that support async delivery + DLQ via RedrivePolicy.
    DLQ_ELIGIBLE_PROTOCOLS = {'sqs', 'lambda', 'firehose'}

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.snsClient = ssBoto.client('sns', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        topics = []
        try:
            paginator = self.snsClient.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page.get('Topics', []):
                    arn = topic.get('TopicArn')
                    if not arn:
                        continue
                    detail = self._describeTopic(arn)
                    if detail is None:
                        continue
                    _pi('Sns', f"Topic: {detail.get('_name', arn)}")
                    topics.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_topics', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"SNS not available in region {self.region}: {e}")
        return topics

    def _describeTopic(self, arn):
        """Build a single topic descriptor dict with all fields the driver needs."""
        try:
            resp = self.snsClient.get_topic_attributes(TopicArn=arn)
            attrs = resp.get('Attributes', {}) or {}
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_topic_attributes({arn})', e)
            return None

        # Optional tag filtering
        tags = self._listTags(arn)
        if self.tags and not self.resourceHasTags(tags):
            return None

        subscriptions = self._listSubscriptions(arn)

        detail = {
            '_arn': arn,
            '_name': arn.split(':')[-1],
            '_attributes': attrs,
            '_tags': tags,
            '_subscriptions': subscriptions,
        }
        return detail

    def _listTags(self, arn):
        try:
            resp = self.snsClient.list_tags_for_resource(ResourceArn=arn)
            return resp.get('Tags', [])
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_resource({arn})', e)
            return []

    def _listSubscriptions(self, arn):
        """Return a list of subscription descriptors. For DLQ-eligible protocols,
        also fetch subscription attributes to inspect RedrivePolicy."""
        subs = []
        try:
            paginator = self.snsClient.get_paginator('list_subscriptions_by_topic')
            for page in paginator.paginate(TopicArn=arn):
                for s in page.get('Subscriptions', []):
                    entry = dict(s)  # keys: SubscriptionArn, Protocol, Endpoint, Owner, TopicArn
                    if s.get('Protocol') in self.DLQ_ELIGIBLE_PROTOCOLS and \
                            s.get('SubscriptionArn', '').startswith('arn:'):
                        entry['_attributes'] = self._getSubscriptionAttrs(s['SubscriptionArn'])
                    else:
                        entry['_attributes'] = {}
                    subs.append(entry)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_subscriptions_by_topic({arn})', e)
        return subs

    def _getSubscriptionAttrs(self, subArn):
        try:
            resp = self.snsClient.get_subscription_attributes(SubscriptionArn=subArn)
            return resp.get('Attributes', {}) or {}
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_subscription_attributes({subArn})', e)
            return {}

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        topics = self.getResources()

        for topic in topics:
            try:
                name = topic.get('_name', 'unknown')
                _pi('Sns', f"Analyzing: {name}")
                obj = SnsCommon(topic, self.snsClient)
                obj.run(self.__class__)
                objs[f"Sns::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing SNS topic {topic.get('_arn')}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Sns {where}: {code} - {msg}")

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
        self._platformAppsCache = None
        # SMS attributes are account-level; cache once per region.
        self._smsAttributesCache = None

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
            '_dataProtectionPolicy': self._getDataProtectionPolicy(arn),
            '_platformApps': self._listPlatformApps(),
            '_currentAccount': self._currentAccount(),
            '_smsAttributes': self._getSmsAttributes(),
            '_isFifo': arn.endswith('.fifo') or str(attrs.get('FifoTopic', 'false')).lower() == 'true',
        }
        return detail

    def _getSmsAttributes(self):
        """Fetch account-level SMS attributes once per region."""
        if self._smsAttributesCache is not None:
            return self._smsAttributesCache
        attrs = {}
        try:
            resp = self.snsClient.get_sms_attributes()
            attrs = resp.get('attributes', {}) or {}
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # Region may not support SMS at all
            if code not in ('AccessDenied', 'AccessDeniedException',
                            'AuthorizationError', 'InvalidAction'):
                self._logClientError('get_sms_attributes', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        self._smsAttributesCache = attrs
        return attrs

    def _currentAccount(self):
        from utils.Config import Config
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    def _listPlatformApps(self):
        """Fetch platform-application descriptors once per region, then reuse.

        Each entry is a dict with 'PlatformApplicationArn' + attribute map.
        Empty list means the account has no platform applications (mobile push).
        """
        if self._platformAppsCache is not None:
            return self._platformAppsCache
        apps = []
        try:
            marker = None
            while True:
                kwargs = {}
                if marker:
                    kwargs['NextToken'] = marker
                resp = self.snsClient.list_platform_applications(**kwargs)
                for entry in resp.get('PlatformApplications', []) or []:
                    arn = entry.get('PlatformApplicationArn')
                    if not arn:
                        continue
                    attrs = {}
                    try:
                        detail = self.snsClient.get_platform_application_attributes(
                            PlatformApplicationArn=arn
                        )
                        attrs = detail.get('Attributes') or {}
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(
                            f'get_platform_application_attributes({arn})', e
                        )
                    apps.append({'PlatformApplicationArn': arn, 'Attributes': attrs})
                marker = resp.get('NextToken')
                if not marker:
                    break
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # Some accounts / regions don't have mobile-push endpoints at all
            if code not in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError',
                            'InvalidAction'):
                self._logClientError('list_platform_applications', e)
        self._platformAppsCache = apps
        return apps

    def _getDataProtectionPolicy(self, arn):
        """Return the DataProtectionPolicy JSON string, or None if not set / call fails."""
        try:
            resp = self.snsClient.get_data_protection_policy(ResourceArn=arn)
            return resp.get('DataProtectionPolicy')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # SNS returns InvalidParameter when no policy is attached.
            if code in ('InvalidParameter', 'InvalidParameterValue',
                        'ResourceNotFoundException', 'NotFound'):
                return None
            self._logClientError(f'get_data_protection_policy({arn})', e)
            return None

    def _listTags(self, arn):
        try:
            resp = self.snsClient.list_tags_for_resource(ResourceArn=arn)
            return resp.get('Tags', [])
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_resource({arn})', e)
            return []

    def _listSubscriptions(self, arn):
        """Return a list of subscription descriptors. For every CONFIRMED
        subscription we fetch the full attribute set (needed for
        RedrivePolicy check #7 AND for ConfirmationWasAuthenticated check
        #17). Pending-confirmation subs are returned with empty _attributes."""
        subs = []
        try:
            paginator = self.snsClient.get_paginator('list_subscriptions_by_topic')
            for page in paginator.paginate(TopicArn=arn):
                for s in page.get('Subscriptions', []):
                    entry = dict(s)  # keys: SubscriptionArn, Protocol, Endpoint, Owner, TopicArn
                    subArn = s.get('SubscriptionArn', '')
                    if subArn.startswith('arn:'):
                        entry['_attributes'] = self._getSubscriptionAttrs(subArn)
                    else:
                        # PendingConfirmation / "pending confirmation" — no attrs API.
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

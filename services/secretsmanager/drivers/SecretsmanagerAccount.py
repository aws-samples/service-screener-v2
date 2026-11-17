import fnmatch
import json
import re

import botocore

from services.Evaluator import Evaluator


class SecretsmanagerAccount(Evaluator):
    """
    Account/region-level Secrets Manager checks (run once per region that holds
    at least one secret).

    secretChangeNotMonitored (SEC02-BP03, tier 3 heuristic)
      Looks for an alerting path for the high-impact Secrets Manager API calls
      DeleteSecret and PutResourcePolicy, recorded by CloudTrail:
        1. EventBridge: an ENABLED rule on the default event bus (not managed by
           an AWS service) that has at least one target and whose EventPattern
           would match the CloudTrail "AWS API Call via CloudTrail" event for
           the call.
        2. CloudWatch Logs: a metric filter on the log group of a CloudTrail
           trail that covers this region and is logging, whose filter pattern
           matches the call, with a CloudWatch alarm on the resulting metric
           that has alarm actions (directly, or through a composite alarm that
           has actions).
      Read-only APIs: events.list_rules, events.list_targets_by_rule,
      cloudtrail.describe_trails, cloudtrail.get_trail_status,
      logs.describe_metric_filters, cloudwatch.describe_alarms.

      Precision note: alerting may also live in a SIEM or third-party tool,
      which this check cannot see, so it is reported with Low criticality.
      Pattern matching is conservative: a pattern that additionally narrows on
      fields other than the event source/name (for example one specific secret
      or principal) is not counted as covering the call.
    """

    REQUIRED_EVENTS = ('DeleteSecret', 'PutResourcePolicy')
    EVENT_SOURCE = 'secretsmanager.amazonaws.com'
    SOURCE = 'aws.secretsmanager'
    DETAIL_TYPE = 'AWS API Call via CloudTrail'

    DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnauthorizedOperation', 'UnrecognizedClientException',
    )

    # Metric-filter selectors that do not narrow coverage of an API call.
    NEUTRAL_FILTER_FIELDS = {
        'eventSource', 'eventName', 'eventType', 'eventCategory',
        'awsRegion', 'recipientAccountId', 'readOnly', 'eventVersion',
    }

    def __init__(self, ctx, eventsClient, ctClient, regionalClient):
        """
        ctx            -- {'region': str, 'account': str}
        eventsClient   -- boto3 events client for the scanned region
        ctClient       -- boto3 cloudtrail client for the scanned region
        regionalClient -- callable(serviceName, region) -> boto3 client; used
                          for the logs/cloudwatch clients of a trail's log
                          group, which may live in another region
        """
        super().__init__()
        self.region = ctx.get('region')
        self.account = ctx.get('account')
        self.eventsClient = eventsClient
        self.ctClient = ctClient
        self.regionalClient = regionalClient
        self._resourceName = 'Account'
        self.errors = []

    # ------------------------------------------------------------------ #
    # Check
    # ------------------------------------------------------------------ #
    def _checkSecretChangeNotMonitored(self):
        self.errors = []
        covered = {e: [] for e in self.REQUIRED_EVENTS}

        for source in (self._eventBridgeCoverage, self._metricFilterCoverage):
            try:
                found = source()
            except botocore.exceptions.BotoCoreError as e:
                self.errors.append(type(e).__name__)
                continue
            for label, events in found:
                for e in events:
                    covered[e].append(label)

        missing = [e for e in self.REQUIRED_EVENTS if not covered[e]]
        if not missing:
            parts = [f"{e}: {', '.join(sorted(set(v)))}" for e, v in covered.items()]
            self.results['secretChangeNotMonitored'] = [1, '; '.join(parts)]
            return

        if self.errors:
            self.results['secretChangeNotMonitored'] = [
                0, f"Unable to evaluate ({', '.join(sorted(set(self.errors)))})"
            ]
            return

        have = [e for e in self.REQUIRED_EVENTS if covered[e]]
        msg = (f"No EventBridge rule with a target, and no alarmed CloudTrail metric "
               f"filter, alerts on Secrets Manager {', '.join(missing)} in {self.region}")
        if have:
            msg += f" (only {', '.join(have)} is covered)"
        self.results['secretChangeNotMonitored'] = [-1, msg]

    # ------------------------------------------------------------------ #
    # EventBridge
    # ------------------------------------------------------------------ #
    def _eventBridgeCoverage(self):
        out = []
        try:
            rules = []
            for page in self.eventsClient.get_paginator('list_rules').paginate():
                rules.extend(page.get('Rules', []) or [])
        except botocore.exceptions.ClientError as e:
            self.errors.append(self._code(e))
            return out

        for rule in rules:
            state = rule.get('State') or ''
            if not state.startswith('ENABLED'):
                continue
            if rule.get('ManagedBy'):
                continue
            raw = rule.get('EventPattern')
            if not raw:
                continue  # scheduled rule
            try:
                pattern = json.loads(raw)
            except (TypeError, ValueError):
                continue
            events = [e for e in self.REQUIRED_EVENTS
                      if self.eventPatternMatches(pattern, self._sampleEvent(e))]
            if not events:
                continue
            if not self._ruleHasTargets(rule.get('Name'), rule.get('EventBusName')):
                continue
            out.append((f"EventBridge rule {rule.get('Name')}", events))
        return out

    def _ruleHasTargets(self, name, bus):
        try:
            kwargs = {'Rule': name}
            if bus:
                kwargs['EventBusName'] = bus
            for page in self.eventsClient.get_paginator('list_targets_by_rule').paginate(**kwargs):
                if page.get('Targets'):
                    return True
        except botocore.exceptions.ClientError as e:
            self.errors.append(self._code(e))
        return False

    def _sampleEvent(self, eventName):
        return {
            'version': '0',
            'source': self.SOURCE,
            'detail-type': self.DETAIL_TYPE,
            'account': self.account,
            'region': self.region,
            'detail': {
                'eventSource': self.EVENT_SOURCE,
                'eventName': eventName,
                'eventType': 'AwsApiCall',
                'awsRegion': self.region,
                'readOnly': False,
                'managementEvent': True,
                'eventCategory': 'Management',
            },
        }

    @classmethod
    def eventPatternMatches(cls, pattern, event):
        """Minimal EventBridge pattern matcher. Fields the pattern constrains
        that are absent from the sample event cause a non-match (unless the
        constraint is {"exists": false}), which keeps the check conservative."""
        if not isinstance(pattern, dict):
            return False
        for key, cond in pattern.items():
            if key == '$or':
                if not isinstance(cond, list) or not any(
                        cls.eventPatternMatches(sub, event) for sub in cond):
                    return False
                continue
            present = isinstance(event, dict) and key in event
            value = event.get(key) if present else None
            if isinstance(cond, dict):
                if not present or not isinstance(value, dict):
                    if not cls._allExistsFalse(cond):
                        return False
                    continue
                if not cls.eventPatternMatches(cond, value):
                    return False
            elif isinstance(cond, list):
                if not any(cls._matchElement(c, present, value) for c in cond):
                    return False
            else:
                return False
        return True

    @classmethod
    def _allExistsFalse(cls, cond):
        for v in cond.values():
            if isinstance(v, dict):
                if not cls._allExistsFalse(v):
                    return False
            elif isinstance(v, list):
                if not any(isinstance(x, dict) and x.get('exists') is False for x in v):
                    return False
            else:
                return False
        return True

    @classmethod
    def _matchElement(cls, cond, present, value):
        if isinstance(cond, dict):
            if 'exists' in cond:
                return bool(cond['exists']) == present
            if not present:
                return False
            if isinstance(value, list):
                return any(cls._matchOp(cond, v) for v in value)
            return cls._matchOp(cond, value)
        if not present:
            return False
        if isinstance(value, list):
            return cond in value
        return cond == value

    @classmethod
    def _matchOp(cls, cond, value):
        if 'prefix' in cond:
            p = cond['prefix']
            if isinstance(p, dict) and 'equals-ignore-case' in p:
                return isinstance(value, str) and value.lower().startswith(str(p['equals-ignore-case']).lower())
            return isinstance(value, str) and isinstance(p, str) and value.startswith(p)
        if 'suffix' in cond:
            s = cond['suffix']
            if isinstance(s, dict) and 'equals-ignore-case' in s:
                return isinstance(value, str) and value.lower().endswith(str(s['equals-ignore-case']).lower())
            return isinstance(value, str) and isinstance(s, str) and value.endswith(s)
        if 'equals-ignore-case' in cond:
            return isinstance(value, str) and value.lower() == str(cond['equals-ignore-case']).lower()
        if 'wildcard' in cond:
            return isinstance(value, str) and fnmatch.fnmatchcase(value, str(cond['wildcard']))
        if 'anything-but' in cond:
            ab = cond['anything-but']
            if isinstance(ab, dict):
                return not cls._matchOp(ab, value)
            if isinstance(ab, list):
                return value not in ab
            return value != ab
        # numeric, cidr and unknown operators cannot match our string fields
        return False

    # ------------------------------------------------------------------ #
    # CloudTrail -> CloudWatch Logs metric filters -> alarms
    # ------------------------------------------------------------------ #
    def _metricFilterCoverage(self):
        out = []
        try:
            trails = self.ctClient.describe_trails(includeShadowTrails=True).get('trailList', []) or []
        except botocore.exceptions.ClientError as e:
            self.errors.append(self._code(e))
            return out

        seen = set()
        for trail in trails:
            lgArn = trail.get('CloudWatchLogsLogGroupArn')
            if not lgArn:
                continue
            if not trail.get('IsMultiRegionTrail') and trail.get('HomeRegion') not in (None, self.region):
                continue
            if not self._trailIsLogging(trail):
                continue
            lgRegion, lgName = self._parseLogGroupArn(lgArn)
            if not lgName or (lgRegion, lgName) in seen:
                continue
            seen.add((lgRegion, lgName))

            filters = self._metricFilters(lgRegion or self.region, lgName)
            if not filters:
                continue
            alarmed = None
            for f in filters:
                events = [e for e in self.REQUIRED_EVENTS
                          if self.filterPatternMatches(f.get('filterPattern') or '', e)]
                if not events:
                    continue
                if alarmed is None:
                    alarmed = self._alertingMetrics(lgRegion or self.region)
                for mt in f.get('metricTransformations', []) or []:
                    if (mt.get('metricNamespace'), mt.get('metricName')) in alarmed:
                        out.append((f"metric filter {f.get('filterName')} on {lgName}", events))
                        break
        return out

    def _trailIsLogging(self, trail):
        try:
            resp = self.ctClient.get_trail_status(Name=trail.get('TrailARN') or trail.get('Name'))
            return resp.get('IsLogging', True) is not False
        except botocore.exceptions.ClientError:
            # Shadow / organization trails may not be readable from here; do
            # not discard them on that basis alone.
            return True

    @staticmethod
    def _parseLogGroupArn(arn):
        # arn:aws:logs:<region>:<account>:log-group:<name>[:*]
        parts = arn.split(':')
        if len(parts) < 7 or parts[5] != 'log-group':
            return None, None
        name = ':'.join(parts[6:])
        if name.endswith(':*'):
            name = name[:-2]
        return parts[3] or None, name

    def _metricFilters(self, region, logGroupName):
        filters = []
        try:
            client = self.regionalClient('logs', region)
            for page in client.get_paginator('describe_metric_filters').paginate(logGroupName=logGroupName):
                filters.extend(page.get('metricFilters', []) or [])
        except botocore.exceptions.ClientError as e:
            self.errors.append(self._code(e))
        return filters

    def _alertingMetrics(self, region):
        """Set of (namespace, metricName) watched by an alarm that notifies."""
        metricAlarms, composites = [], []
        try:
            client = self.regionalClient('cloudwatch', region)
            for page in client.get_paginator('describe_alarms').paginate(
                    AlarmTypes=['MetricAlarm', 'CompositeAlarm']):
                metricAlarms.extend(page.get('MetricAlarms', []) or [])
                composites.extend(page.get('CompositeAlarms', []) or [])
        except botocore.exceptions.ClientError as e:
            self.errors.append(self._code(e))
            return set()

        def notifies(a):
            return a.get('ActionsEnabled', True) and bool(a.get('AlarmActions'))

        compositeRules = [c.get('AlarmRule') or '' for c in composites if notifies(c)]

        out = set()
        for a in metricAlarms:
            name = a.get('AlarmName') or ''
            arn = a.get('AlarmArn') or ''
            viaComposite = any(
                re.search(r'\(\s*"?' + re.escape(n) + r'"?\s*\)', rule)
                for rule in compositeRules for n in (name, arn) if n
            )
            if not (notifies(a) or viaComposite):
                continue
            if a.get('MetricName'):
                out.add((a.get('Namespace'), a.get('MetricName')))
            for m in a.get('Metrics', []) or []:
                metric = (m.get('MetricStat') or {}).get('Metric') or {}
                if metric.get('MetricName'):
                    out.add((metric.get('Namespace'), metric.get('MetricName')))
        return out

    # Matches `$.field = value`, `$.field != value` (value optionally quoted).
    _TERM_RE = re.compile(r'\$\.([A-Za-z0-9_.\[\]]+)\s*(!=|=)\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s)&|]+))')
    _SELECTOR_RE = re.compile(r'\$\.([A-Za-z0-9_]+)')

    @classmethod
    def filterPatternMatches(cls, pattern, eventName):
        """Heuristic: does a CloudWatch Logs filter pattern applied to CloudTrail
        logs match the Secrets Manager `eventName` call?"""
        pattern = (pattern or '').strip()
        if not pattern:
            return False
        if not pattern.startswith('{'):
            # Term-based pattern, e.g. "DeleteSecret" or ?DeleteSecret ?PutResourcePolicy
            if '-' + eventName in pattern:
                return False
            return re.search(r'(?<![A-Za-z0-9])' + re.escape(eventName) + r'(?![A-Za-z0-9])', pattern) is not None

        # Any selector beyond the neutral ones narrows coverage -> not counted.
        for field in cls._SELECTOR_RE.findall(pattern):
            if field not in cls.NEUTRAL_FILTER_FIELDS:
                return False

        nameEq, nameNe, srcEq, srcNe = [], [], [], []
        for field, op, v1, v2, v3 in cls._TERM_RE.findall(pattern):
            value = v1 or v2 or v3
            if field == 'eventName':
                (nameEq if op == '=' else nameNe).append(value)
            elif field == 'eventSource':
                (srcEq if op == '=' else srcNe).append(value)

        def m(val, pats):
            return any(fnmatch.fnmatchcase(val, p) for p in pats)

        if srcEq and not m(cls.EVENT_SOURCE, srcEq):
            return False
        if srcNe and m(cls.EVENT_SOURCE, srcNe):
            return False
        if nameNe and m(eventName, nameNe):
            return False
        if nameEq:
            return m(eventName, nameEq)
        # No eventName equality: only counts when scoped to the Secrets Manager source.
        return bool(srcEq)

    @staticmethod
    def _code(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

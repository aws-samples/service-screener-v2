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
      Only trails that are logging, record write management events (event
      selectors) and deliver to a log group in the scanned account count; a
      trail log group in another account (e.g. an organization trail) cannot
      be evaluated from here and yields "Unable to evaluate" unless another
      path already covers both calls.
      Read-only APIs: events.list_rules, events.list_targets_by_rule,
      cloudtrail.describe_trails, cloudtrail.get_trail_status,
      cloudtrail.get_event_selectors, logs.describe_metric_filters,
      cloudwatch.describe_alarms.

      Precision note: alerting may also live in a SIEM or third-party tool,
      which this check cannot see, so it is reported with Low criticality.
      Pattern matching is conservative: a pattern that additionally narrows on
      fields other than the event source/name (for example one specific secret
      or principal, or failed calls only) is not counted as covering the call.
    """

    REQUIRED_EVENTS = ('DeleteSecret', 'PutResourcePolicy')
    EVENT_SOURCE = 'secretsmanager.amazonaws.com'
    SOURCE = 'aws.secretsmanager'
    DETAIL_TYPE = 'AWS API Call via CloudTrail'

    DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnauthorizedOperation', 'UnrecognizedClientException',
    )

    # CloudTrail record fields that are always present on a real API-call
    # event, and fields that are absent on a successful call. Used so that
    # {"exists": ...} conditions are judged against a real event, not just the
    # minimal sample built below.
    ALWAYS_PRESENT_FIELDS = {
        'id', 'time', 'resources', 'userIdentity', 'eventTime', 'eventID',
        'requestID', 'sourceIPAddress', 'userAgent', 'recipientAccountId',
        'eventVersion',
    }
    KNOWN_ABSENT_FIELDS = {'errorCode', 'errorMessage'}

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
        that are absent from the sample event cause a non-match, except
        {"exists": ...} on fields known to be always present (userIdentity,
        ...) or known to be absent on a successful call (errorCode), which
        keeps the check conservative."""
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
                # Nested condition on a field the sample does not model: its
                # value in a real event is unknown, so do not count it.
                if not present or not isinstance(value, dict):
                    return False
                if not cls.eventPatternMatches(cond, value):
                    return False
            elif isinstance(cond, list):
                if not any(cls._matchElement(c, key, present, value) for c in cond):
                    return False
            else:
                return False
        return True

    @classmethod
    def _matchElement(cls, cond, key, present, value):
        if isinstance(cond, dict):
            if 'exists' in cond:
                if present or key in cls.ALWAYS_PRESENT_FIELDS:
                    return cond['exists'] is True
                if key in cls.KNOWN_ABSENT_FIELDS:
                    return cond['exists'] is False
                return False  # unknown whether a real event has this field
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
            lgRegion, lgAccount, lgName = self._parseLogGroupArn(lgArn)
            if not lgName:
                continue
            if self.account and lgAccount and lgAccount != self.account:
                # e.g. an organization trail delivering to a log group in the
                # management account: its metric filters and alarms cannot be
                # read from here, and a same-named local log group is not it.
                self.errors.append('TrailLogGroupInOtherAccount')
                continue
            if (lgRegion, lgName) in seen:
                continue
            ctClient = self._trailClient(trail)
            if not self._trailIsLogging(trail, ctClient):
                continue
            if not self._trailLogsWriteManagementEvents(trail, ctClient):
                continue
            seen.add((lgRegion, lgName))

            filters = self._metricFilters(lgRegion or self.region, lgName)
            if not filters:
                continue
            alarmed = None
            for f in filters:
                events = [e for e in self.REQUIRED_EVENTS
                          if self.filterPatternMatches(f.get('filterPattern') or '', e,
                                                       region=self.region, account=self.account)]
                if not events:
                    continue
                if alarmed is None:
                    alarmed = self._alertingMetrics(lgRegion or self.region)
                for mt in f.get('metricTransformations', []) or []:
                    if (mt.get('metricNamespace'), mt.get('metricName')) in alarmed:
                        out.append((f"metric filter {f.get('filterName')} on {lgName}", events))
                        break
        return out

    def _trailClient(self, trail):
        """CloudTrail client for the trail's home region (shadow trails of a
        multi-region trail are managed from their home region)."""
        home = trail.get('HomeRegion')
        if home and home != self.region and self.regionalClient:
            return self.regionalClient('cloudtrail', home)
        return self.ctClient

    def _trailIsLogging(self, trail, client):
        try:
            resp = client.get_trail_status(Name=trail.get('TrailARN') or trail.get('Name'))
            return resp.get('IsLogging') is True
        except botocore.exceptions.ClientError as e:
            # Unknown logging state: do not count it as coverage.
            self.errors.append(self._code(e))
            return False

    def _trailLogsWriteManagementEvents(self, trail, client):
        """True when the trail records write management events from Secrets
        Manager (DeleteSecret / PutResourcePolicy are write management events)."""
        try:
            resp = client.get_event_selectors(TrailName=trail.get('TrailARN') or trail.get('Name'))
        except botocore.exceptions.ClientError as e:
            self.errors.append(self._code(e))
            return False
        basic = resp.get('EventSelectors')
        advanced = resp.get('AdvancedEventSelectors')
        if not basic and not advanced:
            # No selectors configured: CloudTrail logs all management events.
            return True
        for sel in basic or []:
            if sel.get('IncludeManagementEvents', True) is False:
                continue
            if sel.get('ReadWriteType', 'All') not in ('All', 'WriteOnly'):
                continue
            if self.EVENT_SOURCE in (sel.get('ExcludeManagementEventSources') or []):
                continue
            return True
        for sel in advanced or []:
            if self._advancedSelectorCovers(sel.get('FieldSelectors') or []):
                return True
        return False

    def _advancedSelectorCovers(self, fieldSelectors):
        values = {'eventCategory': 'Management', 'readOnly': 'false', 'eventSource': self.EVENT_SOURCE}
        hasCategory = False
        for fs in fieldSelectors:
            field = fs.get('Field')
            if field not in values:
                return False  # unknown field narrows the selector
            v = values[field]
            if field == 'eventCategory':
                hasCategory = True
            if 'Equals' in fs and v not in (fs.get('Equals') or []):
                return False
            if 'StartsWith' in fs and not any(v.startswith(x) for x in fs.get('StartsWith') or []):
                return False
            if 'EndsWith' in fs and not any(v.endswith(x) for x in fs.get('EndsWith') or []):
                return False
            if v in (fs.get('NotEquals') or []):
                return False
            if any(v.startswith(x) for x in fs.get('NotStartsWith') or []):
                return False
            if any(v.endswith(x) for x in fs.get('NotEndsWith') or []):
                return False
        return hasCategory

    @staticmethod
    def _parseLogGroupArn(arn):
        # arn:aws:logs:<region>:<account>:log-group:<name>[:*]
        parts = arn.split(':')
        if len(parts) < 7 or parts[5] != 'log-group':
            return None, None, None
        name = ':'.join(parts[6:])
        if name.endswith(':*'):
            name = name[:-2]
        return parts[3] or None, parts[4] or None, name

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

    # ------------------------------------------------------------------ #
    # CloudWatch Logs filter pattern evaluation
    # ------------------------------------------------------------------ #
    # Tokens of a JSON filter pattern body.
    _JSON_TOKEN_RE = re.compile(r'''
        \s*(?:
          (?P<lp>\() | (?P<rp>\)) | (?P<and>&&) | (?P<or>\|\|)
        | (?P<sel>\$\.[A-Za-z0-9_.\[\]\-]+)
        | (?P<op>!=|<=|>=|=|<|>)
        | (?P<str>"(?:[^"\\]|\\.)*")
        | (?P<re>%(?:[^%\\]|\\.)*%)
        | (?P<word>[^\s()&|{}"=!<>]+)
        )''', re.X)

    _UNKNOWN = object()   # field value not known for a real CloudTrail event
    _ABSENT = object()    # field known to be absent (successful call)

    class _ParseError(Exception):
        pass

    @classmethod
    def _sampleRecord(cls, eventName, region=None, account=None):
        rec = {
            'eventSource': cls.EVENT_SOURCE,
            'eventName': eventName,
            'eventType': 'AwsApiCall',
            'eventCategory': 'Management',
            'readOnly': False,
            'managementEvent': True,
            # A successful call carries no error fields; alerting only on
            # failures does not cover the change itself.
            'errorCode': cls._ABSENT,
            'errorMessage': cls._ABSENT,
        }
        if region:
            rec['awsRegion'] = region
        if account:
            rec['recipientAccountId'] = account
        return rec

    @classmethod
    def filterPatternMatches(cls, pattern, eventName, region=None, account=None):
        """Does a CloudWatch Logs filter pattern applied to CloudTrail logs
        match every successful Secrets Manager `eventName` call?

        JSON patterns are parsed and evaluated with three-valued logic against
        a sample CloudTrail record: comparisons on fields whose value differs
        between calls (principal, secret id, source IP ...) are "unknown", and
        the pattern only counts when it is definitely true. Term patterns only
        count as a single term, or an OR (?term) list, naming the event."""
        pattern = (pattern or '').strip()
        if not pattern:
            return False
        if pattern.startswith('{'):
            if not pattern.endswith('}'):
                return False
            try:
                tokens = cls._tokenizeJson(pattern[1:-1])
                expr, pos = cls._parseOr(tokens, 0)
                if pos != len(tokens):
                    raise cls._ParseError('trailing tokens')
            except cls._ParseError:
                return False
            return cls._evalExpr(expr, cls._sampleRecord(eventName, region, account)) is True
        if pattern.startswith('['):
            return False  # space-delimited patterns do not apply to CloudTrail JSON
        return cls._termPatternMatches(pattern, eventName)

    @classmethod
    def _termPatternMatches(cls, pattern, eventName):
        terms = re.findall(r'[?-]?"(?:[^"\\]|\\.)*"|\S+', pattern)

        def unq(t):
            return t[1:-1] if len(t) >= 2 and t[0] == '"' and t[-1] == '"' else t

        if len(terms) == 1 and terms[0][:1] not in ('?', '-'):
            return unq(terms[0]) == eventName
        # Space-separated terms are ANDed; only a pure OR list is broad enough.
        if all(t.startswith('?') for t in terms):
            return any(unq(t[1:]) == eventName for t in terms)
        return False

    @classmethod
    def _tokenizeJson(cls, body):
        tokens, pos = [], 0
        while pos < len(body):
            if body[pos:].strip() == '':
                break
            m = cls._JSON_TOKEN_RE.match(body, pos)
            if not m or m.end() == pos:
                raise cls._ParseError(body[pos:])
            kind = m.lastgroup
            tokens.append((kind, m.group(kind)))
            pos = m.end()
        return tokens

    @classmethod
    def _parseOr(cls, toks, i):
        left, i = cls._parseAnd(toks, i)
        node = [left]
        while i < len(toks) and toks[i][0] == 'or':
            right, i = cls._parseAnd(toks, i + 1)
            node.append(right)
        return (node[0] if len(node) == 1 else ('or', node)), i

    @classmethod
    def _parseAnd(cls, toks, i):
        left, i = cls._parsePrimary(toks, i)
        node = [left]
        while i < len(toks) and toks[i][0] == 'and':
            right, i = cls._parsePrimary(toks, i + 1)
            node.append(right)
        return (node[0] if len(node) == 1 else ('and', node)), i

    @classmethod
    def _parsePrimary(cls, toks, i):
        if i >= len(toks):
            raise cls._ParseError('unexpected end')
        kind, val = toks[i]
        if kind == 'lp':
            expr, i = cls._parseOr(toks, i + 1)
            if i >= len(toks) or toks[i][0] != 'rp':
                raise cls._ParseError('missing )')
            return expr, i + 1
        if kind != 'sel':
            raise cls._ParseError(val)
        field = val[2:]
        i += 1
        if i >= len(toks):
            raise cls._ParseError('missing operator')
        kind, val = toks[i]
        if kind == 'op':
            if i + 1 >= len(toks) or toks[i + 1][0] not in ('str', 're', 'word'):
                raise cls._ParseError('missing value')
            vkind, vval = toks[i + 1]
            if vkind == 'str':
                vval = re.sub(r'\\(.)', r'\1', vval[1:-1])
            elif vkind == 're':
                vval = vval[1:-1]
            return ('cmp', field, val, vkind, vval), i + 2
        if kind == 'word':
            kw = val.upper()
            nxt = toks[i + 1][1].upper() if i + 1 < len(toks) and toks[i + 1][0] == 'word' else None
            if kw == 'IS' and nxt in ('TRUE', 'FALSE', 'NULL'):
                return ('is', field, nxt), i + 2
            if kw == 'NOT' and nxt == 'EXISTS':
                return ('exists', field, False), i + 2
            if kw == 'EXISTS':
                return ('exists', field, True), i + 1
        raise cls._ParseError(val)

    @classmethod
    def _evalExpr(cls, node, rec):
        """Kleene three-valued evaluation: True, False or None (unknown)."""
        kind = node[0]
        if kind in ('and', 'or'):
            vals = [cls._evalExpr(n, rec) for n in node[1]]
            if kind == 'and':
                if any(v is False for v in vals):
                    return False
                return True if all(v is True for v in vals) else None
            if any(v is True for v in vals):
                return True
            return False if all(v is False for v in vals) else None

        field = node[1]
        value = rec.get(field, cls._UNKNOWN)
        if value is cls._UNKNOWN:
            return None
        if kind == 'exists':
            return (value is not cls._ABSENT) == node[2]
        if kind == 'is':
            if value is cls._ABSENT:
                return False
            if node[2] == 'NULL':
                return False
            return value is (node[2] == 'TRUE')

        _, _, op, vkind, target = node
        if value is cls._ABSENT:
            return False if op == '=' else None
        if op in ('<', '>', '<=', '>='):
            # Numeric comparison against a string/boolean field never matches.
            return False if not isinstance(value, (int, float)) or isinstance(value, bool) else None
        sval = str(value).lower() if isinstance(value, bool) else str(value)
        if vkind == 're':
            try:
                eq = re.search(target, sval) is not None
            except re.error:
                return None
        else:
            rx = '^' + '.*'.join(re.escape(p) for p in target.split('*')) + '$'
            eq = re.match(rx, sval) is not None
        return eq if op == '=' else not eq

    @staticmethod
    def _code(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

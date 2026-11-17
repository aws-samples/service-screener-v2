"""
Account / region level CloudWatch security posture checks (WAFS2027).

One instance runs per region. Every check reads configuration only
(describe/get/list APIs). When the data needed for a verdict cannot be read
the check records [0, 'Unable to evaluate (<code>)'] instead of passing.
"""
import fnmatch
import json
import re
import threading

import botocore

from services.Evaluator import Evaluator
from utils.Config import Config
from utils.PolicyPrincipal import iterStatements, statementIsPublic


def _errCode(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return e.response.get('Error', {}).get('Code', 'ClientError')
    return type(e).__name__


def _logGroupNameFromArn(arn):
    """arn:aws:logs:<region>:<acct>:log-group:<name>[:*] -> (region, acct, name)."""
    if not arn or not isinstance(arn, str):
        return None
    parts = arn.split(':')
    if len(parts) < 7 or parts[2] != 'logs' or parts[5] != 'log-group':
        return None
    return parts[3], parts[4], parts[6]


# ---------------------------------------------------------------------------
# Minimal EventBridge event-pattern matcher, used to decide whether a rule
# would fire for a given CloudTrail management event. Unknown matcher types
# are treated as NOT matching so a rule is never credited for coverage it may
# not provide.
# ---------------------------------------------------------------------------
def _matchValue(matcher, value, present):
    if isinstance(matcher, dict):
        if 'exists' in matcher:
            return bool(matcher['exists']) == present
        if not present or isinstance(value, (dict, list)):
            return False
        sval = str(value)
        if 'prefix' in matcher:
            p = matcher['prefix']
            if isinstance(p, dict) and 'equals-ignore-case' in p:
                return sval.lower().startswith(str(p['equals-ignore-case']).lower())
            return isinstance(p, str) and sval.startswith(p)
        if 'suffix' in matcher:
            p = matcher['suffix']
            if isinstance(p, dict) and 'equals-ignore-case' in p:
                return sval.lower().endswith(str(p['equals-ignore-case']).lower())
            return isinstance(p, str) and sval.endswith(p)
        if 'equals-ignore-case' in matcher:
            return sval.lower() == str(matcher['equals-ignore-case']).lower()
        if 'wildcard' in matcher:
            return isinstance(matcher['wildcard'], str) and fnmatch.fnmatchcase(sval, matcher['wildcard'])
        if 'anything-but' in matcher:
            ab = matcher['anything-but']
            if isinstance(ab, dict):
                if 'prefix' in ab:
                    return not sval.startswith(str(ab['prefix']))
                if 'suffix' in ab:
                    return not sval.endswith(str(ab['suffix']))
                return False
            excluded = ab if isinstance(ab, list) else [ab]
            return sval not in [str(x) for x in excluded]
        return False
    if not present:
        return False
    return matcher == value


def eventPatternMatches(pattern, event):
    if not isinstance(pattern, dict):
        return False
    for key, spec in pattern.items():
        if key == '$or':
            if not isinstance(spec, list) or not any(eventPatternMatches(p, event) for p in spec):
                return False
            continue
        present = isinstance(event, dict) and key in event
        value = event.get(key) if present else None
        if isinstance(spec, dict):
            if not present or not isinstance(value, dict):
                return False
            if not eventPatternMatches(spec, value):
                return False
        elif isinstance(spec, list):
            if not any(_matchValue(m, value, present) for m in spec):
                return False
        else:
            return False
    return True


class CloudwatchAccount(Evaluator):
    ## Services whose disablement should raise an alert. Disabling CloudTrail
    ## and AWS Config is already covered by trailWOMATrail5 / trailWOMAConfig9.
    DETECTION_SERVICES = {
        'GuardDuty': {'source': 'aws.guardduty', 'eventSource': 'guardduty.amazonaws.com',
                      'eventName': 'DeleteDetector'},
        'Security Hub': {'source': 'aws.securityhub', 'eventSource': 'securityhub.amazonaws.com',
                         'eventName': 'DisableSecurityHub'},
        'IAM Access Analyzer': {'source': 'aws.access-analyzer', 'eventSource': 'access-analyzer.amazonaws.com',
                                'eventName': 'DeleteAnalyzer'},
    }

    ## Namespaces of AWS-vended metrics that are security signals.
    SECURITY_NAMESPACES = ('AWS/WAFV2', 'AWS/NetworkFirewall', 'AWS/DDoSProtection')

    ACTIVE_ANOMALY_STATES = ('INITIALIZING', 'TRAINING', 'ANALYZING')

    ## Replication lag / latency metrics that indicate data is being replicated
    ## to another copy (read replica, global database/table, S3 replication).
    ## Intra-cluster reader lag (AuroraReplicaLag, ElastiCache ReplicationLag)
    ## is deliberately excluded: it is not a recovery-point signal.
    REPLICATION_LAG_METRICS = (
        ('AWS/RDS', 'ReplicaLag'),
        ('AWS/RDS', 'AuroraGlobalDBReplicationLag'),
        ('AWS/RDS', 'AuroraBinlogReplicaLag'),
        ('AWS/DynamoDB', 'ReplicationLatency'),
        ('AWS/S3', 'ReplicationLatency'),
        ('AWS/ElastiCache', 'GlobalDatastoreReplicationLag'),
    )

    def __init__(self, region, clientFn, ctLogs, logGroups, alarms, compositeAlarms=None):
        super().__init__()
        self.init()

        self.region = region
        self._clientFn = clientFn
        self._clients = {}
        self.ctLogs = ctLogs or []
        self.logGroups = logGroups or []
        self.alarms = alarms or []
        self.compositeAlarms = compositeAlarms or []
        self.accountId = (Config.get('stsInfo', {}) or {}).get('Account')

        self._lock = threading.RLock()
        self._cache = {}

        self._resourceName = f'Account::{region}'
        return

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _client(self, name, region=None):
        region = region or self.region
        with self._lock:
            if (name, region) not in self._clients:
                self._clients[(name, region)] = self._clientFn(name, region)
            return self._clients[(name, region)]

    def _cached(self, key, fn):
        with self._lock:
            if key not in self._cache:
                try:
                    self._cache[key] = (fn(), None)
                except Exception as e:
                    self._cache[key] = (None, _errCode(e))
            return self._cache[key]

    def _paginate(self, service, op, key, **kwargs):
        out = []
        pager = self._client(service).get_paginator(op)
        for page in pager.paginate(**kwargs):
            out.extend(page.get(key, []) or [])
        return out

    def _logGroupMap(self):
        return {lg['logGroupName']: lg for lg in self.logGroups if lg.get('logGroupName')}

    def _orgInfo(self):
        """(inOrg, managementAccountId). inOrg is None when unreadable."""
        def load():
            try:
                org = self._client('organizations').describe_organization().get('Organization', {})
                return True, org.get('MasterAccountId')
            except botocore.exceptions.ClientError as e:
                if _errCode(e) == 'AWSOrganizationsNotInUseException':
                    return False, None
                return None, None
        val, err = self._cached('org', load)
        return val if val else (None, None)

    def _trailLogGroups(self):
        """Names of CloudTrail log groups in this region (that exist)."""
        lgMap = self._logGroupMap()
        names = set()
        for log in self.ctLogs:
            parsed = _logGroupNameFromArn(log[1]) if len(log) > 1 else None
            if not parsed:
                continue
            region, acct, name = parsed
            if region == self.region and name in lgMap:
                names.add(name)
        return names

    def _flowLogGroups(self):
        def load():
            names = set()
            for fl in self._paginate('ec2', 'describe_flow_logs', 'FlowLogs'):
                if fl.get('LogDestinationType', 'cloud-watch-logs') != 'cloud-watch-logs':
                    continue
                name = fl.get('LogGroupName')
                parsed = _logGroupNameFromArn(fl.get('LogDestination'))
                if parsed:
                    region, acct, pname = parsed
                    if region != self.region or (self.accountId and acct != self.accountId):
                        continue
                    name = name or pname
                if name:
                    names.add(name)
            return names
        return self._cached('flowLogGroups', load)

    def _resolverLogGroups(self):
        def load():
            names = set()
            for cfg in self._paginate('route53resolver', 'list_resolver_query_log_configs', 'ResolverQueryLogConfigs'):
                parsed = _logGroupNameFromArn(cfg.get('DestinationArn'))
                if not parsed:
                    continue
                region, acct, name = parsed
                if region == self.region and (not self.accountId or acct == self.accountId):
                    names.add(name)
            return names
        return self._cached('resolverLogGroups', load)

    def _metricFilters(self, logGroupName):
        def load():
            return self._paginate('logs', 'describe_metric_filters', 'metricFilters', logGroupName=logGroupName)
        return self._cached('mf::' + logGroupName, load)

    def _alarmMetrics(self, alarm):
        """(namespace, metricName) pairs an alarm evaluates."""
        out = set()
        if alarm.get('MetricName'):
            out.add((alarm.get('Namespace'), alarm.get('MetricName')))
        for m in alarm.get('Metrics', []) or []:
            metric = (m.get('MetricStat') or {}).get('Metric') or {}
            if metric.get('MetricName'):
                out.add((metric.get('Namespace'), metric.get('MetricName')))
        return out

    # ------------------------------------------------------------------ #
    # checks
    # ------------------------------------------------------------------ #
    def _checkCrossAccountObservability(self):
        key = 'cwCrossAccountObservabilityNotLinked'
        inOrg, _ = self._orgInfo()
        if inOrg is False:
            self.results[key] = [0, 'Not applicable: account is not part of AWS Organizations']
            return
        try:
            links = self._paginate('oam', 'list_links', 'Items')
            sinks = self._paginate('oam', 'list_sinks', 'Items')
        except Exception as e:
            self.results[key] = [0, f'Unable to evaluate ({_errCode(e)})']
            return

        if links:
            sinkArns = sorted({l.get('SinkArn', '') for l in links if l.get('SinkArn')})
            self.results[key] = [1, f'{len(links)} OAM link(s) to monitoring account sink(s): {", ".join(sinkArns)}']
        elif sinks:
            self.results[key] = [1, f'Monitoring account: {len(sinks)} OAM sink(s) configured']
        else:
            self.results[key] = [-1, f'No CloudWatch cross-account observability link or sink in {self.region}']

    def _checkAuditLogGroupEncryption(self):
        key = 'cwLogGroupNotKmsEncrypted'
        lgMap = self._logGroupMap()
        sources = {}
        errors = []

        for name in self._trailLogGroups():
            sources.setdefault(name, set()).add('CloudTrail')

        for label, (names, err) in (('VPC Flow Logs', self._flowLogGroups()),
                                    ('Route 53 Resolver query logs', self._resolverLogGroups())):
            if err:
                errors.append(f'{label}: {err}')
                continue
            for name in names:
                if name in lgMap:
                    sources.setdefault(name, set()).add(label)

        failing = [f"{n} ({', '.join(sorted(s))})" for n, s in sorted(sources.items())
                   if not lgMap[n].get('kmsKeyId')]
        if failing:
            self.results[key] = [-1, f'{len(failing)} audit log group(s) without a customer managed KMS key: '
                                     + '; '.join(failing)]
        elif errors:
            self.results[key] = [0, f'Unable to evaluate ({"; ".join(errors)})']
        elif not sources:
            self.results[key] = [0, 'No CloudTrail, VPC Flow Logs or Route 53 Resolver query log groups in this region']
        else:
            self.results[key] = [1, f'{len(sources)} audit log group(s) encrypted with a customer managed KMS key']

    def _checkDataProtectionPolicy(self):
        key = 'cwLogsNoDataProtectionPolicy'
        activated = [lg['logGroupName'] for lg in self.logGroups
                     if lg.get('dataProtectionStatus') == 'ACTIVATED']
        policies = []
        err = None
        try:
            args = {'policyType': 'DATA_PROTECTION_POLICY'}
            while True:
                resp = self._client('logs').describe_account_policies(**args)
                policies.extend(resp.get('accountPolicies', []) or [])
                token = resp.get('nextToken')
                if not token:
                    break
                args['nextToken'] = token
        except Exception as e:
            err = _errCode(e)

        if policies:
            self.results[key] = [1, f'Account-level data protection policy in place ({policies[0].get("policyName", "")})']
        elif activated:
            self.results[key] = [1, f'{len(activated)} of {len(self.logGroups)} log group(s) have an active data protection policy']
        elif err:
            self.results[key] = [0, f'Unable to evaluate ({err})']
        elif not self.logGroups:
            self.results[key] = [0, 'No log groups in this region']
        else:
            self.results[key] = [-1, f'No account-level data protection policy and none of {len(self.logGroups)} log group(s) has one']

    def _detectionActiveServices(self):
        """{service: True|False|None(unknown)}"""
        state = {}
        try:
            state['GuardDuty'] = bool(self._paginate('guardduty', 'list_detectors', 'DetectorIds'))
        except Exception:
            state['GuardDuty'] = None
        try:
            self._client('securityhub').describe_hub()
            state['Security Hub'] = True
        except botocore.exceptions.ClientError as e:
            state['Security Hub'] = False if _errCode(e) in ('InvalidAccessException', 'ResourceNotFoundException') else None
        except Exception:
            state['Security Hub'] = None
        try:
            state['IAM Access Analyzer'] = bool(self._paginate('accessanalyzer', 'list_analyzers', 'analyzers'))
        except Exception:
            state['IAM Access Analyzer'] = None
        return state

    def _eventRuleCoverage(self):
        """(set of covered services, error code or None)."""
        covered = set()
        events = self._client('events')
        rules = self._paginate('events', 'list_rules', 'Rules')
        for rule in rules:
            if rule.get('State') != 'ENABLED' or not rule.get('EventPattern'):
                continue
            try:
                pattern = json.loads(rule['EventPattern'])
            except (ValueError, TypeError):
                continue
            hits = set()
            for svc, d in self.DETECTION_SERVICES.items():
                ev = {'source': d['source'], 'detail-type': 'AWS API Call via CloudTrail',
                      'account': self.accountId, 'region': self.region,
                      'detail': {'eventSource': d['eventSource'], 'eventName': d['eventName']}}
                if eventPatternMatches(pattern, ev):
                    hits.add(svc)
            if not hits - covered:
                continue
            targets = self._paginate('events', 'list_targets_by_rule', 'Targets', Rule=rule['Name'])
            if targets:
                covered |= hits
        return covered

    def _metricFilterCoverage(self):
        covered = set()
        errors = []
        alarmed = set()
        for a in self.alarms:
            if a.get('ActionsEnabled', True) and a.get('AlarmActions'):
                alarmed |= self._alarmMetrics(a)
        for name in self._trailLogGroups():
            filters, err = self._metricFilters(name)
            if err:
                errors.append(err)
                continue
            for f in filters:
                pattern = f.get('filterPattern', '') or ''
                metrics = {(t.get('metricNamespace'), t.get('metricName')) for t in f.get('metricTransformations', [])}
                if not metrics & alarmed:
                    continue
                onlySource = not re.search(r'\$\.(?!eventSource\b)\w', pattern)
                for svc, d in self.DETECTION_SERVICES.items():
                    if re.search(r'\$\.eventName\s*=\s*["\']?' + d['eventName'] + r'\b', pattern):
                        covered.add(svc)
                    elif onlySource and re.search(r'\$\.eventSource\s*=\s*["\']?' + re.escape(d['eventSource']), pattern):
                        covered.add(svc)
        return covered, errors

    def _checkDetectionDisableAlarm(self):
        key = 'detectionDisableNoAlarm'
        active = self._detectionActiveServices()
        relevant = [s for s, v in active.items() if v is not False]
        if not relevant:
            self.results[key] = [0, 'GuardDuty, Security Hub and IAM Access Analyzer are not enabled in this region']
            return

        covered = set()
        errors = []
        try:
            covered |= self._eventRuleCoverage()
        except Exception as e:
            errors.append(f'events: {_errCode(e)}')
        mfCovered, mfErrors = self._metricFilterCoverage()
        covered |= mfCovered
        errors += [f'logs: {e}' for e in mfErrors]

        missingActive = [s for s in relevant if active[s] is True and s not in covered]
        missingUnknown = [s for s in relevant if active[s] is None and s not in covered]
        if missingActive and not errors:
            self.results[key] = [-1, 'No EventBridge rule or alarmed metric filter alerts when these are disabled: '
                                     + ', '.join(missingActive)]
        elif errors or missingUnknown:
            ## Coverage sources were unreadable: do not FAIL or PASS on partial data.
            detail = '; '.join(errors + [f'{s}: enablement unreadable' for s in missingUnknown])
            self.results[key] = [0, f'Unable to evaluate ({detail})']
        else:
            self.results[key] = [1, 'Disablement alerts configured for: ' + ', '.join(sorted(covered & set(relevant)))]

    def _checkLogsResourcePolicy(self):
        key = 'logsResourcePolicyPublic'
        try:
            policies = self._paginate('logs', 'describe_resource_policies', 'resourcePolicies')
        except Exception as e:
            self.results[key] = [0, f'Unable to evaluate ({_errCode(e)})']
            return
        public = []
        for p in policies:
            if any(statementIsPublic(s) for s in iterStatements(p.get('policyDocument'))):
                public.append(p.get('policyName', '?'))
        if public:
            self.results[key] = [-1, 'Resource policy allows any AWS principal without a scoping condition: '
                                     + ', '.join(public)]
        else:
            self.results[key] = [1, f'{len(policies)} account-level resource policy(ies); none allow any principal']

    def _checkCentralizationRule(self):
        key = 'cwLogsCentralizationRuleMissing'
        inOrg, mgmt = self._orgInfo()
        if inOrg is False:
            self.results[key] = [0, 'Not evaluable: account is not part of AWS Organizations']
            return
        try:
            rules = self._paginate('observabilityadmin', 'list_centralization_rules_for_organization',
                                   'CentralizationRuleSummaries', AllRegions=True)
        except Exception as e:
            code = _errCode(e)
            if mgmt and self.accountId and mgmt != self.accountId:
                self.results[key] = [0, 'Not evaluable from member account']
            else:
                self.results[key] = [0, f'Unable to evaluate ({code})']
            return
        if not rules:
            self.results[key] = [-1, 'No CloudWatch Logs centralization rule in the organization']
            return

        ## Summaries do not say whether a rule centralizes logs (rules can be
        ## metrics-only) or which source regions it covers, so read each rule
        ## from the region it was created in.
        covering, logsRules, unreadable = [], [], []
        for r in rules:
            ident = r.get('RuleArn') or r.get('RuleName')
            try:
                detail = self._client('observabilityadmin', r.get('CreatedRegion') or self.region) \
                    .get_centralization_rule_for_organization(RuleIdentifier=ident)
            except Exception as e:
                unreadable.append(f"{r.get('RuleName', '?')}: {_errCode(e)}")
                continue
            source = (detail.get('CentralizationRule') or {}).get('Source') or {}
            if not source.get('SourceLogsConfiguration'):
                continue
            logsRules.append(r.get('RuleName', '?'))
            if self.region in (source.get('Regions') or []):
                covering.append(r.get('RuleName', '?'))

        if covering:
            self.results[key] = [1, f'Logs in {self.region} centralized by rule(s): {", ".join(sorted(covering))}']
        elif unreadable:
            self.results[key] = [0, f'Unable to evaluate ({"; ".join(unreadable)})']
        elif logsRules:
            self.results[key] = [-1, f'{len(logsRules)} logs centralization rule(s) exist but none include {self.region} as a source region']
        else:
            self.results[key] = [-1, f'{len(rules)} centralization rule(s) exist but none centralize CloudWatch Logs']

    def _checkAnomalyDetection(self):
        key = 'cwNoAnomalyDetection'
        lgMap = self._logGroupMap()
        securityGroups = set(self._trailLogGroups())
        for names, err in (self._flowLogGroups(), self._resolverLogGroups()):
            if not err:
                securityGroups |= {n for n in names if n in lgMap}

        errors = []
        securityMetrics = set()
        for name in self._trailLogGroups():
            filters, err = self._metricFilters(name)
            if err:
                errors.append(f'logs metric filters: {err}')
            for f in filters or []:
                for t in f.get('metricTransformations', []):
                    securityMetrics.add((t.get('metricNamespace'), t.get('metricName')))

        try:
            for d in self._paginate('cloudwatch', 'describe_anomaly_detectors', 'AnomalyDetectors'):
                pairs = set()
                single = d.get('SingleMetricAnomalyDetector') or {}
                if single.get('MetricName'):
                    pairs.add((single.get('Namespace'), single.get('MetricName')))
                elif d.get('MetricName'):
                    pairs.add((d.get('Namespace'), d.get('MetricName')))
                for q in (d.get('MetricMathAnomalyDetector') or {}).get('MetricDataQueries', []) or []:
                    m = (q.get('MetricStat') or {}).get('Metric') or {}
                    if m.get('MetricName'):
                        pairs.add((m.get('Namespace'), m.get('MetricName')))
                for ns, mn in pairs:
                    if (ns, mn) in securityMetrics or ns in self.SECURITY_NAMESPACES:
                        self.results[key] = [1, f'Metric anomaly detector on {ns}/{mn}']
                        return
        except Exception as e:
            errors.append(f'cloudwatch: {_errCode(e)}')

        if securityGroups:
            try:
                for d in self._paginate('logs', 'list_log_anomaly_detectors', 'anomalyDetectors'):
                    if d.get('anomalyDetectorStatus') not in self.ACTIVE_ANOMALY_STATES:
                        continue
                    for arn in d.get('logGroupArnList', []) or []:
                        parsed = _logGroupNameFromArn(arn)
                        if parsed and parsed[2] in securityGroups:
                            self.results[key] = [1, f'Log anomaly detector on {parsed[2]}']
                            return
            except Exception as e:
                errors.append(f'logs: {_errCode(e)}')

        if errors:
            self.results[key] = [0, f'Unable to evaluate ({"; ".join(errors)})']
        elif not securityGroups and not securityMetrics:
            self.results[key] = [0, 'No CloudTrail, VPC Flow Logs or Resolver query log groups to evaluate']
        else:
            self.results[key] = [-1, f'No anomaly detector on security metrics or on {len(securityGroups)} security log group(s)']

    def _alarmMetricDims(self, alarm):
        """(namespace, metricName, frozenset(dimensions)) entries an alarm evaluates."""
        out = set()

        def dims(lst):
            return frozenset((d.get('Name'), d.get('Value')) for d in (lst or []))
        if alarm.get('MetricName'):
            out.add((alarm.get('Namespace'), alarm.get('MetricName'), dims(alarm.get('Dimensions'))))
        for m in alarm.get('Metrics', []) or []:
            metric = (m.get('MetricStat') or {}).get('Metric') or {}
            if metric.get('MetricName'):
                out.add((metric.get('Namespace'), metric.get('MetricName'), dims(metric.get('Dimensions'))))
        return out

    def _notifyingAlarms(self):
        """Metric alarms whose ALARM state triggers an action, directly or through
        a composite alarm (with actions) that references them."""
        viaComposite = set()
        for c in self.compositeAlarms:
            if c.get('ActionsEnabled', True) is False or not c.get('AlarmActions'):
                continue
            for ref in re.findall(r'ALARM\(\s*"?([^")]+?)"?\s*\)', c.get('AlarmRule', '') or ''):
                viaComposite.add(ref.strip())
        out = []
        for a in self.alarms:
            direct = a.get('ActionsEnabled', True) is not False and bool(a.get('AlarmActions'))
            if direct or a.get('AlarmName') in viaComposite or a.get('AlarmArn') in viaComposite:
                out.append(a)
        return out

    def _checkReplicationLagAlarm(self):
        key = 'replicationLagNotAlarmed'
        cw = self._client('cloudwatch')
        streams = {}
        errors = []
        for ns, mn in self.REPLICATION_LAG_METRICS:
            try:
                for page in cw.get_paginator('list_metrics').paginate(
                        Namespace=ns, MetricName=mn, RecentlyActive='PT3H'):
                    for m in page.get('Metrics', []) or []:
                        d = frozenset((x.get('Name'), x.get('Value')) for x in m.get('Dimensions', []) or [])
                        streams.setdefault((ns, mn), set()).add(d)
            except Exception as e:
                errors.append(f'{ns}/{mn}: {_errCode(e)}')

        if not streams:
            if errors:
                self.results[key] = [0, f'Unable to evaluate ({"; ".join(errors)})']
            else:
                self.results[key] = [0, 'No replication lag metrics reported in this region in the last 3 hours']
            return

        notifying = self._notifyingAlarms()
        alarmEntries = set()
        expressions = []
        for a in notifying:
            alarmEntries |= self._alarmMetricDims(a)
            for m in a.get('Metrics', []) or []:
                if m.get('Expression'):
                    expressions.append(m['Expression'])

        uncovered = []
        total = 0
        for (ns, mn), dimSets in sorted(streams.items()):
            onMetric = {e[2] for e in alarmEntries if e[0] == ns and e[1] == mn}
            ## An alarm on an aggregate of this metric (dimension set that is not
            ## one of the per-resource streams) or a SEARCH/metric-math expression
            ## naming the metric covers every stream: do not FAIL those.
            aggregate = any(d not in dimSets for d in onMetric) or \
                any(re.search(r'\b' + re.escape(mn) + r'\b', x) and (ns in x or 'AWS/' not in x)
                    for x in expressions)
            for d in dimSets:
                total += 1
                if aggregate or d in onMetric:
                    continue
                label = ','.join(f'{k}={v}' for k, v in sorted(d, key=lambda kv: (kv[0] or '', kv[1] or ''))) or 'no dimensions'
                uncovered.append(f'{ns}/{mn} [{label}]')

        if uncovered:
            shown = uncovered[:10]
            more = f' (+{len(uncovered) - 10} more)' if len(uncovered) > 10 else ''
            self.results[key] = [-1, f'{len(uncovered)} of {total} replication lag metric stream(s) have no alarm with an alarm action: '
                                     + '; '.join(shown) + more]
        elif errors:
            self.results[key] = [0, f'Unable to evaluate ({"; ".join(errors)})']
        else:
            self.results[key] = [1, f'All {total} replication lag metric stream(s) have an alarm with an alarm action']

    def _checkTelemetryRules(self):
        key = 'telemetryRulesNotConfigured'
        oa = self._client('observabilityadmin')

        def rules(op):
            out = []
            for page in oa.get_paginator(op).paginate():
                out.extend(page.get('TelemetryRuleSummaries', []) or [])
            return out

        acctErr = None
        acctRules, acctStatus = [], None
        try:
            acctStatus = oa.get_telemetry_evaluation_status().get('Status')
            acctRules = rules('list_telemetry_rules')
        except Exception as e:
            acctErr = _errCode(e)
        if acctRules and acctStatus == 'RUNNING':
            self.results[key] = [1, f'{len(acctRules)} account telemetry rule(s); telemetry evaluation RUNNING']
            return

        inOrg, mgmt = self._orgInfo()
        orgErr = None
        orgRules, orgStatus = [], None
        if inOrg is not False:
            try:
                orgStatus = oa.get_telemetry_evaluation_status_for_organization().get('Status')
                orgRules = rules('list_telemetry_rules_for_organization')
            except Exception as e:
                orgErr = _errCode(e)
            if not orgErr and orgRules and orgStatus == 'RUNNING':
                self.results[key] = [1, f'{len(orgRules)} organization telemetry rule(s); organization telemetry evaluation RUNNING']
                return

        if acctErr:
            self.results[key] = [0, f'Unable to evaluate ({acctErr})']
            return
        if inOrg is not False and orgErr:
            ## Organization-wide rules may cover this account but cannot be read here.
            if mgmt and self.accountId and mgmt != self.accountId:
                self.results[key] = [0, 'Not evaluable from member account']
            else:
                self.results[key] = [0, f'Unable to evaluate ({orgErr})']
            return

        detail = [f'account: {len(acctRules)} rule(s), evaluation {acctStatus or "unknown"}']
        if inOrg is not False:
            detail.append(f'organization: {len(orgRules)} rule(s), evaluation {orgStatus or "unknown"}')
        self.results[key] = [-1, 'No active CloudWatch telemetry enablement rule (' + '; '.join(detail) + ')']

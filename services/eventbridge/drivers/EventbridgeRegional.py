import fnmatch
import json

from services.Evaluator import Evaluator


class EventbridgeRegional(Evaluator):
    """
    Region-scoped EventBridge checks (5 of the 14).

      ebArchiveNotConfigured
      ebSchemaDiscoveryDisabled
      ebConnectionNoAuth
      ebApiDestinationHttpEndpoint
      ebGlobalEndpointNoReplication
      securityFindingsNotRouted
      healthEventsNotRouted

    These subjects are per-region collections rather than per-bus or per-rule:
    archives, schema discoverers, connections, API destinations and global
    endpoints all live at the region level. Following the precedent of
    services/ec2/drivers/Ec2Regional.py.

    Input:
      detail -- dict from Eventbridge._getRegionalDetail. Keys: '_region',
        '_accountId', '_archives', '_connections', '_apiDestinations',
        '_endpoints', '_discoverers', '_discovererLookupFailed', '_routing'
        (see Eventbridge._getRoutingDetail).

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    MAX_NAMES_IN_MESSAGE = 5

    ## Connection AuthorizationType values that constitute real authentication.
    ## The EventBridge API has no 'NONE' value — a connection always carries one
    ## of these — so an unrecognised or absent value is the anomaly.
    AUTHENTICATED_TYPES = frozenset(['BASIC', 'OAUTH_CLIENT_CREDENTIALS', 'API_KEY'])

    SECURITY_SOURCES = ('aws.guardduty', 'aws.securityhub', 'aws.inspector2', 'aws.access-analyzer')
    HEALTH_SOURCE = 'aws.health'
    ENABLED_STATES = frozenset(['ENABLED', 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS'])
    ## Pattern fields that do not narrow which service emitted the event. A
    ## pattern that filters only on these (no 'source') matches every source.
    SOURCE_NEUTRAL_FIELDS = frozenset(['account', 'region'])

    ## detail-type values of the events that carry findings / Health events for
    ## each source. A rule whose detail-type filter matches none of these (for
    ## example 'AWS API Call via CloudTrail' on source aws.guardduty, or
    ## 'Security Hub Findings - Custom Action', which only fires when a person
    ## invokes the action) never receives a finding and does not count as
    ## routing it.
    FINDING_DETAIL_TYPES = {
        'aws.guardduty': ('GuardDuty Finding',),
        'aws.securityhub': ('Security Hub Findings - Imported', 'Findings Imported V2'),
        'aws.inspector2': ('Inspector2 Finding',),
        'aws.access-analyzer': ('Access Analyzer Finding', 'Unused Access Finding for IAM entities'),
        'aws.health': ('AWS Health Event', 'AWS Health Abuse Event'),
    }

    ## Top-level 'detail' fields that exist only on CloudTrail API-call events
    ## ('AWS API Call via CloudTrail'). Finding and Health event details never
    ## carry them, so a pattern that requires one of them cannot match a
    ## finding even when it names the finding source.
    CLOUDTRAIL_ONLY_DETAIL_FIELDS = frozenset([
        'eventName', 'eventSource', 'eventType', 'eventCategory', 'eventVersion',
        'eventID', 'eventTime', 'userIdentity', 'userAgent', 'sourceIPAddress',
        'requestParameters', 'responseElements', 'requestID', 'errorCode',
        'errorMessage', 'readOnly', 'managementEvent', 'recipientAccountId',
        'awsRegion', 'apiVersion', 'additionalEventData', 'tlsDetails',
        'sessionCredentialFromConsole', 'vpcEndpointId',
    ])

    def __init__(self, detail, ebClient):
        super().__init__()
        self.detail = detail
        self.ebClient = ebClient

        ## Region-scoped subject; there is no per-resource name.
        self._resourceName = 'Account'

        self.archives = detail.get('_archives') or []
        self.connections = detail.get('_connections') or []
        self.apiDestinations = detail.get('_apiDestinations') or []
        self.endpoints = detail.get('_endpoints') or []
        self.discoverers = detail.get('_discoverers') or []
        self.discovererLookupFailed = bool(detail.get('_discovererLookupFailed'))
        self.routing = detail.get('_routing')

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('archiveCount', str(len(self.archives)))
        self.addII('connectionCount', str(len(self.connections)))
        self.addII('apiDestinationCount', str(len(self.apiDestinations)))
        self.addII('globalEndpointCount', str(len(self.endpoints)))
        self.addII('schemaDiscovererCount', str(len(self.discoverers)))

    # ------------------------------------------------------------------ #
    # 1. No event archive
    # ------------------------------------------------------------------ #
    def _checkEbArchiveNotConfigured(self):
        """
        Without an archive there is no replay capability: an event lost to a bug
        in a downstream consumer cannot be re-delivered once it has been
        processed.
        """
        if not self.archives:
            self.results['ebArchiveNotConfigured'] = [
                -1,
                "No EventBridge archive exists in this region — delivered events "
                "are not retained, so none can be replayed after a downstream "
                "failure"
            ]
            return

        ## An archive in a non-ENABLED state retains nothing.
        enabled = [a for a in self.archives if a.get('State') == 'ENABLED']
        if not enabled:
            states = sorted({a.get('State', 'UNKNOWN') for a in self.archives})
            self.results['ebArchiveNotConfigured'] = [
                -1,
                f"{len(self.archives)} archive(s) exist but none are ENABLED "
                f"(state(s): {', '.join(states)}) — no events are being retained"
            ]
            return

        names = [a.get('ArchiveName', '?') for a in enabled]
        self.results['ebArchiveNotConfigured'] = [
            1,
            f"{len(enabled)} enabled archive(s): " + self._joinNames(names)
        ]

    # ------------------------------------------------------------------ #
    # 2. Schema discovery not enabled
    # ------------------------------------------------------------------ #
    def _checkEbSchemaDiscoveryDisabled(self):
        """
        Schema discovery is provided by the separate 'schemas' service, which is
        absent in some regions and needs its own IAM permission. A failed lookup
        must report INFO, not FAIL — otherwise every region without the endpoint
        raises a finding the customer cannot act on.
        """
        if self.discovererLookupFailed:
            self.results['ebSchemaDiscoveryDisabled'] = [
                0,
                "EventBridge Schema Registry could not be queried in this region "
                "(endpoint unavailable or schemas:ListDiscoverers denied)"
            ]
            return

        if not self.discoverers:
            self.results['ebSchemaDiscoveryDisabled'] = [
                -1,
                "No schema discoverer is configured — event schemas are not "
                "catalogued, so consumers have no generated contract to bind to"
            ]
            return

        started = [d for d in self.discoverers if d.get('State') == 'STARTED']
        if not started:
            self.results['ebSchemaDiscoveryDisabled'] = [
                -1,
                f"{len(self.discoverers)} schema discoverer(s) exist but none are "
                "in the STARTED state — no schemas are being discovered"
            ]
            return

        self.results['ebSchemaDiscoveryDisabled'] = [
            1, f"{len(started)} schema discoverer(s) are running"
        ]

    # ------------------------------------------------------------------ #
    # 3. Connection with no authorization
    # ------------------------------------------------------------------ #
    def _checkEbConnectionNoAuth(self):
        if not self.connections:
            self.results['ebConnectionNoAuth'] = [
                0, "No EventBridge connection exists in this region"
            ]
            return

        unauthenticated = [
            c.get('Name', '?') for c in self.connections
            if c.get('AuthorizationType') not in self.AUTHENTICATED_TYPES
        ]

        if unauthenticated:
            self.results['ebConnectionNoAuth'] = [
                -1,
                "{} of {} connection(s) do not use a recognised authorization "
                "type (BASIC, API_KEY or OAUTH_CLIENT_CREDENTIALS): {}".format(
                    len(unauthenticated), len(self.connections),
                    self._joinNames(unauthenticated))
            ]
        else:
            self.results['ebConnectionNoAuth'] = [
                1,
                f"All {len(self.connections)} connection(s) use an authenticated "
                "authorization type"
            ]

    # ------------------------------------------------------------------ #
    # 4. API destination over plaintext HTTP
    # ------------------------------------------------------------------ #
    def _checkEbApiDestinationHttpEndpoint(self):
        if not self.apiDestinations:
            self.results['ebApiDestinationHttpEndpoint'] = [
                0, "No EventBridge API destination exists in this region"
            ]
            return

        insecure = []
        for destination in self.apiDestinations:
            endpoint = destination.get('InvocationEndpoint') or ''
            if endpoint.lower().startswith('http://'):
                insecure.append(destination.get('Name', '?'))

        if insecure:
            self.results['ebApiDestinationHttpEndpoint'] = [
                -1,
                "{} of {} API destination(s) invoke a plaintext http:// endpoint, "
                "so event payloads and any credentials in them cross the network "
                "unencrypted: {}".format(len(insecure), len(self.apiDestinations),
                                         self._joinNames(insecure))
            ]
        else:
            self.results['ebApiDestinationHttpEndpoint'] = [
                1,
                f"All {len(self.apiDestinations)} API destination(s) use https://"
            ]

    # ------------------------------------------------------------------ #
    # 5. Global endpoint without event replication
    # ------------------------------------------------------------------ #
    def _checkEbGlobalEndpointNoReplication(self):
        if not self.endpoints:
            self.results['ebGlobalEndpointNoReplication'] = [
                0, "No EventBridge global endpoint exists in this region"
            ]
            return

        notReplicating = []
        for endpoint in self.endpoints:
            state = (endpoint.get('ReplicationConfig') or {}).get('State')
            if state != 'ENABLED':
                notReplicating.append(endpoint.get('Name', '?'))

        if notReplicating:
            self.results['ebGlobalEndpointNoReplication'] = [
                -1,
                "{} of {} global endpoint(s) have event replication disabled — "
                "events published before a regional failover are not mirrored to "
                "the secondary region: {}".format(
                    len(notReplicating), len(self.endpoints),
                    self._joinNames(notReplicating))
            ]
        else:
            self.results['ebGlobalEndpointNoReplication'] = [
                1,
                f"All {len(self.endpoints)} global endpoint(s) have replication "
                "ENABLED"
            ]

    # ------------------------------------------------------------------ #
    # 6. Security findings not routed to any responder
    # ------------------------------------------------------------------ #
    def _checkSecurityFindingsNotRouted(self):
        """
        GuardDuty, Security Hub, Inspector and IAM Access Analyzer publish their
        findings to the default event bus of the Region. Without an enabled rule
        that matches at least one of these sources and has a target, no
        responder (ticketing, chat, SOAR, Lambda) is notified automatically.

        Suppressed to INFO when findings are centralised elsewhere: the account
        is an active GuardDuty or Security Hub member (the administrator account
        owns the response), or Security Hub cross-Region aggregation links this
        Region into another aggregation Region.
        """
        key = 'securityFindingsNotRouted'
        routing = self.routing
        if not isinstance(routing, dict):
            self.results[key] = [0, 'Unable to evaluate (routing data not collected)']
            return
        if routing.get('regionError'):
            self.results[key] = [0, f"Unable to evaluate ({routing['regionError']})"]
            return

        routes = self._routesBySource(routing.get('regionRules'), self.SECURITY_SOURCES)
        routed = [s for s in self.SECURITY_SOURCES if routes[s]]
        perSource = '; '.join(
            f"{s}: " + (self._joinNames(routes[s]) if routes[s] else 'not routed')
            for s in self.SECURITY_SOURCES)

        if routed:
            self.results[key] = [1, f"Security findings are routed on the default bus — {perSource}"]
            return

        gdAdmin = routing.get('guardDutyAdmin')
        shAdmin = routing.get('securityHubAdmin')
        if gdAdmin or shAdmin:
            admins = []
            if gdAdmin:
                admins.append(f"GuardDuty administrator {gdAdmin}")
            if shAdmin:
                admins.append(f"Security Hub administrator {shAdmin}")
            self.results[key] = [
                0,
                "No local rule routes security findings, but this account is a member of "
                + ' and '.join(admins) + " — evaluate finding routing in the administrator account"
            ]
            return

        aggRegion = routing.get('securityHubAggregation')
        if aggRegion:
            self.results[key] = [
                0,
                "No local rule routes security findings, but Security Hub aggregates this "
                f"Region's findings into {aggRegion} — evaluate finding routing there"
            ]
            return

        self.results[key] = [
            -1,
            "No ENABLED rule with a target on the default event bus matches finding events "
            "(source and detail-type) from GuardDuty, Security Hub, Inspector or IAM Access "
            "Analyzer — " + perSource
        ]

    # ------------------------------------------------------------------ #
    # 7. AWS Health events not routed
    # ------------------------------------------------------------------ #
    def _checkHealthEventsNotRouted(self):
        """
        AWS Health delivers Region-specific events to the default bus of the
        affected Region and global events to us-east-1. FAIL only when neither
        the scanned Region nor us-east-1 has an ENABLED aws.health rule with a
        target. When only us-east-1 routes Health events, global events are
        covered but this Region's events are not; that is reported as INFO.
        """
        key = 'healthEventsNotRouted'
        routing = self.routing
        if not isinstance(routing, dict):
            self.results[key] = [0, 'Unable to evaluate (routing data not collected)']
            return
        if routing.get('regionError'):
            self.results[key] = [0, f"Unable to evaluate ({routing['regionError']})"]
            return

        region = routing.get('_region', 'this Region')
        local = self._routesBySource(routing.get('regionRules'), [self.HEALTH_SOURCE])[self.HEALTH_SOURCE]
        if local:
            self.results[key] = [1, f"AWS Health events in {region} are routed by: " + self._joinNames(local)]
            return

        if region != 'us-east-1':
            if routing.get('globalError'):
                self.results[key] = [
                    0, f"Unable to evaluate ({routing['globalError']}) — no aws.health rule in {region}, "
                    "and us-east-1 (global events) could not be read"]
                return
            globalRoutes = self._routesBySource(
                routing.get('globalRules'), [self.HEALTH_SOURCE])[self.HEALTH_SOURCE]
            if globalRoutes:
                self.results[key] = [
                    0,
                    "Global AWS Health events are routed in us-east-1 by " + self._joinNames(globalRoutes)
                    + f", but no rule routes Region-specific Health events in {region}"
                ]
                return

        self.results[key] = [
            -1,
            f"No ENABLED rule with a target matches AWS Health events (source aws.health, detail-type "
            f"'AWS Health Event') on the default bus in {region}"
            + ("" if region == 'us-east-1' else " or us-east-1")
            + " — service events and scheduled changes affecting this account reach no responder"
        ]

    # ------------------------------------------------------------------ #
    # Event pattern matching
    # ------------------------------------------------------------------ #
    def _routesBySource(self, rules, sources):
        """{source: [ruleName, ...]} counting only ENABLED rules with >= 1 target."""
        out = {s: [] for s in sources}
        for rule in rules or []:
            if rule.get('State') not in self.ENABLED_STATES:
                continue
            if (rule.get('targetCount') or 0) < 1:
                continue
            for s in rule.get('sources') or []:
                if s in out:
                    out[s].append(rule.get('Name', '?'))
        return out

    @classmethod
    def patternMatchesSource(cls, pattern, source, detailTypes=None):
        """
        True when an EventBridge EventPattern (JSON string or dict) can match a
        finding / Health event published by `source`.

        The event is identified by its 'source' AND its 'detail-type': a rule
        on source aws.guardduty limited to detail-type 'AWS API Call via
        CloudTrail' never sees a GuardDuty finding. `detailTypes` lists the
        detail-type values of the events of interest; when omitted it defaults
        to FINDING_DETAIL_TYPES[source] (no detail-type constraint for a source
        not in that map). A 'detail' filter that requires a CloudTrail-only
        field (eventName, eventSource, userIdentity, ...) also cannot match.

        Understands $or (top level and inside 'detail'), exact values and the
        prefix / suffix / wildcard / equals-ignore-case / anything-but / exists
        content filters. Unparseable patterns never match.
        """
        if isinstance(pattern, str):
            try:
                pattern = json.loads(pattern)
            except (ValueError, TypeError):
                return False
        if not isinstance(pattern, dict):
            return False
        if detailTypes is None:
            detailTypes = cls.FINDING_DETAIL_TYPES.get(source)
        return any(cls._alternativeMatches(alt, source, detailTypes) for alt in cls._expandOr(pattern))

    @classmethod
    def _expandOr(cls, pattern, depth=0):
        if depth > 5 or '$or' not in pattern:
            return [pattern]
        base = {k: v for k, v in pattern.items() if k != '$or'}
        alts = []
        for sub in pattern.get('$or') or []:
            if isinstance(sub, dict):
                merged = dict(base)
                merged.update(sub)
                alts += cls._expandOr(merged, depth + 1)
        return alts

    @staticmethod
    def _asList(values):
        return values if isinstance(values, list) else [values]

    @classmethod
    def _alternativeMatches(cls, pattern, source, detailTypes=None):
        if 'source' in pattern:
            if not any(cls._valueMatches(v, source) for v in cls._asList(pattern.get('source'))):
                return False

        if 'detail-type' in pattern and detailTypes:
            matchers = cls._asList(pattern.get('detail-type'))
            if not any(cls._valueMatches(m, dt) for m in matchers for dt in detailTypes):
                return False

        if 'detail' in pattern and cls._detailRequiresCloudTrailField(pattern.get('detail')):
            return False

        if 'source' not in pattern and not ('detail-type' in pattern and detailTypes):
            ## No source filter and no detail-type that identifies the event:
            ## matches every source only when nothing else in the pattern
            ## narrows the event type.
            return set(pattern.keys()) <= cls.SOURCE_NEUTRAL_FIELDS
        return True

    @classmethod
    def _detailRequiresCloudTrailField(cls, detail):
        """True when every $or alternative of a 'detail' filter requires a
        field that only CloudTrail API-call events carry."""
        if not isinstance(detail, dict):
            return False
        alts = cls._expandOr(detail)
        if not alts:
            return False
        return all(cls._requiresCloudTrailField(alt) for alt in alts)

    @classmethod
    def _requiresCloudTrailField(cls, detail):
        for field in cls.CLOUDTRAIL_ONLY_DETAIL_FIELDS & set(detail.keys()):
            matcher = detail[field]
            if isinstance(matcher, dict):
                return True  ## nested filter: the field must be present
            ## A {"exists": false} alternative is satisfied when the field is absent.
            if not any(isinstance(m, dict) and m.get('exists') is False for m in cls._asList(matcher)):
                return True
        return False

    @classmethod
    def _valueMatches(cls, matcher, source):
        if isinstance(matcher, str):
            return matcher == source
        if not isinstance(matcher, dict):
            return False
        if 'prefix' in matcher:
            p = matcher['prefix']
            if isinstance(p, dict):
                p = p.get('equals-ignore-case')
                return isinstance(p, str) and source.lower().startswith(p.lower())
            return isinstance(p, str) and source.startswith(p)
        if 'suffix' in matcher:
            p = matcher['suffix']
            if isinstance(p, dict):
                p = p.get('equals-ignore-case')
                return isinstance(p, str) and source.lower().endswith(p.lower())
            return isinstance(p, str) and source.endswith(p)
        if 'equals-ignore-case' in matcher:
            p = matcher['equals-ignore-case']
            return isinstance(p, str) and p.lower() == source.lower()
        if 'wildcard' in matcher:
            p = matcher['wildcard']
            return isinstance(p, str) and fnmatch.fnmatchcase(source, p.replace('[', '[[]'))
        if 'exists' in matcher:
            return matcher['exists'] is True
        if 'anything-but' in matcher:
            excluded = matcher['anything-but']
            if isinstance(excluded, str):
                return excluded != source
            if isinstance(excluded, list):
                return source not in excluded
            if isinstance(excluded, dict):
                if 'prefix' in excluded and isinstance(excluded['prefix'], str):
                    return not source.startswith(excluded['prefix'])
                if 'suffix' in excluded and isinstance(excluded['suffix'], str):
                    return not source.endswith(excluded['suffix'])
                if 'wildcard' in excluded and isinstance(excluded['wildcard'], str):
                    return not fnmatch.fnmatchcase(source, excluded['wildcard'].replace('[', '[[]'))
                if 'equals-ignore-case' in excluded:
                    ex = excluded['equals-ignore-case']
                    ex = [ex] if isinstance(ex, str) else (ex or [])
                    return source.lower() not in [str(e).lower() for e in ex]
            return False
        return False

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown

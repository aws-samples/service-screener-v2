import botocore
import botocore.config

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.eventbridge.drivers.EventbridgeBus import EventbridgeBus
from services.eventbridge.drivers.EventbridgeRule import EventbridgeRule
from services.eventbridge.drivers.EventbridgeRegional import EventbridgeRegional


class Eventbridge(Service):
    """
    Amazon EventBridge service scanner.

    The boto3 client is named 'events', not 'eventbridge'.

    EventBridge has three distinct check subjects, so discovery fans out into
    three drivers rather than one:

      EventbridgeBus      -- per event bus (encryption, resource policy, tags)
      EventbridgeRule     -- per rule on each bus (state, targets, DLQ, retry)
      EventbridgeRegional -- region-scoped inventory that is not attached to any
                             one bus or rule: archives, connections, API
                             destinations, global endpoints, schema discoverers

    Hydration calls (all read-only):
      - list_event_buses / describe_event_bus  (KmsKeyIdentifier, Policy)
      - list_rules / list_targets_by_rule
      - list_tags_for_resource                 (per bus)
      - list_archives, list_connections, list_api_destinations, list_endpoints
      - schemas:list_discoverers               (separate 'schemas' client)
    """

    ## Error codes meaning "not permitted to see this" — swallowed quietly so a
    ## least-privilege scan does not spam the console.
    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.ebClient = ssBoto.client('events', config=self.bConfig)
        ## Schema discovery lives in a different service ('schemas'), and is not
        ## available in every region EventBridge is. Created lazily-tolerantly:
        ## a failure here must not abort the whole EventBridge scan.
        try:
            self.schemasClient = ssBoto.client('schemas', config=self.bConfig)
        except Exception:
            self.schemasClient = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        """Return the list of event bus descriptors, each with its rules attached."""
        buses = []
        try:
            paginator = self.ebClient.get_paginator('list_event_buses')
            for page in paginator.paginate():
                summaries = page.get('EventBuses', []) or []
                pendingNames = {s.get('Name') for s in self.registerItems(
                    'EventbridgeBus', summaries, idFn=lambda s: s.get('Name')
                )}

                for summary in summaries:
                    name = summary.get('Name')
                    arn = summary.get('Arn')
                    if not name or not arn:
                        continue

                    if name not in pendingNames:
                        ## Already checkpointed - skip describe_event_bus/list_tags,
                        ## but rules aren't checkpointed on their own, so still fetch
                        ## them (cheap relative to the bus-level calls being saved).
                        detail = {'_name': name, '_arn': arn}
                    else:
                        detail = self._describeBus(name, arn, summary)
                        if detail is None:
                            continue

                    detail['_rules'] = self._listRules(name)
                    _pi('Eventbridge', f"Event bus: {name}")
                    buses.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_event_buses', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"EventBridge not available in region {self.region}: {e}")
        except botocore.exceptions.OperationNotPageableError:
            buses = self._getResourcesUnpaginated()
        return buses

    def _getResourcesUnpaginated(self):
        """Fallback for botocore versions without a list_event_buses paginator."""
        buses = []
        try:
            resp = self.ebClient.list_event_buses()
            for summary in resp.get('EventBuses', []) or []:
                name = summary.get('Name')
                arn = summary.get('Arn')
                if not name or not arn:
                    continue
                detail = self._describeBus(name, arn, summary)
                if detail is not None:
                    detail['_rules'] = self._listRules(name)
                    buses.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_event_buses', e)
        return buses

    def _describeBus(self, name, arn, summary):
        """Build one bus descriptor with its policy, encryption, tags and rules."""
        detail = {k: v for k, v in (summary or {}).items()}
        try:
            resp = self.ebClient.describe_event_bus(Name=name)
            detail.update({k: v for k, v in resp.items() if k != 'ResponseMetadata'})
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'ResourceNotFoundException':
                return None
            self._logClientError(f'describe_event_bus({name})', e)

        tags = self._listTags(arn, name)

        ## Optional --filters tag filtering. Applied to the bus only; a rule is
        ## not independently taggable in a way that would let it survive its
        ## bus being filtered out.
        if self.tags and not self.resourceHasTags(tags):
            return None

        detail['_name'] = name
        detail['_arn'] = arn
        detail['_tags'] = tags
        detail['_isDefault'] = (name == 'default')
        detail['_currentAccount'] = self._currentAccount()
        detail['_region'] = self.region
        return detail

    def _listTags(self, arn, name):
        try:
            resp = self.ebClient.list_tags_for_resource(ResourceARN=arn)
            return resp.get('Tags', []) or []
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'ResourceNotFoundException':
                return []
            self._logClientError(f'list_tags_for_resource({name})', e)
            return []

    def _listRules(self, busName):
        """Return every rule on the bus, each with its target list attached."""
        rules = []
        try:
            paginator = self.ebClient.get_paginator('list_rules')
            for page in paginator.paginate(EventBusName=busName):
                for rule in page.get('Rules', []) or []:
                    ruleName = rule.get('Name')
                    if not ruleName:
                        continue
                    ## list_rules already returns State, Description,
                    ## ScheduleExpression, EventPattern and ManagedBy, so
                    ## describe_rule would add nothing the checks read. Skipped
                    ## deliberately to avoid one extra API call per rule.
                    rule['_busName'] = busName
                    rule['_targets'] = self._listTargets(ruleName, busName)
                    rules.append(rule)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_rules({busName})', e)
        return rules

    def _listTargets(self, ruleName, busName):
        targets = []
        try:
            paginator = self.ebClient.get_paginator('list_targets_by_rule')
            for page in paginator.paginate(Rule=ruleName, EventBusName=busName):
                targets += page.get('Targets', []) or []
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'ResourceNotFoundException':
                return []
            self._logClientError(f'list_targets_by_rule({ruleName})', e)
        return targets

    def _getRegionalDetail(self):
        """Region-scoped EventBridge inventory not owned by any single bus."""
        ## _listDiscoverers sets _discovererLookupFailed as a side effect, so
        ## call it before reading the flag rather than relying on dict-literal
        ## evaluation order.
        discoverers = self._listDiscoverers()
        return {
            '_region': self.region,
            '_accountId': self._currentAccount(),
            '_archives': self._listArchives(),
            '_connections': self._listConnections(),
            '_apiDestinations': self._listApiDestinations(),
            '_endpoints': self._listEndpoints(),
            '_discoverers': discoverers,
            '_discovererLookupFailed': self._discovererLookupFailed,
            '_routing': self._getRoutingDetail(),
        }

    # ------------------------------------------------------------------ #
    # Event routing (securityFindingsNotRouted / healthEventsNotRouted)
    # ------------------------------------------------------------------ #
    def _getRoutingDetail(self):
        """
        Default-bus rules that route security findings or AWS Health events,
        plus the enrichment needed to suppress member-account false positives.
        All calls are read-only. Lookup failures are recorded as error codes so
        the checks can report 'Unable to evaluate' instead of a false PASS/FAIL.
        """
        sources = list(EventbridgeRegional.SECURITY_SOURCES) + [EventbridgeRegional.HEALTH_SOURCE]
        routing = {'_region': self.region}
        routing['regionRules'], routing['regionError'] = self._listRoutingRules(self.ebClient, sources)

        ## Global AWS Health events (IAM, CloudFront, Route 53, ...) are only
        ## delivered to the default bus of the partition's global-event Region
        ## (us-east-1, us-gov-west-1 for GovCloud, cn-north-1 for China).
        globalRegion = self.healthGlobalRegion(self.region)
        routing['_globalRegion'] = globalRegion
        if globalRegion is None:
            routing['globalRules'], routing['globalError'] = [], 'UnknownPartition'
        elif self.region != globalRegion:
            try:
                globalClient = self.ssBoto.client(
                    'events', region_name=globalRegion, config=self.bConfig.merge(botocore.config.Config(region_name=globalRegion)))
                routing['globalRules'], routing['globalError'] = self._listRoutingRules(
                    globalClient, [EventbridgeRegional.HEALTH_SOURCE])
            except Exception as e:
                routing['globalRules'], routing['globalError'] = [], type(e).__name__
        else:
            routing['globalRules'], routing['globalError'] = routing['regionRules'], routing['regionError']

        errors = []
        routing['guardDutyAdmin'] = self._guardDutyAdministrator(errors)
        routing['securityHubAdmin'] = self._securityHubAdministrator(errors)
        routing['securityHubAggregation'] = self._securityHubAggregationRegion(errors)
        ## Membership / aggregation could not be read: a missing local route is then
        ## not proof that findings reach no responder (INFO, not FAIL).
        routing['enrichmentErrors'] = errors
        return routing

    ## Partition -> Region where AWS Health delivers global events.
    HEALTH_GLOBAL_REGION = {'aws': 'us-east-1', 'aws-us-gov': 'us-gov-west-1', 'aws-cn': 'cn-north-1'}

    @classmethod
    def healthGlobalRegion(cls, region):
        """Global-event Region of the partition `region` belongs to; None when unknown
        (ISO partitions), so the caller reports 'Unable to evaluate' rather than guess."""
        region = region or ''
        if region.startswith('us-gov-'):
            partition = 'aws-us-gov'
        elif region.startswith('cn-'):
            partition = 'aws-cn'
        elif '-iso' in region:
            partition = None
        else:
            partition = 'aws'
        return cls.HEALTH_GLOBAL_REGION.get(partition)

    def _listRoutingRules(self, client, sources):
        """
        Return ([{Name, State, sources, targetCount}], errorCode) for every
        default-bus rule whose EventPattern matches at least one of `sources`.
        Targets are only listed for matching rules, keeping the cost low.
        """
        out = []
        try:
            paginator = client.get_paginator('list_rules')
            rules = []
            for page in paginator.paginate(EventBusName='default'):
                rules += page.get('Rules', []) or []
        except botocore.exceptions.ClientError as e:
            return [], e.response.get('Error', {}).get('Code', 'ClientError')
        except botocore.exceptions.BotoCoreError as e:
            return [], type(e).__name__

        for rule in rules:
            name = rule.get('Name')
            pattern = rule.get('EventPattern')
            if not name or not pattern:
                continue
            matched = [s for s in sources if EventbridgeRegional.patternMatchesSource(pattern, s)]
            if not matched:
                continue
            targetCount = 0
            try:
                paginator = client.get_paginator('list_targets_by_rule')
                for page in paginator.paginate(Rule=name, EventBusName='default'):
                    targetCount += len(page.get('Targets', []) or [])
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', 'ClientError')
                if code != 'ResourceNotFoundException':
                    return [], code
                continue
            out.append({'Name': name, 'State': rule.get('State'),
                        'sources': matched, 'targetCount': targetCount})
        return out, None

    @staticmethod
    def _enrichErr(e):
        if isinstance(e, botocore.exceptions.ClientError):
            return e.response.get('Error', {}).get('Code', 'ClientError')
        return type(e).__name__

    ## Security Hub answers InvalidAccessException when the account is not subscribed:
    ## such an account can be neither a member nor part of an aggregation.
    _SH_NOT_ENABLED = ('InvalidAccessException',)

    def _securityHubNotEnabled(self, sh):
        """True only when describe_hub proves Security Hub is not enabled here."""
        try:
            sh.describe_hub()
            return False
        except botocore.exceptions.ClientError as e:
            return self._enrichErr(e) in self._SH_NOT_ENABLED
        except Exception:
            return False

    def _guardDutyAdministrator(self, errors=None):
        """Administrator account ID when this account is an active GuardDuty member, else None.
        A read failure is appended to `errors` (enrichment unknown, not 'not a member')."""
        try:
            gd = self.ssBoto.client('guardduty', config=self.bConfig)
            detectorIds = []
            for page in gd.get_paginator('list_detectors').paginate():
                detectorIds += page.get('DetectorIds', []) or []
            for detectorId in detectorIds:
                admin = gd.get_administrator_account(DetectorId=detectorId).get('Administrator') or {}
                if admin.get('AccountId') and str(admin.get('RelationshipStatus', '')).lower() == 'enabled':
                    return admin.get('AccountId')
        except Exception as e:
            if errors is not None:
                errors.append('guardduty: ' + self._enrichErr(e))
        return None

    def _securityHubAdministrator(self, errors=None):
        """Administrator account ID when this account is an active Security Hub member, else None."""
        sh = None
        try:
            sh = self.ssBoto.client('securityhub', config=self.bConfig)
            admin = sh.get_administrator_account().get('Administrator') or {}
            if admin.get('AccountId') and str(admin.get('MemberStatus', '')).lower() in ('enabled', 'associated'):
                return admin.get('AccountId')
        except Exception as e:
            code = self._enrichErr(e)
            if code in self._SH_NOT_ENABLED or (sh is not None and self._securityHubNotEnabled(sh)):
                return None
            if errors is not None:
                errors.append('securityhub administrator: ' + code)
        return None

    def _securityHubAggregationRegion(self, errors=None):
        """
        The Security Hub aggregation Region when this Region's findings are
        aggregated into a different Region, else None.
        """
        try:
            sh = self.ssBoto.client('securityhub', config=self.bConfig)
            arns = []
            for page in sh.get_paginator('list_finding_aggregators').paginate():
                arns += [a.get('FindingAggregatorArn') for a in page.get('FindingAggregators', []) or []]
            for arn in arns:
                if not arn:
                    continue
                agg = sh.get_finding_aggregator(FindingAggregatorArn=arn)
                aggRegion = agg.get('FindingAggregationRegion')
                if not aggRegion or aggRegion == self.region:
                    continue
                mode = agg.get('RegionLinkingMode')
                regions = agg.get('Regions') or []
                linked = (mode == 'ALL_REGIONS'
                          or (mode == 'ALL_REGIONS_EXCEPT_SPECIFIED' and self.region not in regions)
                          or (mode == 'SPECIFIED_REGIONS' and self.region in regions))
                if linked:
                    return aggRegion
        except Exception as e:
            code = self._enrichErr(e)
            if code not in self._SH_NOT_ENABLED and errors is not None:
                errors.append('securityhub aggregation: ' + code)
        return None

    def _listArchives(self):
        archives = []
        try:
            paginator = self.ebClient.get_paginator('list_archives')
            for page in paginator.paginate():
                archives += page.get('Archives', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_archives', e)
        except botocore.exceptions.OperationNotPageableError:
            try:
                archives = self.ebClient.list_archives().get('Archives', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_archives', e)
        return archives

    def _listConnections(self):
        connections = []
        try:
            paginator = self.ebClient.get_paginator('list_connections')
            for page in paginator.paginate():
                connections += page.get('Connections', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_connections', e)
        except botocore.exceptions.OperationNotPageableError:
            try:
                connections = self.ebClient.list_connections().get(
                    'Connections', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_connections', e)
        return connections

    def _listApiDestinations(self):
        """
        list_api_destinations returns InvocationEndpoint directly, so
        describe_api_destination is not needed for the http:// check.
        """
        destinations = []
        try:
            paginator = self.ebClient.get_paginator('list_api_destinations')
            for page in paginator.paginate():
                destinations += page.get('ApiDestinations', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_api_destinations', e)
        except botocore.exceptions.OperationNotPageableError:
            try:
                destinations = self.ebClient.list_api_destinations().get(
                    'ApiDestinations', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_api_destinations', e)
        return destinations

    def _listEndpoints(self):
        endpoints = []
        try:
            resp = self.ebClient.list_endpoints()
            endpoints = resp.get('Endpoints', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_endpoints', e)
        except AttributeError:
            ## Global endpoints postdate some botocore versions.
            pass
        return endpoints

    def _listDiscoverers(self):
        """
        Schema discoverers come from the separate 'schemas' service, which is not
        present in every region EventBridge is. A lookup failure is recorded
        distinctly from a genuine empty result so the check can report INFO
        rather than a false FAIL.
        """
        self._discovererLookupFailed = False
        if self.schemasClient is None:
            self._discovererLookupFailed = True
            return []

        discoverers = []
        try:
            paginator = self.schemasClient.get_paginator('list_discoverers')
            for page in paginator.paginate():
                discoverers += page.get('Discoverers', []) or []
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in self.ACCESS_DENIED_CODES:
                self._discovererLookupFailed = True
                return []
            self._logClientError('list_discoverers', e)
            self._discovererLookupFailed = True
        except botocore.exceptions.EndpointConnectionError:
            self._discovererLookupFailed = True
        except Exception:
            self._discovererLookupFailed = True
        return discoverers

    def _currentAccount(self):
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        buses = self.getResources()

        for bus in buses:
            busName = bus.get('_name', 'unknown')
            try:
                _pi('Eventbridge', f"Analyzing bus: {busName}")
                obj = EventbridgeBus(bus, self.ebClient)
                obj.run(self.__class__)
                objs[f"EventBridge Bus::{busName}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing event bus {busName}: {e}")

            for rule in bus.get('_rules', []) or []:
                ruleName = rule.get('Name', 'unknown')
                try:
                    _pi('Eventbridge', f"Analyzing rule: {ruleName}")
                    obj = EventbridgeRule(rule, bus, self.ebClient)
                    obj.run(self.__class__)
                    objs[f"EventBridge Rule::{busName}/{ruleName}"] = obj.getInfo()
                    del obj
                except Exception as e:
                    print(f"Error processing rule {ruleName}: {e}")

        ## Region-scoped checks run even when no bus survived tag filtering only
        ## if buses were found at all; a region with no EventBridge endpoint
        ## should not report archive/connection findings.
        if buses:
            try:
                detail = self._getRegionalDetail()
                obj = EventbridgeRegional(detail, self.ebClient)
                obj.run(self.__class__)
                objs['EventBridge::Account'] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing EventBridge regional posture: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Eventbridge {where}: {code} - {msg}")

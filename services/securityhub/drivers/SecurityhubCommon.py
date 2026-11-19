import botocore

from services.Evaluator import Evaluator


class SecurityhubCommon(Evaluator):
    """
    Account/region-scoped Security Hub checks.

    Input:
      detail -- from services/securityhub/Securityhub.py.getResources.
      cisArnFragment -- substring identifying a CIS standard ARN.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    When Security Hub is not enabled, only shubNotEnabled produces a finding;
    every other check reports INFO, because "is auto-enable on" is meaningless
    when the hub does not exist.
    """

    ## Below this many third-party integrations we flag shubIntegrationsMissing.
    MIN_INTEGRATIONS = 3

    ## A FSBP standard ARN contains this fragment regardless of version.
    FSBP_ARN_FRAGMENT = 'aws-foundational-security-best-practices'

    ## Subscription states in which a standard is (or is becoming) active.
    ## FAILED / DELETING are not "on"; INCOMPLETE still evaluates most
    ## controls and PENDING is mid-enable, so both count as enabled.
    ACTIVE_STANDARD_STATES = ('READY', 'INCOMPLETE', 'PENDING')

    def __init__(self, detail, shClient, cisArnFragment, eventsClient=None):
        super().__init__()
        self.detail = detail
        self.shClient = shClient
        self.eventsClient = eventsClient
        self.cisArnFragment = cisArnFragment
        self.standardsError = detail.get('_standardsError')
        self._resourceName = 'Account'

        self.enabled = bool(detail.get('_enabled'))
        self.hub = detail.get('_hub') or {}
        self.standards = detail.get('_standards') or []
        self.aggregators = detail.get('_aggregators') or []
        self.aggregatorsError = detail.get('_aggregatorsError')
        self.products = detail.get('_products') or []
        self.unprocessed = detail.get('_unprocessedFindings')
        self.findingsCapped = bool(detail.get('_findingsCapped'))

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('enabled', str(self.enabled))
        self.addII('autoEnableControls',
                   str(self.hub.get('AutoEnableControls', 'N/A')))
        self.addII('controlFindingGenerator',
                   self.hub.get('ControlFindingGenerator', 'N/A'))
        self.addII('enabledStandardsCount', str(len(self.standards)))
        self.addII('integrationCount', str(len(self.products)))

    def _na(self, key):
        """Report INFO because Security Hub is not enabled here."""
        self.results[key] = [
            0, "Security Hub is not enabled in this region — see shubNotEnabled"
        ]

    # 1. Hub not enabled
    def _checkShubNotEnabled(self):
        if self.enabled:
            self.results['shubNotEnabled'] = [
                1, "Security Hub is enabled in this region"
            ]
        else:
            self.results['shubNotEnabled'] = [
                -1,
                "Security Hub is not enabled in this region — the account has no "
                "aggregated view of control failures across services, and none "
                "of the CIS/FSBP standard checks are running"
            ]

    # 2. No standards enabled
    def _checkShubNoStandardsEnabled(self):
        if not self.enabled:
            return self._na('shubNoStandardsEnabled')
        if self.standardsError:
            self.results['shubNoStandardsEnabled'] = [
                0, f"Unable to evaluate ({self.standardsError})"]
            return
        if self.standards:
            self.results['shubNoStandardsEnabled'] = [
                1, f"{len(self.standards)} security standard(s) enabled"
            ]
        else:
            self.results['shubNoStandardsEnabled'] = [
                -1,
                "Security Hub is enabled but no security standard is turned on — "
                "the hub is collecting nothing, so it reports no control findings"
            ]

    # 3. CIS standard not enabled
    def _checkShubCISStandardDisabled(self):
        if not self.enabled:
            return self._na('shubCISStandardDisabled')
        if self.standardsError:
            self.results['shubCISStandardDisabled'] = [
                0, f"Unable to evaluate ({self.standardsError})"]
            return
        hasCis = any(self.cisArnFragment in (s.get('StandardsArn') or '')
                     for s in self.standards)
        if hasCis:
            self.results['shubCISStandardDisabled'] = [
                1, "A CIS AWS Foundations Benchmark standard is enabled"
            ]
        else:
            self.results['shubCISStandardDisabled'] = [
                -1,
                "No CIS AWS Foundations Benchmark standard is enabled — the most "
                "widely required baseline for AWS audits is not being evaluated"
            ]

    # 4. Auto-enable controls off
    def _checkShubAutoEnableControlsDisabled(self):
        if not self.enabled:
            return self._na('shubAutoEnableControlsDisabled')
        if self.hub.get('AutoEnableControls') is True:
            self.results['shubAutoEnableControlsDisabled'] = [
                1, "New controls are auto-enabled as AWS releases them"
            ]
        else:
            self.results['shubAutoEnableControlsDisabled'] = [
                -1,
                "AutoEnableControls is off — controls AWS adds for newly released "
                "services are not evaluated until someone enables them by hand, so "
                "coverage silently falls behind the services in use"
            ]

    # 5. Legacy control-finding generator
    def _checkShubLegacyControlFindingGenerator(self):
        if not self.enabled:
            return self._na('shubLegacyControlFindingGenerator')
        gen = self.hub.get('ControlFindingGenerator')
        if gen == 'SECURITY_CONTROL':
            self.results['shubLegacyControlFindingGenerator'] = [
                1, "Consolidated control findings (SECURITY_CONTROL) is enabled"
            ]
        else:
            self.results['shubLegacyControlFindingGenerator'] = [
                -1,
                f"ControlFindingGenerator is {gen or 'STANDARD_CONTROL'} (legacy) "
                "— the same control generates a separate finding under every "
                "standard it belongs to, multiplying finding volume and cost. "
                "Switch to consolidated control findings"
            ]

    # 6. No cross-region finding aggregator
    def _checkShubFindingAggregatorMissing(self):
        if not self.enabled:
            return self._na('shubFindingAggregatorMissing')
        if self.aggregatorsError and not self.aggregators:
            self.results['shubFindingAggregatorMissing'] = [
                0, f"Unable to evaluate ({self.aggregatorsError})"]
            return
        if self.aggregators:
            self.results['shubFindingAggregatorMissing'] = [
                1, "A finding aggregator provides a cross-region view"
            ]
        else:
            self.results['shubFindingAggregatorMissing'] = [
                -1,
                "No finding aggregator — findings are siloed per region, so there "
                "is no single place to see the account's posture and a region "
                "nobody watches goes unmonitored"
            ]

    # 7. Too few integrations
    def _checkShubIntegrationsMissing(self):
        if not self.enabled:
            return self._na('shubIntegrationsMissing')
        if len(self.products) >= self.MIN_INTEGRATIONS:
            self.results['shubIntegrationsMissing'] = [
                1, f"{len(self.products)} product integration(s) importing findings"
            ]
        else:
            self.results['shubIntegrationsMissing'] = [
                -1,
                f"Only {len(self.products)} product integration(s) enabled — "
                "Security Hub is most useful as the single pane that aggregates "
                "GuardDuty, Inspector, Macie and partner findings; too few "
                "integrations means it is not seeing much"
            ]

    # 8. Backlog of unprocessed findings
    def _checkShubUnprocessedFindings(self):
        if not self.enabled:
            return self._na('shubUnprocessedFindings')
        if self.unprocessed is None:
            self.results['shubUnprocessedFindings'] = [
                0, "Finding count could not be read"
            ]
            return
        ## Threshold is 100 NEW findings; the page cap is high enough to
        ## distinguish "under 100" from "well over".
        if self.unprocessed <= 100 and not self.findingsCapped:
            self.results['shubUnprocessedFindings'] = [
                1, f"{self.unprocessed} finding(s) in the NEW workflow state"
            ]
        else:
            atLeast = "at least " if self.findingsCapped else ""
            self.results['shubUnprocessedFindings'] = [
                -1,
                f"{atLeast}{self.unprocessed} finding(s) are still in the NEW "
                "workflow state — a backlog this size means findings are not "
                "being triaged, so a real one is unlikely to be noticed among them"
            ]

    # ------------------------------------------------------------------ #
    # WAFS2027 additions
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def _activeStandards(self):
        return [s for s in self.standards
                if (s.get('StandardsStatus') or '') in self.ACTIVE_STANDARD_STATES]

    # 9. AWS Foundational Security Best Practices not enabled
    def _checkShubFsbpStandardDisabled(self):
        key = 'shubFsbpStandardDisabled'
        if not self.enabled:
            return self._na(key)
        if self.standardsError:
            self.results[key] = [0, f"Unable to evaluate ({self.standardsError})"]
            return
        fsbp = [s for s in self.standards
                if self.FSBP_ARN_FRAGMENT in (s.get('StandardsArn') or '')]
        active = [s for s in fsbp
                  if (s.get('StandardsStatus') or '') in self.ACTIVE_STANDARD_STATES]
        if active:
            self.results[key] = [
                1, "AWS Foundational Security Best Practices is enabled "
                   f"({active[0].get('StandardsStatus')})"
            ]
        elif fsbp:
            self.results[key] = [
                -1,
                "The AWS Foundational Security Best Practices subscription is "
                f"{fsbp[0].get('StandardsStatus')} — its controls are not being "
                "evaluated"
            ]
        else:
            self.results[key] = [
                -1,
                "AWS Foundational Security Best Practices is not enabled — the "
                "AWS-curated baseline of controls across services is not being "
                "evaluated in this region"
            ]

    # 10. New Security Hub (v2) not enabled
    def _checkSecurityHubV2NotEnabled(self):
        key = 'securityHubV2NotEnabled'
        try:
            resp = self.shClient.describe_security_hub_v2()
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if code == 'ResourceNotFoundException':
                self.results[key] = [
                    -1,
                    "The new AWS Security Hub is not enabled in this region — "
                    "findings from GuardDuty, Inspector, Macie and Security Hub "
                    "CSPM are not correlated into exposures and prioritised "
                    "risks"
                ]
            else:
                self.results[key] = [0, f"Unable to evaluate ({code})"]
            return
        except botocore.exceptions.BotoCoreError as e:
            self.results[key] = [0, f"Unable to evaluate ({type(e).__name__})"]
            return
        if resp.get('HubV2Arn'):
            self.results[key] = [1, "The new AWS Security Hub is enabled"]
        else:
            self.results[key] = [0, "Unable to evaluate (no HubV2Arn returned)"]

    # 11. Controls disabled without a recorded reason
    def _checkShubControlsDisabledNoReason(self):
        key = 'shubControlsDisabledNoReason'
        if not self.enabled:
            return self._na(key)
        if self.standardsError:
            self.results[key] = [0, f"Unable to evaluate ({self.standardsError})"]
            return
        ## Only READY/INCOMPLETE subscriptions have a control list to read;
        ## PENDING ones are still being provisioned.
        subs = [s for s in self.standards
                if (s.get('StandardsStatus') or '') in ('READY', 'INCOMPLETE')
                and s.get('StandardsSubscriptionArn')]
        if not subs:
            self.results[key] = [0, "No ready standard subscription to evaluate"]
            return

        noReason, disabled, errors = [], 0, []
        for sub in subs:
            arn = sub['StandardsSubscriptionArn']
            try:
                pag = self.shClient.get_paginator('describe_standards_controls')
                for page in pag.paginate(StandardsSubscriptionArn=arn):
                    for c in page.get('Controls', []) or []:
                        if (c.get('ControlStatus') or '') != 'DISABLED':
                            continue
                        disabled += 1
                        if not (c.get('DisabledReason') or '').strip():
                            noReason.append(c.get('ControlId')
                                            or c.get('StandardsControlArn', '?'))
            except botocore.exceptions.ClientError as e:
                errors.append(self._errCode(e))

        if noReason:
            shown = ', '.join(sorted(set(noReason))[:10])
            more = '' if len(set(noReason)) <= 10 else ', ...'
            self.results[key] = [
                -1,
                f"{len(noReason)} disabled control(s) have no recorded reason "
                f"({shown}{more}) — the exception cannot be traced or reviewed"
            ]
        elif errors and len(errors) == len(subs):
            self.results[key] = [0, f"Unable to evaluate ({errors[0]})"]
        elif errors:
            self.results[key] = [
                0, f"Unable to evaluate every standard ({errors[0]}); "
                   f"{disabled} disabled control(s) read all have a reason"
            ]
        else:
            msg = (f"{disabled} disabled control(s), all with a recorded reason"
                   if disabled else "No controls are disabled")
            self.results[key] = [1, msg]

    # 12. No automated response wired to Security Hub findings
    ## detail-type values of Security Hub events a response can be wired to.
    ## Imported findings (CSPM and the new Security Hub) fire automatically;
    ## custom-action / insight events start a wired response on demand from
    ## the console. All are delivered to the default bus only.
    SH_RESPONSE_DETAIL_TYPES = (
        'Security Hub Findings - Imported', 'Findings Imported V2',
        'Security Hub Findings - Custom Action', 'Security Hub Insight Results',
    )
    EB_ENABLED_STATES = ('ENABLED', 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS')

    def _automationEvidence(self):
        """
        Returns (evidence, error codes). Evidence is the first ENABLED Security
        Hub automation rule, or the first ENABLED default-bus EventBridge rule
        that matches Security Hub finding events (source AND detail-type) and
        has at least one target. A custom action without a rule, or an SSM
        document nothing invokes, responds to nothing and is not evidence.
        """
        from services.eventbridge.drivers.EventbridgeRegional import EventbridgeRegional
        errors = []

        def _first(fn):
            try:
                return fn()
            except botocore.exceptions.ClientError as e:
                errors.append(self._errCode(e))
            except botocore.exceptions.BotoCoreError as e:
                errors.append(type(e).__name__)
            return None

        def rules():
            ## list_automation_rules has no paginator: walk NextToken so a page
            ## of DISABLED rules cannot hide an ENABLED one.
            token = None
            while True:
                kw = {'MaxResults': 100}
                if token:
                    kw['NextToken'] = token
                r = self.shClient.list_automation_rules(**kw)
                for m in r.get('AutomationRulesMetadata', []) or []:
                    if (m.get('RuleStatus') or '') == 'ENABLED':
                        return f"automation rule {m.get('RuleName', '')}".strip()
                token = r.get('NextToken')
                if not token:
                    return None

        def eventRules():
            if self.eventsClient is None:
                errors.append('EventBridge client unavailable')
                return None
            candidates = []
            pag = self.eventsClient.get_paginator('list_rules')
            for page in pag.paginate(EventBusName='default'):
                for r in page.get('Rules', []) or []:
                    if (r.get('State') or '') not in self.EB_ENABLED_STATES:
                        continue
                    pattern = r.get('EventPattern')
                    if pattern and r.get('Name') and EventbridgeRegional.patternMatchesSource(
                            pattern, 'aws.securityhub', self.SH_RESPONSE_DETAIL_TYPES):
                        candidates.append(r['Name'])
            for name in candidates:
                try:
                    tpag = self.eventsClient.get_paginator('list_targets_by_rule')
                    for tpage in tpag.paginate(Rule=name, EventBusName='default'):
                        if tpage.get('Targets'):
                            return f"EventBridge rule {name}"
                except botocore.exceptions.ClientError as e:
                    ## Rule deleted between the two calls.
                    if self._errCode(e) != 'ResourceNotFoundException':
                        raise
            return None

        for fn in (rules, eventRules):
            ev = _first(fn)
            if ev:
                return ev, errors
        return None, errors

    def _centralisedElsewhere(self):
        """
        (reason, errorCode). reason is set when automation for this Region's
        findings is owned elsewhere: the account is an active Security Hub
        member (automation rules can only be created by the administrator), or
        cross-Region aggregation links this Region into another aggregation
        Region (automation rules apply in the aggregation Region). errorCode is
        set when this could not be determined.
        """
        firstErr = None
        try:
            admin = self.shClient.get_administrator_account().get('Administrator') or {}
            if admin.get('AccountId') and \
                    str(admin.get('MemberStatus', '')).lower() in ('enabled', 'associated'):
                return (f"this account is a member of Security Hub administrator "
                        f"{admin['AccountId']}, which owns automation rules"), None
        except botocore.exceptions.ClientError as e:
            firstErr = f"get_administrator_account: {self._errCode(e)}"
        except botocore.exceptions.BotoCoreError as e:
            firstErr = f"get_administrator_account: {type(e).__name__}"

        if self.aggregatorsError:
            return None, firstErr or f"list_finding_aggregators: {self.aggregatorsError}"
        region = self.detail.get('_region')
        for a in self.aggregators:
            arn = a.get('FindingAggregatorArn')
            if not arn:
                continue
            try:
                agg = self.shClient.get_finding_aggregator(FindingAggregatorArn=arn)
            except botocore.exceptions.ClientError as e:
                firstErr = firstErr or f"get_finding_aggregator: {self._errCode(e)}"
                continue
            except botocore.exceptions.BotoCoreError as e:
                firstErr = firstErr or f"get_finding_aggregator: {type(e).__name__}"
                continue
            aggRegion = agg.get('FindingAggregationRegion')
            if not aggRegion or aggRegion == region:
                continue
            mode = agg.get('RegionLinkingMode')
            regions = agg.get('Regions') or []
            if (mode == 'ALL_REGIONS'
                    or (mode == 'ALL_REGIONS_EXCEPT_SPECIFIED' and region not in regions)
                    or (mode == 'SPECIFIED_REGIONS' and region in regions)):
                return (f"Security Hub aggregates this Region's findings into {aggRegion}, "
                        "where automation rules for them are evaluated"), None
        return None, firstErr

    def _checkSecurityHubNoAutomationRules(self):
        key = 'securityHubNoAutomationRules'
        if not self.enabled:
            return self._na(key)
        evidence, errors = self._automationEvidence()
        if evidence:
            self.results[key] = [
                1, f"Response automation found ({evidence})"
            ]
            return
        central, centralErr = self._centralisedElsewhere()
        if central:
            self.results[key] = [
                0,
                "No local automation rule or EventBridge rule responds to Security Hub "
                f"findings, but {central} — evaluate finding response there"
            ]
            return
        if errors:
            self.results[key] = [0, f"Unable to evaluate ({errors[0]})"]
            return
        if centralErr:
            self.results[key] = [
                0,
                f"Unable to evaluate ({centralErr}) — no local response automation found, "
                "but it could not be determined whether a Security Hub administrator "
                "account or aggregation Region owns finding response"
            ]
            return
        self.results[key] = [
            -1,
            "No ENABLED Security Hub automation rule and no ENABLED EventBridge rule with a "
            "target matching Security Hub finding events on the default bus — findings appear "
            "to be handled entirely by hand"
        ]

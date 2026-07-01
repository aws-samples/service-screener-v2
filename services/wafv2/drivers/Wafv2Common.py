from services.Evaluator import Evaluator


class Wafv2Common(Evaluator):
    """
    All 12 WAFv2 checks.

    Input:
      acl -- dict produced by Wafv2.py._describeWebAcl. Keys:
        '_arn', '_name', '_id', '_scope', '_webAcl' (raw GetWebACL.WebACL body),
        '_loggingConfiguration' (dict or None), '_associatedResources' (list of
        ARNs), '_tags' (list of {'Key','Value'}).
      wafClient -- boto3 wafv2 client (unused today but kept for future extension).
    """

    # Statement keys that identify a "grouped" rule (managed OR custom rule
    # group) whose action is controlled via OverrideAction, not Action.
    # We deliberately exclude these from wafv2RulesInCountMode so managed
    # groups in Count mode are not double-flagged (they are handled by
    # wafv2NoManagedRuleGroups instead).
    RULE_GROUP_STATEMENT_KEYS = (
        'ManagedRuleGroupStatement',
        'RuleGroupReferenceStatement',
    )

    # Statement key that identifies a managed rule group at any nesting depth.
    MANAGED_RG_KEY = 'ManagedRuleGroupStatement'
    RATE_BASED_KEY = 'RateBasedStatement'

    # Statement types whose sub-rules we descend into. Rate-based rules
    # optionally hold a ScopeDownStatement; And/Or/Not compose others.
    NESTED_STATEMENT_KEYS = ('AndStatement', 'OrStatement', 'NotStatement')

    def __init__(self, acl, wafClient):
        super().__init__()
        self.acl = acl
        self.wafClient = wafClient

        self._resourceName = acl.get('_name', 'unknown')
        self.webAcl = acl.get('_webAcl') or {}
        self.rules = self.webAcl.get('Rules') or []
        self.visibility = self.webAcl.get('VisibilityConfig') or {}
        self.defaultAction = self.webAcl.get('DefaultAction') or {}
        self.loggingConfig = acl.get('_loggingConfiguration')
        self.associatedResources = acl.get('_associatedResources') or []
        self.associationLookupFailed = bool(acl.get('_associationLookupFailed'))

        self.addII('name', self._resourceName)
        self.addII('arn', acl.get('_arn', 'N/A'))
        self.addII('id', acl.get('_id', 'N/A'))
        self.addII('scope', acl.get('_scope', 'N/A'))
        self.addII('capacity', self.webAcl.get('Capacity', 'N/A'))
        self.addII('ruleCount', len(self.rules))
        self.addII('defaultAction', self._describeAction(self.defaultAction))
        self.addII('managedByFirewallManager',
                   'true' if self.webAcl.get('ManagedByFirewallManager') else 'false')
        self.addII('loggingConfigured', 'true' if self.loggingConfig else 'false')
        self.addII('associatedResourceCount', len(self.associatedResources))

    # ------------------------------------------------------------------ #
    # 1. Empty WebACL (no rules)
    # ------------------------------------------------------------------ #
    def _checkWafv2NoRules(self):
        if not self.rules:
            self.results['wafv2NoRules'] = [-1, "WebACL has 0 rules configured"]
        else:
            self.results['wafv2NoRules'] = [
                1, f"{len(self.rules)} rule(s) configured"
            ]

    # ------------------------------------------------------------------ #
    # 2. No managed rule groups
    # ------------------------------------------------------------------ #
    def _checkWafv2NoManagedRuleGroups(self):
        if not self.rules:
            # Redundant with #1 — skip to avoid double-counting.
            self.results['wafv2NoManagedRuleGroups'] = [
                0, "WebACL has no rules — see wafv2NoRules"
            ]
            return

        managed = [
            r for r in self.rules
            if self._statementContainsKey(r.get('Statement') or {}, self.MANAGED_RG_KEY)
        ]
        if managed:
            names = [r.get('Name', '?') for r in managed]
            self.results['wafv2NoManagedRuleGroups'] = [
                1, f"{len(managed)} managed rule group(s): {', '.join(names[:5])}"
            ]
        else:
            self.results['wafv2NoManagedRuleGroups'] = [
                -1, "No managed rule groups (AWS or Marketplace) attached"
            ]

    # ------------------------------------------------------------------ #
    # 3. No rate-based rules
    # ------------------------------------------------------------------ #
    def _checkWafv2NoRateBasedRules(self):
        if not self.rules:
            self.results['wafv2NoRateBasedRules'] = [
                0, "WebACL has no rules — see wafv2NoRules"
            ]
            return

        rate = [
            r for r in self.rules
            if self._statementContainsKey(r.get('Statement') or {}, self.RATE_BASED_KEY)
        ]
        if rate:
            names = [r.get('Name', '?') for r in rate]
            self.results['wafv2NoRateBasedRules'] = [
                1, f"{len(rate)} rate-based rule(s): {', '.join(names[:5])}"
            ]
        else:
            self.results['wafv2NoRateBasedRules'] = [
                -1, "No rate-based rules configured"
            ]

    # ------------------------------------------------------------------ #
    # 4. Custom (non-managed) rules in COUNT mode
    #
    #    We deliberately EXCLUDE ManagedRuleGroupStatement and
    #    RuleGroupReferenceStatement here. Those "grouped" rules are governed
    #    by OverrideAction and their absence / count-override is already
    #    handled by wafv2NoManagedRuleGroups. This check focuses on inline
    #    custom rules with Action=Count, which are the ones most likely to
    #    have been left in tuning-mode by accident.
    # ------------------------------------------------------------------ #
    def _checkWafv2RulesInCountMode(self):
        if not self.rules:
            self.results['wafv2RulesInCountMode'] = [
                0, "WebACL has no rules — see wafv2NoRules"
            ]
            return

        count_rules = []
        skipped_managed = 0
        for r in self.rules:
            name = r.get('Name', '?')
            stmt = r.get('Statement') or {}

            # Skip rule-group rules — they're governed by OverrideAction,
            # not Action, and are handled by wafv2NoManagedRuleGroups.
            if self._topLevelStatementIsRuleGroup(stmt):
                override = r.get('OverrideAction') or {}
                if 'Count' in override:
                    skipped_managed += 1
                continue

            action = r.get('Action') or {}
            if 'Count' in action:
                count_rules.append(name)

        if count_rules:
            msg = f"Custom rule(s) in COUNT mode: {', '.join(count_rules[:5])}"
            if len(count_rules) > 5:
                msg += f" (+{len(count_rules)-5} more)"
            if skipped_managed:
                msg += (f" [note: {skipped_managed} managed/reference rule(s) "
                        "also in Count — see wafv2NoManagedRuleGroups]")
            self.results['wafv2RulesInCountMode'] = [-1, msg]
        else:
            hint = ""
            if skipped_managed:
                hint = (f" (note: {skipped_managed} managed/reference rule(s) "
                        "in Count — see wafv2NoManagedRuleGroups)")
            self.results['wafv2RulesInCountMode'] = [
                1, "No custom rules stuck in COUNT mode" + hint
            ]

    # ------------------------------------------------------------------ #
    # 5. Default action ALLOW with no blocking rules (pass-through WAF)
    #
    #    A rule can block only via its top-level Action (Block/Captcha/Challenge)
    #    or, for grouped rules, by OverrideAction != Count. Blocking is a
    #    property of the top-level rule structure, not of nested match
    #    conditions — but we do use the recursive walker to detect managed
    #    rule groups nested inside And/Or/Not/RateBased.ScopeDown so a WebACL
    #    whose only blocking rule is composed still passes.
    # ------------------------------------------------------------------ #
    def _checkWafv2DefaultActionAllow(self):
        if 'Allow' not in self.defaultAction:
            self.results['wafv2DefaultActionAllow'] = [
                1, f"DefaultAction={self._describeAction(self.defaultAction)}"
            ]
            return

        # DefaultAction is Allow — check that at least one rule can block/challenge/captcha.
        blocking = []
        for r in self.rules:
            action = r.get('Action') or {}
            if any(k in action for k in ('Block', 'Captcha', 'Challenge')):
                blocking.append(r.get('Name', '?'))
                continue

            # Grouped rules: managed OR custom rule group. If OverrideAction !=
            # Count, the group's own actions apply (which include blocks in
            # every AWS-managed core rule set). Search the statement tree
            # recursively so composed groups also count.
            override = r.get('OverrideAction') or {}
            stmt = r.get('Statement') or {}
            if self._topLevelStatementIsRuleGroup(stmt) and 'Count' not in override:
                blocking.append(r.get('Name', '?') + " (rule group)")
                continue
            # Also catch managed rule groups nested inside And/Or/Not/RateBased.
            if (self._statementContainsKey(stmt, self.MANAGED_RG_KEY)
                    and 'Count' not in override):
                blocking.append(r.get('Name', '?') + " (nested managed group)")

        if blocking:
            self.results['wafv2DefaultActionAllow'] = [
                1,
                f"DefaultAction=Allow but {len(blocking)} rule(s) block: "
                f"{', '.join(blocking[:5])}"
                + (f" (+{len(blocking)-5} more)" if len(blocking) > 5 else "")
            ]
        else:
            self.results['wafv2DefaultActionAllow'] = [
                -1,
                "DefaultAction=Allow and no rule blocks/captchas/challenges — pass-through WAF"
            ]

    # ------------------------------------------------------------------ #
    # 6. Logging not configured
    # ------------------------------------------------------------------ #
    def _checkWafv2LoggingNotConfigured(self):
        if self.loggingConfig:
            dests = self.loggingConfig.get('LogDestinationConfigs') or []
            self.results['wafv2LoggingNotConfigured'] = [
                1, f"Logging configured with {len(dests)} destination(s)"
            ]
        else:
            self.results['wafv2LoggingNotConfigured'] = [
                -1, "No logging configuration (GetLoggingConfiguration → nonexistent)"
            ]

    # ------------------------------------------------------------------ #
    # 7. Logging filter effectively drops everything
    # ------------------------------------------------------------------ #
    def _checkWafv2LoggingFilterAllDrop(self):
        if not self.loggingConfig:
            self.results['wafv2LoggingFilterAllDrop'] = [
                0, "Logging not configured — see wafv2LoggingNotConfigured"
            ]
            return

        lf = self.loggingConfig.get('LoggingFilter') or {}
        if not lf:
            self.results['wafv2LoggingFilterAllDrop'] = [
                1, "No LoggingFilter (all traffic logged)"
            ]
            return

        default_behavior = lf.get('DefaultBehavior', 'KEEP')
        filters = lf.get('Filters') or []

        if default_behavior == 'DROP':
            # DefaultBehavior=DROP means only Filters with Behavior=KEEP escape
            # the drop. If there are no KEEP filters, nothing is ever logged.
            keep_filters = [f for f in filters if f.get('Behavior') == 'KEEP']
            if not keep_filters:
                self.results['wafv2LoggingFilterAllDrop'] = [
                    -1, "LoggingFilter: DefaultBehavior=DROP with no KEEP filters — nothing logged"
                ]
                return

        self.results['wafv2LoggingFilterAllDrop'] = [
            1,
            f"LoggingFilter: DefaultBehavior={default_behavior}, {len(filters)} filter(s)"
        ]

    # ------------------------------------------------------------------ #
    # 8. CloudWatch metrics disabled at WebACL level
    # ------------------------------------------------------------------ #
    def _checkWafv2CloudWatchMetricsDisabled(self):
        if self.visibility.get('CloudWatchMetricsEnabled'):
            self.results['wafv2CloudWatchMetricsDisabled'] = [
                1, "CloudWatchMetricsEnabled=true"
            ]
        else:
            self.results['wafv2CloudWatchMetricsDisabled'] = [
                -1, "CloudWatchMetricsEnabled=false on WebACL VisibilityConfig"
            ]

    # ------------------------------------------------------------------ #
    # 9. Sampled requests disabled at WebACL level
    # ------------------------------------------------------------------ #
    def _checkWafv2SampledRequestsDisabled(self):
        if self.visibility.get('SampledRequestsEnabled'):
            self.results['wafv2SampledRequestsDisabled'] = [
                1, "SampledRequestsEnabled=true"
            ]
        else:
            self.results['wafv2SampledRequestsDisabled'] = [
                -1, "SampledRequestsEnabled=false on WebACL VisibilityConfig"
            ]

    # ------------------------------------------------------------------ #
    # 10. Per-rule visibility disabled
    # ------------------------------------------------------------------ #
    def _checkWafv2RuleVisibilityDisabled(self):
        if not self.rules:
            self.results['wafv2RuleVisibilityDisabled'] = [
                0, "WebACL has no rules — see wafv2NoRules"
            ]
            return

        offending = []
        for r in self.rules:
            name = r.get('Name', '?')
            vc = r.get('VisibilityConfig') or {}
            problems = []
            if not vc.get('CloudWatchMetricsEnabled'):
                problems.append("CW=off")
            if not vc.get('SampledRequestsEnabled'):
                problems.append("Sampled=off")
            if problems:
                offending.append(f"{name}({','.join(problems)})")

        if offending:
            self.results['wafv2RuleVisibilityDisabled'] = [
                -1, f"Rule(s) with visibility off: {', '.join(offending[:5])}"
                + (f" (+{len(offending)-5} more)" if len(offending) > 5 else "")
            ]
        else:
            self.results['wafv2RuleVisibilityDisabled'] = [
                1, "All rules have full VisibilityConfig"
            ]

    # ------------------------------------------------------------------ #
    # 11. WebACL not associated with any resource
    #
    #    Downgrades to INFO if the underlying association lookup was denied
    #    (cloudfront:ListDistributionsByWebACLId or wafv2:ListResourcesForWebACL)
    #    so we don't false-positive on a missing IAM permission.
    # ------------------------------------------------------------------ #
    def _checkWafv2NotAssociated(self):
        n = len(self.associatedResources)
        if self.associationLookupFailed and n == 0:
            self.results['wafv2NotAssociated'] = [
                0,
                "Association could not be determined — missing "
                "cloudfront:ListDistributionsByWebACLId or "
                "wafv2:ListResourcesForWebACL permission"
            ]
            return

        if n == 0:
            self.results['wafv2NotAssociated'] = [
                -1, "WebACL is not associated with any resource"
            ]
        else:
            suffix = ""
            if self.associationLookupFailed:
                # We found SOME associations but at least one lookup was denied —
                # be honest about partial data.
                suffix = " (partial; some lookups were denied)"
            self.results['wafv2NotAssociated'] = [
                1, f"Associated with {n} resource(s){suffix}"
            ]

    # ------------------------------------------------------------------ #
    # 12. No tags
    # ------------------------------------------------------------------ #
    def _checkWafv2ResourcesWithoutTags(self):
        tags = self.acl.get('_tags') or []
        if not tags:
            self.results['wafv2ResourcesWithoutTags'] = [-1, "No tags applied"]
        else:
            keys = [t.get('Key') for t in tags if t.get('Key')]
            self.results['wafv2ResourcesWithoutTags'] = [
                1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _describeAction(action):
        """Return a short label for an Action dict like {'Allow': {}}."""
        if not action or not isinstance(action, dict):
            return 'None'
        keys = list(action.keys())
        return keys[0] if keys else 'None'

    def _topLevelStatementIsRuleGroup(self, statement):
        """
        Return True if the rule's TOP-LEVEL Statement is a managed rule group
        or custom rule-group reference. These rules are governed by
        OverrideAction, not Action, and we treat them as a single unit for
        the RulesInCountMode / DefaultActionAllow checks.
        """
        if not isinstance(statement, dict):
            return False
        return any(k in statement for k in self.RULE_GROUP_STATEMENT_KEYS)

    def _statementContainsKey(self, statement, key):
        """
        Return True if `key` appears anywhere in a nested rule Statement dict.

        Descends into:
          - AndStatement.Statements[*]
          - OrStatement.Statements[*]
          - NotStatement.Statement
          - RateBasedStatement.ScopeDownStatement

        This handles the composition patterns that AWS WAFv2 allows for rule
        statements. If AWS adds new composite statement types in future, they
        will simply not be descended into (safe default).
        """
        if not isinstance(statement, dict):
            return False
        if key in statement:
            return True

        for nk in self.NESTED_STATEMENT_KEYS:
            sub = statement.get(nk)
            if not sub:
                continue
            if nk == 'NotStatement':
                # NotStatement wraps a single Statement dict under 'Statement'
                inner = sub.get('Statement') if isinstance(sub, dict) else None
                if inner and self._statementContainsKey(inner, key):
                    return True
            else:
                # And/Or wrap a list under 'Statements'
                for inner in (sub.get('Statements') or []):
                    if self._statementContainsKey(inner, key):
                        return True

        # RateBasedStatement.ScopeDownStatement
        rb = statement.get('RateBasedStatement')
        if isinstance(rb, dict):
            sd = rb.get('ScopeDownStatement')
            if sd and self._statementContainsKey(sd, key):
                return True

        return False

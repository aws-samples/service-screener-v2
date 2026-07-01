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
    # 13. Missing AWSManagedRulesAmazonIpReputationList
    #
    #    Only flagged when the ACL already uses ≥1 managed rule group.
    #    Empty ACLs are covered by wafv2NoRules / wafv2NoManagedRuleGroups.
    # ------------------------------------------------------------------ #
    IP_REPUTATION_MANAGED_GROUP = 'AWSManagedRulesAmazonIpReputationList'

    def _checkWafv2NoIpReputationList(self):
        managed = self._managedRuleGroupNames()
        if not managed:
            self.results['wafv2NoIpReputationList'] = [
                0, "No managed rule groups — see wafv2NoManagedRuleGroups"
            ]
            return
        if self.IP_REPUTATION_MANAGED_GROUP in managed:
            self.results['wafv2NoIpReputationList'] = [
                1, f"{self.IP_REPUTATION_MANAGED_GROUP} attached"
            ]
        else:
            self.results['wafv2NoIpReputationList'] = [
                -1,
                f"Managed groups present ({', '.join(sorted(managed)[:3])}) "
                f"but no {self.IP_REPUTATION_MANAGED_GROUP}"
            ]

    # ------------------------------------------------------------------ #
    # 14. No SQL-injection protection
    # ------------------------------------------------------------------ #
    SQLI_MANAGED_GROUP = 'AWSManagedRulesSQLiRuleSet'
    SQLI_STATEMENT_KEY = 'SqliMatchStatement'

    def _checkWafv2NoSqlInjectionProtection(self):
        if not self.rules:
            self.results['wafv2NoSqlInjectionProtection'] = [
                0, "WebACL has no rules — see wafv2NoRules"
            ]
            return
        managed = self._managedRuleGroupNames()
        has_managed_sqli = self.SQLI_MANAGED_GROUP in managed
        has_custom_sqli = any(
            self._statementContainsKey(r.get('Statement') or {}, self.SQLI_STATEMENT_KEY)
            for r in self.rules
        )
        if has_managed_sqli:
            self.results['wafv2NoSqlInjectionProtection'] = [
                1, f"{self.SQLI_MANAGED_GROUP} attached"
            ]
        elif has_custom_sqli:
            self.results['wafv2NoSqlInjectionProtection'] = [
                1, "Custom rule with SqliMatchStatement present"
            ]
        else:
            self.results['wafv2NoSqlInjectionProtection'] = [
                -1,
                "No SQLi protection: neither AWSManagedRulesSQLiRuleSet nor "
                "custom SqliMatchStatement"
            ]

    # ------------------------------------------------------------------ #
    # 15. No XSS protection
    # ------------------------------------------------------------------ #
    XSS_STATEMENT_KEY = 'XssMatchStatement'
    # Managed groups that cover XSS: CommonRuleSet includes cross-site rules
    # in its body/query-string set. We accept it as XSS coverage.
    XSS_MANAGED_GROUPS = ('AWSManagedRulesCommonRuleSet',)

    def _checkWafv2NoXssProtection(self):
        if not self.rules:
            self.results['wafv2NoXssProtection'] = [
                0, "WebACL has no rules — see wafv2NoRules"
            ]
            return
        managed = self._managedRuleGroupNames()
        managed_xss = [g for g in self.XSS_MANAGED_GROUPS if g in managed]
        has_custom_xss = any(
            self._statementContainsKey(r.get('Statement') or {}, self.XSS_STATEMENT_KEY)
            for r in self.rules
        )
        if managed_xss:
            self.results['wafv2NoXssProtection'] = [
                1, f"XSS coverage via {', '.join(managed_xss)}"
            ]
        elif has_custom_xss:
            self.results['wafv2NoXssProtection'] = [
                1, "Custom rule with XssMatchStatement present"
            ]
        else:
            self.results['wafv2NoXssProtection'] = [
                -1,
                "No XSS protection: no CommonRuleSet coverage and no "
                "custom XssMatchStatement"
            ]

    # ------------------------------------------------------------------ #
    # 16. Capacity usage > 80% of scope limit
    # ------------------------------------------------------------------ #
    WCU_LIMIT_BY_SCOPE = {'REGIONAL': 5000, 'CLOUDFRONT': 1500}
    WCU_THRESHOLD = 0.80

    def _checkWafv2HighCapacityUsage(self):
        capacity = self.webAcl.get('Capacity')
        if not isinstance(capacity, (int, float)) or capacity <= 0:
            self.results['wafv2HighCapacityUsage'] = [
                0, "Capacity not reported by GetWebACL"
            ]
            return

        scope = self.acl.get('_scope', 'REGIONAL')
        limit = self.WCU_LIMIT_BY_SCOPE.get(scope, 5000)
        pct = capacity / limit
        if pct >= self.WCU_THRESHOLD:
            self.results['wafv2HighCapacityUsage'] = [
                -1,
                f"WCU usage {int(capacity)}/{limit} ({pct*100:.0f}%) — near {scope} limit"
            ]
        else:
            self.results['wafv2HighCapacityUsage'] = [
                1,
                f"WCU usage {int(capacity)}/{limit} ({pct*100:.0f}%)"
            ]

    # ------------------------------------------------------------------ #
    # Helper: collect every ManagedRuleGroupStatement.Name in the WebACL
    # (top-level rules only — nesting managed groups inside And/Or/Not is
    # legal but rare, and CommonRuleSet et al. are always applied at top
    # level in practice).
    # ------------------------------------------------------------------ #
    def _managedRuleGroupNames(self):
        names = set()
        for r in self.rules:
            stmt = r.get('Statement') or {}
            mrg = stmt.get(self.MANAGED_RG_KEY)
            if isinstance(mrg, dict):
                name = mrg.get('Name')
                if name:
                    names.add(name)
        return names

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

    # ------------------------------------------------------------------ #
    # 17. Managed rule group with ALL rules overridden to Count / excluded
    # ------------------------------------------------------------------ #
    def _checkWafv2ManagedRuleGroupAllCountOverride(self):
        mrg_details = self.acl.get('_managedRuleGroupDetails') or {}
        offenders = []
        for r in self.rules:
            stmt = r.get('Statement') or {}
            mrg = stmt.get(self.MANAGED_RG_KEY)
            if not isinstance(mrg, dict):
                continue
            name = mrg.get('Name')
            vendor = mrg.get('VendorName')
            key = (vendor, name)
            info = mrg_details.get(key) or {}
            total = info.get('total_rules')

            excluded = mrg.get('ExcludedRules') or []
            overrides = mrg.get('RuleActionOverrides') or []
            count_overrides = [
                o for o in overrides
                if isinstance(o, dict) and 'Count' in (o.get('ActionToUse') or {})
            ]

            all_neutered = False
            if isinstance(total, int) and total > 0:
                affected = {e.get('Name') for e in excluded if isinstance(e, dict)}
                affected.update({o.get('Name') for o in count_overrides if isinstance(o, dict)})
                if len(affected) >= total:
                    all_neutered = True
            else:
                # We couldn't count total rules; fall back to "override count is
                # very large" heuristic — only fire when both lists together
                # look excessive (>10 entries) as a conservative signal.
                if len(excluded) + len(count_overrides) >= 20:
                    all_neutered = True

            if all_neutered:
                offenders.append(f"{r.get('Name','?')}[{vendor}/{name}]")

        if offenders:
            self.results['wafv2ManagedRuleGroupAllCountOverride'] = [
                -1,
                f"Managed group(s) with every rule neutered: {', '.join(offenders[:3])}"
                + (f" (+{len(offenders)-3} more)" if len(offenders) > 3 else "")
            ]
        else:
            self.results['wafv2ManagedRuleGroupAllCountOverride'] = [
                1, "No managed rule groups with blanket Count/Excluded overrides"
            ]

    # ------------------------------------------------------------------ #
    # 18. Missing Core Rule Set
    # ------------------------------------------------------------------ #
    CORE_RULE_SET = 'AWSManagedRulesCommonRuleSet'

    def _checkWafv2NoCoreRuleSet(self):
        managed = self._managedRuleGroupNames()
        if not managed:
            self.results['wafv2NoCoreRuleSet'] = [
                0, "No managed rule groups — see wafv2NoManagedRuleGroups"
            ]
            return
        if self.CORE_RULE_SET in managed:
            self.results['wafv2NoCoreRuleSet'] = [
                1, f"{self.CORE_RULE_SET} attached"
            ]
        else:
            self.results['wafv2NoCoreRuleSet'] = [
                -1,
                f"Managed groups present ({', '.join(sorted(managed)[:3])}) "
                f"but no {self.CORE_RULE_SET}"
            ]

    # ------------------------------------------------------------------ #
    # 19. Allow-action rule ordered before a managed rule group
    # ------------------------------------------------------------------ #
    def _checkWafv2AllowRuleBeforeManagedRules(self):
        if not self.rules:
            self.results['wafv2AllowRuleBeforeManagedRules'] = [
                0, "WebACL has no rules"
            ]
            return

        # Priority is an int; lower runs first.
        managed_priorities = []
        for r in self.rules:
            stmt = r.get('Statement') or {}
            if self.MANAGED_RG_KEY in stmt or 'RuleGroupReferenceStatement' in stmt:
                p = r.get('Priority')
                if isinstance(p, int):
                    managed_priorities.append(p)
        if not managed_priorities:
            self.results['wafv2AllowRuleBeforeManagedRules'] = [
                0, "No managed/reference rule groups to order against"
            ]
            return

        earliest_managed = min(managed_priorities)
        offenders = []
        for r in self.rules:
            action = r.get('Action') or {}
            if 'Allow' not in action:
                continue
            p = r.get('Priority')
            if isinstance(p, int) and p < earliest_managed:
                offenders.append(f"{r.get('Name','?')}(prio={p})")

        if offenders:
            self.results['wafv2AllowRuleBeforeManagedRules'] = [
                -1,
                f"Allow rule(s) run BEFORE managed groups (earliest managed prio={earliest_managed}): "
                + ", ".join(offenders[:5])
            ]
        else:
            self.results['wafv2AllowRuleBeforeManagedRules'] = [
                1, "All Allow rules run after managed groups"
            ]

    # ------------------------------------------------------------------ #
    # 20. Managed rule group version pinned (with expiry escalation)
    # ------------------------------------------------------------------ #
    import datetime as _dt_module
    PINNED_VERSION_EXPIRY_DAYS = 30

    def _checkWafv2ManagedRuleGroupVersionPinned(self):
        mrg_details = self.acl.get('_managedRuleGroupDetails') or {}
        pinned = []           # (rule_name, group, version_name)
        expiring = []         # (rule_name, group, version_name, days)
        for r in self.rules:
            stmt = r.get('Statement') or {}
            mrg = stmt.get(self.MANAGED_RG_KEY)
            if not isinstance(mrg, dict):
                continue
            ver = mrg.get('VersionName') or mrg.get('Version')
            if not ver:
                continue
            vendor = mrg.get('VendorName')
            name = mrg.get('Name')
            pinned.append((r.get('Name', '?'), name, ver))

            # Check expiry
            info = mrg_details.get((vendor, name)) or {}
            for v in info.get('versions', []) or []:
                if v.get('Name') != ver:
                    continue
                exp = v.get('ExpiryTimestamp')
                if not exp:
                    break
                exp_dt = self._parseAwsDatetime(exp)
                if exp_dt is None:
                    break
                days = (exp_dt - self._dt_module.datetime.now(self._dt_module.timezone.utc)).days
                if days <= self.PINNED_VERSION_EXPIRY_DAYS:
                    expiring.append((r.get('Name', '?'), name, ver, days))
                break

        if expiring:
            self.results['wafv2ManagedRuleGroupVersionPinned'] = [
                -1,
                "Pinned managed group version expiring soon: "
                + ", ".join([f"{rn}[{g}={v},{d}d]" for rn, g, v, d in expiring[:3]])
            ]
        elif pinned:
            self.results['wafv2ManagedRuleGroupVersionPinned'] = [
                0,
                f"{len(pinned)} managed group version(s) pinned (informational): "
                + ", ".join([f"{rn}[{g}={v}]" for rn, g, v in pinned[:3]])
            ]
        else:
            self.results['wafv2ManagedRuleGroupVersionPinned'] = [
                1, "No pinned managed rule group versions"
            ]

    @classmethod
    def _parseAwsDatetime(cls, val):
        dt = cls._dt_module
        if isinstance(val, dt.datetime):
            return val if val.tzinfo else val.replace(tzinfo=dt.timezone.utc)
        if isinstance(val, str):
            try:
                p = dt.datetime.fromisoformat(val.replace('Z', '+00:00'))
                return p if p.tzinfo else p.replace(tzinfo=dt.timezone.utc)
            except ValueError:
                return None
        return None

    # ------------------------------------------------------------------ #
    # 21. Bot Control not attached (informational for internet-facing ACLs)
    # ------------------------------------------------------------------ #
    BOT_CONTROL_GROUP = 'AWSManagedRulesBotControlRuleSet'

    def _checkWafv2NoBotControl(self):
        if not self.associatedResources:
            self.results['wafv2NoBotControl'] = [
                0, "WebACL is not associated with any resource (see wafv2NotAssociated)"
            ]
            return
        if self.BOT_CONTROL_GROUP in self._managedRuleGroupNames():
            self.results['wafv2NoBotControl'] = [
                1, f"{self.BOT_CONTROL_GROUP} attached"
            ]
        else:
            self.results['wafv2NoBotControl'] = [
                0,
                f"No {self.BOT_CONTROL_GROUP} on this internet-facing WebACL "
                "(paid add-on — informational)"
            ]

    # ------------------------------------------------------------------ #
    # 22. Rate-based rule threshold too high
    # ------------------------------------------------------------------ #
    RATE_LIMIT_THRESHOLD = 10000

    def _checkWafv2RateBasedRuleThresholdTooHigh(self):
        offenders = []
        found = 0
        for r in self.rules:
            stmt = r.get('Statement') or {}
            rb = stmt.get(self.RATE_BASED_KEY)
            if not isinstance(rb, dict):
                continue
            found += 1
            limit = rb.get('Limit')
            if isinstance(limit, int) and limit > self.RATE_LIMIT_THRESHOLD:
                offenders.append(f"{r.get('Name','?')}(limit={limit})")
        if found == 0:
            self.results['wafv2RateBasedRuleThresholdTooHigh'] = [
                0, "No rate-based rules — see wafv2NoRateBasedRules"
            ]
        elif offenders:
            self.results['wafv2RateBasedRuleThresholdTooHigh'] = [
                -1,
                f"Rate-based rule Limit > {self.RATE_LIMIT_THRESHOLD}: "
                + ", ".join(offenders[:5])
            ]
        else:
            self.results['wafv2RateBasedRuleThresholdTooHigh'] = [
                1, f"All {found} rate-based rule Limit(s) ≤ {self.RATE_LIMIT_THRESHOLD}"
            ]

    # ------------------------------------------------------------------ #
    # 23. LoggingFilter drops BLOCK-action requests
    # ------------------------------------------------------------------ #
    def _checkWafv2LoggingFilterDropsBlocked(self):
        if not self.loggingConfig:
            self.results['wafv2LoggingFilterDropsBlocked'] = [
                0, "Logging not configured"
            ]
            return
        lf = self.loggingConfig.get('LoggingFilter') or {}
        if not lf:
            self.results['wafv2LoggingFilterDropsBlocked'] = [
                1, "No LoggingFilter (all traffic logged)"
            ]
            return
        # A filter DROPS blocked requests if a Behavior=DROP filter matches
        # on ActionCondition.Action=BLOCK.
        drops_blocked = []
        for f in lf.get('Filters', []) or []:
            if f.get('Behavior') != 'DROP':
                continue
            for cond in (f.get('Conditions') or []):
                ac = cond.get('ActionCondition')
                if isinstance(ac, dict) and ac.get('Action') == 'BLOCK':
                    drops_blocked.append(f)
                    break
        if drops_blocked:
            self.results['wafv2LoggingFilterDropsBlocked'] = [
                -1,
                f"LoggingFilter DROPs BLOCK actions ({len(drops_blocked)} filter(s))"
            ]
        else:
            self.results['wafv2LoggingFilterDropsBlocked'] = [
                1, "LoggingFilter does not drop BLOCK actions"
            ]

    # ------------------------------------------------------------------ #
    # 24. Allow-listed IP set with overly-broad CIDR
    # ------------------------------------------------------------------ #
    IPV4_BROAD_PREFIX = 8   # /8 or shorter is considered too broad
    IPV6_BROAD_PREFIX = 32  # /32 or shorter is considered too broad for IPv6

    def _checkWafv2IpSetOverlyPermissive(self):
        ipsets = self.acl.get('_ipSets') or {}
        if not ipsets:
            self.results['wafv2IpSetOverlyPermissive'] = [
                0, "No IP sets referenced by this WebACL"
            ]
            return

        # Only inspect IPSets referenced by an ALLOW-action rule.
        allow_ipset_arns = set()
        for r in self.rules:
            action = r.get('Action') or {}
            if 'Allow' not in action:
                continue
            for arn in self._collectIpSetArns(r.get('Statement') or {}):
                allow_ipset_arns.add(arn)
        if not allow_ipset_arns:
            self.results['wafv2IpSetOverlyPermissive'] = [
                0, "IP sets present but none used in Allow-action rules"
            ]
            return

        offenders = []
        for arn in allow_ipset_arns:
            ipset = ipsets.get(arn) or {}
            name = ipset.get('Name', arn.split('/')[-2] if '/' in arn else arn)
            for cidr in ipset.get('Addresses') or []:
                if '/' not in cidr:
                    continue
                addr, _, prefix = cidr.partition('/')
                try:
                    prefix_i = int(prefix)
                except ValueError:
                    continue
                if ':' in addr:
                    if prefix_i <= self.IPV6_BROAD_PREFIX:
                        offenders.append(f"{name}({cidr})")
                else:
                    if prefix_i <= self.IPV4_BROAD_PREFIX:
                        offenders.append(f"{name}({cidr})")

        if offenders:
            self.results['wafv2IpSetOverlyPermissive'] = [
                -1,
                f"Allow-listed IP set with broad CIDR: {', '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['wafv2IpSetOverlyPermissive'] = [
                1, "All allow-listed IP set CIDRs are appropriately narrow"
            ]

    @staticmethod
    def _collectIpSetArns(statement):
        arns = set()
        def walk(stmt):
            if not isinstance(stmt, dict):
                return
            ipset = stmt.get('IPSetReferenceStatement')
            if isinstance(ipset, dict) and ipset.get('ARN'):
                arns.add(ipset['ARN'])
            for k in ('AndStatement', 'OrStatement'):
                sub = stmt.get(k)
                if isinstance(sub, dict):
                    for s in (sub.get('Statements') or []):
                        walk(s)
            nsub = stmt.get('NotStatement')
            if isinstance(nsub, dict):
                walk(nsub.get('Statement'))
            rb = stmt.get('RateBasedStatement')
            if isinstance(rb, dict):
                walk(rb.get('ScopeDownStatement'))
        walk(statement)
        return arns

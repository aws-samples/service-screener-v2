from services.Evaluator import Evaluator


class Route53Resolver(Evaluator):
    """
    Route 53 Resolver checks (per-region).

    Input:
      resolver -- dict from Route53.getResolverConfig(). Keys:
        '_region', '_firewallAssociations', '_queryLogConfigs',
        '_queryLogAssociations', '_dnssecConfigs'.
      resolverClient -- boto3 route53resolver client (unused, kept for parity).
    """

    def __init__(self, resolver, resolverClient):
        super().__init__()
        self.resolver = resolver
        self.resolverClient = resolverClient

        self._resourceName = resolver.get('_region') or 'unknown'

        self.addII('region', self._resourceName)
        self.addII('firewallAssociations',
                   len(resolver.get('_firewallAssociations') or []))
        self.addII('queryLogConfigs',
                   len(resolver.get('_queryLogConfigs') or []))
        self.addII('queryLogAssociations',
                   len(resolver.get('_queryLogAssociations') or []))
        self.addII('dnssecConfigs',
                   len(resolver.get('_dnssecConfigs') or []))

    # ------------------------------------------------------------------ #
    # 9. DNS Firewall not configured
    # ------------------------------------------------------------------ #
    def _checkRoute53ResolverDnsFirewallNotConfigured(self):
        assocs = self.resolver.get('_firewallAssociations') or []
        # Only count active associations (StatusMessage != DELETING, etc.)
        active = [a for a in assocs
                  if (a.get('Status') or '').upper() not in ('DELETING', 'DELETE_FAILED')]
        if active:
            self.results['route53ResolverDnsFirewallNotConfigured'] = [
                1,
                f"{len(active)} DNS Firewall rule group association(s) in "
                f"{self._resourceName}"
            ]
        else:
            self.results['route53ResolverDnsFirewallNotConfigured'] = [
                -1,
                f"No DNS Firewall rule group associations in {self._resourceName}"
            ]

    # ------------------------------------------------------------------ #
    # 10. Resolver query logging not enabled
    # ------------------------------------------------------------------ #
    def _checkRoute53ResolverQueryLoggingNotEnabled(self):
        configs = self.resolver.get('_queryLogConfigs') or []
        assocs = self.resolver.get('_queryLogAssociations') or []
        active_assocs = [
            a for a in assocs
            if (a.get('Status') or '').upper() in
               ('ACTIVE', 'CREATING', 'ACTION_NEEDED', '')  # empty status = unknown, still count
        ]
        if not configs:
            self.results['route53ResolverQueryLoggingNotEnabled'] = [
                -1,
                f"No ResolverQueryLogConfigs in {self._resourceName}"
            ]
            return
        if not active_assocs:
            self.results['route53ResolverQueryLoggingNotEnabled'] = [
                -1,
                f"{len(configs)} query log config(s) exist but no VPCs are "
                f"associated in {self._resourceName}"
            ]
            return
        self.results['route53ResolverQueryLoggingNotEnabled'] = [
            1,
            f"{len(configs)} config(s), {len(active_assocs)} VPC association(s) "
            f"in {self._resourceName}"
        ]

    # ------------------------------------------------------------------ #
    # 11. DNSSEC validation not enabled on Resolver
    # ------------------------------------------------------------------ #
    def _checkRoute53ResolverDnssecValidationDisabled(self):
        configs = self.resolver.get('_dnssecConfigs') or []
        enabled = [c for c in configs
                   if (c.get('ValidationStatus') or '').upper() == 'ENABLED']
        if enabled:
            self.results['route53ResolverDnssecValidationDisabled'] = [
                1,
                f"{len(enabled)} VPC(s) with DNSSEC validation ENABLED in "
                f"{self._resourceName}"
            ]
        else:
            if configs:
                # Configs exist but none are ENABLED — some are DISABLED / UPDATING.
                statuses = ','.join(sorted({
                    (c.get('ValidationStatus') or 'UNKNOWN') for c in configs
                }))
                self.results['route53ResolverDnssecValidationDisabled'] = [
                    -1,
                    f"No VPCs with DNSSEC validation ENABLED in "
                    f"{self._resourceName} (statuses: {statuses})"
                ]
            else:
                self.results['route53ResolverDnssecValidationDisabled'] = [
                    -1,
                    f"No Resolver DNSSEC validation configs in {self._resourceName}"
                ]

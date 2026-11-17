from services.Evaluator import Evaluator


class Route53DnsFirewallVpc(Evaluator):
    """
    Route 53 Resolver DNS Firewall content check, one resource per VPC that has
    at least one active (non-DELETING) DNS Firewall rule group association.

    A VPC is evaluated as a whole: DNS Firewall applies every associated rule
    group in priority order, so a VPC whose rule groups include at least one
    BLOCK rule is enforcing, even if another associated group is ALERT-only.

    Input:
      vpc -- dict from Route53.getDnsFirewallVpcs(). Keys:
        '_region', '_vpcId',
        '_ruleGroups': list of {
            'ruleGroupId', 'associationName', 'rules' (list|None),
            'error' (str|None) }
        '_domainLists': {domainListId: domain-list summary} (may be empty)
        '_domainListsError': str|None
    """

    def __init__(self, vpc, resolverClient):
        super().__init__()
        self.vpc = vpc
        self.resolverClient = resolverClient

        self._resourceName = f"{vpc.get('_region') or 'unknown'}/{vpc.get('_vpcId') or 'unknown'}"

        self.addII('vpcId', vpc.get('_vpcId'))
        self.addII('ruleGroups', [g.get('ruleGroupId') for g in vpc.get('_ruleGroups') or []])

    def _isManagedList(self, domainListId):
        dl = (self.vpc.get('_domainLists') or {}).get(domainListId) or {}
        return bool(dl.get('ManagedOwnerName'))

    # ------------------------------------------------------------------ #
    # DNS Firewall associated, but no rule group BLOCKs anything
    # ------------------------------------------------------------------ #
    def _checkDnsFirewallNoBlockRules(self):
        key = 'dnsFirewallNoBlockRules'
        groups = self.vpc.get('_ruleGroups') or []
        vpcId = self.vpc.get('_vpcId')

        blockRules = []
        errors = []
        actions = set()
        for g in groups:
            if g.get('error'):
                errors.append(g['error'])
                continue
            for r in g.get('rules') or []:
                action = (r.get('Action') or '').upper()
                actions.add(action or 'UNKNOWN')
                if action == 'BLOCK':
                    blockRules.append(r)

        if blockRules:
            managed = [r for r in blockRules
                       if r.get('FirewallThreatProtectionId')
                       or (r.get('FirewallDomainListId')
                           and self._isManagedList(r.get('FirewallDomainListId')))]
            if managed:
                detail = f"{len(managed)} of them use AWS-managed domain lists or DNS Firewall Advanced"
            elif self.vpc.get('_domainListsError'):
                detail = "managed-list usage could not be determined"
            else:
                detail = "none use AWS-managed threat domain lists; consider adding them"
            self.results[key] = [
                1,
                f"VPC {vpcId}: {len(blockRules)} BLOCK rule(s) across "
                f"{len(groups)} associated rule group(s) ({detail})"
            ]
            return

        if errors:
            self.results[key] = [
                0,
                f"Unable to evaluate ({','.join(sorted(set(errors)))}) for VPC {vpcId}"
            ]
            return

        seen = ','.join(sorted(actions)) if actions else 'no rules'
        self.results[key] = [
            -1,
            f"VPC {vpcId}: {len(groups)} associated DNS Firewall rule group(s) "
            f"contain no BLOCK rules (actions: {seen}) - queries are only "
            f"allowed/alerted, never blocked"
        ]

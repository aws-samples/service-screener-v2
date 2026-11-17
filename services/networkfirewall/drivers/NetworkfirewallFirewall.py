from services.Evaluator import Evaluator


DEFAULT_V4 = '0.0.0.0/0'
DEFAULT_V6 = '::/0'


def defaultRoutes(routeTable):
    """Active 0.0.0.0/0 and ::/0 routes of a route table."""
    out = []
    for r in (routeTable or {}).get('Routes', []) or []:
        if r.get('State') == 'blackhole':
            continue
        if r.get('DestinationCidrBlock') == DEFAULT_V4 or r.get('DestinationIpv6CidrBlock') == DEFAULT_V6:
            out.append(r)
    return out


def subnetRouteTables(net):
    """{subnetId: routeTable} using explicit associations, falling back to the
    VPC main route table."""
    main = None
    explicit = {}
    for rt in (net or {}).get('routeTables', []) or []:
        for a in rt.get('Associations', []) or []:
            if a.get('Main'):
                main = rt
            elif a.get('SubnetId'):
                explicit[a['SubnetId']] = rt
    out = {}
    for s in (net or {}).get('subnets', []) or []:
        sid = s.get('SubnetId')
        out[sid] = explicit.get(sid, main)
    return out


class NetworkfirewallFirewall(Evaluator):
    """
    Per-firewall AWS Network Firewall checks.

    Input:
      fw           -- detail from Networkfirewall.getResources (Firewall,
                      FirewallStatus, _logging, _loggingError, _policy,
                      _policyError, or _error when describe_firewall failed)
      net          -- EC2 network inventory of the firewall's VPC (subnets,
                      routeTables, natGateways, gwlbEndpoints) or None
      netError     -- error code if the EC2 inventory could not be read
      fwEndpoints  -- firewall endpoint ids of all firewalls in the VPC

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    REQUIRED_LOG_TYPES = ('ALERT', 'FLOW')
    STATEFUL_DROP_DEFAULTS = ('aws:drop_strict', 'aws:drop_established',
                              'aws:drop_established_app_layer')
    MAX_LISTED = 10

    def __init__(self, fw, net, netError, fwEndpoints):
        super().__init__()
        self.fw = fw
        self.firewall = fw.get('Firewall') or {}
        self.status = fw.get('FirewallStatus') or {}
        self.net = net
        self.netError = netError
        self.fwEndpoints = set(fwEndpoints or [])
        self._resourceName = fw.get('FirewallName') or fw.get('FirewallArn')

        self.addII('firewallArn', fw.get('FirewallArn'))
        self.addII('vpcId', self.firewall.get('VpcId') or 'N/A')
        self.addII('firewallPolicyArn', self.firewall.get('FirewallPolicyArn') or 'N/A')

    def _describeError(self, key):
        if self.fw.get('_error'):
            self.results[key] = [0, f"Unable to evaluate ({self.fw['_error']})"]
            return True
        return False

    # ------------------------------------------------------------------ #
    def _checkNetworkFirewallLoggingDisabled(self):
        key = 'networkFirewallLoggingDisabled'
        if self._describeError(key):
            return
        if self.fw.get('_loggingError'):
            self.results[key] = [0, f"Unable to evaluate ({self.fw['_loggingError']})"]
            return
        configs = (self.fw.get('_logging') or {}).get('LogDestinationConfigs') or []
        present = {c.get('LogType') for c in configs if c.get('LogType')}
        missing = [t for t in self.REQUIRED_LOG_TYPES if t not in present]
        if missing:
            have = ', '.join(sorted(present)) or 'none'
            self.results[key] = [
                -1,
                f"Logging not configured for log type(s): {', '.join(missing)} "
                f"(configured: {have})"
            ]
        else:
            self.results[key] = [1, f"Logging configured for: {', '.join(sorted(present))}"]

    # ------------------------------------------------------------------ #
    def _checkNetworkFirewallPolicyWeak(self):
        key = 'networkFirewallPolicyWeak'
        if self._describeError(key):
            return
        if self.fw.get('_policyError'):
            self.results[key] = [0, f"Unable to evaluate ({self.fw['_policyError']})"]
            return
        policy = self.fw.get('_policy') or {}
        statelessDefault = policy.get('StatelessDefaultActions') or []
        fragmentDefault = policy.get('StatelessFragmentDefaultActions') or []
        statefulRefs = policy.get('StatefulRuleGroupReferences') or []
        statefulDefault = policy.get('StatefulDefaultActions') or []

        problems = []
        if 'aws:pass' in statelessDefault:
            problems.append("StatelessDefaultActions is aws:pass (unmatched packets "
                            "bypass stateful inspection)")
        if 'aws:pass' in fragmentDefault:
            problems.append("StatelessFragmentDefaultActions is aws:pass (unmatched "
                            "fragmented packets bypass stateful inspection)")

        if not statefulRefs:
            ## With no stateful rule groups, traffic reaching the stateful engine
            ## is passed unless a stateful default drop (strict order) is set, or
            ## the stateless default already drops everything unmatched.
            dropsAll = 'aws:drop' in statelessDefault and 'aws:pass' not in statelessDefault
            statefulDrops = any(a in self.STATEFUL_DROP_DEFAULTS for a in statefulDefault)
            if not dropsAll and not statefulDrops:
                problems.append("no stateful rule groups are referenced, so forwarded "
                                "traffic is passed without inspection")

        managed = [r.get('ResourceArn') for r in statefulRefs
                   if ':aws-managed:' in (r.get('ResourceArn') or '')]

        if problems:
            self.results[key] = [-1, 'Weak firewall policy: ' + '; '.join(problems)]
        elif statefulRefs and not managed:
            self.results[key] = [
                1,
                f"{len(statefulRefs)} stateful rule group(s) referenced; none are AWS "
                "managed (consider AWS managed threat signature / domain list groups)"
            ]
        else:
            self.results[key] = [
                1,
                f"Stateless default forwards/drops; {len(statefulRefs)} stateful rule "
                f"group(s) referenced ({len(managed)} AWS managed)"
            ]

    # ------------------------------------------------------------------ #
    def _checkNetworkFirewallRouteBypass(self):
        key = 'networkFirewallRouteBypass'
        if self._describeError(key):
            return
        vpcId = self.firewall.get('VpcId')
        if not vpcId:
            self.results[key] = [0, "Firewall is not deployed into a VPC (e.g. transit "
                                    "gateway attachment); route bypass not evaluated"]
            return
        if self.netError:
            self.results[key] = [0, f"Unable to evaluate ({self.netError})"]
            return
        if not self.net:
            self.results[key] = [0, f"Unable to evaluate (VPC {vpcId} not found)"]
            return

        ## Any Gateway Load Balancer endpoint in the VPC counts as an inspection
        ## hop: Network Firewall endpoints (including VPC endpoint associations)
        ## and third-party GWLB appliances are both GWLB endpoints.
        inspection = set(self.fwEndpoints) | set(self.net.get('gwlbEndpoints') or [])
        if not inspection:
            self.results[key] = [0, "Unable to evaluate (firewall endpoints not yet provisioned)"]
            return

        fwSubnets = {m.get('SubnetId') for m in self.firewall.get('SubnetMappings') or []}
        rtBySubnet = subnetRouteTables(self.net)
        natSubnet = {n.get('NatGatewayId'): n.get('SubnetId')
                     for n in self.net.get('natGateways') or []}
        natSubnets = set(natSubnet.values())

        def isInspected(route):
            return route.get('VpcEndpointId') in inspection

        def toInternet(route):
            gw = route.get('GatewayId') or ''
            return gw.startswith('igw-') or bool(route.get('EgressOnlyInternetGatewayId'))

        def hasInspectionReturnRoute(rt):
            return any(r.get('VpcEndpointId') in inspection
                       for r in (rt or {}).get('Routes', []) or []
                       if r.get('State') != 'blackhole')

        bypass = []
        for sid, rt in rtBySubnet.items():
            if sid in fwSubnets or rt is None:
                continue
            for r in defaultRoutes(rt):
                dest = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock')
                if isInspected(r):
                    continue
                if toInternet(r):
                    ## NAT subnet placed after the firewall (protected subnet ->
                    ## firewall -> NAT -> IGW) routes return traffic for the
                    ## protected CIDRs back through the firewall endpoint.
                    if sid in natSubnets and hasInspectionReturnRoute(rt):
                        continue
                    target = r.get('GatewayId') or r.get('EgressOnlyInternetGatewayId')
                    bypass.append(f"{sid} ({dest} -> {target})")
                elif r.get('NatGatewayId'):
                    ## Follow the NAT gateway: bypass when the NAT's own subnet
                    ## sends its default route straight to the internet gateway
                    ## (outbound traffic never meets the firewall, whatever the
                    ## return routes are).
                    nsid = natSubnet.get(r['NatGatewayId'])
                    nrt = rtBySubnet.get(nsid)
                    if nsid is None or nrt is None:
                        continue
                    nroutes = [x for x in defaultRoutes(nrt)
                               if x.get('DestinationCidrBlock') == DEFAULT_V4]
                    if nroutes and all(toInternet(x) for x in nroutes):
                        bypass.append(f"{sid} ({dest} -> {r['NatGatewayId']} -> "
                                      f"{nroutes[0].get('GatewayId')})")
                ## Transit gateway, peering, ENI, VGW etc. targets are not judged:
                ## centralised inspection designs use them legitimately.

        if bypass:
            listed = ', '.join(bypass[:self.MAX_LISTED])
            more = f" and {len(bypass) - self.MAX_LISTED} more" if len(bypass) > self.MAX_LISTED else ''
            self.results[key] = [
                -1,
                f"{len(bypass)} subnet default route(s) in {vpcId} reach the internet "
                f"without passing a firewall endpoint: {listed}{more}"
            ]
        else:
            self.results[key] = [1, f"No subnet in {vpcId} routes to the internet around the firewall"]

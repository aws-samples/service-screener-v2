from services.Evaluator import Evaluator
from services.networkfirewall.drivers.NetworkfirewallFirewall import defaultRoutes


class NetworkfirewallVpc(Evaluator):
    """
    Per-VPC check: an internet-connected VPC with no traffic inspection.

    "Internet-connected" = an internet gateway is attached to the VPC and at
    least one route table in use (the main table or one with a subnet
    association) sends 0.0.0.0/0 or ::/0 to it (or ::/0 to an egress-only
    internet gateway). Inspection is present when a Network
    Firewall is deployed in the VPC or the VPC has any Gateway Load Balancer
    endpoint (Network Firewall endpoints, VPC endpoint associations and
    third-party appliances all surface as GWLB endpoints).

    VPCs that route to the internet only via a transit gateway (centralised
    inspection) are never internet-connected under this definition, and VPCs
    with no network interfaces are not flagged.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    def __init__(self, vpc, net, hasFirewall, listError, hasEni):
        super().__init__()
        self.vpc = vpc
        self.net = net or {}
        self.hasFirewall = hasFirewall
        self.listError = listError
        self.hasEni = hasEni
        self._resourceName = vpc.get('VpcId')

        self.addII('vpcId', vpc.get('VpcId'))
        self.addII('isDefault', str(bool(vpc.get('IsDefault'))))

    @staticmethod
    def internetRoutes(net):
        """Default routes in the VPC that target an attached internet gateway
        or an egress-only internet gateway. Only route tables that subnets
        actually use count: the main route table and tables with at least one
        subnet association. Orphan tables (no associations) and gateway
        edge-associated tables route no subnet traffic to the internet."""
        igws = set((net or {}).get('igws') or [])
        out = []
        for rt in (net or {}).get('routeTables', []) or []:
            assocs = [a for a in rt.get('Associations', []) or []
                      if (a.get('AssociationState') or {}).get('State') not in ('disassociating', 'disassociated')]
            if not any(a.get('Main') or a.get('SubnetId') for a in assocs):
                continue
            for r in defaultRoutes(rt):
                gw = r.get('GatewayId') or ''
                if (gw.startswith('igw-') and gw in igws) or r.get('EgressOnlyInternetGatewayId'):
                    out.append((rt.get('RouteTableId'), gw or r.get('EgressOnlyInternetGatewayId')))
        return out

    def _checkNetworkFirewallNotDeployed(self):
        key = 'networkFirewallNotDeployed'
        vpcId = self.vpc.get('VpcId')
        routes = self.internetRoutes(self.net)
        if not routes:
            self.results[key] = [1, f"{vpcId} has no default route to an internet gateway"]
            return
        if self.hasFirewall:
            self.results[key] = [1, f"Network Firewall deployed in {vpcId}"]
            return
        if self.net.get('gwlbEndpoints'):
            self.results[key] = [
                1, f"{vpcId} has Gateway Load Balancer endpoint(s): "
                   f"{', '.join(self.net['gwlbEndpoints'][:5])}"]
            return
        if self.listError:
            self.results[key] = [0, f"Unable to evaluate ({self.listError})"]
            return
        if isinstance(self.hasEni, str):
            self.results[key] = [0, f"Unable to evaluate ({self.hasEni})"]
            return
        if self.hasEni is False:
            self.results[key] = [1, f"{vpcId} routes to the internet but has no network interfaces (no workloads)"]
            return
        rts = ', '.join(sorted({f"{rt} -> {gw}" for rt, gw in routes})[:5])
        self.results[key] = [
            -1,
            f"{vpcId} routes to the internet ({rts}) with no Network Firewall or "
            "Gateway Load Balancer inspection endpoint"
        ]

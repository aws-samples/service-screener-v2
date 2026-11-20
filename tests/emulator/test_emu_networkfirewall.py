"""Flag -> fix -> re-run tests for the AWS Network Firewall checks."""
from tests.emulator.conftest import assertFlagFixCycle

FORWARD = {'StatelessDefaultActions': ['aws:forward_to_sfe'],
           'StatelessFragmentDefaultActions': ['aws:forward_to_sfe']}


def _safe(fn, *a, **k):
    try:
        fn(*a, **k)
    except Exception:
        pass


class Env:
    """A VPC with a firewall subnet, a workload subnet, an attached internet
    gateway and (optionally) a Network Firewall. Everything is removed in
    cleanup()."""

    def __init__(self, emu, uid, cidr, withFirewall=True, policy=None):
        self.ec2 = emu.client('ec2')
        self.nf = emu.client('network-firewall')
        self.uid = uid
        self.fwName = f'ss-fw-{uid}'
        self.polName = f'ss-pol-{uid}'
        self.rgNames = []
        self.routeTables = []
        self.extra = []
        self.firewall = None
        ec2 = self.ec2
        self.vpc = ec2.create_vpc(CidrBlock=f'{cidr}.0.0/16')['Vpc']['VpcId']
        self.fwSubnet = ec2.create_subnet(VpcId=self.vpc, CidrBlock=f'{cidr}.1.0/24',
                                          AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
        self.wlSubnet = ec2.create_subnet(VpcId=self.vpc, CidrBlock=f'{cidr}.2.0/24',
                                          AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
        self.igw = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']
        ec2.attach_internet_gateway(InternetGatewayId=self.igw, VpcId=self.vpc)
        if withFirewall:
            self.createFirewall(policy)

    def createFirewall(self, policy=None):
        pol = self.nf.create_firewall_policy(FirewallPolicyName=self.polName,
                                             FirewallPolicy=policy or FORWARD)
        self.polArn = pol['FirewallPolicyResponse']['FirewallPolicyArn']
        resp = self.nf.create_firewall(FirewallName=self.fwName, FirewallPolicyArn=self.polArn,
                                       VpcId=self.vpc, SubnetMappings=[{'SubnetId': self.fwSubnet}])
        self.firewall = resp['Firewall']
        self.fwArn = resp['Firewall']['FirewallArn']
        states = resp['FirewallStatus']['SyncStates']
        self.endpoint = list(states.values())[0]['Attachment']['EndpointId']

    def routeTable(self, subnet):
        rt = self.ec2.create_route_table(VpcId=self.vpc)['RouteTable']['RouteTableId']
        assoc = self.ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)['AssociationId']
        self.routeTables.append((rt, assoc))
        return rt

    def setDefault(self, rt, **target):
        _safe(self.ec2.delete_route, RouteTableId=rt, DestinationCidrBlock='0.0.0.0/0')
        self.ec2.create_route(RouteTableId=rt, DestinationCidrBlock='0.0.0.0/0', **target)

    def ruleGroup(self, name):
        arn = self.nf.create_rule_group(
            RuleGroupName=name, Type='STATEFUL', Capacity=10,
            Rules='drop tcp any any -> any 23 (msg:"telnet"; sid:1; rev:1;)'
        )['RuleGroupResponse']['RuleGroupArn']
        self.rgNames.append(name)
        return arn

    def updatePolicy(self, policy):
        token = self.nf.describe_firewall_policy(FirewallPolicyArn=self.polArn)['UpdateToken']
        self.nf.update_firewall_policy(FirewallPolicyArn=self.polArn, UpdateToken=token,
                                       FirewallPolicy=policy)

    def cleanup(self):
        ec2, nf = self.ec2, self.nf
        for fn in self.extra:
            _safe(fn)
        if self.firewall:
            _safe(nf.delete_firewall, FirewallName=self.fwName)
            _safe(nf.delete_firewall_policy, FirewallPolicyName=self.polName)
        for name in self.rgNames:
            _safe(nf.delete_rule_group, RuleGroupName=name, Type='STATEFUL')
        for rt, assoc in self.routeTables:
            _safe(ec2.disassociate_route_table, AssociationId=assoc)
            _safe(ec2.delete_route_table, RouteTableId=rt)
        _safe(ec2.detach_internet_gateway, InternetGatewayId=self.igw, VpcId=self.vpc)
        _safe(ec2.delete_internet_gateway, InternetGatewayId=self.igw)
        for s in (self.fwSubnet, self.wlSubnet):
            _safe(ec2.delete_subnet, SubnetId=s)
        _safe(ec2.delete_vpc, VpcId=self.vpc)


def test_networkfirewall_logging_disabled(emu, uid):
    env = Env(emu, uid, '10.71')
    try:
        def logs(types):
            return {'LogDestinationConfigs': [
                {'LogType': t, 'LogDestinationType': 'CloudWatchLogs',
                 'LogDestination': {'logGroup': f'/ss/{uid}/{t.lower()}'}} for t in types]}

        def misconfigure():
            ## ALERT only: FLOW missing must still be flagged.
            env.nf.update_logging_configuration(FirewallArn=env.fwArn, LoggingConfiguration=logs(['ALERT']))

        def fix():
            env.nf.update_logging_configuration(FirewallArn=env.fwArn, LoggingConfiguration=logs(['ALERT', 'FLOW']))

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallLoggingDisabled', env.fwName, misconfigure, fix)
    finally:
        _safe(env.nf.update_logging_configuration, FirewallArn=env.fwArn,
              LoggingConfiguration={'LogDestinationConfigs': []})
        env.cleanup()


def test_networkfirewall_logging_none_flagged(emu, uid):
    env = Env(emu, uid, '10.72')
    try:
        def misconfigure():
            pass  # a new firewall has no logging configuration

        def fix():
            env.nf.update_logging_configuration(FirewallArn=env.fwArn, LoggingConfiguration={
                'LogDestinationConfigs': [
                    {'LogType': t, 'LogDestinationType': 'S3',
                     'LogDestination': {'bucketName': f'ss-logs-{uid}'}} for t in ('ALERT', 'FLOW', 'TLS')]})

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallLoggingDisabled', env.fwName, misconfigure, fix)
    finally:
        _safe(env.nf.update_logging_configuration, FirewallArn=env.fwArn,
              LoggingConfiguration={'LogDestinationConfigs': []})
        env.cleanup()


def test_networkfirewall_policy_stateless_pass(emu, uid):
    env = Env(emu, uid, '10.73')
    try:
        rg = env.ruleGroup(f'ss-rg-{uid}')

        def misconfigure():
            ## Stateful groups attached, but the stateless default passes
            ## everything around them.
            env.updatePolicy({'StatelessDefaultActions': ['aws:pass'],
                              'StatelessFragmentDefaultActions': ['aws:forward_to_sfe'],
                              'StatefulRuleGroupReferences': [{'ResourceArn': rg}]})

        def fix():
            env.updatePolicy(dict(FORWARD, StatefulRuleGroupReferences=[{'ResourceArn': rg}]))

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallPolicyWeak', env.fwName, misconfigure, fix)
    finally:
        _safe(env.updatePolicy, FORWARD)
        env.cleanup()


def test_networkfirewall_policy_no_stateful_groups(emu, uid):
    env = Env(emu, uid, '10.74')
    try:
        rg = env.ruleGroup(f'ss-rg-{uid}')

        def misconfigure():
            env.updatePolicy(FORWARD)  # forwards to an empty stateful engine

        def fix():
            env.updatePolicy(dict(FORWARD, StatefulRuleGroupReferences=[{'ResourceArn': rg}]))

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallPolicyWeak', env.fwName, misconfigure, fix)
    finally:
        _safe(env.updatePolicy, FORWARD)
        env.cleanup()


def test_networkfirewall_route_bypass_igw(emu, uid):
    env = Env(emu, uid, '10.75')
    try:
        fwRt = env.routeTable(env.fwSubnet)
        env.setDefault(fwRt, GatewayId=env.igw)   # firewall subnet -> IGW (expected)
        wlRt = env.routeTable(env.wlSubnet)

        def misconfigure():
            env.setDefault(wlRt, GatewayId=env.igw)   # workload subnet skips the firewall

        def fix():
            env.setDefault(wlRt, VpcEndpointId=env.endpoint)

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallRouteBypass', env.fwName, misconfigure, fix)
    finally:
        env.cleanup()


def test_networkfirewall_route_bypass_via_nat(emu, uid):
    """Private subnet -> NAT gateway; the NAT subnet must route through the
    firewall (documented NAT design), not straight to the IGW."""
    env = Env(emu, uid, '10.76')
    ec2 = env.ec2
    try:
        natSubnet = ec2.create_subnet(VpcId=env.vpc, CidrBlock='10.76.3.0/24',
                                      AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
        env.extra.append(lambda: ec2.delete_subnet(SubnetId=natSubnet))
        eip = ec2.allocate_address(Domain='vpc')['AllocationId']
        nat = ec2.create_nat_gateway(SubnetId=natSubnet, AllocationId=eip)['NatGateway']['NatGatewayId']
        env.extra.insert(0, lambda: ec2.release_address(AllocationId=eip))
        env.extra.insert(0, lambda: ec2.delete_nat_gateway(NatGatewayId=nat))

        fwRt = env.routeTable(env.fwSubnet)
        env.setDefault(fwRt, GatewayId=env.igw)
        wlRt = env.routeTable(env.wlSubnet)
        env.setDefault(wlRt, NatGatewayId=nat)
        natRt = env.routeTable(natSubnet)

        def misconfigure():
            env.setDefault(natRt, GatewayId=env.igw)

        def fix():
            env.setDefault(natRt, VpcEndpointId=env.endpoint)

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallRouteBypass', env.fwName, misconfigure, fix)
    finally:
        env.cleanup()


def test_networkfirewall_route_firewall_before_nat(emu, uid):
    """Firewall-before-NAT design: workload subnet -> firewall endpoint ->
    NAT -> IGW. The NAT subnet's 0.0.0.0/0 -> IGW route is only acceptable
    when it returns the workload CIDR through the firewall endpoint. The
    emulator, like EC2, reports that route as GatewayId='vpce-...'."""
    env = Env(emu, uid, '10.78')
    ec2 = env.ec2
    try:
        natSubnet = ec2.create_subnet(VpcId=env.vpc, CidrBlock='10.78.3.0/24',
                                      AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
        env.extra.append(lambda: ec2.delete_subnet(SubnetId=natSubnet))
        eip = ec2.allocate_address(Domain='vpc')['AllocationId']
        nat = ec2.create_nat_gateway(SubnetId=natSubnet, AllocationId=eip)['NatGateway']['NatGatewayId']
        env.extra.insert(0, lambda: ec2.release_address(AllocationId=eip))
        env.extra.insert(0, lambda: ec2.delete_nat_gateway(NatGatewayId=nat))

        fwRt = env.routeTable(env.fwSubnet)
        env.setDefault(fwRt, NatGatewayId=nat)
        wlRt = env.routeTable(env.wlSubnet)
        env.setDefault(wlRt, VpcEndpointId=env.endpoint)
        natRt = env.routeTable(natSubnet)
        env.setDefault(natRt, GatewayId=env.igw)

        def misconfigure():
            _safe(ec2.delete_route, RouteTableId=natRt, DestinationCidrBlock='10.78.2.0/24')

        def fix():
            ec2.create_route(RouteTableId=natRt, DestinationCidrBlock='10.78.2.0/24',
                             VpcEndpointId=env.endpoint)

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallRouteBypass', env.fwName, misconfigure, fix)
    finally:
        env.cleanup()


def test_networkfirewall_not_deployed(emu, uid):
    env = Env(emu, uid, '10.77', withFirewall=False)
    ec2 = env.ec2
    try:
        rt = env.routeTable(env.wlSubnet)
        env.setDefault(rt, GatewayId=env.igw)
        eni = ec2.create_network_interface(SubnetId=env.wlSubnet)['NetworkInterface']['NetworkInterfaceId']
        env.extra.append(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni))

        def misconfigure():
            pass  # internet-connected VPC with a workload ENI and no inspection

        def fix():
            env.createFirewall()

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallNotDeployed', env.vpc, misconfigure, fix)
    finally:
        env.cleanup()


def test_networkfirewall_not_deployed_ignores_orphan_route_table(emu, uid):
    """A custom route table with 0.0.0.0/0 -> IGW but no subnet association
    routes no traffic: the VPC is not internet-connected through it. Flag while
    the table is associated with the workload subnet; after disassociating it
    (orphan table, route still present) the VPC must PASS."""
    env = Env(emu, uid, '10.79', withFirewall=False)
    ec2 = env.ec2
    try:
        rt = env.routeTable(env.wlSubnet)
        env.setDefault(rt, GatewayId=env.igw)
        eni = ec2.create_network_interface(SubnetId=env.wlSubnet)['NetworkInterface']['NetworkInterfaceId']
        env.extra.append(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni))

        def misconfigure():
            pass  # workload subnet uses the IGW route table

        def fix():
            ec2.disassociate_route_table(AssociationId=env.routeTables[-1][1])

        assertFlagFixCycle(emu, 'networkfirewall', 'networkFirewallNotDeployed', env.vpc, misconfigure, fix)
    finally:
        env.cleanup()

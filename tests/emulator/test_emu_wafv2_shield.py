"""Flag -> fix -> re-run tests for the Shield Advanced / Firewall Manager checks
in services/wafv2 against the local AWS Emulator.

Emulator notes:
- shield.delete_subscription is NotImplemented, so the Shield Advanced
  subscription created here cannot be removed afterwards. That is harmless for
  the private emulator (real accounts cannot cancel it on demand either).
- enable_proactive_engagement / enable_application_layer_automatic_response are
  NotImplemented; the FIX half of those checks is covered by
  tests/test_stub_wafv2_shield.py. Here we only assert the FLAG end to end.
"""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck


def _ensureSubscription(emu):
    sh = emu.client('shield')
    if sh.get_subscription_state().get('SubscriptionState') != 'ACTIVE':
        sh.create_subscription()
    return sh


def test_shield_public_hosted_zone_unprotected(emu, uid):
    sh = _ensureSubscription(emu)
    r53 = emu.client('route53')
    zone = r53.create_hosted_zone(Name=f'ss-{uid}.example.com', CallerReference=f'ss-{uid}')
    zid = zone['HostedZone']['Id'].replace('/hostedzone/', '')
    arn = f'arn:aws:route53:::hostedzone/{zid}'
    state = {}
    try:
        def misconfigure():
            pass  # a public hosted zone without a protection

        def fix():
            state['pid'] = sh.create_protection(Name=f'ss-{uid}', ResourceArn=arn)['ProtectionId']

        assertFlagFixCycle(emu, 'wafv2', 'shieldAdvancedPublicResourcesUnprotected',
                           'Shield::Account', misconfigure, fix)
    finally:
        if state.get('pid'):
            sh.delete_protection(ProtectionId=state['pid'])
        r53.delete_hosted_zone(Id=zid)


def test_shield_associated_eip_unprotected(emu, uid):
    sh = _ensureSubscription(emu)
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.77.0.0/16')['Vpc']['VpcId']
    sn = ec2.create_subnet(VpcId=vpc, CidrBlock='10.77.1.0/24')['Subnet']['SubnetId']
    eni = ec2.create_network_interface(SubnetId=sn)['NetworkInterface']['NetworkInterfaceId']
    alloc = ec2.allocate_address(Domain='vpc')['AllocationId']
    acct = emu.client('sts').get_caller_identity()['Account']
    state = {}
    try:
        def misconfigure():
            state['assoc'] = ec2.associate_address(AllocationId=alloc, NetworkInterfaceId=eni)['AssociationId']

        def fix():
            state['pid'] = sh.create_protection(
                Name=f'ss-{uid}', ResourceArn=f'arn:aws:ec2:us-east-1:{acct}:eip-allocation/{alloc}'
            )['ProtectionId']

        assertFlagFixCycle(emu, 'wafv2', 'shieldAdvancedPublicResourcesUnprotected',
                           'Shield::Account', misconfigure, fix)
    finally:
        if state.get('pid'):
            sh.delete_protection(ProtectionId=state['pid'])
        if state.get('assoc'):
            ec2.disassociate_address(AssociationId=state['assoc'])
        ec2.release_address(AllocationId=alloc)
        ec2.delete_network_interface(NetworkInterfaceId=eni)
        ec2.delete_subnet(SubnetId=sn)
        ec2.delete_vpc(VpcId=vpc)


def test_shield_unassociated_eip_not_flagged(emu, uid):
    """An idle Elastic IP carries no traffic, so it must not be reported."""
    _ensureSubscription(emu)
    ec2 = emu.client('ec2')
    alloc = ec2.allocate_address(Domain='vpc')['AllocationId']
    try:
        st = runCheck(emu, 'wafv2', 'shieldAdvancedPublicResourcesUnprotected', 'Shield::Account').statuses()
        assert st and all(s != -1 for s in st.values()), st
    finally:
        ec2.release_address(AllocationId=alloc)


def test_shield_no_proactive_engagement_flagged(emu, uid):
    """Flag only (enable_proactive_engagement is NotImplemented in the emulator):
    ACTIVE subscription with proactive engagement DISABLED -> -1."""
    _ensureSubscription(emu)
    st = runCheck(emu, 'wafv2', 'shieldAdvancedNoProactiveEngagement', 'Shield::Account').statuses()
    assert st and all(s == -1 for s in st.values()), st


def test_shield_alb_protection_without_l7_auto_mitigation_flagged(emu, uid):
    """Flag only (enable_application_layer_automatic_response is NotImplemented)."""
    sh = _ensureSubscription(emu)
    ec2 = emu.client('ec2')
    elb = emu.client('elbv2')
    vpc = ec2.create_vpc(CidrBlock='10.78.0.0/16')['Vpc']['VpcId']
    igw = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    sn1 = ec2.create_subnet(VpcId=vpc, CidrBlock='10.78.1.0/24', AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
    sn2 = ec2.create_subnet(VpcId=vpc, CidrBlock='10.78.2.0/24', AvailabilityZone='us-east-1b')['Subnet']['SubnetId']
    lbArn, pid = None, None
    try:
        lbArn = elb.create_load_balancer(Name=f'ss-{uid}', Subnets=[sn1, sn2], Scheme='internet-facing',
                                         Type='application')['LoadBalancers'][0]['LoadBalancerArn']
        pid = sh.create_protection(Name=f'ss-alb-{uid}', ResourceArn=lbArn)['ProtectionId']
        st = runCheck(emu, 'wafv2', 'shieldAutoL7MitigationDisabled', f'ss-alb-{uid}').statuses()
        assert st and all(s == -1 for s in st.values()), st
        # The protected ALB must not appear as unprotected in the coverage check.
        cov = runCheck(emu, 'wafv2', 'shieldAdvancedPublicResourcesUnprotected', 'Shield::Account').statuses()
        assert cov and all(s != -1 for s in cov.values()), cov
    finally:
        if pid:
            sh.delete_protection(ProtectionId=pid)
        if lbArn:
            elb.delete_load_balancer(LoadBalancerArn=lbArn)
        ec2.delete_subnet(SubnetId=sn1)
        ec2.delete_subnet(SubnetId=sn2)
        ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
        ec2.delete_internet_gateway(InternetGatewayId=igw)
        ec2.delete_vpc(VpcId=vpc)


def test_fms_admin_without_policies(emu, uid):
    fms = emu.client('fms')
    acct = emu.client('sts').get_caller_identity()['Account']
    try:
        orig = fms.get_admin_account()
    except fms.exceptions.ResourceNotFoundException:
        orig = {}
    wasReady = orig.get('AdminAccount') == acct and orig.get('RoleStatus') == 'READY'
    state = {}
    try:
        def misconfigure():
            fms.associate_admin_account(AdminAccount=acct)
            for p in fms.list_policies().get('PolicyList', []):
                assert False, f'unexpected pre-existing FMS policy {p}'

        def fix():
            state['pid'] = fms.put_policy(Policy={
                'PolicyName': f'ss-{uid}',
                'SecurityServicePolicyData': {
                    'Type': 'SECURITY_GROUPS_USAGE_AUDIT',
                    'ManagedServiceData': json.dumps({'type': 'SECURITY_GROUPS_USAGE_AUDIT',
                                                      'deleteUnusedSecurityGroups': False,
                                                      'coalesceRedundantSecurityGroups': False})},
                'ResourceType': 'AWS::EC2::SecurityGroup',
                'ExcludeResourceTags': False,
                'RemediationEnabled': False,
            })['Policy']['PolicyId']

        assertFlagFixCycle(emu, 'wafv2', 'fmsNoNetworkPolicies', 'FirewallManager', misconfigure, fix)
    finally:
        if state.get('pid'):
            fms.delete_policy(PolicyId=state['pid'])
        if not wasReady:
            fms.disassociate_admin_account()


def test_fms_member_account_not_evaluable(emu):
    """No READY FMS admin -> list_policies is denied -> INFO, never FAIL."""
    fms = emu.client('fms')
    acct = emu.client('sts').get_caller_identity()['Account']
    try:
        cur = fms.get_admin_account()
    except fms.exceptions.ResourceNotFoundException:
        cur = {}
    if cur.get('AdminAccount') == acct and cur.get('RoleStatus') == 'READY':
        return  # state left by an external actor; nothing to assert safely
    st = runCheck(emu, 'wafv2', 'fmsNoNetworkPolicies', 'FirewallManager').statuses()
    assert st and all(s == 0 for s in st.values()), st

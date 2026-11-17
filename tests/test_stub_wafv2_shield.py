"""botocore Stubber flag -> fix tests for the Shield Advanced / Firewall Manager
checks in services/wafv2.

Why Stubber and not the emulator: the AWS Emulator returns NotImplemented for
shield.enable_proactive_engagement, associate_proactive_engagement_details and
enable_application_layer_automatic_response, and cannot cancel a Shield
subscription, so the FIX state of shieldAdvancedNoProactiveEngagement /
shieldAutoL7MitigationDisabled and the not-subscribed / AccessDenied paths
cannot be produced there. Real boto3 clients (real API shapes) are wrapped by
Stubber; no network call is made (Stubber intercepts before sending).
"""
import os
import sys
from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.wafv2.drivers.Wafv2Shield import Wafv2Shield, Wafv2ShieldProtection, listShieldProtections  # noqa: E402
from services.wafv2.drivers.Wafv2Fms import Wafv2Fms  # noqa: E402

ACCT = '111122223333'
ALB = f'arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/app/web/0123456789abcdef'
CF = f'arn:aws:cloudfront::{ACCT}:distribution/E1ABCDEFGHIJKL'
PID = '11111111-2222-3333-4444-555555555555'
FMS_PID = 'a' * 36


@pytest.fixture
def session():
    # Dummy static credentials: Stubber never sends requests.
    return boto3.session.Session(aws_access_key_id='testing', aws_secret_access_key='testing',
                                 region_name='us-east-1')


def _client(session, name):
    c = session.client(name, region_name='us-east-1', endpoint_url='https://127.0.0.1:1')
    st = Stubber(c)
    return c, st


def _sub(status):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return {'Subscription': {'StartTime': now, 'TimeCommitmentInSeconds': 31536000, 'AutoRenew': 'ENABLED',
                             'ProactiveEngagementStatus': status,
                             'SubscriptionLimits': {
                                 'ProtectionLimits': {'ProtectedResourceTypeLimits': []},
                                 'ProtectionGroupLimits': {'MaxProtectionGroups': 1000, 'PatternTypeLimits': {
                                     'ArbitraryPatternLimits': {'MaxMembers': 100}}}}}}


def _run(drv, method):
    getattr(drv, method)()
    return drv.results


# --------------------------------------------------------------------------- #
# shieldAdvancedNoProactiveEngagement
# --------------------------------------------------------------------------- #
def _proactive(session, status, contacts, state='ACTIVE'):
    sh, st = _client(session, 'shield')
    st.add_response('get_subscription_state', {'SubscriptionState': state})
    if state == 'ACTIVE':
        st.add_response('describe_subscription', _sub(status))
        st.add_response('describe_emergency_contact_settings', {'EmergencyContactList': contacts})
    with st:
        r = _run(Wafv2Shield({'shield': sh}, 'us-east-1', ACCT), '_checkShieldAdvancedNoProactiveEngagement')
        st.assert_no_pending_responses()
    return r['shieldAdvancedNoProactiveEngagement'][0]


def test_proactive_flag_fix(session):
    assert _proactive(session, 'DISABLED', []) == -1
    assert _proactive(session, 'ENABLED', []) == -1            # enabled but no contacts
    assert _proactive(session, 'PENDING', [{'EmailAddress': 'soc@example.com'}]) == -1
    assert _proactive(session, 'ENABLED', [{'EmailAddress': 'soc@example.com',
                                            'PhoneNumber': '+15555550100'}]) == 1


def test_proactive_not_subscribed_is_info(session):
    assert _proactive(session, None, None, state='INACTIVE') == 0


def test_proactive_access_denied_is_unable(session):
    sh, st = _client(session, 'shield')
    st.add_client_error('get_subscription_state', 'AccessDeniedException')
    with st:
        r = _run(Wafv2Shield({'shield': sh}, 'us-east-1', ACCT), '_checkShieldAdvancedNoProactiveEngagement')
    assert r['shieldAdvancedNoProactiveEngagement'][0] == 0
    assert 'Unable to evaluate (AccessDeniedException)' in r['shieldAdvancedNoProactiveEngagement'][1]


def test_proactive_only_in_global_region(session):
    sh, st = _client(session, 'shield')
    with st:
        r = _run(Wafv2Shield({'shield': sh}, 'eu-west-1', ACCT, isGlobalRegion=False),
                 '_checkShieldAdvancedNoProactiveEngagement')
    assert 'shieldAdvancedNoProactiveEngagement' not in r


# --------------------------------------------------------------------------- #
# shieldAdvancedPublicResourcesUnprotected
# --------------------------------------------------------------------------- #
def _coverage(session, protections, lbs, cfItems=None, cfError=None, state='ACTIVE'):
    sh, ssh = _client(session, 'shield')
    elb, selb = _client(session, 'elbv2')
    cf, scf = _client(session, 'cloudfront')
    ssh.add_response('get_subscription_state', {'SubscriptionState': state})
    if state == 'ACTIVE':
        ssh.add_response('list_protections', {'Protections': protections})
        selb.add_response('describe_load_balancers', {'LoadBalancers': lbs})
        if cfError:
            scf.add_client_error('list_distributions', cfError)
        else:
            scf.add_response('list_distributions', {'DistributionList': {
                'Marker': '', 'MaxItems': 100, 'IsTruncated': False,
                'Quantity': len(cfItems or []), **({'Items': cfItems} if cfItems else {})}})
    with ssh, selb, scf:
        drv = Wafv2Shield({'shield': sh, 'elbv2': elb, 'cloudfront': cf}, 'us-east-1', ACCT)
        r = _run(drv, '_checkShieldAdvancedPublicResourcesUnprotected')
    return r['shieldAdvancedPublicResourcesUnprotected']


def _lb(scheme):
    return [{'LoadBalancerArn': ALB, 'LoadBalancerName': 'web', 'Scheme': scheme, 'Type': 'application'}]


def test_coverage_flag_fix(session):
    assert _coverage(session, [], _lb('internet-facing'))[0] == -1
    prot = [{'Id': PID, 'Name': 'web', 'ResourceArn': ALB}]
    assert _coverage(session, prot, _lb('internet-facing'))[0] == 1


def test_coverage_internal_alb_ignored(session):
    assert _coverage(session, [], _lb('internal'))[0] == 1


def test_coverage_not_subscribed_is_info(session):
    assert _coverage(session, [], [], state='INACTIVE')[0] == 0


def test_coverage_partial_enumeration_failure_is_unable(session):
    prot = [{'Id': PID, 'Name': 'web', 'ResourceArn': ALB}]
    res = _coverage(session, prot, _lb('internet-facing'), cfError='AccessDenied')
    assert res[0] == 0 and 'Unable to evaluate' in res[1]


# --------------------------------------------------------------------------- #
# shieldAutoL7MitigationDisabled
# --------------------------------------------------------------------------- #
def _l7(session, protection, describeCfg='absent'):
    sh, st = _client(session, 'shield')
    st.add_response('list_protections', {'Protections': [protection]})
    if 'ApplicationLayerAutomaticResponseConfiguration' not in protection:
        p = dict(protection)
        if describeCfg != 'absent':
            p['ApplicationLayerAutomaticResponseConfiguration'] = describeCfg
        st.add_response('describe_protection', {'Protection': p},
                        {'ProtectionId': protection['Id']})
    with st:
        prot = listShieldProtections(sh)[0]
        r = _run(Wafv2ShieldProtection(prot, sh), '_checkShieldAutoL7MitigationDisabled')
        st.assert_no_pending_responses()
    return r['shieldAutoL7MitigationDisabled'][0]


@pytest.mark.parametrize('arn', [ALB, CF])
def test_l7_flag_fix(session, arn):
    base = {'Id': PID, 'Name': 'web', 'ResourceArn': arn}
    assert _l7(session, base) == -1
    assert _l7(session, dict(base, ApplicationLayerAutomaticResponseConfiguration={
        'Status': 'DISABLED', 'Action': {'Count': {}}})) == -1
    assert _l7(session, dict(base, ApplicationLayerAutomaticResponseConfiguration={
        'Status': 'ENABLED', 'Action': {'Block': {}}})) == 1
    # Field absent from list output but present on describe_protection.
    assert _l7(session, base, describeCfg={'Status': 'ENABLED', 'Action': {'Count': {}}}) == 1


# --------------------------------------------------------------------------- #
# fmsNoNetworkPolicies
# --------------------------------------------------------------------------- #
def _fms(session, admin=None, listResp=None, listErr=None):
    fms, st = _client(session, 'fms')
    if admin:
        st.add_response('get_admin_account', admin)
    else:
        st.add_client_error('get_admin_account', 'ResourceNotFoundException')
    if listErr:
        st.add_client_error('list_policies', listErr)
    elif listResp is not None:
        st.add_response('list_policies', listResp)
    with st:
        r = _run(Wafv2Fms(fms, 'us-east-1', ACCT), '_checkFmsNoNetworkPolicies')
    return r['fmsNoNetworkPolicies']


def test_fms_flag_fix(session):
    admin = {'AdminAccount': ACCT, 'RoleStatus': 'READY'}
    assert _fms(session, admin, {'PolicyList': []})[0] == -1
    assert _fms(session, admin, {'PolicyList': [{
        'PolicyArn': f'arn:aws:fms:us-east-1:{ACCT}:policy/{FMS_PID}', 'PolicyId': FMS_PID, 'PolicyName': 'waf',
        'ResourceType': 'AWS::ElasticLoadBalancingV2::LoadBalancer', 'SecurityServiceType': 'WAFV2'}]})[0] == 1


def test_fms_member_account_not_evaluable(session):
    res = _fms(session, {'AdminAccount': '999999999999', 'RoleStatus': 'READY'},
               listErr='AccessDeniedException')
    assert res == [0, 'Not evaluable from member account']
    res = _fms(session, None, listErr='AccessDeniedException')
    assert res == [0, 'Not evaluable from member account']


def test_fms_admin_being_removed_is_info(session):
    assert _fms(session, {'AdminAccount': ACCT, 'RoleStatus': 'PENDING_DELETION'})[0] == 0


# --------------------------------------------------------------------------- #
# shieldAdvancedPublicResourcesUnprotected - CLB / EIP scope / CloudFront scope
# --------------------------------------------------------------------------- #
def _coverageMulti(session, protections, clbs=None, addresses=None, enis=None, cfItems=None):
    """Drive the coverage check with only the clients given (others absent)."""
    clients = {}
    stubs = []
    sh, ssh = _client(session, 'shield')
    ssh.add_response('get_subscription_state', {'SubscriptionState': 'ACTIVE'})
    ssh.add_response('list_protections', {'Protections': protections})
    clients['shield'] = sh
    stubs.append(ssh)
    if clbs is not None:
        elb, selb = _client(session, 'elb')
        selb.add_response('describe_load_balancers', {'LoadBalancerDescriptions': clbs})
        clients['elb'] = elb
        stubs.append(selb)
    if addresses is not None:
        ec2, sec2 = _client(session, 'ec2')
        sec2.add_response('describe_addresses', {'Addresses': addresses})
        if enis is not None:
            sec2.add_response('describe_network_interfaces', {'NetworkInterfaces': enis})
        clients['ec2'] = ec2
        stubs.append(sec2)
    if cfItems is not None:
        cf, scf = _client(session, 'cloudfront')
        scf.add_response('list_distributions', {'DistributionList': {
            'Marker': '', 'MaxItems': 100, 'IsTruncated': False,
            'Quantity': len(cfItems), **({'Items': cfItems} if cfItems else {})}})
        clients['cloudfront'] = cf
        stubs.append(scf)
    for s in stubs:
        s.activate()
    try:
        r = _run(Wafv2Shield(clients, 'us-east-1', ACCT), '_checkShieldAdvancedPublicResourcesUnprotected')
        for s in stubs:
            s.assert_no_pending_responses()
    finally:
        for s in stubs:
            s.deactivate()
    return r['shieldAdvancedPublicResourcesUnprotected']


CLB_ARN = f'arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/classic-web'


def test_coverage_internet_facing_clb_flag_fix(session):
    clbs = [{'LoadBalancerName': 'classic-web', 'Scheme': 'internet-facing'}]
    res = _coverageMulti(session, [], clbs=clbs)
    assert res[0] == -1 and 'CLB classic-web' in res[1]
    prot = [{'Id': PID, 'Name': 'clb', 'ResourceArn': CLB_ARN}]
    assert _coverageMulti(session, prot, clbs=clbs)[0] == 1
    # internal CLB is out of scope
    assert _coverageMulti(session, [], clbs=[{'LoadBalancerName': 'x', 'Scheme': 'internal'}])[0] == 1


def _addr(alloc, eni):
    return {'AllocationId': alloc, 'AssociationId': f'eipassoc-{alloc[-8:]}', 'Domain': 'vpc',
            'NetworkInterfaceId': eni, 'PublicIp': '198.51.100.10'}


def _eni(eni, itype, requesterManaged):
    return {'NetworkInterfaceId': eni, 'InterfaceType': itype, 'RequesterManaged': requesterManaged}


def test_coverage_eip_on_nat_gateway_skipped(session):
    alloc, eni = 'eipalloc-0123456789abcdef0', 'eni-0123456789abcdef0'
    res = _coverageMulti(session, [], addresses=[_addr(alloc, eni)],
                         enis=[_eni(eni, 'nat_gateway', True)])
    assert res[0] == 1


def test_coverage_eip_on_instance_eni_and_nlb_flag_fix(session):
    a1, e1 = 'eipalloc-0123456789abcdef1', 'eni-0123456789abcdef1'
    a2, e2 = 'eipalloc-0123456789abcdef2', 'eni-0123456789abcdef2'
    addrs = [_addr(a1, e1), _addr(a2, e2)]
    enis = [_eni(e1, 'interface', False), _eni(e2, 'network_load_balancer', True)]
    res = _coverageMulti(session, [], addresses=addrs, enis=enis)
    assert res[0] == -1 and res[1].startswith('2 of 2')
    prot = [{'Id': PID, 'Name': 'a', 'ResourceArn': f'arn:aws:ec2:us-east-1:{ACCT}:eip-allocation/{a1}'},
            {'Id': PID, 'Name': 'b', 'ResourceArn': f'arn:aws:ec2:us-east-1:{ACCT}:eip-allocation/{a2}'}]
    assert _coverageMulti(session, prot, addresses=addrs, enis=enis)[0] == 1


def _dist(enabled):
    return {'Id': 'E1ABCDEFGHIJKL', 'ARN': CF, 'Status': 'Deployed', 'Enabled': enabled,
            'LastModifiedTime': datetime(2026, 1, 1, tzinfo=timezone.utc),
            'DomainName': 'd111111abcdef8.cloudfront.net', 'Aliases': {'Quantity': 0},
            'Origins': {'Quantity': 1, 'Items': [{'Id': 'o', 'DomainName': 'example.com'}]},
            'DefaultCacheBehavior': {'TargetOriginId': 'o', 'ViewerProtocolPolicy': 'allow-all'},
            'CacheBehaviors': {'Quantity': 0}, 'CustomErrorResponses': {'Quantity': 0},
            'Comment': '', 'PriceClass': 'PriceClass_All',
            'ViewerCertificate': {}, 'Restrictions': {'GeoRestriction': {
                'RestrictionType': 'none', 'Quantity': 0}},
            'WebACLId': '', 'HttpVersion': 'http2', 'IsIPV6Enabled': True, 'Staging': False}


def test_coverage_disabled_cloudfront_skipped(session):
    assert _coverageMulti(session, [], cfItems=[_dist(True)])[0] == -1
    assert _coverageMulti(session, [], cfItems=[_dist(False)])[0] == 1


# --------------------------------------------------------------------------- #
# shieldAutoL7MitigationDisabled - protection list unreadable
# --------------------------------------------------------------------------- #
def test_l7_protections_unreadable_is_unable():
    from services.wafv2.drivers.Wafv2Shield import Wafv2ShieldProtectionsUnavailable
    drv = Wafv2ShieldProtectionsUnavailable('AccessDeniedException')
    r = _run(drv, '_checkShieldAutoL7MitigationDisabled')
    assert r['shieldAutoL7MitigationDisabled'] == [0, 'Unable to evaluate (AccessDeniedException)']


def test_shield_region_is_partition_aware():
    from services.wafv2.Wafv2 import Wafv2
    assert Wafv2.shieldRegion('eu-west-1') == 'us-east-1'
    assert Wafv2.shieldRegion('us-east-1') == 'us-east-1'
    assert Wafv2.shieldRegion('us-gov-west-1') == 'us-gov-west-1'
    assert Wafv2.shieldRegion('cn-north-1') == 'cn-north-1'

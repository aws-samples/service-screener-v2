"""Stubber-based flag -> fix tests for WAFS2027 ec2 checks the AWS Emulator cannot drive.

Why not the emulator:
- ec2AmiPublic: ec2.ModifyImageAttribute (make an AMI public / private) and DeregisterImage
  are NotImplemented in the emulator.
- ebsSnapshotSharedExternally: ec2.ModifySnapshotAttribute (share a snapshot with an
  account) and organizations.ListAccounts are NotImplemented, and the emulator is a
  single account inside an organization (no "not in an organization" case).
- ebsRecycleBinMissing (locked / tag-level paths): a locked Recycle Bin rule cannot be
  deleted, so locking would leave permanent emulator state.
- elbTlsPolicyOutdated (CLB policy with expanded Protocol-* attributes, unresolvable
  policy): exercises the real-AWS response shape that the emulator does not return.
- ec2AmiSharedExternally: ModifyImageAttribute is NotImplemented (an AMI cannot be shared)
  and DeregisterImage is NotImplemented (a registered test AMI could never be removed).
- ec2AmiUntrustedOrStale: an instance's source AMI cannot be changed, and DeregisterImage /
  DisableImage are NotImplemented and past deprecation times are rejected, so the
  same-instance flag -> fix cycle (deprecated -> current, third-party -> verified) is stubbed.
- ec2InstanceWithKeyPair: an EC2 instance cannot become an SSM managed node in the emulator,
  so the FAIL path (SSM-managed, PingStatus Online, KeyName set) is stubbed.
- ec2InstanceInPublicSubnet (RDS / ElastiCache / ECS interfaces, shared-VPC subnets): those
  managed-service ENIs and RAM-shared subnets cannot be created in the emulator.
- vpcEndpointPolicyFullAccess (services without endpoint-policy support, unknown service
  names, perimeter Deny statements): response shapes the emulator does not produce.
- vpnWeakTunnelCrypto: ec2.ModifyVpnTunnelOptions is NotImplemented, so the same-connection
  fix (default options -> IKEv2/SHA2/DH 20) is stubbed.
- ec2AutoRecoveryDisabled: ec2.ModifyInstanceMaintenanceOptions is NotImplemented.
- ec2SshdRunning: an emulator instance cannot become an SSM managed node, and the emulator
  rejects ssm.ListInventoryEntries TypeName=AWS:Service (InvalidTypeNameException).
- albMtlsOff (passthrough / internet-facing / trust-store paths) and vpcNoGatewayEndpoints
  (shared VPC, interface endpoint, unassociated route table): response shapes beyond the
  emulator flag -> fix test.
- EBSUpToDateSnapshot: DescribeSnapshots result ordering (newest not first).
- selfManagedDataStoreOnEc2: emulator instances cannot become SSM managed nodes, so the
  AWS:Application inventory evidence (server package FAIL, port-only INFO, client-library
  non-match) is stubbed.
- imagebuilderNoPipeline: custom / cross-account AMIs (INFO), deregistered AMIs in a
  describe_images batch and AccessDenied responses are shapes the emulator cannot produce
  on demand.
- ssmVpcEndpointsMissing: NAT / transit-gateway default routes, private-DNS-disabled
  endpoints and shared VPCs (RAM) are beyond the emulator flag -> fix test.
- naclAllowAllIngress (IPv6 / deny-ordering details) and sgUnrestrictedEgress ENI
  classification (ElastiCache / Redshift / OpenSearch interfaces cannot be created).
- getNetworkACLs pagination (NextToken) - the emulator returns a single page.
- vpcPeeringFullRoute (transit gateway path): emulator TGW attachments carry no Association
  and search_transit_gateway_routes returns no propagated routes, so the association ->
  route-table -> propagated-CIDR path, RAM-shared TGWs, IPv6 / prefix-list / blackhole
  routes and AccessDenied responses are stubbed. The FAIL path (whole-CIDR route to a
  peer VPC owned by ANOTHER account) needs a second account, which the single-account
  emulator does not have.
- albTargetGroupPlaintext: the FAIL path needs an ip target outside the VPC
  (AvailabilityZone 'all') reported by describe_target_health; the emulator flag -> fix
  test covers it where supported, the stub pins the real response shape.
- elbUsesIamOrImportedCert: additional listener certificates (describe_listener_certificates
  pages) and AccessDenied on that call are stubbed.

Every client is a real botocore client (real API shapes / parameter validation) wrapped by
botocore.stub.Stubber, pointed at an unroutable loopback endpoint with dummy credentials,
so no request can leave the process.
"""
import os
import sys
import types

import botocore.session
import pytest
from botocore.stub import Stubber, ANY

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Config import Config  # noqa: E402
from services.ec2.Ec2 import Ec2  # noqa: E402
from services.ec2.drivers.Ec2Ami import Ec2Ami  # noqa: E402
from services.ec2.drivers.Ec2EbsSnapshotSharing import Ec2EbsSnapshotSharing  # noqa: E402
from services.ec2.drivers.Ec2Regional import Ec2Regional  # noqa: E402
from services.ec2.drivers.Ec2ElbClassic import Ec2ElbClassic  # noqa: E402
from services.ec2.drivers.Ec2ElbCommon import Ec2ElbCommon  # noqa: E402

# Evaluator.__del__ writes to __fork/error.txt, which only exists in a full scan run.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

SELF = '111111111111'
ORG_MEMBER = '222222222222'
OUTSIDER = '999999999999'


def _client(service):
    return botocore.session.get_session().create_client(
        service, region_name='us-east-1', endpoint_url='https://127.0.0.1:1',
        aws_access_key_id='testing', aws_secret_access_key='testing')


def _run(driver, method):
    getattr(driver, method)()
    return driver.results


# --------------------------------------------------------------------------- #
# ec2AmiPublic
# --------------------------------------------------------------------------- #
def _image(public):
    return {'ImageId': 'ami-0123456789abcdef0', 'Name': 'app', 'OwnerId': SELF, 'Public': public,
            'State': 'available', 'ImageType': 'machine'}


def _amiResult(public):
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_images', {'Images': [_image(public)]}, {'Owners': ['self']})
        images = Ec2.getSelfImages(types.SimpleNamespace(ec2Client=ec2, tags=[]))
        st.assert_no_pending_responses()
    assert [i['ImageId'] for i in images] == ['ami-0123456789abcdef0']
    return _run(Ec2Ami(images[0]), '_checkEc2AmiPublic')['ec2AmiPublic']


def test_ami_public_flag_fix():
    assert _amiResult(True)[0] == -1       # misconfigured: launch permission group 'all'
    assert _amiResult(False)[0] == 1       # fixed: private


def test_ami_public_missing_field_not_pass():
    res = _run(Ec2Ami({'ImageId': 'ami-1'}), '_checkEc2AmiPublic')['ec2AmiPublic']
    assert res[0] == 0


def test_ami_listing_paginates():
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_images', {'Images': [_image(False)], 'NextToken': 't'}, {'Owners': ['self']})
        st.add_response('describe_images', {'Images': [dict(_image(True), ImageId='ami-2')]},
                        {'Owners': ['self'], 'NextToken': 't'})
        images = Ec2.getSelfImages(types.SimpleNamespace(ec2Client=ec2, tags=[]))
    assert [i['ImageId'] for i in images] == ['ami-0123456789abcdef0', 'ami-2']


# --------------------------------------------------------------------------- #
# ebsSnapshotSharedExternally
# --------------------------------------------------------------------------- #
SNAP = {'SnapshotId': 'snap-0123456789abcdef0', 'OwnerId': SELF, 'VolumeId': 'vol-1', 'State': 'completed'}


def _orgContext(mode):
    """mode: 'none' (not in org) | 'mgmt' (org accounts listable) | 'member' (ListAccounts denied)"""
    Config.set('ec2::orgContext', None)
    org = _client('organizations')
    with Stubber(org) as st:
        if mode == 'none':
            st.add_client_error('describe_organization', service_error_code='AWSOrganizationsNotInUseException',
                                http_status_code=400)
        else:
            st.add_response('describe_organization', {'Organization': {'Id': 'o-abc123defg', 'FeatureSet': 'ALL'}})
            if mode == 'mgmt':
                st.add_response('list_accounts', {'Accounts': [{'Id': SELF}, {'Id': ORG_MEMBER}]})
            else:
                st.add_client_error('list_accounts', service_error_code='AccessDeniedException', http_status_code=400)
        ctx = Ec2.getOrgContext(types.SimpleNamespace(orgClient=org))
        st.assert_no_pending_responses()
    Config.set('ec2::orgContext', None)
    return ctx


def _sharingResult(perms, mode):
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_snapshots', {'Snapshots': [SNAP]}, {'OwnerIds': ['self']})
        st.add_response('describe_snapshot_attribute',
                        {'SnapshotId': SNAP['SnapshotId'], 'CreateVolumePermissions': perms},
                        {'SnapshotId': SNAP['SnapshotId'], 'Attribute': 'createVolumePermission'})
        sharing = Ec2.getSnapshotSharing(types.SimpleNamespace(ec2Client=ec2, tags=[]))
        st.assert_no_pending_responses()
    snap, p = sharing[0]
    return _run(Ec2EbsSnapshotSharing(snap, p, SELF, _orgContext(mode)),
                '_checkEbsSnapshotSharedExternally')['ebsSnapshotSharedExternally']


def test_snapshot_shared_outside_org_flag_fix_not_in_org():
    assert _sharingResult([{'UserId': OUTSIDER}], 'none')[0] == -1   # misconfigured
    assert _sharingResult([], 'none')[0] == 1                       # fixed: sharing removed


def test_snapshot_shared_outside_org_flag_fix_mgmt_account():
    flagged = _sharingResult([{'UserId': ORG_MEMBER}, {'UserId': OUTSIDER}], 'mgmt')
    assert flagged[0] == -1 and OUTSIDER in flagged[1] and ORG_MEMBER not in flagged[1]
    assert _sharingResult([{'UserId': ORG_MEMBER}], 'mgmt')[0] == 1  # fixed: only in-org sharing left


def test_snapshot_shared_member_account_not_evaluable():
    res = _sharingResult([{'UserId': OUTSIDER}], 'member')
    assert res[0] == 0 and 'not evaluable from member account' in res[1]


def test_snapshot_public_only_left_to_existing_check():
    assert _sharingResult([{'Group': 'all'}], 'none')[0] == 0


def test_snapshot_attribute_error_not_pass():
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_snapshots', {'Snapshots': [SNAP]}, {'OwnerIds': ['self']})
        st.add_client_error('describe_snapshot_attribute', service_error_code='UnauthorizedOperation', http_status_code=403)
        snap, p = Ec2.getSnapshotSharing(types.SimpleNamespace(ec2Client=ec2, tags=[]))[0]
    res = _run(Ec2EbsSnapshotSharing(snap, p, SELF, {'inOrg': False}), '_checkEbsSnapshotSharedExternally')
    assert res['ebsSnapshotSharedExternally'] == [0, 'Unable to evaluate (UnauthorizedOperation)']


# --------------------------------------------------------------------------- #
# ebsRecycleBinMissing
# --------------------------------------------------------------------------- #
def _rbinResult(rules, hasSnap=True, hasImage=False):
    """rules: {resourceType: [get_rule response dicts]}"""
    ec2, rbin = _client('ec2'), _client('rbin')
    with Stubber(ec2) as se, Stubber(rbin) as sr:
        se.add_response('describe_snapshots', {'Snapshots': [SNAP] if hasSnap else []},
                        {'OwnerIds': ['self'], 'MaxResults': 5})
        se.add_response('describe_images', {'Images': [_image(False)] if hasImage else []},
                        {'Owners': ['self'], 'MaxResults': 5})
        for rtype in [t for t, need in (('EBS_SNAPSHOT', hasSnap), ('EC2_IMAGE', hasImage)) if need]:
            rr = rules.get(rtype, [])
            sr.add_response('list_rules', {'Rules': [{'Identifier': r['Identifier']} for r in rr]},
                            {'ResourceType': rtype})
            for r in rr:
                sr.add_response('get_rule', r, {'Identifier': r['Identifier']})
        res = _run(Ec2Regional(ec2, None, rbin), '_checkEbsRecycleBinMissing')['ebsRecycleBinMissing']
        se.assert_no_pending_responses()
        sr.assert_no_pending_responses()
    return res


def _rule(ident, rtype='EBS_SNAPSHOT', lock='locked', tags=None):
    r = {'Identifier': ident, 'ResourceType': rtype, 'Status': 'available',
         'RetentionPeriod': {'RetentionPeriodValue': 7, 'RetentionPeriodUnit': 'DAYS'}, 'LockState': lock}
    if tags:
        r['ResourceTags'] = tags
    return r


def test_recycle_bin_flag_fix_locked():
    assert _rbinResult({})[0] == -1                                                  # no rule
    assert _rbinResult({'EBS_SNAPSHOT': [_rule('r1', lock='unlocked')]})[0] == 0     # unlocked -> INFO
    assert _rbinResult({'EBS_SNAPSHOT': [_rule('r1')]})[0] == 1                      # locked region-level


def test_recycle_bin_tag_level_only_info():
    res = _rbinResult({'EBS_SNAPSHOT': [_rule('r1', tags=[{'ResourceTagKey': 'backup', 'ResourceTagValue': 'yes'}])]})
    assert res[0] == 0 and 'tag-level' in res[1]


def test_recycle_bin_ami_rule_required_when_amis_exist():
    res = _rbinResult({'EBS_SNAPSHOT': [_rule('r1')]}, hasImage=True)
    assert res[0] == -1 and 'EC2_IMAGE' in res[1]
    assert _rbinResult({'EBS_SNAPSHOT': [_rule('r1')], 'EC2_IMAGE': [_rule('r2', rtype='EC2_IMAGE')]}, hasImage=True)[0] == 1


def test_recycle_bin_access_denied_not_pass():
    ec2, rbin = _client('ec2'), _client('rbin')
    with Stubber(ec2) as se, Stubber(rbin) as sr:
        se.add_response('describe_snapshots', {'Snapshots': [SNAP]}, {'OwnerIds': ['self'], 'MaxResults': 5})
        se.add_response('describe_images', {'Images': []}, {'Owners': ['self'], 'MaxResults': 5})
        sr.add_client_error('list_rules', service_error_code='AccessDeniedException', http_status_code=400)
        res = _run(Ec2Regional(ec2, None, rbin), '_checkEbsRecycleBinMissing')['ebsRecycleBinMissing']
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']


# --------------------------------------------------------------------------- #
# Regional settings: unreadable -> not evaluable (never PASS)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize('op,method,key', [
    ('get_image_block_public_access_state', '_checkEc2ImageBlockPublicAccessOff', 'ec2ImageBlockPublicAccessOff'),
    ('get_instance_metadata_defaults', '_checkEc2ImdsDefaultNotRequired', 'ec2ImdsDefaultNotRequired'),
    ('get_snapshot_block_public_access_state', '_checkEc2SnapshotBlockPublicAccessOff', 'ec2SnapshotBlockPublicAccessOff'),
    ('get_allowed_images_settings', '_checkEc2AllowedAmisNotEnforced', 'ec2AllowedAmisNotEnforced'),
])
def test_regional_access_denied_not_pass(op, method, key):
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_client_error(op, service_error_code='UnauthorizedOperation', http_status_code=403)
        res = _run(Ec2Regional(ec2), method)[key]
    assert res == [0, 'Unable to evaluate (UnauthorizedOperation)']


def test_imds_endpoint_disabled_passes():
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('get_instance_metadata_defaults', {'AccountLevel': {'HttpEndpoint': 'disabled'}})
        assert _run(Ec2Regional(ec2), '_checkEc2ImdsDefaultNotRequired')['ec2ImdsDefaultNotRequired'][0] == 1


# --------------------------------------------------------------------------- #
# elbTlsPolicyOutdated / elbAccessLogsDisabled - real-AWS shapes the emulator lacks
# --------------------------------------------------------------------------- #
def _clbPolicy(name, tls10):
    attrs = [{'AttributeName': 'Reference-Security-Policy', 'AttributeValue': 'ELBSecurityPolicy-2016-08' if tls10 else 'ELBSecurityPolicy-TLS-1-2-2017-01'},
             {'AttributeName': 'Protocol-SSLv3', 'AttributeValue': 'false'},
             {'AttributeName': 'Protocol-TLSv1', 'AttributeValue': 'true' if tls10 else 'false'},
             {'AttributeName': 'Protocol-TLSv1.1', 'AttributeValue': 'true' if tls10 else 'false'},
             {'AttributeName': 'Protocol-TLSv1.2', 'AttributeValue': 'true'}]
    return {'PolicyName': name, 'PolicyTypeName': 'SSLNegotiationPolicyType', 'PolicyAttributeDescriptions': attrs}


def _clbTls(tls10):
    elb = _client('elb')
    lb = {'LoadBalancerName': 'clb1', 'ListenerDescriptions': [
        {'Listener': {'Protocol': 'HTTPS', 'LoadBalancerPort': 443, 'InstanceProtocol': 'HTTP', 'InstancePort': 80},
         'PolicyNames': ['pol']}], 'SecurityGroups': []}
    with Stubber(elb) as st:
        st.add_response('describe_load_balancer_policies', {'PolicyDescriptions': [_clbPolicy('pol', tls10)]},
                        {'LoadBalancerName': 'clb1'})
        return _run(Ec2ElbClassic(lb, elb), '_checkElbTlsPolicyOutdated')['elbTlsPolicyOutdated']


def test_clb_tls_policy_expanded_attributes_flag_fix():
    flagged = _clbTls(True)
    assert flagged[0] == -1 and 'TLSv1' in flagged[1]
    assert _clbTls(False)[0] == 1


def test_clb_listener_without_ssl_policy_not_pass():
    elb = _client('elb')
    lb = {'LoadBalancerName': 'clb1', 'ListenerDescriptions': [
        {'Listener': {'Protocol': 'SSL', 'LoadBalancerPort': 443, 'InstanceProtocol': 'TCP', 'InstancePort': 80},
         'PolicyNames': []}], 'SecurityGroups': []}
    with Stubber(elb) as st:
        st.add_response('describe_load_balancer_policies', {'PolicyDescriptions': []}, {'LoadBalancerName': 'clb1'})
        res = _run(Ec2ElbClassic(lb, elb), '_checkElbTlsPolicyOutdated')['elbTlsPolicyOutdated']
    assert res[0] == 0


def _nlb():
    return {'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/net/n1/abc',
            'LoadBalancerName': 'n1', 'Type': 'network'}


def test_nlb_tls_listener_policy_and_access_logs():
    Config.set('ec2::elbv2SslPolicies::us-east-1', None)
    elbv2 = _client('elbv2')
    lb = _nlb()
    listeners = {'Listeners': [{'ListenerArn': lb['LoadBalancerArn'].replace('loadbalancer', 'listener') + '/l1',
                                'Port': 443, 'Protocol': 'TLS', 'SslPolicy': 'ELBSecurityPolicy-TLS-1-1-2017-01'}]}
    with Stubber(elbv2) as st:
        st.add_response('describe_listeners', listeners, {'LoadBalancerArn': lb['LoadBalancerArn']})
        st.add_response('describe_ssl_policies', {'SslPolicies': [
            {'Name': 'ELBSecurityPolicy-TLS-1-1-2017-01', 'SslProtocols': ['TLSv1.1', 'TLSv1.2']},
            {'Name': 'ELBSecurityPolicy-TLS13-1-2-2021-06', 'SslProtocols': ['TLSv1.2', 'TLSv1.3']}]}, {})
        st.add_response('describe_load_balancer_attributes',
                        {'Attributes': [{'Key': 'access_logs.s3.enabled', 'Value': 'false'}]},
                        {'LoadBalancerArn': lb['LoadBalancerArn']})
        d = Ec2ElbCommon(lb, [], elbv2, None)
        tls = _run(d, '_checkElbTlsPolicyOutdated')['elbTlsPolicyOutdated']
        logs = _run(d, '_checkElbAccessLogsDisabled')['elbAccessLogsDisabled']
        st.assert_no_pending_responses()
    Config.set('ec2::elbv2SslPolicies::us-east-1', None)
    assert tls[0] == -1 and 'TLSv1.1' in tls[1]
    assert logs == [-1, 'Disabled']


def test_elbv2_attributes_access_denied_not_pass():
    elbv2 = _client('elbv2')
    lb = dict(_nlb(), Type='application')
    with Stubber(elbv2) as st:
        st.add_client_error('describe_load_balancer_attributes', service_error_code='AccessDenied', http_status_code=403)
        res = _run(Ec2ElbCommon(lb, [], elbv2, None), '_checkElbAccessLogsDisabled')['elbAccessLogsDisabled']
    assert res == [0, 'Unable to evaluate (AccessDenied)']


# --------------------------------------------------------------------------- #
# ec2AmiSharedExternally
# --------------------------------------------------------------------------- #
OWN_ORG = 'o-abc123defg'   # matches _orgContext()


def _amiSharingResult(perms, mode):
    ec2 = _client('ec2')
    image = _image(False)
    with Stubber(ec2) as st:
        st.add_response('describe_image_attribute',
                        {'ImageId': image['ImageId'], 'LaunchPermissions': perms},
                        {'ImageId': image['ImageId'], 'Attribute': 'launchPermission'})
        permsById = Ec2.getImageLaunchPermissions(types.SimpleNamespace(ec2Client=ec2), [image])
        st.assert_no_pending_responses()
    return _run(Ec2Ami(image, permsById[image['ImageId']], SELF, _orgContext(mode)),
                '_checkEc2AmiSharedExternally')['ec2AmiSharedExternally']


def test_ami_shared_outside_org_flag_fix_not_in_org():
    assert _amiSharingResult([{'UserId': OUTSIDER}], 'none')[0] == -1    # misconfigured
    assert _amiSharingResult([], 'none')[0] == 1                         # fixed: launch permission removed


def test_ami_shared_outside_org_flag_fix_mgmt_account():
    flagged = _amiSharingResult([{'UserId': ORG_MEMBER}, {'UserId': OUTSIDER}], 'mgmt')
    assert flagged[0] == -1 and OUTSIDER in flagged[1] and ORG_MEMBER not in flagged[1]
    assert _amiSharingResult([{'UserId': ORG_MEMBER}], 'mgmt')[0] == 1


def test_ami_shared_with_own_org_or_ou_passes_foreign_org_fails():
    own = [{'OrganizationArn': f'arn:aws:organizations::{SELF}:organization/{OWN_ORG}'},
           {'OrganizationalUnitArn': f'arn:aws:organizations::{SELF}:ou/{OWN_ORG}/ou-ab12-cdef3456'}]
    assert _amiSharingResult(own, 'member')[0] == 1
    foreign = [{'OrganizationArn': f'arn:aws:organizations::{OUTSIDER}:organization/o-zzzzzzzzzz'}]
    res = _amiSharingResult(foreign, 'member')
    assert res[0] == -1 and 'o-zzzzzzzzzz' in res[1]


def test_ami_shared_member_account_not_evaluable():
    res = _amiSharingResult([{'UserId': OUTSIDER}], 'member')
    assert res[0] == 0 and res[1].startswith('Not evaluable from member account')


def test_ami_public_only_left_to_ec2AmiPublic():
    assert _amiSharingResult([{'Group': 'all'}], 'none')[0] == 0


def test_ami_attribute_error_not_pass():
    ec2 = _client('ec2')
    image = _image(False)
    with Stubber(ec2) as st:
        st.add_client_error('describe_image_attribute', service_error_code='UnauthorizedOperation', http_status_code=403)
        permsById = Ec2.getImageLaunchPermissions(types.SimpleNamespace(ec2Client=ec2), [image])
    res = _run(Ec2Ami(image, permsById[image['ImageId']], SELF, {'inOrg': False}), '_checkEc2AmiSharedExternally')
    assert res['ec2AmiSharedExternally'] == [0, 'Unable to evaluate (UnauthorizedOperation)']


def test_ami_sharing_not_fetched_records_nothing():
    assert _run(Ec2Ami(_image(False)), '_checkEc2AmiSharedExternally') == {}


# --------------------------------------------------------------------------- #
# ebsSnapshotUnencrypted (main flag/fix cycle runs on the emulator)
# --------------------------------------------------------------------------- #
def test_snapshot_unencrypted_labels_ami_and_missing_field_not_pass():
    res = _run(Ec2EbsSnapshotSharing(dict(SNAP, Encrypted=False), None, SELF, None, ['ami-1']),
               '_checkEbsSnapshotUnencrypted')['ebsSnapshotUnencrypted']
    assert res[0] == -1 and 'ami-1' in res[1]
    assert _run(Ec2EbsSnapshotSharing(dict(SNAP, Encrypted=True), None, SELF, None),
                '_checkEbsSnapshotUnencrypted')['ebsSnapshotUnencrypted'][0] == 1
    assert _run(Ec2EbsSnapshotSharing(SNAP, None, SELF, None),
                '_checkEbsSnapshotUnencrypted')['ebsSnapshotUnencrypted'][0] == 0
    # sharing permissions not fetched -> sharing check records nothing
    assert _run(Ec2EbsSnapshotSharing(SNAP, None, SELF, None), '_checkEbsSnapshotSharedExternally') == {}


# --------------------------------------------------------------------------- #
# ec2AmiUntrustedOrStale
# --------------------------------------------------------------------------- #
import datetime as _dt  # noqa: E402
from services.ec2.drivers.Ec2Instance import Ec2Instance  # noqa: E402


def _instance(imageId, state='running', **extra):
    d = {'InstanceId': 'i-0123456789abcdef0', 'ImageId': imageId, 'InstanceType': 't3.micro',
         'State': {'Name': state}, 'LaunchTime': _dt.datetime.now(_dt.timezone.utc)}
    d.update(extra)
    return d


def _staleResult(imageId, imageResponse=None, error=None):
    for k in ('ec2::image::' + imageId, 'ec2::imagestatus::' + imageId):
        Config.set(k, '__unset__')
    Config.set('stsInfo', {'Account': SELF})
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        params = {'ImageIds': [imageId], 'IncludeDeprecated': True, 'IncludeDisabled': True}
        if error:
            st.add_client_error('describe_images', service_error_code=error, http_status_code=400, expected_params=params)
        else:
            st.add_response('describe_images', {'Images': imageResponse}, params)
        inst = Ec2Instance(_instance(imageId), ec2, None)
        st.assert_no_pending_responses()
    for k in ('ec2::image::' + imageId, 'ec2::imagestatus::' + imageId):
        Config.set(k, '__unset__')
    return _run(inst, '_checkEc2AmiUntrustedOrStale').get('ec2AmiUntrustedOrStale')


def _img(imageId, **kw):
    d = {'ImageId': imageId, 'OwnerId': SELF, 'Public': False, 'State': 'available'}
    d.update(kw)
    return d


def test_ami_stale_deprecated_flag_fix():
    past = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=10)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    future = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    assert _staleResult('ami-0aaa', [_img('ami-0aaa', DeprecationTime=past)])[0] == -1     # deprecated
    assert _staleResult('ami-0aaa', [_img('ami-0aaa', DeprecationTime=future)])[0] == 1    # fixed: deprecation cancelled / pushed out
    assert _staleResult('ami-0aaa', [_img('ami-0aaa')])[0] == 1


def test_ami_untrusted_third_party_flag_fix():
    res = _staleResult('ami-0bbb', [_img('ami-0bbb', OwnerId=OUTSIDER, Public=True)])
    assert res[0] == -1 and OUTSIDER in res[1]
    # fixed: rebuilt from an Amazon / verified-provider AMI (ImageOwnerAlias present)
    assert _staleResult('ami-0bbb', [_img('ami-0bbb', OwnerId='137112412989', Public=True, ImageOwnerAlias='amazon')])[0] == 1
    # privately shared (not public) AMIs from another account are not "unverified public" AMIs
    assert _staleResult('ami-0bbb', [_img('ami-0bbb', OwnerId=ORG_MEMBER, Public=False)])[0] == 1


def test_ami_deregistered_or_disabled_flagged():
    assert _staleResult('ami-0ccc', [])[0] == -1                                    # empty result
    assert _staleResult('ami-0ccc', error='InvalidAMIID.NotFound')[0] == -1         # NotFound error
    assert _staleResult('ami-0ccc', [_img('ami-0ccc', State='disabled')])[0] == -1


def test_ami_lookup_denied_not_pass():
    assert _staleResult('ami-0ddd', error='UnauthorizedOperation') == [0, 'Unable to evaluate (UnauthorizedOperation)']


def test_ami_stale_only_running_instances():
    Config.set('ec2::image::ami-0eee', _img('ami-0eee', State='disabled'))
    Config.set('ec2::imagestatus::ami-0eee', 'found')
    inst = Ec2Instance(_instance('ami-0eee', state='stopped'), _client('ec2'), None)
    Config.set('ec2::image::ami-0eee', '__unset__')
    assert _run(inst, '_checkEc2AmiUntrustedOrStale') == {}


# --------------------------------------------------------------------------- #
# ec2InstanceWithKeyPair
# --------------------------------------------------------------------------- #
from services.ec2.drivers.Ec2SSM import Ec2SSM  # noqa: E402


def _keyPairResult(instance, ssmInfo=None, ssmError=None):
    ssm = _client('ssm')
    ns = types.SimpleNamespace(ssmClient=ssm)
    with Stubber(ssm) as st:
        if ssmError:
            st.add_client_error('describe_instance_information', service_error_code=ssmError, http_status_code=400)
        else:
            st.add_response('describe_instance_information', {'InstanceInformationList': ssmInfo or []}, {'MaxResults': 50})
        managed = Ec2.getSSMManagedInstances(ns)
        st.assert_no_pending_responses()
    obj = Ec2SSM(instance['InstanceId'], managed, instance, ns.ssmError, ns.ssmPingStatus)
    return _run(obj, '_checkEc2InstanceWithKeyPair').get('ec2InstanceWithKeyPair')


def test_instance_with_key_pair_flag_fix():
    online = [{'InstanceId': 'i-0123456789abcdef0', 'PingStatus': 'Online'}]
    res = _keyPairResult(_instance('ami-1', KeyName='legacy-key'), online)
    assert res[0] == -1 and 'legacy-key' in res[1]                         # SSM-managed + key pair
    assert _keyPairResult(_instance('ami-1'), online)[0] == 1               # fixed: relaunched without a key pair


def test_instance_with_key_pair_unmanaged_or_offline_info():
    assert _keyPairResult(_instance('ami-1', KeyName='k'), [])[0] == 0
    lost = [{'InstanceId': 'i-0123456789abcdef0', 'PingStatus': 'ConnectionLost'}]
    assert _keyPairResult(_instance('ami-1', KeyName='k'), lost)[0] == 0


def test_instance_with_key_pair_ssm_denied_not_pass():
    res = _keyPairResult(_instance('ami-1', KeyName='k'), ssmError='AccessDeniedException')
    assert res[0] == 0 and 'Unable to evaluate (AccessDeniedException)' in res[1]
    # EC2SSMNotManaged keeps skipping when the lookup failed
    assert _run(Ec2SSM('i-1', None), '_checkSSMManaged') == {}


# --------------------------------------------------------------------------- #
# ec2InstanceInPublicSubnet (managed-service ENIs, main route table, shared VPC)
# --------------------------------------------------------------------------- #
from services.ec2.drivers.Ec2NetworkInterface import Ec2NetworkInterface, classifyEni, getSubnetRouting  # noqa: E402

_ROUTING_KEY = 'ec2::subnetRouting::us-east-1'


def _routing(routeTables, subnets, error=None):
    Config.set(_ROUTING_KEY, None)
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        if error:
            st.add_client_error('describe_route_tables', service_error_code=error, http_status_code=403)
        else:
            st.add_response('describe_route_tables', {'RouteTables': routeTables})
            st.add_response('describe_subnets', {'Subnets': subnets})
        ctx = getSubnetRouting(ec2)
        st.assert_no_pending_responses()
    Config.set(_ROUTING_KEY, None)
    return ctx


def _rt(rtId, vpc, routes, main=False, subnet=None):
    assoc = {'RouteTableAssociationId': 'rtbassoc-' + rtId[4:], 'RouteTableId': rtId, 'Main': main,
             'AssociationState': {'State': 'associated'}}
    if subnet:
        assoc['SubnetId'] = subnet
    return {'RouteTableId': rtId, 'VpcId': vpc, 'Associations': [assoc],
            'Routes': [{'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local', 'State': 'active'}] + routes}


IGW_ROUTE = {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-0123', 'State': 'active'}
NAT_ROUTE = {'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': 'nat-0123', 'State': 'active'}
RDS_ENI = {'NetworkInterfaceId': 'eni-0rds', 'SubnetId': 'subnet-a', 'VpcId': 'vpc-1',
           'Description': 'RDSNetworkInterface', 'RequesterId': 'amazon-rds', 'InterfaceType': 'interface'}


def _eniResult(eni, routing):
    return _run(Ec2NetworkInterface(eni, classifyEni(eni), routing),
                '_checkEc2InstanceInPublicSubnet')['ec2InstanceInPublicSubnet']


def test_rds_eni_in_public_subnet_flag_fix():
    subnets = [{'SubnetId': 'subnet-a', 'VpcId': 'vpc-1'}]
    public = _routing([_rt('rtb-main', 'vpc-1', [], main=True), _rt('rtb-pub', 'vpc-1', [IGW_ROUTE], subnet='subnet-a')], subnets)
    res = _eniResult(RDS_ENI, public)
    assert res[0] == -1 and 'RDS' in res[1] and 'igw-0123' in res[1]
    # fixed: default route via a NAT gateway instead of the IGW
    private = _routing([_rt('rtb-main', 'vpc-1', [], main=True), _rt('rtb-pub', 'vpc-1', [NAT_ROUTE], subnet='subnet-a')], subnets)
    assert _eniResult(RDS_ENI, private)[0] == 1


def test_public_subnet_via_main_route_table_and_ipv6():
    subnets = [{'SubnetId': 'subnet-a', 'VpcId': 'vpc-1'}]
    v6 = {'DestinationIpv6CidrBlock': '::/0', 'GatewayId': 'igw-0123', 'State': 'active'}
    assert _eniResult(RDS_ENI, _routing([_rt('rtb-main', 'vpc-1', [v6], main=True)], subnets))[0] == -1
    blackhole = dict(IGW_ROUTE, State='blackhole')
    assert _eniResult(RDS_ENI, _routing([_rt('rtb-main', 'vpc-1', [blackhole], main=True)], subnets))[0] == 1


def test_public_subnet_shared_vpc_or_denied_not_pass():
    # subnet visible (RAM share) but its route table belongs to the owner account
    res = _eniResult(RDS_ENI, _routing([], [{'SubnetId': 'subnet-a', 'VpcId': 'vpc-1'}]))
    assert res[0] == 0 and 'route table not visible' in res[1]
    res = _eniResult(RDS_ENI, _routing([], [], error='UnauthorizedOperation'))
    assert res[0] == 0 and 'Unable to evaluate (UnauthorizedOperation)' in res[1]


def test_classify_eni():
    assert classifyEni(RDS_ENI) == 'RDS'
    assert classifyEni({'Description': 'ElastiCache my-redis-0001-001', 'RequesterId': 'amazon-elasticache'}) == 'ElastiCache'
    assert classifyEni({'Description': 'arn:aws:ecs:us-east-1:111111111111:attachment/abc'}) == 'ECS'
    assert classifyEni({'Description': 'ELB app/my-alb/123', 'RequesterId': 'amazon-elb'}) is None
    assert classifyEni({'Description': 'Interface for NAT Gateway nat-1'}) is None


# --------------------------------------------------------------------------- #
# ec2UserDataSecrets - pattern accuracy (instance / launch-template cycles run on the emulator)
# --------------------------------------------------------------------------- #
import base64 as _b64  # noqa: E402
import gzip as _gzip  # noqa: E402
from services.ec2.drivers.Ec2UserDataScan import decodeUserData, findSecrets  # noqa: E402


@pytest.mark.parametrize('text,expected', [
    ('export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', ['AWS access key ID']),
    ('aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', ['AWS secret access key']),
    ('"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', ['AWS secret access key']),
    ('-----BEGIN OPENSSH PRIVATE KEY-----\nabc', ['private key (PEM)']),
    ('-----BEGIN RSA PRIVATE KEY-----', ['private key (PEM)']),
    ('MYSQL_ROOT_PASSWORD=Sup3rS3cret!', ['password literal']),
    ('password: "hunter22"', ['password literal']),
    # no match: references, placeholders, unrelated words
    ('export AWS_SECRET_ACCESS_KEY=$(aws secretsmanager get-secret-value --secret-id x)', []),
    ('DB_PASSWORD=${DB_PASSWORD}', []),
    ('password={{resolve:secretsmanager:db}}', []),
    ('password=<changeme>', []),
    ('docker login --password-stdin', []),
    ('PWD=/home/ec2-user', []),
    ('-----BEGIN PUBLIC KEY-----', []),
    # cloud-init account settings and boolean / null values are not credentials (review fix round 2)
    ('#cloud-config\nusers:\n  - name: bob\n    lock_passwd: false\n', []),
    ('users:\n  - name: bob\n    lock_passwd: true\n    ssh_pwauth: true\n', []),
    ('chpasswd:\n  expire: false\n', []),
    ('password: null', []),
    ('password: None\n', []),
    ('DB_PASSWORD=false', []),
    ('password: "yes"', []),
    # real literals that merely start like a boolean still match
    ('password: falsehood1', ['password literal']),
    ('plain_text_passwd: hunter22', ['password literal']),
    ('ssh-rsa AAAAB3NzaC1yc2E user@host', []),
])
def test_user_data_patterns(text, expected):
    assert findSecrets(text) == expected


def test_user_data_decoding_gzip_and_masking():
    raw = b'#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
    assert findSecrets(decodeUserData(_b64.b64encode(_gzip.compress(raw)).decode())) == ['AWS access key ID']
    assert decodeUserData(None) == ''


def test_launch_template_user_data_denied_not_pass():
    from services.ec2.drivers.Ec2LaunchTemplate import Ec2LaunchTemplate
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_client_error('describe_launch_template_versions', service_error_code='UnauthorizedOperation', http_status_code=403)
        res = _run(Ec2LaunchTemplate({'LaunchTemplateId': 'lt-0123'}, ec2), '_checkEc2UserDataSecrets')
    assert res['ec2UserDataSecrets'] == [0, 'Unable to evaluate (UnauthorizedOperation)']


# --------------------------------------------------------------------------- #
# vpcEndpointPolicyFullAccess
# --------------------------------------------------------------------------- #
import json as _json  # noqa: E402
from services.ec2.drivers.Ec2VpcEndpoint import Ec2VpcEndpoint, evaluateEndpointPolicy  # noqa: E402

FULL = {'Effect': 'Allow', 'Principal': '*', 'Action': '*', 'Resource': '*'}


def _pol(*stmts):
    return _json.dumps({'Version': '2012-10-17', 'Statement': list(stmts)})


@pytest.mark.parametrize('policy,status', [
    (_pol(FULL), -1),
    (_pol(dict(FULL, Principal={'AWS': '*'})), -1),
    (_pol(dict(FULL, Action=['*'], Resource=['*'])), -1),
    # restricted
    (_pol(dict(FULL, Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}})), 1),
    (_pol(dict(FULL, Condition={'StringEquals': {'aws:ResourceOrgID': 'o-abc123defg'}})), 1),
    (_pol(dict(FULL, Condition={'StringEquals': {'aws:PrincipalAccount': ['111111111111']}})), 1),
    (_pol(FULL, {'Effect': 'Deny', 'Principal': '*', 'Action': '*', 'Resource': '*',
                 'Condition': {'StringNotEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}}}), 1),
    (_pol(dict(FULL, Action='s3:GetObject', Resource='arn:aws:s3:::bucket/*')), 1),
    # not restricting: wildcard value, unrelated key, narrow Deny
    (_pol(dict(FULL, Condition={'StringLike': {'aws:PrincipalOrgID': '*'}})), -1),
    (_pol(dict(FULL, Condition={'StringEquals': {'aws:SourceVpc': 'vpc-1'}})), -1),
    (_pol(FULL, {'Effect': 'Deny', 'Principal': '*', 'Action': 's3:DeleteObject', 'Resource': '*',
                 'Condition': {'StringNotEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}}}), -1),
    (None, 0),
])
def test_endpoint_policy_evaluation(policy, status):
    assert evaluateEndpointPolicy(policy)[0] == status


def _endpointResult(policy, supported=True, epType='Gateway', state='available'):
    ep = {'VpcEndpointId': 'vpce-0123', 'VpcEndpointType': epType, 'ServiceName': 'com.amazonaws.us-east-1.s3',
          'State': state, 'PolicyDocument': policy}
    return _run(Ec2VpcEndpoint(ep, supported), '_checkVpcEndpointPolicyFullAccess').get('vpcEndpointPolicyFullAccess')


def test_endpoint_policy_flag_fix_and_not_supported():
    assert _endpointResult(_pol(FULL))[0] == -1
    assert _endpointResult(_pol(dict(FULL, Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}})))[0] == 1
    assert _endpointResult(_pol(FULL), supported=False)[0] == 0          # service has no endpoint policies
    assert _endpointResult(_pol(FULL), supported=None)[0] == 0           # support unknown -> not evaluable
    assert _endpointResult(None, epType='GatewayLoadBalancer')[0] == 0
    assert _endpointResult(_pol(FULL), state='deleted') is None


def test_endpoint_policy_support_lookup_falls_back_per_service():
    ec2 = _client('ec2')
    good, bad = 'com.amazonaws.us-east-1.s3', 'com.amazonaws.vpce.us-east-1.vpce-svc-gone'
    with Stubber(ec2) as st:
        st.add_client_error('describe_vpc_endpoint_services', service_error_code='InvalidServiceName', http_status_code=400)
        st.add_response('describe_vpc_endpoint_services',
                        {'ServiceDetails': [{'ServiceName': good, 'VpcEndpointPolicySupported': True}]},
                        {'ServiceNames': [good]})
        st.add_client_error('describe_vpc_endpoint_services', service_error_code='InvalidServiceName', http_status_code=400)
        support, err = Ec2.getEndpointPolicySupport(types.SimpleNamespace(ec2Client=ec2), [good, bad])
        st.assert_no_pending_responses()
    assert support == {good: True} and err == 'InvalidServiceName'


# --------------------------------------------------------------------------- #
# vpcNoGatewayEndpoints
# --------------------------------------------------------------------------- #
from services.ec2.drivers.Ec2Vpc import Ec2Vpc  # noqa: E402

VPC = {'VpcId': 'vpc-1', 'OwnerId': SELF}


def _vpcEndpointsResult(endpoints, vpc=VPC, routeTables=None, endpointsError=None):
    routeTables = routeTables if routeTables is not None else [
        _rt('rtb-main', 'vpc-1', [NAT_ROUTE], main=True),
        _rt('rtb-pub', 'vpc-1', [IGW_ROUTE], subnet='subnet-pub')]
    routing = _routing(routeTables, [{'SubnetId': 'subnet-a', 'VpcId': 'vpc-1'},
                                     {'SubnetId': 'subnet-pub', 'VpcId': 'vpc-1'}])
    obj = Ec2Vpc(vpc, [], None, routing, endpoints, endpointsError, SELF)
    return _run(obj, '_checkVpcNoGatewayEndpoints').get('vpcNoGatewayEndpoints')


def _gw(service, rts, state='available', epType='Gateway'):
    return {'VpcEndpointId': 'vpce-' + service, 'VpcId': 'vpc-1', 'VpcEndpointType': epType, 'State': state,
            'ServiceName': f'com.amazonaws.us-east-1.{service}', 'RouteTableIds': rts}


def test_vpc_no_gateway_endpoint_flag_fix():
    res = _vpcEndpointsResult([])
    assert res[0] == -1 and 'subnet-a' in res[1] and 'subnet-pub' not in res[1]
    # endpoint on the public route table only does not cover the private subnet
    assert _vpcEndpointsResult([_gw('s3', ['rtb-pub'])])[0] == -1
    assert _vpcEndpointsResult([_gw('s3', ['rtb-main'], state='deleted')])[0] == -1
    res = _vpcEndpointsResult([_gw('s3', ['rtb-main'])])
    assert res[0] == 1 and 'DynamoDB' in res[1]
    assert _vpcEndpointsResult([_gw('s3', ['rtb-main']), _gw('dynamodb', ['rtb-main'])]) == \
        [1, 'S3 endpoint covers all 1 private subnet(s)']
    # an S3 interface endpoint keeps S3 traffic private for the whole VPC
    assert _vpcEndpointsResult([_gw('s3', [], epType='Interface')])[0] == 1


def test_vpc_no_gateway_endpoint_not_evaluable_paths():
    assert _vpcEndpointsResult([], vpc={'VpcId': 'vpc-1', 'OwnerId': OUTSIDER})[0] == 0      # shared VPC
    res = _vpcEndpointsResult(None, endpointsError='UnauthorizedOperation')
    assert res == [0, 'Unable to evaluate (UnauthorizedOperation)']
    routing = _routing(None, None, error='UnauthorizedOperation')
    assert _run(Ec2Vpc(VPC, [], None, routing, [], None, SELF),
                '_checkVpcNoGatewayEndpoints')['vpcNoGatewayEndpoints'][0] == 0
    # only public subnets -> nothing to cover
    assert _vpcEndpointsResult([], routeTables=[_rt('rtb-main', 'vpc-1', [IGW_ROUTE], main=True)]) == [1, 'No private subnets']


# --------------------------------------------------------------------------- #
# vpnWeakTunnelCrypto
# --------------------------------------------------------------------------- #
from services.ec2.drivers.Ec2VpnConnection import Ec2VpnConnection  # noqa: E402


def _vals(*v):
    return [{'Value': x} for x in v]


STRONG_TUNNEL_OPTS = {'OutsideIpAddress': '198.51.100.1', 'IkeVersions': _vals('ikev2'),
                      'Phase1IntegrityAlgorithms': _vals('SHA2-256'), 'Phase2IntegrityAlgorithms': _vals('SHA2-256'),
                      'Phase1DHGroupNumbers': _vals(19, 20), 'Phase2DHGroupNumbers': _vals(19, 20)}


def _vpnResult(tunnels):
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_vpn_connections', {'VpnConnections': [
            {'VpnConnectionId': 'vpn-0123', 'State': 'available', 'Type': 'ipsec.1', 'CustomerGatewayId': 'cgw-1',
             'Options': {'TunnelOptions': tunnels}}]})
        vpns = Ec2.getVpnConnections(types.SimpleNamespace(ec2Client=ec2, tags=[]))
        st.assert_no_pending_responses()
    return _run(Ec2VpnConnection(vpns[0]), '_checkVpnWeakTunnelCrypto')['vpnWeakTunnelCrypto']


def test_vpn_weak_tunnel_flag_fix_same_connection():
    # misconfigured: tunnel options never customised (AWS defaults, lists omitted)
    res = _vpnResult([{'OutsideIpAddress': '198.51.100.1'}, {'OutsideIpAddress': '198.51.100.2'}])
    assert res[0] == -1 and 'default' in res[1] and '198.51.100.2' in res[1]
    # fixed with modify-vpn-tunnel-options on both tunnels
    assert _vpnResult([STRONG_TUNNEL_OPTS, dict(STRONG_TUNNEL_OPTS, OutsideIpAddress='198.51.100.2')])[0] == 1


def test_vpn_weak_tunnel_individual_settings():
    assert _vpnResult([dict(STRONG_TUNNEL_OPTS, IkeVersions=_vals('ikev1', 'ikev2'))])[0] == -1
    assert _vpnResult([dict(STRONG_TUNNEL_OPTS, Phase2IntegrityAlgorithms=_vals('SHA1', 'SHA2-256'))])[0] == -1
    assert _vpnResult([dict(STRONG_TUNNEL_OPTS, Phase1DHGroupNumbers=_vals(2, 20))])[0] == -1
    res = _vpnResult([dict(STRONG_TUNNEL_OPTS, Phase2DHGroupNumbers=_vals(14))])
    assert res[0] == -1 and 'only DH group 14' in res[1]
    assert _vpnResult([dict(STRONG_TUNNEL_OPTS, Phase2DHGroupNumbers=_vals(14, 20))])[0] == 1
    assert _vpnResult([])[0] == 0


# --------------------------------------------------------------------------- #
# albMtlsOff / albTargetGroupPlaintext
# --------------------------------------------------------------------------- #
TS_ARN = 'arn:aws:elasticloadbalancing:us-east-1:111111111111:truststore/ts/0123456789abcdef'


def _alb(scheme='internal'):
    return {'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a/1',
            'LoadBalancerName': 'a', 'Type': 'application', 'Scheme': scheme}


def _mtlsResult(mutualAuth, scheme='internal', trustStore=None, tsError=None):
    Config.set('ec2::elbv2TrustStores::us-east-1', None)
    elbv2 = _client('elbv2')
    listener = {'ListenerArn': 'arn:l', 'Protocol': 'HTTPS', 'Port': 443}
    if mutualAuth is not None:
        listener['MutualAuthentication'] = mutualAuth
    with Stubber(elbv2) as st:
        st.add_response('describe_listeners', {'Listeners': [listener]})
        if trustStore is not None:
            st.add_response('describe_trust_stores', {'TrustStores': [trustStore]}, {'TrustStoreArns': [TS_ARN]})
        elif tsError:
            st.add_client_error('describe_trust_stores', service_error_code=tsError, http_status_code=400)
        res = _run(Ec2ElbCommon(_alb(scheme), [], elbv2, None), '_checkAlbMtlsOff').get('albMtlsOff')
        st.assert_no_pending_responses()
    Config.set('ec2::elbv2TrustStores::us-east-1', None)
    return res


TRUST_STORE = {'Name': 'ts', 'TrustStoreArn': TS_ARN, 'Status': 'ACTIVE', 'NumberOfCaCertificates': 1,
               'TotalRevokedEntries': 3}


def test_alb_mtls_flag_fix_and_informational_paths():
    # FLAG: verify mode weakened to accept expired client certificates
    res = _mtlsResult({'Mode': 'verify', 'TrustStoreArn': TS_ARN, 'IgnoreClientCertificateExpiry': True},
                      trustStore=dict(TRUST_STORE, TotalRevokedEntries=0))
    assert res[0] == -1 and 'expired' in res[1] and 'no revocation list' in res[1]
    # FIX: same listener without IgnoreClientCertificateExpiry
    res = _mtlsResult({'Mode': 'verify', 'TrustStoreArn': TS_ARN, 'IgnoreClientCertificateExpiry': False},
                      trustStore=TRUST_STORE)
    assert res == [1, 'mTLS verify on HTTPS:443']
    res = _mtlsResult({'Mode': 'verify', 'TrustStoreArn': TS_ARN}, trustStore=dict(TRUST_STORE, TotalRevokedEntries=0))
    assert res[0] == 1 and 'no revocation list' in res[1]
    assert _mtlsResult({'Mode': 'verify', 'TrustStoreArn': TS_ARN}, tsError='AccessDenied')[0] == 1
    # mTLS off / passthrough: informational for every scheme (review fix round 2 - use-case dependent)
    assert _mtlsResult(None)[0] == 0                                     # internal, mTLS never configured
    assert _mtlsResult({'Mode': 'off'})[0] == 0
    assert _mtlsResult({'Mode': 'passthrough'})[0] == 0
    assert _mtlsResult({'Mode': 'off'}, scheme='internet-facing')[0] == 0


def test_alb_mtls_listener_access_denied_not_pass():
    elbv2 = _client('elbv2')
    with Stubber(elbv2) as st:
        st.add_client_error('describe_listeners', service_error_code='AccessDenied', http_status_code=403)
        res = _run(Ec2ElbCommon(_alb(), [], elbv2, None), '_checkAlbMtlsOff')['albMtlsOff']
    assert res == [0, 'Unable to evaluate (AccessDenied)']


def _tgResult(pages, health=None):
    """health: {targetGroupArn: TargetHealthDescriptions | error code}"""
    elbv2 = _client('elbv2')
    health = health or {}
    with Stubber(elbv2) as st:
        for i, groups in enumerate(pages):
            resp = {'TargetGroups': groups}
            if i < len(pages) - 1:
                resp['NextMarker'] = f'm{i}'
            st.add_response('describe_target_groups', resp)
        for groups in pages:
            for g in groups:
                if g.get('Protocol') == 'HTTP' and g.get('TargetType') == 'ip':
                    h = health.get(g['TargetGroupArn'], [])
                    if isinstance(h, str):
                        st.add_client_error('describe_target_health', service_error_code=h, http_status_code=403)
                    else:
                        st.add_response('describe_target_health', {'TargetHealthDescriptions': h},
                                        {'TargetGroupArn': g['TargetGroupArn']})
        res = _run(Ec2ElbCommon(_alb(), [], elbv2, None), '_checkAlbTargetGroupPlaintext').get('albTargetGroupPlaintext')
        st.assert_no_pending_responses()
    return res


def _tg(name, protocol, targetType='instance'):
    return {'TargetGroupName': name, 'Protocol': protocol, 'Port': 443 if protocol == 'HTTPS' else 80,
            'TargetType': targetType,
            'TargetGroupArn': f'arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/{name}/0123456789abcdef'}


def _tgt(ip, az):
    return {'Target': {'Id': ip, 'Port': 80, 'AvailabilityZone': az}, 'TargetHealth': {'State': 'healthy'}}


def test_alb_target_group_plaintext_paginates_and_lambda_ignored():
    https = _tg('tls', 'HTTPS')
    http = _tg('plain', 'HTTP')
    lam = {'TargetGroupName': 'fn', 'TargetType': 'lambda'}
    # HTTP to instances inside the VPC: TLS terminated at the ALB is standard -> informational
    res = _tgResult([[https], [http]])
    assert res[0] == 0 and 'plain' in res[1]
    assert _tgResult([[https, lam]])[0] == 1
    assert _tgResult([[lam]]) is None


def test_alb_target_group_plaintext_ip_outside_vpc_flag_fix():
    ipTg = _tg('onprem', 'HTTP', 'ip')
    bad = _tgResult([[ipTg]], {ipTg['TargetGroupArn']: [_tgt('10.0.1.5', 'us-east-1a'), _tgt('192.168.10.5', 'all')]})
    assert bad[0] == -1 and '192.168.10.5' in bad[1] and '10.0.1.5' not in bad[1]
    # fix: the out-of-VPC target moved to an HTTPS target group
    fixed = _tgResult([[ipTg, _tg('onprem-tls', 'HTTPS', 'ip')]], {ipTg['TargetGroupArn']: [_tgt('10.0.1.5', 'us-east-1a')]})
    assert fixed[0] == 0
    assert _tgResult([[_tg('onprem-tls', 'HTTPS', 'ip')]])[0] == 1


def test_alb_target_group_plaintext_health_access_denied_not_pass():
    ipTg = _tg('onprem', 'HTTP', 'ip')
    res = _tgResult([[ipTg]], {ipTg['TargetGroupArn']: 'AccessDenied'})
    assert res[0] == 0 and 'AccessDenied' in res[1]


# --------------------------------------------------------------------------- #
# elbUsesIamOrImportedCert
# --------------------------------------------------------------------------- #
IAM_CERT = 'arn:aws:iam::111111111111:server-certificate/legacy-cert'
ACM_CERT = 'arn:aws:acm:us-east-1:111111111111:certificate/01234567-89ab-cdef-0123-456789abcdef'


def _certResult(default, extra=None, extraError=None, protocol='HTTPS'):
    elbv2 = _client('elbv2')
    larn = 'arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/app/a/1/2'
    with Stubber(elbv2) as st:
        st.add_response('describe_listeners', {'Listeners': [
            {'ListenerArn': larn, 'Protocol': protocol, 'Port': 443, 'Certificates': [{'CertificateArn': default}]}]})
        if protocol in ('HTTPS', 'TLS'):
            if extraError:
                st.add_client_error('describe_listener_certificates', service_error_code=extraError, http_status_code=403)
            else:
                pages = extra or [[]]
                for i, certs in enumerate(pages):
                    resp = {'Certificates': [{'CertificateArn': c, 'IsDefault': False} for c in certs]}
                    if i < len(pages) - 1:
                        resp['NextMarker'] = f'm{i}'
                    st.add_response('describe_listener_certificates', resp)
        res = _run(Ec2ElbCommon(_alb(), [], elbv2, None), '_checkElbUsesIamOrImportedCert').get('elbUsesIamOrImportedCert')
        st.assert_no_pending_responses()
    return res


def test_elb_iam_cert_flag_fix():
    bad = _certResult(IAM_CERT)
    assert bad[0] == -1 and 'legacy-cert' in bad[1]
    assert _certResult(ACM_CERT)[0] == 1
    # an IAM certificate attached as an additional (SNI) certificate on the second page
    assert _certResult(ACM_CERT, extra=[[ACM_CERT], [IAM_CERT]])[0] == -1
    assert _certResult(ACM_CERT, extraError='AccessDenied')[0] == 0
    assert _certResult(ACM_CERT, protocol='HTTP') is None


def test_elb_iam_cert_classic():
    from services.ec2.drivers.Ec2ElbClassic import Ec2ElbClassic
    def clb(cert, proto='HTTPS'):
        return {'LoadBalancerName': 'c', 'ListenerDescriptions': [{'Listener': {
            'Protocol': proto, 'LoadBalancerPort': 443, 'InstanceProtocol': 'HTTP', 'InstancePort': 80,
            'SSLCertificateId': cert}, 'PolicyNames': []}]}
    run = lambda lb: _run(Ec2ElbClassic(lb, _client('elb')), '_checkElbUsesIamOrImportedCert').get('elbUsesIamOrImportedCert')
    assert run(clb(IAM_CERT))[0] == -1
    assert run(clb(ACM_CERT))[0] == 1
    assert run(clb(None, 'HTTP')) is None


# --------------------------------------------------------------------------- #
# ec2AutoRecoveryDisabled
# --------------------------------------------------------------------------- #
from services.ec2.drivers.Ec2Instance import Ec2Instance  # noqa: E402


def _autoRecoveryResult(mode, state='running'):
    inst = {'InstanceId': 'i-0123456789abcdef0', 'State': {'Name': state}}
    if mode is not None:
        inst['MaintenanceOptions'] = {'AutoRecovery': mode, 'RebootMigration': 'default'}
    obj = Ec2Instance.__new__(Ec2Instance)       # skip __init__ (image / CloudWatch lookups)
    obj.results = {}
    obj.ec2InstanceData = inst
    return _run(obj, '_checkEc2AutoRecoveryDisabled').get('ec2AutoRecoveryDisabled')


def test_auto_recovery_flag_fix_same_instance():
    assert _autoRecoveryResult('disabled')[0] == -1
    assert _autoRecoveryResult('default')[0] == 1          # after modify-instance-maintenance-options
    assert _autoRecoveryResult(None)[0] == 0
    assert _autoRecoveryResult('disabled', state='terminated') is None


# --------------------------------------------------------------------------- #
# ec2SshdRunning
# --------------------------------------------------------------------------- #
IID = 'i-0123456789abcdef0'


def _svc(name, status):
    return {'Name': name, 'DisplayName': name, 'Status': status, 'ServiceType': 'Win32OwnProcess', 'StartType': 'Automatic'}


def _sshdResult(platform='Windows', pages=None, invError=None, managed=True):
    ssm = _client('ssm')
    ns = types.SimpleNamespace(ssmClient=ssm)
    info = [{'InstanceId': IID, 'PingStatus': 'Online', 'PlatformType': platform}] if managed else []
    with Stubber(ssm) as st:
        st.add_response('describe_instance_information', {'InstanceInformationList': info}, {'MaxResults': 50})
        managedSet = Ec2.getSSMManagedInstances(ns)
        if invError:
            st.add_client_error('list_inventory_entries', service_error_code=invError, http_status_code=400)
        for i, entries in enumerate(pages or []):
            resp = {'TypeName': 'AWS:Service', 'InstanceId': IID, 'CaptureTime': '2026-11-16T00:00:00Z', 'Entries': entries}
            expected = {'InstanceId': IID, 'TypeName': 'AWS:Service', 'MaxResults': 50}
            if i:
                expected['NextToken'] = f't{i}'
            if i < len(pages) - 1:
                resp['NextToken'] = f't{i + 1}'
            st.add_response('list_inventory_entries', resp, expected)
        obj = Ec2SSM(IID, managedSet, {'InstanceId': IID, 'State': {'Name': 'running'}}, ns.ssmError,
                     ns.ssmPingStatus, ssm, ns.ssmPlatform)
        res = _run(obj, '_checkEc2SshdRunning').get('ec2SshdRunning')
        st.assert_no_pending_responses()
    return res


def test_sshd_rdp_running_flag_fix():
    res = _sshdResult(pages=[[_svc('Dhcp', 'Running')], [_svc('TermService', 'Running'), _svc('sshd', 'Stopped')]])
    assert res[0] == -1 and 'RDP' in res[1] and 'sshd' not in res[1]
    # fixed: TermService stopped / disabled, inventory refreshed
    assert _sshdResult(pages=[[_svc('TermService', 'Stopped'), _svc('Dhcp', 'Running')]])[0] == 1
    assert _sshdResult(pages=[[_svc('sshd', 'Running')]])[0] == -1


def test_sshd_not_evaluable_paths():
    assert _sshdResult(platform='Linux')[0] == 0                    # AWS:Service is Windows-only
    assert _sshdResult(managed=False)[0] == 0
    assert _sshdResult(pages=[[]])[0] == 0                          # inventory not collected
    assert _sshdResult(invError='InvalidInstanceId') == [0, 'Unable to evaluate (InvalidInstanceId)']


# --------------------------------------------------------------------------- #
# EBSUpToDateSnapshot (overlap of dlmNoSnapshotPolicy): newest snapshot, not the first returned
# --------------------------------------------------------------------------- #
import datetime as _dt  # noqa: E402
from services.ec2.drivers.Ec2EbsVolume import Ec2EbsVolume  # noqa: E402


def _snapshotFreshness(ages):
    ec2 = _client('ec2')
    now = _dt.datetime.now(_dt.timezone.utc)
    snaps = [{'SnapshotId': f'snap-{i}', 'VolumeId': 'vol-1', 'StartTime': now - _dt.timedelta(days=a), 'State': 'completed'}
             for i, a in enumerate(ages)]
    obj = Ec2EbsVolume.__new__(Ec2EbsVolume)
    obj.results = {}
    obj.ec2Client = ec2
    obj.ebsVolumeData = {'VolumeId': 'vol-1', 'SnapshotId': ''}
    with Stubber(ec2) as st:
        st.add_response('describe_snapshots', {'Snapshots': snaps})
        st.add_response('describe_fast_snapshot_restores', {'FastSnapshotRestores': []})
        _run(obj, '_checkSnapshot')
    return obj.results


def test_up_to_date_snapshot_uses_newest():
    assert _snapshotFreshness([30, 1]) == {}                        # oldest returned first: still up to date
    assert _snapshotFreshness([30, 20])['EBSUpToDateSnapshot'][0] == -1


# --------------------------------------------------------------------------- #
# WAFS2027 chunk 4
# --------------------------------------------------------------------------- #
from services.ec2.drivers.Ec2NACL import Ec2NACL  # noqa: E402
from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup  # noqa: E402
from services.ec2.drivers.Ec2DataTierSecGroup import Ec2DataTierSecGroup, classifyDataTierEni  # noqa: E402
from services.ec2.drivers.Ec2ImageBuilder import Ec2ImageBuilder  # noqa: E402


def _naclResult(entries, default=False, assoc=True):
    nacl = {'NetworkAclId': 'acl-1', 'IsDefault': default, 'Entries': entries,
            'Associations': [{'SubnetId': 'subnet-a'}] if assoc else []}
    return _run(Ec2NACL(nacl, None), '_checkNaclAllowAllIngress').get('naclAllowAllIngress')


def _entry(num, action, proto='-1', cidr='0.0.0.0/0', egress=False, v6=False):
    e = {'RuleNumber': num, 'RuleAction': action, 'Protocol': proto, 'Egress': egress}
    e['Ipv6CidrBlock' if v6 else 'CidrBlock'] = cidr
    return e


IMPLICIT = [_entry(32767, 'deny'), _entry(32768, 'deny', cidr='::/0', v6=True)]


def test_nacl_allow_all_ingress_flag_fix():
    assert _naclResult([_entry(100, 'allow')] + IMPLICIT)[0] == -1
    assert _naclResult([_entry(100, 'allow', proto='6')] + IMPLICIT)[0] == 1        # tcp only
    assert _naclResult([_entry(100, 'allow', cidr='::/0', v6=True)] + IMPLICIT)[0] == -1
    # IPv4 deny before allow-all, IPv6 still open
    res = _naclResult([_entry(50, 'deny', proto='6'), _entry(100, 'allow'),
                       _entry(101, 'allow', cidr='::/0', v6=True)] + IMPLICIT)
    assert res[0] == -1 and '::/0' in res[1] and 'rule 100' not in res[1]
    assert _naclResult([_entry(100, 'allow', egress=True)] + IMPLICIT)[0] == 1     # egress only
    assert _naclResult([_entry(100, 'allow')] + IMPLICIT, default=True)[0] == 0     # default NACL: INFO
    assert _naclResult([_entry(100, 'allow')] + IMPLICIT, assoc=False) is None      # not associated


def test_network_acls_paginate():
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_network_acls', {'NetworkAcls': [{'NetworkAclId': 'acl-1'}], 'NextToken': 't'}, {})
        st.add_response('describe_network_acls', {'NetworkAcls': [{'NetworkAclId': 'acl-2'}]}, {'NextToken': 't'})
        nacls = Ec2.getNetworkACLs(types.SimpleNamespace(ec2Client=ec2))
        st.assert_no_pending_responses()
    assert [n['NetworkAclId'] for n in nacls] == ['acl-1', 'acl-2']


def _sg(ingress=None, egress=None):
    return {'GroupId': 'sg-1', 'GroupName': 'app', 'IpPermissions': ingress or [], 'IpPermissionsEgress': egress or []}


def _perm(proto, lo, hi, v4=(), v6=()):
    p = {'IpProtocol': proto, 'IpRanges': [{'CidrIp': c} for c in v4], 'Ipv6Ranges': [{'CidrIpv6': c} for c in v6],
         'UserIdGroupPairs': [], 'PrefixListIds': []}
    if proto != '-1':
        p.update(FromPort=lo, ToPort=hi)
    return p


def test_sg_ingress_broad_cidr_flag_fix():
    run = lambda perms: _run(Ec2SecGroup(_sg(perms), None), '_checkSgIngressBroadCidr')['sgIngressBroadCidr']
    for cidr in ('0.0.0.0/1', '128.0.0.0/1', '52.0.0.0/8', '10.0.0.0/7'):
        assert run([_perm('tcp', 443, 443, v4=[cidr])])[0] == -1, cidr
    assert run([_perm('-1', None, None, v6=['2000::/3'])])[0] == -1
    # fixed / not in scope: 0.0.0.0/0 (other checks), /16 or narrower, private ranges, ULA
    for cidr in ('0.0.0.0/0', '52.94.0.0/16', '203.0.113.0/24', '10.0.0.0/8', '172.16.0.0/12', '100.64.0.0/10'):
        assert run([_perm('tcp', 443, 443, v4=[cidr])])[0] == 1, cidr
    assert run([_perm('tcp', 443, 443, v6=['::/0', 'fc00::/7', '2001:db8::/32'])])[0] == 1


def test_sg_sensitive_port_open_to_all_per_permission():
    def run(perms):
        return _run(Ec2SecGroup(_sg(perms), None), '_checkSensitivePortOpenToAll').get('SGSensitivePortOpenToAll')
    web = _perm('tcp', 443, 443, v4=['0.0.0.0/0'])
    assert run([web, _perm('tcp', 22, 22, v4=['10.0.0.0/8'])]) is None        # was a false FAIL
    assert run([web, _perm('tcp', 22, 22, v4=['0.0.0.0/0'])])[0] == -1
    assert run([_perm('tcp', 0, 65535, v6=['::/0'])])[0] == -1
    assert run([_perm('-1', None, None, v4=['0.0.0.0/0'])])[0] == -1
    assert run([_perm('udp', 3389, 3389, v4=['0.0.0.0/0'])]) is None          # RDP is tcp in the port map
    assert run([_perm('udp', 53, 53, v4=['0.0.0.0/0'])])[0] == -1              # DNS: tcp and udp
    # ICMP (FromPort -1) open to all is not "all ports open to all"
    icmp = _perm('icmp', -1, -1, v4=['0.0.0.0/0'])
    assert 'SGAllPortOpenToAll' not in _run(Ec2SecGroup(_sg([icmp]), None), '_checkAllPortOpenToAll')


def test_sg_unrestricted_egress_classification_and_rules():
    assert classifyDataTierEni({'RequesterId': 'amazon-elasticache'}) == 'ElastiCache'
    assert classifyDataTierEni({'Description': 'RedshiftNetworkInterface'}) == 'Redshift'
    assert classifyDataTierEni({'RequesterId': 'amazon-elasticsearch', 'Description': 'ES my-domain'}) == 'OpenSearch'
    assert classifyDataTierEni({'Description': 'Primary network interface'}) is None
    run = lambda egress: _run(Ec2DataTierSecGroup(_sg(egress=egress), {'RDS': ['eni-1']}),
                              '_checkSgUnrestrictedEgress')['sgUnrestrictedEgress']
    assert run([_perm('-1', None, None, v4=['0.0.0.0/0'])])[0] == -1
    assert run([_perm('tcp', 0, 65535, v6=['::/0'])])[0] == -1
    assert run([_perm('tcp', 443, 443, v4=['0.0.0.0/0'])])[0] == 1
    assert run([_perm('-1', None, None, v4=['10.0.0.0/16'])])[0] == 1
    assert run([])[0] == 1


def _dsResult(perms, managed=True, entries=None, invError=None):
    ssm = _client('ssm')
    sgs = [_sg(perms)]
    with Stubber(ssm) as st:
        if managed:
            if invError:
                st.add_client_error('list_inventory_entries', service_error_code=invError, http_status_code=400)
            else:
                st.add_response('list_inventory_entries',
                                {'TypeName': 'AWS:Application', 'InstanceId': IID, 'Entries': entries or []},
                                {'InstanceId': IID, 'TypeName': 'AWS:Application', 'MaxResults': 50})
        obj = Ec2SSM(IID, {IID} if managed else set(), {'InstanceId': IID, 'State': {'Name': 'running'}},
                     None, {IID: 'Online'}, ssm, {IID: 'Linux'}, sgs)
        res = _run(obj, '_checkSelfManagedDataStoreOnEc2').get('selfManagedDataStoreOnEc2')
        st.assert_no_pending_responses()
    return res


def test_self_managed_datastore_inventory_flag_fix():
    pkg = lambda n: {'Name': n, 'Version': '1'}
    res = _dsResult([], entries=[pkg('bash'), pkg('postgresql15-server'), pkg('postgresql15')])
    assert res[0] == -1 and 'postgresql15-server' in res[1]
    assert _dsResult([], entries=[pkg('Microsoft SQL Server 2019 (64-bit)')])[0] == -1
    assert _dsResult([], entries=[pkg('redis6')])[0] == -1
    # fixed: engine removed, only clients / libraries left
    assert _dsResult([], entries=[pkg('postgresql15'), pkg('mysql-community-client'), pkg('libpq'),
                                  pkg('redis-tools'), pkg('python3-redis')])[0] == 1
    # port evidence with clean inventory -> INFO (proxy / shared SG)
    pg = _perm('tcp', 5432, 5432, v4=['10.0.0.0/16'])
    assert _dsResult([pg], entries=[pkg('pgbouncer')])[0] == 0
    # port evidence without inventory -> heuristic FAIL; wide ranges are not evidence
    assert _dsResult([pg], managed=False)[0] == -1
    assert _dsResult([pg], entries=[])[0] == -1                                # inventory not collected
    assert _dsResult([pg], invError='InvalidInstanceId')[0] == -1
    assert _dsResult([_perm('tcp', 0, 65535, v4=['10.0.0.0/16'])], managed=False)[0] == 1


def _ibResult(pipelines, images=None, instances=None, ibError=None, imageError=None):
    ib, ec2 = _client('imagebuilder'), _client('ec2')
    instances = instances if instances is not None else [
        {'InstanceId': IID, 'ImageId': 'ami-0aaa', 'State': {'Name': 'running'}}]
    with Stubber(ib) as sib, Stubber(ec2) as sec2:
        if instances:
            if ibError:
                sib.add_client_error('list_image_pipelines', service_error_code=ibError, http_status_code=403)
            else:
                sib.add_response('list_image_pipelines', {'imagePipelineList': pipelines})
            if not ibError and not any(p.get('status') == 'ENABLED' for p in pipelines):
                if imageError:
                    sec2.add_client_error('describe_images', service_error_code=imageError, http_status_code=400)
                    if imageError.startswith('InvalidAMIID'):
                        sec2.add_response('describe_images', {'Images': images or []}, {'ImageIds': ['ami-0aaa'], 'IncludeDeprecated': True})
                else:
                    sec2.add_response('describe_images', {'Images': images or []}, {'ImageIds': ['ami-0aaa'], 'IncludeDeprecated': True})
        res = _run(Ec2ImageBuilder(ib, ec2, instances), '_checkImagebuilderNoPipeline')['imagebuilderNoPipeline']
        sib.assert_no_pending_responses()
        sec2.assert_no_pending_responses()
    return res


def test_imagebuilder_no_pipeline_paths():
    stock = [{'ImageId': 'ami-0aaa', 'ImageOwnerAlias': 'amazon', 'OwnerId': '137112412989'}]
    pipe = lambda status: {'arn': 'arn:aws:imagebuilder:us-east-1:111111111111:image-pipeline/p', 'status': status}
    assert _ibResult([], stock)[0] == -1
    assert _ibResult([pipe('DISABLED')], stock)[0] == -1
    assert _ibResult([pipe('ENABLED')])[0] == 1
    # self-owned / cross-account / Image Builder-tagged AMIs: possibly built by other tooling -> INFO
    assert _ibResult([], [{'ImageId': 'ami-0aaa', 'OwnerId': SELF}])[0] == 0
    assert _ibResult([], [{'ImageId': 'ami-0aaa', 'OwnerId': ORG_MEMBER}])[0] == 0
    # AWS Marketplace AMIs (vendor appliances meant to run as published) -> INFO, not stock
    assert _ibResult([], [{'ImageId': 'ami-0aaa', 'ImageOwnerAlias': 'aws-marketplace', 'OwnerId': '679593333241'}])[0] == 0
    assert _ibResult([], [{'ImageId': 'ami-0aaa', 'ImageOwnerAlias': 'amazon',
                           'Tags': [{'Key': 'Ec2ImageBuilderArn', 'Value': 'x'}]}])[0] == 0
    # deregistered AMI -> per-image retry, still not evaluable
    assert _ibResult([], [], imageError='InvalidAMIID.NotFound')[0] == 0
    assert _ibResult([], ibError='AccessDeniedException') == [0, 'Unable to evaluate (AccessDeniedException)']
    assert _ibResult([], stock, imageError='UnauthorizedOperation')[0] == 0
    assert _ibResult([], instances=[]) == [1, 'No EC2 instances in region']


def _ssmEpResult(endpoints, routes=(), vpc=VPC, endpointsError=None, instSubnet='subnet-a'):
    routing = _routing([_rt('rtb-main', 'vpc-1', list(routes), main=True)],
                       [{'SubnetId': 'subnet-a', 'VpcId': 'vpc-1'}])
    inst = [{'InstanceId': IID, 'VpcId': 'vpc-1', 'SubnetId': instSubnet, 'State': {'Name': 'running'}},
            {'InstanceId': 'i-gone', 'VpcId': 'vpc-1', 'SubnetId': 'subnet-a', 'State': {'Name': 'terminated'}}]
    obj = Ec2Vpc(vpc, [], None, routing, endpoints, endpointsError, SELF, inst)
    return _run(obj, '_checkSsmVpcEndpointsMissing').get('ssmVpcEndpointsMissing')


def _iep(service, dns=True, state='available'):
    return {'VpcEndpointId': 'vpce-' + service, 'VpcId': 'vpc-1', 'VpcEndpointType': 'Interface', 'State': state,
            'ServiceName': f'com.amazonaws.us-east-1.{service}', 'PrivateDnsEnabled': dns}


def test_ssm_vpc_endpoints_missing_flag_fix():
    res = _ssmEpResult([])
    assert res[0] == -1 and IID in res[1] and 'i-gone' not in res[1]
    assert _ssmEpResult([_iep('ssm')])[0] == -1                                  # ssmmessages missing
    assert _ssmEpResult([_iep('ssm'), _iep('ssmmessages', state='deleted')])[0] == -1
    res = _ssmEpResult([_iep('ssm'), _iep('ssmmessages')])
    assert res[0] == 1 and 'ec2messages' in res[1]
    # private DNS disabled on the endpoints -> verify a private hosted zone (INFO)
    assert _ssmEpResult([_iep('ssm', dns=False), _iep('ssmmessages', dns=False)])[0] == 0


def test_ssm_vpc_endpoints_not_flagged_paths():
    # any default route (NAT, transit gateway) is a valid path to the public SSM endpoints
    assert _ssmEpResult([], routes=[NAT_ROUTE])[0] == 1
    tgw = {'DestinationCidrBlock': '0.0.0.0/0', 'TransitGatewayId': 'tgw-1', 'State': 'active'}
    assert _ssmEpResult([], routes=[tgw])[0] == 1
    # a blackholed default route does not count
    assert _ssmEpResult([], routes=[dict(NAT_ROUTE, State='blackhole')])[0] == -1
    assert _ssmEpResult([], vpc={'VpcId': 'vpc-1', 'OwnerId': OUTSIDER})[0] == 0
    assert _ssmEpResult(None, endpointsError='UnauthorizedOperation') == [0, 'Unable to evaluate (UnauthorizedOperation)']
    assert _ssmEpResult([], instSubnet='subnet-shared')[0] == 0                  # route table not visible


# --------------------------------------------------------------------------- #
# vpcPeeringFullRoute
# --------------------------------------------------------------------------- #
from services.ec2.drivers.Ec2Vpc import Ec2Vpc, getPeerRouteContext  # noqa: E402

VPC_A, VPC_B = 'vpc-0aaaaaaaaaaaaaaa1', 'vpc-0bbbbbbbbbbbbbbb2'
TGW, TGW_RT = 'tgw-0123456789abcdef0', 'tgw-rtb-0123456789abcdef0'
PCX = 'pcx-0123456789abcdef0'


def _vpcA(owner=SELF):
    return {'VpcId': VPC_A, 'OwnerId': owner, 'CidrBlock': '10.1.0.0/16',
            'CidrBlockAssociationSet': [{'CidrBlock': '10.1.0.0/16', 'CidrBlockState': {'State': 'associated'}}]}


def _rtWith(*routes):
    base = [{'DestinationCidrBlock': '10.1.0.0/16', 'GatewayId': 'local', 'State': 'active'}]
    return {'RouteTables': [{'RouteTableId': 'rtb-0123456789abcdef0', 'VpcId': VPC_A,
                             'Routes': base + list(routes), 'Associations': []}]}


def _pcx(status='active', peerOwner=OUTSIDER):
    return {'VpcPeeringConnectionId': PCX, 'Status': {'Code': status},
            'RequesterVpcInfo': {'VpcId': VPC_A, 'OwnerId': SELF, 'CidrBlock': '10.1.0.0/16'},
            'AccepterVpcInfo': {'VpcId': VPC_B, 'OwnerId': peerOwner, 'CidrBlock': '10.2.0.0/16',
                                'CidrBlockSet': [{'CidrBlock': '10.2.0.0/16'}, {'CidrBlock': '10.3.0.0/16'}],
                                'Ipv6CidrBlockSet': [{'Ipv6CidrBlock': '2600:1f18:aa:bb00::/56'}]}}


def _tgwAttachments(assoc=True, tgwOwner=SELF):
    a = {'TransitGatewayAttachmentId': 'tgw-attach-0aaaaaaaaaaaaaaa1', 'TransitGatewayId': TGW,
         'TransitGatewayOwnerId': tgwOwner, 'ResourceOwnerId': SELF, 'ResourceType': 'vpc',
         'ResourceId': VPC_A, 'State': 'available'}
    if assoc:
        a['Association'] = {'TransitGatewayRouteTableId': TGW_RT, 'State': 'associated'}
    return {'TransitGatewayAttachments': [a]}


def _peerResult(routes, pcx=None, attachments=None, search=None, vpcOwner=SELF, errors=None):
    """Drive getPeerRouteContext + Ec2Vpc._checkVpcPeeringFullRoute with stubbed responses."""
    errors = errors or {}
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        if 'describe_route_tables' in errors:
            st.add_client_error('describe_route_tables', errors['describe_route_tables'])
        else:
            st.add_response('describe_route_tables', _rtWith(*routes), {})
            if any(r.get('VpcPeeringConnectionId') and r.get('State', 'active') == 'active' for r in routes):
                if 'describe_vpc_peering_connections' in errors:
                    st.add_client_error('describe_vpc_peering_connections', errors['describe_vpc_peering_connections'])
                else:
                    st.add_response('describe_vpc_peering_connections', {'VpcPeeringConnections': pcx or []}, {})
            if any(r.get('TransitGatewayId') and r.get('State', 'active') == 'active' for r in routes):
                st.add_response('describe_transit_gateway_attachments', attachments or _tgwAttachments(),
                                {'Filters': [{'Name': 'resource-type', 'Values': ['vpc']}]})
                if search is not None:
                    if isinstance(search, str):
                        st.add_client_error('search_transit_gateway_routes', search)
                    else:
                        st.add_response('search_transit_gateway_routes',
                                        {'Routes': search, 'AdditionalRoutesAvailable': False},
                                        {'TransitGatewayRouteTableId': TGW_RT, 'Filters': ANY})
        ctx = getPeerRouteContext(ec2, [_vpcA(vpcOwner)])
        st.assert_no_pending_responses()
    drv = Ec2Vpc(_vpcA(vpcOwner), [], ec2, selfAccount=SELF, peerRouting=ctx)
    return _run(drv, '_checkVpcPeeringFullRoute').get('vpcPeeringFullRoute')


def _pcxRoute(dest, **kw):
    r = {'VpcPeeringConnectionId': PCX, 'State': 'active'}
    r['DestinationIpv6CidrBlock' if ':' in dest else 'DestinationCidrBlock'] = dest
    r.update(kw)
    return r


def test_peering_full_cidr_flag_fix():
    bad = _peerResult([_pcxRoute('10.2.0.0/16')], pcx=[_pcx()])
    assert bad[0] == -1 and '10.2.0.0/16' in bad[1] and VPC_B in bad[1]
    good = _peerResult([_pcxRoute('10.2.4.0/24'), _pcxRoute('10.3.8.0/22')], pcx=[_pcx()])
    assert good[0] == 1


def test_peering_same_account_full_cidr_is_review_only():
    # full-CIDR peering inside one account is the documented default -> INFO, not FAIL
    res = _peerResult([_pcxRoute('10.2.0.0/16')], pcx=[_pcx(peerOwner=SELF)])
    assert res[0] == 0 and res[1].startswith('Review') and VPC_B in res[1]
    assert _peerResult([_pcxRoute('10.2.4.0/24')], pcx=[_pcx(peerOwner=SELF)])[0] == 1


def test_peering_supernet_second_cidr_and_ipv6_flagged():
    # a supernet route covering the peer's secondary CIDR, and a whole-IPv6-block route
    # (a peering connection carries only the peer's CIDRs, so a supernet is a full route)
    assert _peerResult([_pcxRoute('10.0.0.0/8')], pcx=[_pcx()])[0] == -1
    assert _peerResult([_pcxRoute('2600:1f18:aa:bb00::/56')], pcx=[_pcx()])[0] == -1
    assert _peerResult([_pcxRoute('2600:1f18:aa:bb00::/64')], pcx=[_pcx()])[0] == 1


def test_peering_inactive_or_blackhole_not_flagged():
    assert _peerResult([_pcxRoute('10.2.0.0/16')], pcx=[_pcx('deleted')])[0] == 1
    assert _peerResult([_pcxRoute('10.2.0.0/16', State='blackhole')])[0] == 1


def test_peering_access_denied_not_pass():
    res = _peerResult([_pcxRoute('10.2.0.0/16')], errors={'describe_vpc_peering_connections': 'UnauthorizedOperation'})
    assert res[0] == 0 and 'UnauthorizedOperation' in res[1]
    res = _peerResult([], errors={'describe_route_tables': 'UnauthorizedOperation'})
    assert res == [0, 'Unable to evaluate (UnauthorizedOperation)']


def test_prefix_list_destination_not_pass():
    res = _peerResult([{'DestinationPrefixListId': 'pl-0123456789abcdef0', 'VpcPeeringConnectionId': PCX,
                        'State': 'active'}], pcx=[_pcx()])
    assert res[0] == 0


def test_shared_vpc_not_evaluable():
    res = _peerResult([], vpcOwner=OUTSIDER)
    assert res[0] == 0 and 'shared' in res[1]


def _tgwRoute(dest):
    return {'DestinationCidrBlock': dest, 'TransitGatewayId': TGW, 'State': 'active'}


PROPAGATED_B = [{'DestinationCidrBlock': '10.2.0.0/16', 'Type': 'propagated', 'State': 'active',
                 'TransitGatewayAttachments': [{'ResourceId': VPC_B, 'ResourceType': 'vpc',
                                                'TransitGatewayAttachmentId': 'tgw-attach-0bbbbbbbbbbbbbbb2'}]},
                {'DestinationCidrBlock': '10.1.0.0/16', 'Type': 'propagated', 'State': 'active',
                 'TransitGatewayAttachments': [{'ResourceId': VPC_A, 'ResourceType': 'vpc',
                                                'TransitGatewayAttachmentId': 'tgw-attach-0aaaaaaaaaaaaaaa1'}]}]


def test_tgw_associated_route_table_review_fix():
    # exact full-CIDR route to a TGW peer: review item (INFO), never a FAIL
    review = _peerResult([_tgwRoute('10.2.0.0/16')], search=PROPAGATED_B)
    assert review[0] == 0 and VPC_B in review[1] and VPC_A not in review[1].split('covers')[1]
    good = _peerResult([_tgwRoute('10.2.1.0/24')], search=PROPAGATED_B)
    assert good[0] == 1


def test_tgw_default_and_summary_routes_not_full_peer_routes():
    # hub-and-spoke centralized egress / inspection: 0.0.0.0/0 and 10.0.0.0/8 -> tgw
    # with peers 10.2.0.0/16 must not be reported as opening whole peer VPCs
    for dest in ('0.0.0.0/0', '10.0.0.0/8'):
        res = _peerResult([_tgwRoute(dest)], search=PROPAGATED_B)
        assert res[0] == 1 and 'summary' in res[1], res


def test_tgw_default_route_with_isolated_route_table_passes():
    # the associated TGW route table has no route to another VPC (inspection / egress only)
    assert _peerResult([_tgwRoute('0.0.0.0/0')], search=[PROPAGATED_B[1]])[0] == 1


def test_tgw_search_access_denied_not_pass():
    res = _peerResult([_tgwRoute('10.2.0.0/16')], search='UnauthorizedOperation')
    assert res[0] == 0 and 'UnauthorizedOperation' in res[1]


def test_tgw_shared_from_other_account_without_association_not_pass():
    res = _peerResult([_tgwRoute('10.2.0.0/16')], attachments=_tgwAttachments(assoc=False, tgwOwner=OUTSIDER))
    assert res[0] == 0 and 'shared' in res[1]


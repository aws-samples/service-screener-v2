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

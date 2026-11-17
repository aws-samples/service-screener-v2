"""Flag -> fix -> re-run tests for the WAFS2027 ec2 checks (AWS Emulator).

Account-level settings are restored to their original value in `finally`.

Not covered here (emulator gaps -> tests/test_stub_ec2.py):
- ec2AmiPublic: ModifyImageAttribute / DeregisterImage are NotImplemented, so an AMI
  cannot be made public (or cleaned up). No AMIs are registered here on purpose -
  a leftover AMI would also change what ebsRecycleBinMissing requires.
- ebsSnapshotSharedExternally: ModifySnapshotAttribute and organizations.ListAccounts
  are NotImplemented; only the not-shared PASS path is exercised here.
- Locked Recycle Bin rules: a locked rule cannot be deleted, so the emulator test
  stops at an unlocked rule (INFO); the locked PASS path is stubbed.
"""
import json
import os
import subprocess
import tempfile
import time

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

REGIONAL = 'EC2::Regional'


# --------------------------------------------------------------------------- #
# Account / region-level settings
# --------------------------------------------------------------------------- #
def test_ec2_image_block_public_access(emu):
    ec2 = emu.client('ec2')
    original = ec2.get_image_block_public_access_state()['ImageBlockPublicAccessState']
    try:
        assertFlagFixCycle(
            emu, 'ec2', 'ec2ImageBlockPublicAccessOff', REGIONAL,
            misconfigure=lambda: ec2.disable_image_block_public_access(),
            fix=lambda: ec2.enable_image_block_public_access(ImageBlockPublicAccessState='block-new-sharing'))
        res = runCheck(emu, 'ec2', 'ec2ImageBlockPublicAccessOff', REGIONAL)
        assert list(res.statuses().values()) == [1]
    finally:
        if original == 'unblocked':
            ec2.disable_image_block_public_access()
        else:
            ec2.enable_image_block_public_access(ImageBlockPublicAccessState=original)


def test_ec2_imds_defaults(emu):
    ec2 = emu.client('ec2')
    original = ec2.get_instance_metadata_defaults().get('AccountLevel', {}) or {}
    try:
        def misconfigure():
            ec2.modify_instance_metadata_defaults(HttpTokens='optional')

        def fix():
            ec2.modify_instance_metadata_defaults(HttpTokens='required', HttpPutResponseHopLimit=2)

        assertFlagFixCycle(emu, 'ec2', 'ec2ImdsDefaultNotRequired', REGIONAL, misconfigure, fix)

        # required but hop limit > 2 is still flagged
        ec2.modify_instance_metadata_defaults(HttpTokens='required', HttpPutResponseHopLimit=5)
        assert list(runCheck(emu, 'ec2', 'ec2ImdsDefaultNotRequired', REGIONAL).statuses().values()) == [-1]

        # no account default at all (the AWS default) is flagged
        ec2.modify_instance_metadata_defaults(HttpTokens='no-preference', HttpPutResponseHopLimit=-1)
        assert list(runCheck(emu, 'ec2', 'ec2ImdsDefaultNotRequired', REGIONAL).statuses().values()) == [-1]
    finally:
        ec2.modify_instance_metadata_defaults(
            HttpTokens=original.get('HttpTokens', 'no-preference'),
            HttpPutResponseHopLimit=original.get('HttpPutResponseHopLimit', -1))


def test_ec2_snapshot_block_public_access(emu):
    ec2 = emu.client('ec2')
    original = ec2.get_snapshot_block_public_access_state()['State']
    try:
        assertFlagFixCycle(
            emu, 'ec2', 'ec2SnapshotBlockPublicAccessOff', REGIONAL,
            misconfigure=lambda: ec2.disable_snapshot_block_public_access(),
            fix=lambda: ec2.enable_snapshot_block_public_access(State='block-all-sharing'))
        assert list(runCheck(emu, 'ec2', 'ec2SnapshotBlockPublicAccessOff', REGIONAL).statuses().values()) == [1]

        # block-new-sharing is INFO (existing public snapshots stay public), not PASS
        ec2.enable_snapshot_block_public_access(State='block-new-sharing')
        assert list(runCheck(emu, 'ec2', 'ec2SnapshotBlockPublicAccessOff', REGIONAL).statuses().values()) == [0]
    finally:
        if original == 'unblocked':
            ec2.disable_snapshot_block_public_access()
        else:
            ec2.enable_snapshot_block_public_access(State=original)


@pytest.fixture
def snapshot(emu, uid):
    ec2 = emu.client('ec2')
    vol = ec2.create_volume(AvailabilityZone='us-east-1a', Size=1,
                            TagSpecifications=[{'ResourceType': 'volume', 'Tags': [{'Key': 'Name', 'Value': f'ss-test-{uid}'}]}])
    snap = ec2.create_snapshot(VolumeId=vol['VolumeId'])
    try:
        yield snap['SnapshotId']
    finally:
        try:
            ec2.delete_snapshot(SnapshotId=snap['SnapshotId'])
        finally:
            ec2.delete_volume(VolumeId=vol['VolumeId'])


def test_ebs_recycle_bin_missing(emu, snapshot):
    rbin = emu.client('rbin')
    assert not rbin.list_rules(ResourceType='EBS_SNAPSHOT')['Rules'], 'leftover EBS_SNAPSHOT Recycle Bin rule in emulator'
    created = []
    try:
        def misconfigure():
            pass  # a self-owned snapshot exists and there is no Recycle Bin rule

        def fix():
            r = rbin.create_rule(ResourceType='EBS_SNAPSHOT',
                                 RetentionPeriod={'RetentionPeriodValue': 7, 'RetentionPeriodUnit': 'DAYS'})
            created.append(r['Identifier'])

        before, after = assertFlagFixCycle(emu, 'ec2', 'ebsRecycleBinMissing', REGIONAL, misconfigure, fix)
        # an unlocked region-level rule is INFO, not PASS (it can be deleted)
        assert list(after.values()) == [0]
    finally:
        for ident in created:
            rbin.delete_rule(Identifier=ident)


def test_ebs_snapshot_not_shared_passes(emu, snapshot):
    """PASS path end to end (sharing itself cannot be emulated - see module docstring)."""
    res = runCheck(emu, 'ec2', 'ebsSnapshotSharedExternally', snapshot)
    assert res.statuses() == {f'EBSSnapshot::{snapshot}': 1}, (res.results, res.errors[:1])


# --------------------------------------------------------------------------- #
# Load balancers
# --------------------------------------------------------------------------- #
def _subnets(emu):
    subnets = emu.client('ec2').describe_subnets()['Subnets']
    byAz = {}
    for s in subnets:
        byAz.setdefault(s['AvailabilityZone'], s['SubnetId'])
    return list(byAz.values())[:2]


@pytest.fixture
def certificate(emu, uid):
    d = tempfile.mkdtemp()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', d + '/k.pem',
                    '-out', d + '/c.pem', '-days', '30', '-subj', f'/CN=ss-test-{uid}.example.com'],
                   check=True, capture_output=True)
    acm = emu.client('acm')
    arn = acm.import_certificate(Certificate=open(d + '/c.pem', 'rb').read(),
                                 PrivateKey=open(d + '/k.pem', 'rb').read())['CertificateArn']
    try:
        yield arn
    finally:
        for f in ('k.pem', 'c.pem'):
            os.remove(os.path.join(d, f))
        os.rmdir(d)
        # the certificate is released asynchronously after the listener/LB is deleted
        for attempt in range(20):
            try:
                acm.delete_certificate(CertificateArn=arn)
                break
            except acm.exceptions.ResourceInUseException:
                if attempt == 19:
                    raise
                time.sleep(0.5)


@pytest.fixture
def alb(emu, uid):
    elbv2 = emu.client('elbv2')
    lb = elbv2.create_load_balancer(Name=f'ss-alb-{uid}', Subnets=_subnets(emu), Type='application')['LoadBalancers'][0]
    try:
        yield lb
    finally:
        for l in elbv2.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn']).get('Listeners', []):
            elbv2.delete_listener(ListenerArn=l['ListenerArn'])
        elbv2.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])


@pytest.fixture
def clb(emu, uid, certificate):
    elb = emu.client('elb')
    name = f'ss-clb-{uid}'
    elb.create_load_balancer(LoadBalancerName=name, AvailabilityZones=['us-east-1a'], Listeners=[
        {'Protocol': 'HTTPS', 'LoadBalancerPort': 443, 'InstanceProtocol': 'HTTP', 'InstancePort': 80,
         'SSLCertificateId': certificate}])
    try:
        yield name
    finally:
        elb.delete_load_balancer(LoadBalancerName=name)


def test_elb_access_logs_alb(emu, uid, alb):
    elbv2 = emu.client('elbv2')
    s3 = emu.client('s3')
    bucket = f'ss-test-alb-logs-{uid}'
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'logdelivery.elasticloadbalancing.amazonaws.com'},
                       'Action': 's3:PutObject', 'Resource': f'arn:aws:s3:::{bucket}/*'}]}))
    try:
        def misconfigure():
            elbv2.modify_load_balancer_attributes(LoadBalancerArn=alb['LoadBalancerArn'], Attributes=[
                {'Key': 'access_logs.s3.enabled', 'Value': 'false'}])

        def fix():
            elbv2.modify_load_balancer_attributes(LoadBalancerArn=alb['LoadBalancerArn'], Attributes=[
                {'Key': 'access_logs.s3.enabled', 'Value': 'true'},
                {'Key': 'access_logs.s3.bucket', 'Value': bucket}])

        assertFlagFixCycle(emu, 'ec2', 'elbAccessLogsDisabled', f"ELB::{alb['LoadBalancerName']}", misconfigure, fix)
    finally:
        elbv2.modify_load_balancer_attributes(LoadBalancerArn=alb['LoadBalancerArn'], Attributes=[
            {'Key': 'access_logs.s3.enabled', 'Value': 'false'}])
        for obj in s3.list_objects_v2(Bucket=bucket).get('Contents', []):
            s3.delete_object(Bucket=bucket, Key=obj['Key'])  # ELB writes a test object
        s3.delete_bucket_policy(Bucket=bucket)
        s3.delete_bucket(Bucket=bucket)


def test_elb_access_logs_nlb_without_tls_listener_not_evaluated(emu, uid):
    """NLB access logs only capture TLS listener traffic -> no finding for a TCP-only NLB."""
    elbv2 = emu.client('elbv2')
    lb = elbv2.create_load_balancer(Name=f'ss-nlb-{uid}', Subnets=_subnets(emu), Type='network')['LoadBalancers'][0]
    try:
        res = runCheck(emu, 'ec2', 'elbAccessLogsDisabled', f"ELB::{lb['LoadBalancerName']}")
        assert res.statuses() == {}, res.results
    finally:
        elbv2.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])


def test_elb_access_logs_clb(emu, clb):
    elb = emu.client('elb')

    def misconfigure():
        elb.modify_load_balancer_attributes(LoadBalancerName=clb, LoadBalancerAttributes={'AccessLog': {'Enabled': False}})

    def fix():
        elb.modify_load_balancer_attributes(LoadBalancerName=clb, LoadBalancerAttributes={
            'AccessLog': {'Enabled': True, 'S3BucketName': f'{clb}-logs', 'EmitInterval': 60}})

    assertFlagFixCycle(emu, 'ec2', 'elbAccessLogsDisabled', f'ELB Classic::{clb}', misconfigure, fix)


def test_elb_tls_policy_alb(emu, certificate, alb):
    # certificate before alb: fixtures tear down in reverse, the LB/listener must go first
    elbv2 = emu.client('elbv2')
    listener = {}

    def misconfigure():
        listener.update(elbv2.create_listener(
            LoadBalancerArn=alb['LoadBalancerArn'], Protocol='HTTPS', Port=443,
            SslPolicy='ELBSecurityPolicy-2016-08', Certificates=[{'CertificateArn': certificate}],
            DefaultActions=[{'Type': 'fixed-response', 'FixedResponseConfig': {'StatusCode': '200'}}])['Listeners'][0])

    def fix():
        elbv2.modify_listener(ListenerArn=listener['ListenerArn'], SslPolicy='ELBSecurityPolicy-TLS13-1-2-2021-06')

    assertFlagFixCycle(emu, 'ec2', 'elbTlsPolicyOutdated', f"ELB::{alb['LoadBalancerName']}", misconfigure, fix)


def test_elb_tls_policy_clb(emu, clb):
    elb = emu.client('elb')

    def misconfigure():
        elb.create_load_balancer_policy(LoadBalancerName=clb, PolicyName='ss-old', PolicyTypeName='SSLNegotiationPolicyType',
                                        PolicyAttributes=[{'AttributeName': 'Reference-Security-Policy',
                                                           'AttributeValue': 'ELBSecurityPolicy-2016-08'}])
        elb.set_load_balancer_policies_of_listener(LoadBalancerName=clb, LoadBalancerPort=443, PolicyNames=['ss-old'])

    def fix():
        elb.create_load_balancer_policy(LoadBalancerName=clb, PolicyName='ss-new', PolicyTypeName='SSLNegotiationPolicyType',
                                        PolicyAttributes=[{'AttributeName': 'Reference-Security-Policy',
                                                           'AttributeValue': 'ELBSecurityPolicy-TLS-1-2-2017-01'}])
        elb.set_load_balancer_policies_of_listener(LoadBalancerName=clb, LoadBalancerPort=443, PolicyNames=['ss-new'])

    assertFlagFixCycle(emu, 'ec2', 'elbTlsPolicyOutdated', f'ELB Classic::{clb}', misconfigure, fix)


# --------------------------------------------------------------------------- #
# WAFS2027 chunk 2: AMIs, snapshots, instances, launch templates, endpoints
#
# Emulator gaps (-> tests/test_stub_ec2.py):
# - ec2AmiSharedExternally: ModifyImageAttribute is NotImplemented, and registering an
#   AMI is permanent (DeregisterImage NotImplemented) - so no AMI is registered here.
# - ec2AmiUntrustedOrStale: an instance's AMI cannot be changed and DeregisterImage /
#   DisableImage are NotImplemented; the emulator test covers a missing AMI (FAIL) and
#   an available Amazon AMI (PASS) on two instances, the same-instance cycle is stubbed.
# - ec2InstanceWithKeyPair: EC2 instances cannot be registered as SSM managed nodes in
#   the emulator; only the not-managed (INFO) and no-key (PASS) paths run here.
# --------------------------------------------------------------------------- #
def _amazonAmi(ec2):
    return ec2.describe_images(Owners=['amazon'], MaxResults=5)['Images'][0]['ImageId']


def _waitState(ec2, iid, state, tries=40):
    for _ in range(tries):
        if ec2.describe_instances(InstanceIds=[iid])['Reservations'][0]['Instances'][0]['State']['Name'] == state:
            return
        time.sleep(0.5)
    raise AssertionError(f'{iid} did not reach {state}')


def _terminate(ec2, *iids):
    iids = [i for i in iids if i]
    if iids:
        ec2.terminate_instances(InstanceIds=iids)
        for iid in iids:
            _waitState(ec2, iid, 'terminated')


def test_ec2_allowed_amis_not_enforced(emu):
    ec2 = emu.client('ec2')
    original = ec2.get_allowed_images_settings().get('State')
    try:
        assertFlagFixCycle(
            emu, 'ec2', 'ec2AllowedAmisNotEnforced', REGIONAL,
            misconfigure=lambda: ec2.disable_allowed_images_settings(),
            fix=lambda: ec2.enable_allowed_images_settings(AllowedImagesSettingsState='enabled'))
        assert list(runCheck(emu, 'ec2', 'ec2AllowedAmisNotEnforced', REGIONAL).statuses().values()) == [1]

        # audit-mode only identifies non-allowed AMIs -> still flagged
        ec2.enable_allowed_images_settings(AllowedImagesSettingsState='audit-mode')
        assert list(runCheck(emu, 'ec2', 'ec2AllowedAmisNotEnforced', REGIONAL).statuses().values()) == [-1]
    finally:
        if original in ('enabled', 'audit-mode'):
            ec2.enable_allowed_images_settings(AllowedImagesSettingsState=original)
        else:
            ec2.disable_allowed_images_settings()


def test_ebs_snapshot_unencrypted(emu, uid):
    """A snapshot's encryption cannot be changed in place: the fix is an encrypted
    copy + deleting the original, so the cycle is asserted across both snapshot IDs."""
    ec2 = emu.client('ec2')
    vol = ec2.create_volume(AvailabilityZone='us-east-1a', Size=1, Encrypted=False,
                            TagSpecifications=[{'ResourceType': 'volume', 'Tags': [{'Key': 'Name', 'Value': f'ss-test-{uid}'}]}])
    created = []
    try:
        snap = ec2.create_snapshot(VolumeId=vol['VolumeId'])['SnapshotId']
        created.append(snap)
        before = runCheck(emu, 'ec2', 'ebsSnapshotUnencrypted', snap)
        assert before.statuses() == {f'EBSSnapshot::{snap}': -1}, (before.results, before.errors[:1])

        # fix: encrypted copy, delete the unencrypted original
        copy = ec2.copy_snapshot(SourceSnapshotId=snap, SourceRegion='us-east-1', Encrypted=True)['SnapshotId']
        created.append(copy)
        ec2.delete_snapshot(SnapshotId=snap)
        created.remove(snap)

        after = runCheck(emu, 'ec2', 'ebsSnapshotUnencrypted', 'EBSSnapshot::')
        statuses = after.statuses()
        assert f'EBSSnapshot::{snap}' not in statuses
        assert statuses.get(f'EBSSnapshot::{copy}') == 1, (after.results, after.errors[:1])
    finally:
        for s in created:
            ec2.delete_snapshot(SnapshotId=s)
        ec2.delete_volume(VolumeId=vol['VolumeId'])


def test_ec2_ami_untrusted_or_stale(emu):
    ec2 = emu.client('ec2')
    stale = good = None
    try:
        # AMI that does not exist (deregistered / no longer shared)
        stale = ec2.run_instances(ImageId='ami-0123456789abcdef0', MinCount=1, MaxCount=1,
                                  InstanceType='t3.micro')['Instances'][0]['InstanceId']
        good = ec2.run_instances(ImageId=_amazonAmi(ec2), MinCount=1, MaxCount=1,
                                 InstanceType='t3.micro')['Instances'][0]['InstanceId']
        _waitState(ec2, stale, 'running')
        _waitState(ec2, good, 'running')
        res = runCheck(emu, 'ec2', 'ec2AmiUntrustedOrStale', 'EC2::i-').statuses()
        assert res.get(f'EC2::{stale}') == -1, res
        assert res.get(f'EC2::{good}') == 1, res
    finally:
        _terminate(ec2, stale, good)


@pytest.fixture
def publicSubnet(emu):
    """VPC with a subnet whose explicit route table sends 0.0.0.0/0 and ::/0 to an IGW."""
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.98.0.0/16')['Vpc']['VpcId']
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock='10.98.1.0/24', AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
    igw = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rt = ec2.create_route_table(VpcId=vpc)['RouteTable']['RouteTableId']
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=sub)['AssociationId']
    ctx = {'vpc': vpc, 'subnet': sub, 'igw': igw, 'rt': rt}
    try:
        yield ctx
    finally:
        for dest in ({'DestinationCidrBlock': '0.0.0.0/0'}, {'DestinationIpv6CidrBlock': '::/0'}):
            try:
                ec2.delete_route(RouteTableId=rt, **dest)
            except Exception:
                pass
        try:
            ec2.disassociate_route_table(AssociationId=assoc)
        except Exception:
            pass
        ec2.delete_subnet(SubnetId=sub)
        ec2.delete_route_table(RouteTableId=rt)
        ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
        ec2.delete_internet_gateway(InternetGatewayId=igw)
        ec2.delete_vpc(VpcId=vpc)


def test_ec2_instance_in_public_subnet(emu, publicSubnet):
    ec2 = emu.client('ec2')
    rt, igw = publicSubnet['rt'], publicSubnet['igw']
    iid = ec2.run_instances(ImageId=_amazonAmi(ec2), MinCount=1, MaxCount=1, InstanceType='t3.micro',
                            SubnetId=publicSubnet['subnet'])['Instances'][0]['InstanceId']
    try:
        def misconfigure():
            ec2.create_route(RouteTableId=rt, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw)

        def fix():
            ec2.delete_route(RouteTableId=rt, DestinationCidrBlock='0.0.0.0/0')

        assertFlagFixCycle(emu, 'ec2', 'ec2InstanceInPublicSubnet', f'EC2::{iid}', misconfigure, fix)

        # an IPv6 default route to the IGW is public too
        ec2.create_route(RouteTableId=rt, DestinationIpv6CidrBlock='::/0', GatewayId=igw)
        assert list(runCheck(emu, 'ec2', 'ec2InstanceInPublicSubnet', f'EC2::{iid}').statuses().values()) == [-1]
    finally:
        _terminate(ec2, iid)


def test_ec2_instance_with_key_pair_not_managed(emu, uid):
    """Not SSM-managed + key pair -> INFO (the key may be the only access path); no key -> PASS.
    The SSM-managed FAIL path is in tests/test_stub_ec2.py."""
    ec2 = emu.client('ec2')
    kp = f'ss-test-{uid}'
    ec2.create_key_pair(KeyName=kp)
    withKey = noKey = None
    try:
        withKey = ec2.run_instances(ImageId=_amazonAmi(ec2), MinCount=1, MaxCount=1, InstanceType='t3.micro',
                                    KeyName=kp)['Instances'][0]['InstanceId']
        noKey = ec2.run_instances(ImageId=_amazonAmi(ec2), MinCount=1, MaxCount=1,
                                  InstanceType='t3.micro')['Instances'][0]['InstanceId']
        _waitState(ec2, withKey, 'running')
        _waitState(ec2, noKey, 'running')
        res = runCheck(emu, 'ec2', 'ec2InstanceWithKeyPair', 'SSM::').statuses()
        assert res.get(f'SSM::{withKey}') == 0, res
        assert res.get(f'SSM::{noKey}') == 1, res
    finally:
        _terminate(ec2, withKey, noKey)
        ec2.delete_key_pair(KeyName=kp)


# AWS documentation example credentials (not real)
_SECRET_USER_DATA = ('#!/bin/bash\n'
                     'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
                     'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n')
_CLEAN_USER_DATA = '#!/bin/bash\nexport DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id app --query SecretString --output text)\n'


def test_ec2_user_data_secrets_instance(emu):
    ec2 = emu.client('ec2')
    iid = None
    try:
        def misconfigure():
            nonlocal iid
            iid = ec2.run_instances(ImageId=_amazonAmi(ec2), MinCount=1, MaxCount=1, InstanceType='t3.micro',
                                    UserData=_SECRET_USER_DATA)['Instances'][0]['InstanceId']

        def fix():
            ec2.stop_instances(InstanceIds=[iid])
            _waitState(ec2, iid, 'stopped')
            ec2.modify_instance_attribute(InstanceId=iid, UserData={'Value': _CLEAN_USER_DATA.encode()})

        misconfigure()
        before = runCheck(emu, 'ec2', 'ec2UserDataSecrets', f'EC2::{iid}')
        assert before.statuses() == {f'EC2::{iid}': -1}, (before.results, before.errors[:1])
        msg = before.results[f'EC2::{iid}']['ec2UserDataSecrets'][1]
        assert 'AKIAIOSFODNN7EXAMPLE' not in msg and 'wJalrXUtnFEMI' not in msg  # values masked
        fix()
        after = runCheck(emu, 'ec2', 'ec2UserDataSecrets', f'EC2::{iid}')
        assert after.statuses() == {f'EC2::{iid}': 1}, after.results
    finally:
        _terminate(ec2, iid)


def test_ec2_user_data_secrets_launch_template(emu, uid):
    import base64
    ec2 = emu.client('ec2')
    name = f'ss-test-lt-{uid}'
    lt = ec2.create_launch_template(LaunchTemplateName=name, LaunchTemplateData={
        'ImageId': _amazonAmi(ec2), 'UserData': base64.b64encode(b'#!/bin/bash\necho hi\n').decode()})['LaunchTemplate']
    ltId = lt['LaunchTemplateId']
    try:
        def misconfigure():
            ec2.create_launch_template_version(LaunchTemplateId=ltId, SourceVersion='1', LaunchTemplateData={
                'UserData': base64.b64encode(_SECRET_USER_DATA.encode()).decode()})

        def fix():
            # secrets stay readable in old versions: delete the version, not just the default pointer
            ec2.delete_launch_template_versions(LaunchTemplateId=ltId, Versions=['2'])

        assertFlagFixCycle(emu, 'ec2', 'ec2UserDataSecrets', f'LaunchTemplate::{ltId}', misconfigure, fix)
    finally:
        ec2.delete_launch_template(LaunchTemplateId=ltId)


_CLOUD_INIT_USER_DATA = ('#cloud-config\n'
                         'users:\n'
                         '  - name: bob\n'
                         '    lock_passwd: false\n'
                         '    ssh_pwauth: false\n'
                         'chpasswd:\n'
                         '  expire: false\n'
                         'password: null\n')


def test_ec2_user_data_cloud_init_settings_not_flagged(emu, uid):
    """Regression (review round 2): cloud-init 'lock_passwd: false' / 'password: null' are
    settings, not credentials -> must not FAIL; adding a real literal password -> FAIL."""
    import base64
    ec2 = emu.client('ec2')
    lt = ec2.create_launch_template(LaunchTemplateName=f'ss-test-ci-{uid}', LaunchTemplateData={
        'ImageId': _amazonAmi(ec2),
        'UserData': base64.b64encode(_CLOUD_INIT_USER_DATA.encode()).decode()})['LaunchTemplate']
    ltId = lt['LaunchTemplateId']
    try:
        st = runCheck(emu, 'ec2', 'ec2UserDataSecrets', f'LaunchTemplate::{ltId}').statuses()
        assert st and -1 not in st.values(), st
        ec2.create_launch_template_version(LaunchTemplateId=ltId, SourceVersion='1', LaunchTemplateData={
            'UserData': base64.b64encode((_CLOUD_INIT_USER_DATA + '    plain_text_passwd: hunter22\n').encode()).decode()})
        st = runCheck(emu, 'ec2', 'ec2UserDataSecrets', f'LaunchTemplate::{ltId}').statuses()
        assert list(st.values()) == [-1], st
    finally:
        ec2.delete_launch_template(LaunchTemplateId=ltId)


def test_vpc_endpoint_policy_full_access(emu):
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.97.0.0/16')['Vpc']['VpcId']
    ep = {}
    try:
        def misconfigure():
            # no PolicyDocument -> default full-access policy
            ep.update(ec2.create_vpc_endpoint(VpcId=vpc, ServiceName='com.amazonaws.us-east-1.s3',
                                              VpcEndpointType='Gateway')['VpcEndpoint'])

        def fix():
            ec2.modify_vpc_endpoint(VpcEndpointId=ep['VpcEndpointId'], PolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': '*', 'Resource': '*',
                               'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-exampleorgid',
                                                              'aws:ResourceOrgID': 'o-exampleorgid'}}}]}))

        # the endpoint ID only exists after misconfigure(), so the cycle is spelled out
        misconfigure()
        key = f"VPCEndpoint::{ep['VpcEndpointId']}"
        before = runCheck(emu, 'ec2', 'vpcEndpointPolicyFullAccess', key).statuses()
        assert before == {key: -1}, before
        fix()
        after = runCheck(emu, 'ec2', 'vpcEndpointPolicyFullAccess', key).statuses()
        assert after == {key: 1}, after
    finally:
        if ep:
            ec2.delete_vpc_endpoints(VpcEndpointIds=[ep['VpcEndpointId']])
        ec2.delete_vpc(VpcId=vpc)


# --------------------------------------------------------------------------- #
# WAFS2027 chunk 3: network / VPN / ALB / instance recovery
# Not covered here (emulator gaps -> tests/test_stub_ec2.py):
# - vpnWeakTunnelCrypto same-connection fix: ModifyVpnTunnelOptions is NotImplemented, so the
#   emulator test compares a default connection (FAIL) with one created with strong options (PASS).
# - ec2AutoRecoveryDisabled same-instance fix: ModifyInstanceMaintenanceOptions is NotImplemented.
# - ec2SshdRunning: emulator instances cannot become SSM managed nodes and AWS:Service inventory
#   is rejected (InvalidTypeNameException).
# --------------------------------------------------------------------------- #
def _mainRouteTable(ec2, vpc):
    rts = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc]},
                                             {'Name': 'association.main', 'Values': ['true']}])['RouteTables']
    return rts[0]['RouteTableId']


def test_vpc_no_gateway_endpoints(emu):
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.96.0.0/16')['Vpc']['VpcId']
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock='10.96.1.0/24', AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
    ep = {}
    try:
        def fix():
            ep.update(ec2.create_vpc_endpoint(VpcId=vpc, ServiceName='com.amazonaws.us-east-1.s3',
                                              VpcEndpointType='Gateway',
                                              RouteTableIds=[_mainRouteTable(ec2, vpc)])['VpcEndpoint'])

        # misconfigure: a private subnet (main route table, no IGW route) and no endpoint
        before, after = assertFlagFixCycle(emu, 'ec2', 'vpcNoGatewayEndpoints', f'VPC::{vpc}', lambda: None, fix)
        assert list(after.values()) == [1]
    finally:
        if ep:
            ec2.delete_vpc_endpoints(VpcEndpointIds=[ep['VpcEndpointId']])
        ec2.delete_subnet(SubnetId=sub)
        ec2.delete_vpc(VpcId=vpc)


STRONG_TUNNEL = {'IKEVersions': [{'Value': 'ikev2'}],
                 'Phase1IntegrityAlgorithms': [{'Value': 'SHA2-256'}],
                 'Phase2IntegrityAlgorithms': [{'Value': 'SHA2-256'}],
                 'Phase1DHGroupNumbers': [{'Value': 20}],
                 'Phase2DHGroupNumbers': [{'Value': 20}]}


def test_vpn_weak_tunnel_crypto(emu):
    """Default tunnel options (IKEv1/SHA1/DH 2 allowed) -> FAIL; a connection created with
    IKEv2/SHA2-256/DH 20 only -> PASS. ModifyVpnTunnelOptions is NotImplemented, so the
    same-connection fix is in tests/test_stub_ec2.py."""
    ec2 = emu.client('ec2')
    cgws = [ec2.create_customer_gateway(BgpAsn=65000, PublicIp=ip, Type='ipsec.1')['CustomerGateway']['CustomerGatewayId']
            for ip in ('203.0.113.10', '203.0.113.11')]
    vgws = [ec2.create_vpn_gateway(Type='ipsec.1')['VpnGateway']['VpnGatewayId'] for _ in range(2)]
    vpns = []
    try:
        weak = ec2.create_vpn_connection(CustomerGatewayId=cgws[0], VpnGatewayId=vgws[0], Type='ipsec.1',
                                         Options={'StaticRoutesOnly': True})['VpnConnection']['VpnConnectionId']
        vpns.append(weak)
        strong = ec2.create_vpn_connection(CustomerGatewayId=cgws[1], VpnGatewayId=vgws[1], Type='ipsec.1',
                                           Options={'StaticRoutesOnly': True,
                                                    'TunnelOptions': [STRONG_TUNNEL, STRONG_TUNNEL]})['VpnConnection']['VpnConnectionId']
        vpns.append(strong)
        res = runCheck(emu, 'ec2', 'vpnWeakTunnelCrypto', 'VPN::')
        st = res.statuses()
        assert st.get(f'VPN::{weak}') == -1, st
        assert st.get(f'VPN::{strong}') == 1, st
        msg = res.results[f'VPN::{weak}']['vpnWeakTunnelCrypto'][1]
        assert 'IKEv1' in msg and 'SHA1' in msg and 'DH group(s) 2' in msg, msg
    finally:
        for v in vpns:
            ec2.delete_vpn_connection(VpnConnectionId=v)
        for g in vgws:
            ec2.delete_vpn_gateway(VpnGatewayId=g)
        for g in cgws:
            ec2.delete_customer_gateway(CustomerGatewayId=g)


def test_alb_target_group_plaintext(emu, uid, alb):
    """HTTP to instances inside the VPC is informational (0) -> HTTPS target group (1);
    an HTTP ip target group with a target outside the VPC (AvailabilityZone 'all') is the
    FAIL -> deregistering it is the fix."""
    elbv2 = emu.client('elbv2')
    vpc = alb['VpcId']
    httpTg = elbv2.create_target_group(Name=f'ss-http-{uid}', Protocol='HTTP', Port=80, VpcId=vpc,
                                       TargetType='instance')['TargetGroups'][0]['TargetGroupArn']
    httpsTg = elbv2.create_target_group(Name=f'ss-https-{uid}', Protocol='HTTPS', Port=443, VpcId=vpc,
                                        TargetType='instance')['TargetGroups'][0]['TargetGroupArn']
    ipTg = elbv2.create_target_group(Name=f'ss-ip-{uid}', Protocol='HTTP', Port=80, VpcId=vpc,
                                     TargetType='ip')['TargetGroups'][0]['TargetGroupArn']
    outside = {'Id': '192.168.77.10', 'Port': 80, 'AvailabilityZone': 'all'}
    res = f"ELB::{alb['LoadBalancerName']}"
    listener = {}
    try:
        listener.update(elbv2.create_listener(LoadBalancerArn=alb['LoadBalancerArn'], Protocol='HTTP', Port=80,
                                              DefaultActions=[{'Type': 'forward', 'TargetGroupArn': httpTg}])['Listeners'][0])
        assert runCheck(emu, 'ec2', 'albTargetGroupPlaintext', res).statuses() == {res: 0}

        def misconfigure():
            elbv2.modify_listener(ListenerArn=listener['ListenerArn'],
                                  DefaultActions=[{'Type': 'forward', 'TargetGroupArn': ipTg}])
            elbv2.register_targets(TargetGroupArn=ipTg, Targets=[outside])

        def fix():
            elbv2.deregister_targets(TargetGroupArn=ipTg, Targets=[outside])
            elbv2.modify_listener(ListenerArn=listener['ListenerArn'],
                                  DefaultActions=[{'Type': 'forward', 'TargetGroupArn': httpsTg}])

        _, after = assertFlagFixCycle(emu, 'ec2', 'albTargetGroupPlaintext', res, misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        if listener:
            elbv2.delete_listener(ListenerArn=listener['ListenerArn'])
        for tg in (httpTg, httpsTg, ipTg):
            elbv2.delete_target_group(TargetGroupArn=tg)


def test_elb_uses_iam_server_certificate(emu, uid, alb, certificate):
    """HTTPS listener serving an IAM server certificate -> FAIL; switched to an ACM
    certificate -> PASS."""
    elbv2, iam = emu.client('elbv2'), emu.client('iam')
    d = tempfile.mkdtemp()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', d + '/k.pem',
                    '-out', d + '/c.pem', '-days', '30', '-subj', f'/CN=ss-iam-{uid}.example.com'],
                   check=True, capture_output=True)
    name = f'ss-iam-cert-{uid}'
    iamArn = iam.upload_server_certificate(ServerCertificateName=name, CertificateBody=open(d + '/c.pem').read(),
                                           PrivateKey=open(d + '/k.pem').read())['ServerCertificateMetadata']['Arn']
    listener = {}
    try:
        def misconfigure():
            listener.update(elbv2.create_listener(LoadBalancerArn=alb['LoadBalancerArn'], Protocol='HTTPS', Port=443,
                                                  Certificates=[{'CertificateArn': iamArn}],
                                                  DefaultActions=[{'Type': 'fixed-response',
                                                                   'FixedResponseConfig': {'StatusCode': '200'}}])['Listeners'][0])

        def fix():
            elbv2.modify_listener(ListenerArn=listener['ListenerArn'], Certificates=[{'CertificateArn': certificate}])

        _, after = assertFlagFixCycle(emu, 'ec2', 'elbUsesIamOrImportedCert', f"ELB::{alb['LoadBalancerName']}",
                                      misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        if listener:
            elbv2.delete_listener(ListenerArn=listener['ListenerArn'])
        iam.delete_server_certificate(ServerCertificateName=name)
        for f in ('k.pem', 'c.pem'):
            os.remove(os.path.join(d, f))
        os.rmdir(d)


def test_ec2_auto_recovery_disabled(emu):
    """Instance launched with AutoRecovery=disabled -> FAIL, default -> PASS.
    ModifyInstanceMaintenanceOptions is NotImplemented, so the same-instance fix is stubbed."""
    ec2 = emu.client('ec2')
    ami = _amazonAmi(ec2)
    off = on = None
    try:
        off = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType='t3.micro',
                                MaintenanceOptions={'AutoRecovery': 'disabled'})['Instances'][0]['InstanceId']
        on = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType='t3.micro')['Instances'][0]['InstanceId']
        _waitState(ec2, off, 'running')
        _waitState(ec2, on, 'running')
        st = runCheck(emu, 'ec2', 'ec2AutoRecoveryDisabled', 'EC2::').statuses()
        assert st.get(f'EC2::{off}') == -1, st
        assert st.get(f'EC2::{on}') == 1, st
    finally:
        _terminate(ec2, off, on)


def test_alb_mtls_off_internal(emu, uid, certificate):
    """Internal ALB: HTTPS listener with mTLS off -> INFO (use-case dependent);
    verify mode with IgnoreClientCertificateExpiry=True -> FAIL; expiry enforced -> PASS."""
    elbv2 = emu.client('elbv2')
    s3 = emu.client('s3')
    bucket = f'ss-test-ts-{uid}'
    s3.create_bucket(Bucket=bucket)
    d = tempfile.mkdtemp()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', d + '/ca.key',
                    '-out', d + '/ca.pem', '-days', '30', '-subj', f'/CN=ss-test-ca-{uid}'],
                   check=True, capture_output=True)
    s3.put_object(Bucket=bucket, Key='ca.pem', Body=open(d + '/ca.pem', 'rb').read())
    lb = elbv2.create_load_balancer(Name=f'ss-ialb-{uid}', Subnets=_subnets(emu), Type='application',
                                    Scheme='internal')['LoadBalancers'][0]
    tg = elbv2.create_target_group(Name=f'ss-mtls-{uid}', Protocol='HTTPS', Port=443, VpcId=lb['VpcId'],
                                   TargetType='instance')['TargetGroups'][0]['TargetGroupArn']
    listener, ts = {}, {}
    try:
        listener.update(elbv2.create_listener(LoadBalancerArn=lb['LoadBalancerArn'], Protocol='HTTPS', Port=443,
                                              Certificates=[{'CertificateArn': certificate}],
                                              DefaultActions=[{'Type': 'forward', 'TargetGroupArn': tg}])['Listeners'][0])
        st = runCheck(emu, 'ec2', 'albMtlsOff', f"ELB::{lb['LoadBalancerName']}").statuses()
        assert list(st.values()) == [0], st
        ts.update(elbv2.create_trust_store(Name=f'ss-ts-{uid}', CaCertificatesBundleS3Bucket=bucket,
                                           CaCertificatesBundleS3Key='ca.pem')['TrustStores'][0])

        def misconfigure():
            elbv2.modify_listener(ListenerArn=listener['ListenerArn'],
                                  MutualAuthentication={'Mode': 'verify', 'TrustStoreArn': ts['TrustStoreArn'],
                                                        'IgnoreClientCertificateExpiry': True})

        def fix():
            elbv2.modify_listener(ListenerArn=listener['ListenerArn'],
                                  MutualAuthentication={'Mode': 'verify', 'TrustStoreArn': ts['TrustStoreArn'],
                                                        'IgnoreClientCertificateExpiry': False})

        _, after = assertFlagFixCycle(emu, 'ec2', 'albMtlsOff', f"ELB::{lb['LoadBalancerName']}", misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        if listener:
            elbv2.delete_listener(ListenerArn=listener['ListenerArn'])
        elbv2.delete_load_balancer(LoadBalancerArn=lb['LoadBalancerArn'])
        elbv2.delete_target_group(TargetGroupArn=tg)
        if ts:
            elbv2.delete_trust_store(TrustStoreArn=ts['TrustStoreArn'])
        s3.delete_object(Bucket=bucket, Key='ca.pem')
        s3.delete_bucket(Bucket=bucket)
        for f in ('ca.key', 'ca.pem'):
            os.remove(os.path.join(d, f))
        os.rmdir(d)


# --------------------------------------------------------------------------- #
# WAFS2027 chunk 4: NACL / security groups / data stores / image pipeline / SSM endpoints
# Not covered here (emulator gaps -> tests/test_stub_ec2.py):
# - selfManagedDataStoreOnEc2 inventory paths: emulator instances cannot become SSM managed
#   nodes, so AWS:Application inventory evidence is stubbed.
# - imagebuilderNoPipeline custom / cross-account AMI (INFO) and AccessDenied paths.
# --------------------------------------------------------------------------- #
@pytest.fixture
def isolatedVpc(emu):
    """VPC with one subnet on the main route table (local route only = isolated)."""
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.94.0.0/16')['Vpc']['VpcId']
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock='10.94.1.0/24', AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
    try:
        yield {'vpc': vpc, 'subnet': sub}
    finally:
        ec2.delete_subnet(SubnetId=sub)
        for sg in ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc]}])['SecurityGroups']:
            if sg['GroupName'] != 'default':
                ec2.delete_security_group(GroupId=sg['GroupId'])
        ec2.delete_vpc(VpcId=vpc)


def test_nacl_allow_all_ingress(emu, isolatedVpc):
    ec2 = emu.client('ec2')
    vpc, sub = isolatedVpc['vpc'], isolatedVpc['subnet']
    nacl = ec2.create_network_acl(VpcId=vpc)['NetworkAcl']['NetworkAclId']
    current = ec2.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [sub]}])['NetworkAcls'][0]
    defaultNacl = current['NetworkAclId']
    assocId = next(a['NetworkAclAssociationId'] for a in current['Associations'] if a['SubnetId'] == sub)
    assocId = ec2.replace_network_acl_association(AssociationId=assocId, NetworkAclId=nacl)['NewAssociationId']
    try:
        def misconfigure():
            ec2.create_network_acl_entry(NetworkAclId=nacl, RuleNumber=100, Protocol='-1', RuleAction='allow',
                                         Egress=False, CidrBlock='0.0.0.0/0')

        def fix():
            ec2.replace_network_acl_entry(NetworkAclId=nacl, RuleNumber=100, Protocol='6', RuleAction='allow',
                                          Egress=False, CidrBlock='0.0.0.0/0', PortRange={'From': 443, 'To': 443})

        _, after = assertFlagFixCycle(emu, 'ec2', 'naclAllowAllIngress', f'NACL::{nacl}', misconfigure, fix)
        assert list(after.values()) == [1]

        # a lower-numbered deny before the allow-all rule -> not flagged
        ec2.replace_network_acl_entry(NetworkAclId=nacl, RuleNumber=100, Protocol='-1', RuleAction='allow',
                                      Egress=False, CidrBlock='0.0.0.0/0')
        ec2.create_network_acl_entry(NetworkAclId=nacl, RuleNumber=50, Protocol='6', RuleAction='deny',
                                     Egress=False, CidrBlock='0.0.0.0/0', PortRange={'From': 22, 'To': 22})
        res = runCheck(emu, 'ec2', 'naclAllowAllIngress', f'NACL::{nacl}').statuses()
        assert list(res.values()) == [1], res
        # the default NACL allows all by design -> INFO, never FAIL
        res = runCheck(emu, 'ec2', 'naclAllowAllIngress', f'NACL::{defaultNacl}').statuses()
        assert -1 not in res.values(), res
    finally:
        ec2.replace_network_acl_association(AssociationId=assocId, NetworkAclId=defaultNacl)
        ec2.delete_network_acl(NetworkAclId=nacl)


@pytest.fixture
def sgInstance(emu, uid):
    """An instance in the default VPC with its own (initially ingress-free) security group."""
    ec2 = emu.client('ec2')
    sg = ec2.create_security_group(GroupName=f'ss-test-{uid}', Description='ss test')['GroupId']
    iid = None
    try:
        iid = ec2.run_instances(ImageId=_amazonAmi(ec2), MinCount=1, MaxCount=1, InstanceType='t3.micro',
                                SecurityGroupIds=[sg])['Instances'][0]['InstanceId']
        _waitState(ec2, iid, 'running')
        yield {'sg': sg, 'instance': iid}
    finally:
        _terminate(ec2, iid)
        ec2.delete_security_group(GroupId=sg)


def _ingress(cidr, port, v6=False):
    rng = {'Ipv6Ranges': [{'CidrIpv6': cidr}]} if v6 else {'IpRanges': [{'CidrIp': cidr}]}
    return [dict(IpProtocol='tcp', FromPort=port, ToPort=port, **rng)]


def test_sg_ingress_broad_cidr(emu, sgInstance):
    ec2 = emu.client('ec2')
    sg = sgInstance['sg']

    def misconfigure():
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=_ingress('0.0.0.0/1', 443))

    def fix():
        ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=_ingress('0.0.0.0/1', 443))
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=_ingress('203.0.113.0/24', 443)
                                             + _ingress('10.0.0.0/8', 8443))

    _, after = assertFlagFixCycle(emu, 'ec2', 'sgIngressBroadCidr', f'SG::{sg}', misconfigure, fix)
    assert list(after.values()) == [1]
    # a broad public IPv6 range is flagged too
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=_ingress('2000::/3', 443, v6=True))
    assert list(runCheck(emu, 'ec2', 'sgIngressBroadCidr', f'SG::{sg}').statuses().values()) == [-1]


def test_sg_sensitive_port_open_to_all_per_permission(emu, sgInstance):
    """Regression: an open CIDR on one permission (443 from 0.0.0.0/0) must not make another
    permission's sensitive port (22 from a private range) count as open to all."""
    ec2 = emu.client('ec2')
    sg = sgInstance['sg']
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=_ingress('0.0.0.0/0', 443))

    def misconfigure():
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=_ingress('0.0.0.0/0', 22))

    def fix():
        ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=_ingress('0.0.0.0/0', 22))
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=_ingress('10.0.0.0/16', 22))

    res = runCheck(emu, 'ec2', 'SGSensitivePortOpenToAll', f'SG::{sg}').results
    assert 'SGSensitivePortOpenToAll' not in res.get(f'SG::{sg}', {}), res
    misconfigure()
    res = runCheck(emu, 'ec2', 'SGSensitivePortOpenToAll', f'SG::{sg}').results
    assert res[f'SG::{sg}']['SGSensitivePortOpenToAll'][0] == -1, res
    fix()
    res = runCheck(emu, 'ec2', 'SGSensitivePortOpenToAll', f'SG::{sg}').results
    assert 'SGSensitivePortOpenToAll' not in res.get(f'SG::{sg}', {}), res


def test_self_managed_datastore_on_ec2(emu, sgInstance):
    """Port evidence only (emulator instances are never SSM managed nodes)."""
    ec2 = emu.client('ec2')
    sg, iid = sgInstance['sg'], sgInstance['instance']
    perm = _ingress('10.0.0.0/16', 5432)
    _, after = assertFlagFixCycle(
        emu, 'ec2', 'selfManagedDataStoreOnEc2', f'SSM::{iid}',
        misconfigure=lambda: ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=perm),
        fix=lambda: ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=perm))
    assert list(after.values()) == [1]
    # an all-traffic rule is not data-store evidence
    allTraffic = [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=allTraffic)
    assert list(runCheck(emu, 'ec2', 'selfManagedDataStoreOnEc2', f'SSM::{iid}').statuses().values()) == [1]


def test_sg_unrestricted_egress_data_tier(emu, uid):
    """An ENI described as an RDS interface marks its SG as data tier (classifyDataTierEni)."""
    ec2 = emu.client('ec2')
    sg = ec2.create_security_group(GroupName=f'ss-db-{uid}', Description='ss db test')['GroupId']
    subnet = ec2.describe_subnets(Filters=[{'Name': 'default-for-az', 'Values': ['true']}])['Subnets'][0]['SubnetId']
    eni = ec2.create_network_interface(SubnetId=subnet, Groups=[sg], Description='RDSNetworkInterface')
    eniId = eni['NetworkInterface']['NetworkInterfaceId']
    allOut = [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    try:
        def misconfigure():
            groups = ec2.describe_security_groups(GroupIds=[sg])['SecurityGroups'][0]
            if not any(p['IpProtocol'] == '-1' for p in groups['IpPermissionsEgress']):
                ec2.authorize_security_group_egress(GroupId=sg, IpPermissions=allOut)

        def fix():
            ec2.revoke_security_group_egress(GroupId=sg, IpPermissions=allOut)
            ec2.authorize_security_group_egress(GroupId=sg, IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '10.0.0.0/8'}]}])

        _, after = assertFlagFixCycle(emu, 'ec2', 'sgUnrestrictedEgress', f'DataTierSG::{sg}', misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        ec2.delete_network_interface(NetworkInterfaceId=eniId)
        ec2.delete_security_group(GroupId=sg)


def test_imagebuilder_no_pipeline(emu, uid):
    ec2, ib, iam = emu.client('ec2'), emu.client('imagebuilder'), emu.client('iam')
    assert not ib.list_image_pipelines()['imagePipelineList'], 'emulator already has Image Builder pipelines'
    ami = _amazonAmi(ec2)
    iid = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType='t3.micro')['Instances'][0]['InstanceId']
    doc = ("name: ss\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: s\n"
           "        action: ExecuteBash\n        inputs:\n          commands: ['echo ok']\n")
    made = {}
    try:
        def fix():
            iam.create_instance_profile(InstanceProfileName=f'ss-ib-{uid}')
            made['profile'] = f'ss-ib-{uid}'
            made['component'] = ib.create_component(name=f'ss-c-{uid}', semanticVersion='1.0.0', platform='Linux',
                                                    data=doc)['componentBuildVersionArn']
            made['recipe'] = ib.create_image_recipe(name=f'ss-r-{uid}', semanticVersion='1.0.0', parentImage=ami,
                                                    components=[{'componentArn': made['component']}])['imageRecipeArn']
            made['infra'] = ib.create_infrastructure_configuration(
                name=f'ss-i-{uid}', instanceProfileName=made['profile'])['infrastructureConfigurationArn']
            made['pipeline'] = ib.create_image_pipeline(name=f'ss-p-{uid}', imageRecipeArn=made['recipe'],
                                                        infrastructureConfigurationArn=made['infra'])['imagePipelineArn']

        # misconfigure: an instance on a stock Amazon AMI and no pipeline
        _, after = assertFlagFixCycle(emu, 'ec2', 'imagebuilderNoPipeline', 'EC2::ImageBuilder', lambda: None, fix)
        assert list(after.values()) == [1]

        # a disabled pipeline does not count
        ib.update_image_pipeline(imagePipelineArn=made['pipeline'], imageRecipeArn=made['recipe'],
                                 infrastructureConfigurationArn=made['infra'], status='DISABLED')
        assert list(runCheck(emu, 'ec2', 'imagebuilderNoPipeline', 'EC2::ImageBuilder').statuses().values()) == [-1]
    finally:
        _terminate(ec2, iid)
        if 'pipeline' in made:
            ib.delete_image_pipeline(imagePipelineArn=made['pipeline'])
        if 'infra' in made:
            ib.delete_infrastructure_configuration(infrastructureConfigurationArn=made['infra'])
        if 'recipe' in made:
            ib.delete_image_recipe(imageRecipeArn=made['recipe'])
        if 'component' in made:
            ib.delete_component(componentBuildVersionArn=made['component'])
        if 'profile' in made:
            iam.delete_instance_profile(InstanceProfileName=made['profile'])


def test_ssm_vpc_endpoints_missing(emu, isolatedVpc):
    ec2 = emu.client('ec2')
    vpc, sub = isolatedVpc['vpc'], isolatedVpc['subnet']
    iid = ec2.run_instances(ImageId=_amazonAmi(ec2), MinCount=1, MaxCount=1, InstanceType='t3.micro',
                            SubnetId=sub)['Instances'][0]['InstanceId']
    eps = []
    try:
        def fix():
            ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={'Value': True})
            ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={'Value': True})
            for svc in ('ssm', 'ssmmessages'):
                eps.append(ec2.create_vpc_endpoint(VpcId=vpc, VpcEndpointType='Interface', SubnetIds=[sub],
                                                   ServiceName=f'com.amazonaws.us-east-1.{svc}',
                                                   PrivateDnsEnabled=True)['VpcEndpoint']['VpcEndpointId'])

        # misconfigure: instance in a subnet without any default route and no SSM endpoints
        _, after = assertFlagFixCycle(emu, 'ec2', 'ssmVpcEndpointsMissing', f'VPC::{vpc}', lambda: None, fix)
        assert list(after.values()) == [1]
    finally:
        if eps:
            ec2.delete_vpc_endpoints(VpcEndpointIds=eps)
        _terminate(ec2, iid)


# --------------------------------------------------------------------------- #
# vpcPeeringFullRoute (review flag)
# --------------------------------------------------------------------------- #
def _peerVpcs(ec2, a, b):
    va = ec2.create_vpc(CidrBlock=a)['Vpc']['VpcId']
    vb = ec2.create_vpc(CidrBlock=b)['Vpc']['VpcId']
    return va, vb


def test_vpc_peering_full_route(emu):
    """Same-account full-CIDR peering is the documented default: review item (0), fixed
    to a subnet route -> 1. The FAIL path (peer VPC in another account) needs a second
    account and is covered in tests/test_stub_ec2.py."""
    ec2 = emu.client('ec2')
    va, vb = _peerVpcs(ec2, '10.211.0.0/16', '10.212.0.0/16')
    pcx = ec2.create_vpc_peering_connection(VpcId=va, PeerVpcId=vb)['VpcPeeringConnection']['VpcPeeringConnectionId']
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)
    rt = _mainRouteTable(ec2, va)
    try:
        def misconfigure():
            ec2.create_route(RouteTableId=rt, DestinationCidrBlock='10.212.0.0/16', VpcPeeringConnectionId=pcx)

        def fix():
            ec2.delete_route(RouteTableId=rt, DestinationCidrBlock='10.212.0.0/16')
            ec2.create_route(RouteTableId=rt, DestinationCidrBlock='10.212.1.0/24', VpcPeeringConnectionId=pcx)

        misconfigure()
        res = runCheck(emu, 'ec2', 'vpcPeeringFullRoute', f'VPC::{va}')
        assert res.statuses() == {f'VPC::{va}': 0}, res.statuses()
        assert res.results[f'VPC::{va}']['vpcPeeringFullRoute'][1].startswith('Review')
        fix()
        assert runCheck(emu, 'ec2', 'vpcPeeringFullRoute', f'VPC::{va}').statuses() == {f'VPC::{va}': 1}
        # the peer side without any peering route passes
        assert runCheck(emu, 'ec2', 'vpcPeeringFullRoute', f'VPC::{vb}').statuses() == {f'VPC::{vb}': 1}
    finally:
        for cidr in ('10.212.0.0/16', '10.212.1.0/24'):
            try:
                ec2.delete_route(RouteTableId=rt, DestinationCidrBlock=cidr)
            except Exception:
                pass
        ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)
        ec2.delete_vpc(VpcId=va)
        ec2.delete_vpc(VpcId=vb)


def test_vpc_tgw_full_route(emu):
    """The emulator returns no Association on TGW attachments, so this exercises the
    fallback (other VPC attachments of the same TGW); the association +
    search_transit_gateway_routes path is stubbed in tests/test_stub_ec2.py.
    A TGW route covering a whole peer CIDR is a review item (0, never -1); summary /
    default routes (hub-and-spoke egress) are not full peer routes (1)."""
    ec2 = emu.client('ec2')
    va, vb = _peerVpcs(ec2, '10.213.0.0/16', '10.214.0.0/16')
    sa = ec2.create_subnet(VpcId=va, CidrBlock='10.213.1.0/24')['Subnet']['SubnetId']
    sb = ec2.create_subnet(VpcId=vb, CidrBlock='10.214.1.0/24')['Subnet']['SubnetId']
    tgw = ec2.create_transit_gateway()['TransitGateway']['TransitGatewayId']
    atts = [ec2.create_transit_gateway_vpc_attachment(TransitGatewayId=tgw, VpcId=v, SubnetIds=[s])
            ['TransitGatewayVpcAttachment']['TransitGatewayAttachmentId'] for v, s in ((va, sa), (vb, sb))]
    rt = _mainRouteTable(ec2, va)
    try:
        res = f'VPC::{va}'
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock='10.0.0.0/8', TransitGatewayId=tgw)
        assert runCheck(emu, 'ec2', 'vpcPeeringFullRoute', res).statuses() == {res: 1}       # summary route
        ec2.delete_route(RouteTableId=rt, DestinationCidrBlock='10.0.0.0/8')
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock='10.214.0.0/16', TransitGatewayId=tgw)
        assert runCheck(emu, 'ec2', 'vpcPeeringFullRoute', res).statuses() == {res: 0}       # whole peer CIDR
        ec2.delete_route(RouteTableId=rt, DestinationCidrBlock='10.214.0.0/16')
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock='10.214.1.0/24', TransitGatewayId=tgw)
        assert runCheck(emu, 'ec2', 'vpcPeeringFullRoute', res).statuses() == {res: 1}       # partial route
    finally:
        for cidr in ('10.0.0.0/8', '10.214.0.0/16', '10.214.1.0/24'):
            try:
                ec2.delete_route(RouteTableId=rt, DestinationCidrBlock=cidr)
            except Exception:
                pass
        for a in atts:
            ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=a)
        for _ in range(30):  # attachments are deleted asynchronously
            left = [x for x in ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=atts)
                    ['TransitGatewayVpcAttachments'] if x.get('State') != 'deleted']
            if not left:
                break
            time.sleep(1)
        ec2.delete_transit_gateway(TransitGatewayId=tgw)
        ec2.delete_subnet(SubnetId=sa)
        ec2.delete_subnet(SubnetId=sb)
        ec2.delete_vpc(VpcId=va)
        ec2.delete_vpc(VpcId=vb)

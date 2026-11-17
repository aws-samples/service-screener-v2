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

"""Stubber tests for eks.eksNoIRSAConfigured (Pod Identity agent / Auto Mode
without associations) and a lock on eksNodeGroupAmiOutdated's "any lag" rule.

Why Stubber: EKS Auto Mode (computeConfig.enabled) cannot be created in the
local AWS Emulator. These tests drive the real EksCommon driver with real boto3
clients wrapped in botocore Stubber (real API shapes); no network calls.
"""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.eks.drivers.EksCommon import EksCommon  # noqa: E402
from utils.Config import Config  # noqa: E402

CLUSTER = 'demo'
ACCT = '111122223333'
ISSUER = 'https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789'
OIDC_ARN = f'arn:aws:iam::{ACCT}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789'


def _clients():
    kw = dict(region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')
    return boto3.client('eks', **kw), boto3.client('iam', **kw)


def _run(autoMode=False, addons=(), associations=0, oidcProviders=()):
    Config.init()  # fresh scan: drop the shared IAM cache
    eks, iam = _clients()
    info = {'name': CLUSTER, 'version': '1.31', 'identity': {'oidc': {'issuer': ISSUER}}}
    if autoMode:
        info['computeConfig'] = {'enabled': True}
    with Stubber(eks) as es, Stubber(iam) as ist:
        ist.add_response('list_open_id_connect_providers',
                         {'OpenIDConnectProviderList': [{'Arn': a} for a in oidcProviders]}, {})
        assoc = [{'clusterName': CLUSTER, 'namespace': 'default', 'serviceAccount': f'sa{i}',
                  'associationArn': f'arn:aws:eks:us-east-1:{ACCT}:podidentityassociation/{CLUSTER}/a-{i}',
                  'associationId': f'a-{i}'} for i in range(associations)]
        es.add_response('list_pod_identity_associations', {'associations': assoc}, {'clusterName': CLUSTER})
        if not autoMode:
            es.add_response('list_addons', {'addons': list(addons)}, {'clusterName': CLUSTER})
        obj = EksCommon(CLUSTER, info, eks, None, iam)
        obj._checkNoIRSAConfigured()
    return obj.results['eksNoIRSAConfigured']


def test_agent_addon_without_associations_is_not_pass():
    r = _run(addons=['eks-pod-identity-agent', 'vpc-cni'])
    assert r[0] == 0, r
    assert 'eks-pod-identity-agent' in r[1] and 'no pod identity associations' in r[1], r


def test_auto_mode_without_associations_is_not_pass():
    r = _run(autoMode=True)
    assert r[0] == 0, r
    assert 'Auto Mode' in r[1], r


def test_agent_addon_flag_fix_with_association():
    assert _run(addons=['eks-pod-identity-agent'])[0] == 0
    fixed = _run(addons=['eks-pod-identity-agent'], associations=1)
    assert fixed[0] == 1 and 'EKS Pod Identity associations' in fixed[1], fixed


def test_auto_mode_with_association_passes():
    assert _run(autoMode=True, associations=2)[0] == 1


def test_oidc_provider_still_passes():
    r = _run(oidcProviders=[OIDC_ARN])
    assert r[0] == 1 and 'IRSA' in r[1], r


def test_nothing_configured_fails():
    assert _run(addons=['vpc-cni'])[0] == -1


# ---- eksNodeGroupAmiOutdated: any release older than the latest is flagged ----
# The reporter text ("running an EKS-optimized AMI release older than the latest
# release") defines the rule: no grace period. The lag is reported in the message.

AL2023_PATH = '/aws/service/eks/optimized-ami/1.31/amazon-linux-2023/x86_64/standard/recommended/release_version'


def _amiRun(release, latest):
    Config.init()
    kw = dict(region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')
    eks, ssm = boto3.client('eks', **kw), boto3.client('ssm', **kw)
    with Stubber(eks) as es, Stubber(ssm) as ss:
        es.add_response('list_nodegroups', {'nodegroups': ['ng1']}, {'clusterName': CLUSTER})
        es.add_response('describe_nodegroup', {'nodegroup': {
            'nodegroupName': 'ng1', 'clusterName': CLUSTER, 'version': '1.31',
            'amiType': 'AL2023_x86_64_STANDARD', 'releaseVersion': release}},
            {'clusterName': CLUSTER, 'nodegroupName': 'ng1'})
        ss.add_response('get_parameter', {'Parameter': {'Name': AL2023_PATH, 'Type': 'String',
                                                        'Value': latest, 'Version': 1}}, {'Name': AL2023_PATH})
        obj = EksCommon(CLUSTER, {'name': CLUSTER, 'version': '1.31'}, eks, None, None, ssm)
        obj._checkNodeGroupAmiOutdated()
    return obj.results['eksNodeGroupAmiOutdated']


def test_ami_one_release_behind_is_flagged_with_versions_in_message():
    r = _amiRun('1.31.2-20241114', '1.31.2-20241121')
    assert r[0] == -1, r
    assert '1.31.2-20241114 < 1.31.2-20241121' in r[1], r


def test_ami_on_latest_release_passes():
    assert _amiRun('1.31.2-20241121', '1.31.2-20241121')[0] == 1

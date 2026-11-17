"""EKS checks against the local AWS Emulator (flag -> fix -> re-run).

eksNoIRSAConfigured: every EKS cluster has an OIDC issuer URL, but IRSA only
works once that issuer is registered as an IAM OIDC provider. The check must
FAIL when neither IRSA nor EKS Pod Identity is configured and PASS once either
is added.

eksNodeGroupAmiOutdated: the emulator refuses writes to the reserved
/aws/service/* SSM namespace and does not publish the public EKS AMI
parameters, so the flag/fix cycle is covered by tests/test_stub_eks.py. Here we
only verify end to end that a missing parameter yields 0 (not a false PASS).
"""
import json
import time

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

TRUST_EKS = {'Version': '2012-10-17', 'Statement': [
    {'Effect': 'Allow', 'Principal': {'Service': ['eks.amazonaws.com', 'pods.eks.amazonaws.com', 'ec2.amazonaws.com']},
     'Action': ['sts:AssumeRole', 'sts:TagSession']}]}


@pytest.fixture
def cluster(emu, uid):
    eks, ec2, iam = emu.client('eks'), emu.client('ec2'), emu.client('iam')
    roleName = f'ss-eks-{uid}'
    roleArn = iam.create_role(RoleName=roleName, AssumeRolePolicyDocument=json.dumps(TRUST_EKS))['Role']['Arn']
    vpc = ec2.create_vpc(CidrBlock='10.42.0.0/16')['Vpc']['VpcId']
    subnets = [ec2.create_subnet(VpcId=vpc, CidrBlock=f'10.42.{i}.0/24', AvailabilityZone='us-east-1' + 'ab'[i])['Subnet']['SubnetId']
               for i in range(2)]
    name = f'ss-eks-{uid}'
    eks.create_cluster(name=name, version='1.31', roleArn=roleArn, resourcesVpcConfig={'subnetIds': subnets})
    ctx = {'name': name, 'roleArn': roleArn, 'subnets': subnets}
    try:
        for _ in range(60):
            if eks.describe_cluster(name=name)['cluster'].get('status') == 'ACTIVE':
                break
            time.sleep(0.5)
        yield ctx
    finally:
        for ng in eks.list_nodegroups(clusterName=name).get('nodegroups', []):
            try:
                eks.delete_nodegroup(clusterName=name, nodegroupName=ng)
            except Exception:
                pass
        for _ in range(60):
            if not eks.list_nodegroups(clusterName=name).get('nodegroups'):
                break
            time.sleep(0.5)
        for a in eks.list_pod_identity_associations(clusterName=name).get('associations', []):
            try:
                eks.delete_pod_identity_association(clusterName=name, associationId=a['associationId'])
            except Exception:
                pass
        for ad in eks.list_addons(clusterName=name).get('addons', []):
            try:
                eks.delete_addon(clusterName=name, addonName=ad)
            except Exception:
                pass
        if ctx.get('oidcArn'):
            try:
                iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=ctx['oidcArn'])
            except Exception:
                pass
        try:
            eks.delete_cluster(name=name)
        except Exception:
            pass
        for s in subnets:
            try:
                ec2.delete_subnet(SubnetId=s)
            except Exception:
                pass
        try:
            ec2.delete_vpc(VpcId=vpc)
        except Exception:
            pass
        try:
            iam.delete_role(RoleName=roleName)
        except Exception:
            pass


def test_eks_workload_identity_fixed_by_pod_identity(emu, cluster):
    eks = emu.client('eks')

    def misconfigure():
        # Fresh cluster: OIDC issuer URL exists, but no IAM OIDC provider and no Pod Identity.
        pass

    def fix():
        eks.create_pod_identity_association(clusterName=cluster['name'], namespace='default',
                                            serviceAccount='app', roleArn=cluster['roleArn'])

    assertFlagFixCycle(emu, 'eks', 'eksNoIRSAConfigured', cluster['name'], misconfigure, fix)


def test_eks_workload_identity_fixed_by_irsa_oidc_provider(emu, cluster):
    eks, iam = emu.client('eks'), emu.client('iam')
    issuer = eks.describe_cluster(name=cluster['name'])['cluster']['identity']['oidc']['issuer']

    def fix():
        cluster['oidcArn'] = iam.create_open_id_connect_provider(
            Url=issuer, ClientIDList=['sts.amazonaws.com'],
            ThumbprintList=['9e99a48a9960b14926bb7f3b02e22da2b0ab7280'])['OpenIDConnectProviderArn']

    assertFlagFixCycle(emu, 'eks', 'eksNoIRSAConfigured', cluster['name'], lambda: None, fix)


def test_eks_workload_identity_fixed_by_pod_identity_agent_addon(emu, cluster):
    eks = emu.client('eks')

    def fix():
        eks.create_addon(clusterName=cluster['name'], addonName='eks-pod-identity-agent')

    assertFlagFixCycle(emu, 'eks', 'eksNoIRSAConfigured', cluster['name'], lambda: None, fix)


def test_eks_nodegroup_ami_missing_ssm_param_is_not_pass(emu, cluster):
    eks = emu.client('eks')
    eks.create_nodegroup(clusterName=cluster['name'], nodegroupName='ng1', subnets=cluster['subnets'],
                         nodeRole=cluster['roleArn'], amiType='AL2023_x86_64_STANDARD',
                         releaseVersion='1.31.0-20240901', version='1.31')
    st = runCheck(emu, 'eks', 'eksNodeGroupAmiOutdated', cluster['name']).statuses()
    assert st and all(s == 0 for s in st.values()), st

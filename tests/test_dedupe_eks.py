"""EKS: each piece of AWS data is fetched once per cluster (per-driver _memo) or once
per scan (_sharedMemo for account/region-level data), while every check keeps its
results. Checks of one driver run concurrently in the real scan, so the per-cluster
test runs them in threads."""
import concurrent.futures as cf
import os
import sys
from unittest.mock import MagicMock

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.eks.drivers.EksCommon import EksCommon  # noqa: E402
from utils.Config import Config  # noqa: E402

REGION = 'us-east-1'
ISSUER = 'https://oidc.eks.us-east-1.amazonaws.com/id/ABC123'
AL2023_PATH = '/aws/service/eks/optimized-ami/1.31/amazon-linux-2023/x86_64/standard/recommended/release_version'
ADMIN_DOC = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}

NODEGROUP_CHECKS = ['_checkNoManagedNodeGroups', '_checkNodeGroupSingleAZ', '_checkNoSpotInstances',
                    '_checkNoAutoscaling', '_checkNodeGroupAmiOutdated']
ADDON_CHECKS = ['_checkNoKarpenter', '_checkNoAutoscaling', '_checkNoManagedStorageDrivers', '_checkNoIRSAConfigured']


def _clusterInfo(name):
    return {'name': name, 'version': '1.31', 'roleArn': 'arn:aws:iam::111122223333:role/eksRole',
            'identity': {'oidc': {'issuer': ISSUER}}}


def _nodegroup(cluster, name, minSize, maxSize):
    return {'nodegroup': {'nodegroupName': name, 'clusterName': cluster, 'version': '1.31',
                          'amiType': 'AL2023_x86_64_STANDARD', 'releaseVersion': '1.31.0-20240901',
                          'capacityType': 'ON_DEMAND', 'subnets': ['subnet-a', 'subnet-b'],
                          'scalingConfig': {'minSize': minSize, 'maxSize': maxSize}}}


def _mockClients():
    def client(svc):
        c = MagicMock(name=svc)
        c.meta.region_name = REGION
        return c
    eks, ec2, iam, ssm = client('eks'), client('ec2'), client('iam'), client('ssm')
    eks.list_nodegroups.return_value = {'nodegroups': ['ng1', 'ng2']}
    eks.describe_nodegroup.side_effect = lambda clusterName, nodegroupName: _nodegroup(
        clusterName, nodegroupName, *({'ng1': (1, 3), 'ng2': (2, 2)}[nodegroupName]))
    eks.list_addons.return_value = {'addons': ['vpc-cni', 'coredns']}
    eks.get_paginator.return_value.paginate.return_value = [{'associations': []}]
    ec2.describe_subnets.return_value = {'Subnets': [{'SubnetId': 'subnet-a', 'AvailabilityZone': 'us-east-1a'},
                                                     {'SubnetId': 'subnet-b', 'AvailabilityZone': 'us-east-1a'}]}
    iam.list_open_id_connect_providers.return_value = {'OpenIDConnectProviderList': [
        {'Arn': 'arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/abc123'}]}
    iam.list_role_policies.return_value = {'PolicyNames': []}
    iam.list_attached_role_policies.return_value = {'AttachedPolicies': [
        {'PolicyName': 'Admin', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]}
    iam.get_policy.return_value = {'Policy': {'Arn': 'arn:aws:iam::aws:policy/AdministratorAccess',
                                              'DefaultVersionId': 'v1'}}
    iam.get_policy_version.return_value = {'PolicyVersion': {'Document': ADMIN_DOC, 'VersionId': 'v1'}}
    ssm.get_parameter.return_value = {'Parameter': {'Name': AL2023_PATH, 'Value': '1.31.2-20241121'}}
    return eks, ec2, iam, ssm


def _runConcurrently(obj, methods):
    with cf.ThreadPoolExecutor(max_workers=len(methods)) as ex:
        for f in [ex.submit(getattr(obj, m)) for m in methods]:
            f.result()


def _expectedResults():
    return {
        'eksNodeGroupSingleAZ': [-1, 'ng2 (AZ: us-east-1a)'],
        'eksNoSpotInstances': [-1, 'No Spot instances configured'],
        'eksNoKarpenter': [-1, 'Karpenter add-on not installed'],
        'eksNoManagedStorageDrivers': [-1, 'No EBS or EFS CSI driver installed'],
        'eksNoIRSAConfigured': [1, 'Workload identity: IRSA (IAM OIDC provider registered)'],
        'eksNodeGroupAmiOutdated': [-1, 'ng1: 1.31.0-20240901 < 1.31.2-20241121; ng2: 1.31.0-20240901 < 1.31.2-20241121'],
        'eksClusterRoleLeastPrivilege': [-1, 'eksRole'],
    }


def test_cluster_data_fetched_once_per_cluster_across_concurrent_checks():
    Config.init()
    eks, ec2, iam, ssm = _mockClients()
    obj = EksCommon('c1', _clusterInfo('c1'), eks, ec2, iam, ssm)
    _runConcurrently(obj, sorted(set(NODEGROUP_CHECKS + ADDON_CHECKS + ['_checkRoleLeastPrivilege'])))

    assert obj.results == _expectedResults()
    assert eks.list_nodegroups.call_count == 1
    assert eks.describe_nodegroup.call_count == 2  # once per node group, not once per check
    assert eks.list_addons.call_count == 1
    assert ec2.describe_subnets.call_count == 1  # both node groups use the same subnets
    assert ssm.get_parameter.call_count == 1
    assert iam.list_open_id_connect_providers.call_count == 1
    eks.list_nodegroups.assert_called_once_with(clusterName='c1')
    eks.list_addons.assert_called_once_with(clusterName='c1')


def test_account_level_data_fetched_once_per_scan_across_clusters():
    Config.init()
    eks, ec2, iam, ssm = _mockClients()
    objs = [EksCommon(c, _clusterInfo(c), eks, ec2, iam, ssm) for c in ('c1', 'c2')]
    for obj in objs:
        _runConcurrently(obj, ['_checkNoIRSAConfigured', '_checkNodeGroupAmiOutdated',
                               '_checkNodeGroupSingleAZ', '_checkRoleLeastPrivilege'])
    exp = {k: v for k, v in _expectedResults().items() if k in (
        'eksNoIRSAConfigured', 'eksNodeGroupAmiOutdated', 'eksNodeGroupSingleAZ', 'eksClusterRoleLeastPrivilege')}
    for obj in objs:
        assert obj.results == exp

    # per-cluster data: once per cluster
    assert eks.list_nodegroups.call_count == 2
    assert eks.describe_nodegroup.call_count == 4
    # account/region-level data: once per scan
    assert iam.list_open_id_connect_providers.call_count == 1
    assert ssm.get_parameter.call_count == 1
    assert ec2.describe_subnets.call_count == 1
    assert iam.list_role_policies.call_count == 1
    assert iam.list_attached_role_policies.call_count == 1
    assert iam.get_policy.call_count == 1
    assert iam.get_policy_version.call_count == 1

    # a new scan reads fresh data
    Config.init()
    EksCommon('c3', _clusterInfo('c3'), eks, ec2, iam, ssm)._checkNoIRSAConfigured()
    assert iam.list_open_id_connect_providers.call_count == 2


def _botoClients():
    kw = dict(region_name=REGION, aws_access_key_id='x', aws_secret_access_key='x')
    return boto3.client('eks', **kw), boto3.client('ssm', **kw)


def test_paginated_and_single_page_readers_share_pages_stubber():
    """list_nodegroups has two pages: the paginated AMI check and the single-page checks
    reuse them. Each response is queued exactly once, so any extra call fails."""
    Config.init()
    eks, ssm = _botoClients()
    with Stubber(eks) as es, Stubber(ssm) as ss:
        es.add_response('list_nodegroups', {'nodegroups': ['ng1'], 'nextToken': 't1'}, {'clusterName': 'c1'})
        es.add_response('list_nodegroups', {'nodegroups': ['ng2']}, {'clusterName': 'c1', 'nextToken': 't1'})
        for ng, sizes in (('ng1', (1, 1)), ('ng2', (1, 1))):
            n = _nodegroup('c1', ng, *sizes)
            del n['nodegroup']['subnets']
            es.add_response('describe_nodegroup', n, {'clusterName': 'c1', 'nodegroupName': ng})
        ss.add_response('get_parameter', {'Parameter': {'Name': AL2023_PATH, 'Type': 'String',
                                                        'Value': '1.31.0-20240901', 'Version': 1}},
                        {'Name': AL2023_PATH})
        es.add_response('list_addons', {'addons': []}, {'clusterName': 'c1'})

        obj = EksCommon('c1', {'name': 'c1', 'version': '1.31'}, eks, None, None, ssm)
        obj._checkNodeGroupAmiOutdated()
        obj._checkNoManagedNodeGroups()
        obj._checkNoSpotInstances()
        obj._checkNodeGroupSingleAZ()
        obj._checkNoAutoscaling()
        es.assert_no_pending_responses()
        ss.assert_no_pending_responses()

    assert obj.results == {
        'eksNodeGroupAmiOutdated': [1, 'Latest AMI release: ng1, ng2'],
        'eksNoSpotInstances': [-1, 'No Spot instances configured'],
        'eksNoAutoscaling': [-1, 'No Karpenter and no node group autoscaling'],
    }


def test_cached_error_reaches_every_checks_handler_stubber():
    """An AccessDenied from list_addons is fetched once and handled by each check as before."""
    Config.init()
    eks, _ = _botoClients()
    with Stubber(eks) as es:
        es.add_client_error('list_addons', service_error_code='AccessDeniedException', http_status_code=403,
                            expected_params={'clusterName': 'c1'})
        es.add_response('list_pod_identity_associations', {'associations': []}, {'clusterName': 'c1'})
        obj = EksCommon('c1', {'name': 'c1', 'version': '1.31'}, eks, None, None, None)
        obj._checkNoKarpenter()
        obj._checkNoManagedStorageDrivers()
        obj._checkNoAutoscaling()
        obj._checkNoIRSAConfigured()
        es.assert_no_pending_responses()

    assert obj.results == {'eksNoIRSAConfigured': [0, 'Unable to evaluate (eks:AccessDeniedException)']}

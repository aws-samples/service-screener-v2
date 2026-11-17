"""Stubber tests for eks.eksNodeGroupAmiOutdated (flag -> fix -> re-run).

Why Stubber: the check reads the AWS-published public SSM parameters
(/aws/service/eks/optimized-ami/... and /aws/service/bottlerocket/...). The
local AWS Emulator does not serve them and rejects writes to the reserved
/aws/service/* namespace, so the latest-release side cannot be set up there.
These tests drive the real EksCommon driver with real boto3 clients wrapped in
botocore Stubber (real API shapes); no network calls are made.
"""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.eks.drivers.EksCommon import EksCommon  # noqa: E402

CLUSTER = 'demo'
CLUSTER_INFO = {'name': CLUSTER, 'version': '1.31'}
AL2023_PATH = '/aws/service/eks/optimized-ami/1.31/amazon-linux-2023/x86_64/standard/recommended/release_version'
BR_PATH = '/aws/service/bottlerocket/aws-k8s-1.31/x86_64/latest/image_version'


def _clients():
    kw = dict(region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')
    return boto3.client('eks', **kw), boto3.client('ssm', **kw)


def _nodegroup(name, amiType, release, version='1.31'):
    ng = {'nodegroupName': name, 'clusterName': CLUSTER, 'version': version, 'amiType': amiType}
    if release is not None:
        ng['releaseVersion'] = release
    return {'nodegroup': ng}


def _param(path, value):
    return {'Parameter': {'Name': path, 'Type': 'String', 'Value': value, 'Version': 1}}


def _run(nodegroups, params):
    """nodegroups: list of describe_nodegroup responses; params: list of (path, value|errorCode)."""
    eks, ssm = _clients()
    with Stubber(eks) as es, Stubber(ssm) as ss:
        es.add_response('list_nodegroups', {'nodegroups': [n['nodegroup']['nodegroupName'] for n in nodegroups]},
                        {'clusterName': CLUSTER})
        pi = iter(params)
        seen = set()
        for n in nodegroups:
            es.add_response('describe_nodegroup', n,
                            {'clusterName': CLUSTER, 'nodegroupName': n['nodegroup']['nodegroupName']})
            if n['nodegroup']['amiType'] in EksCommon.AMI_RELEASE_SSM_PATHS:
                path = EksCommon.AMI_RELEASE_SSM_PATHS[n['nodegroup']['amiType']].format(v=n['nodegroup']['version'])
                if path in seen:
                    continue
                seen.add(path)
                p, v = next(pi)
                assert p == path
                if v in ('ParameterNotFound', 'AccessDeniedException'):
                    ss.add_client_error('get_parameter', service_error_code=v, expected_params={'Name': p})
                else:
                    ss.add_response('get_parameter', _param(p, v), {'Name': p})
        obj = EksCommon(CLUSTER, CLUSTER_INFO, eks, None, None, ssm)
        obj._checkNodeGroupAmiOutdated()
        es.assert_no_pending_responses()
        ss.assert_no_pending_responses()
    return obj.results.get('eksNodeGroupAmiOutdated')


def test_al2023_flag_fix_cycle():
    flagged = _run([_nodegroup('ng1', 'AL2023_x86_64_STANDARD', '1.31.0-20240901')],
                   [(AL2023_PATH, '1.31.2-20241121')])
    assert flagged[0] == -1, flagged
    assert 'ng1' in flagged[1]
    fixed = _run([_nodegroup('ng1', 'AL2023_x86_64_STANDARD', '1.31.2-20241121')],
                 [(AL2023_PATH, '1.31.2-20241121')])
    assert fixed[0] == 1, fixed


def test_same_k8s_patch_older_build_date_is_flagged():
    r = _run([_nodegroup('ng1', 'AL2023_x86_64_STANDARD', '1.31.2-20241101')], [(AL2023_PATH, '1.31.2-20241121')])
    assert r[0] == -1, r


def test_bottlerocket_flag_fix_cycle_ignores_commit_hash():
    flagged = _run([_nodegroup('br', 'BOTTLEROCKET_x86_64', '1.19.2-29cc92cc')], [(BR_PATH, '1.26.2-360b7a38')])
    assert flagged[0] == -1, flagged
    fixed = _run([_nodegroup('br', 'BOTTLEROCKET_x86_64', '1.26.2-360b7a38')], [(BR_PATH, '1.26.2-360b7a38')])
    assert fixed[0] == 1, fixed


def test_one_outdated_among_several_is_flagged_and_ssm_lookup_cached():
    r = _run([_nodegroup('a', 'AL2023_x86_64_STANDARD', '1.31.2-20241121'),
              _nodegroup('b', 'AL2023_x86_64_STANDARD', '1.31.0-20240901'),
              _nodegroup('c', 'CUSTOM', None)],
             [(AL2023_PATH, '1.31.2-20241121')])
    assert r[0] == -1 and 'b:' in r[1] and 'a:' not in r[1], r


def test_custom_and_windows_are_not_evaluable():
    r = _run([_nodegroup('c', 'CUSTOM', None), _nodegroup('w', 'WINDOWS_CORE_2022_x86_64', '1.31-2024.11.12')], [])
    assert r[0] == 0, r


def test_missing_parameter_is_unable_to_evaluate_not_pass():
    r = _run([_nodegroup('ng1', 'AL2023_x86_64_STANDARD', '1.31.0-20240901')], [(AL2023_PATH, 'ParameterNotFound')])
    assert r[0] == 0 and 'ParameterNotFound' in r[1], r


def test_access_denied_with_other_current_group_is_not_pass():
    r = _run([_nodegroup('a', 'AL2023_x86_64_STANDARD', '1.31.2-20241121'),
              _nodegroup('br', 'BOTTLEROCKET_x86_64', '1.26.2-360b7a38')],
             [(AL2023_PATH, '1.31.2-20241121'), (BR_PATH, 'AccessDeniedException')])
    assert r[0] == 0, r


def test_no_nodegroups_records_nothing():
    assert _run([], []) is None


def test_parse_release_version():
    assert EksCommon.parseReleaseVersion('1.31.2-20241121') == ((1, 31, 2), 20241121)
    assert EksCommon.parseReleaseVersion('1.26.2-360b7a38', True) == ((1, 26, 2), 0)
    assert EksCommon.parseReleaseVersion('garbage') is None
    assert EksCommon.parseReleaseVersion(None) is None

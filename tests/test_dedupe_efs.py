"""EfsDriver: describe_lifecycle_configuration, describe_file_system_policy, describe_mount_targets
and describe_access_points are each called once per file system (driver instance), however many
checks read them, and every check still produces the same result as before the de-duplication."""
import concurrent.futures
import os
import subprocess
import sys
import types
from unittest import mock

import boto3
import botocore.exceptions
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.efs.drivers.EfsDriver import EfsDriver  # noqa: E402

FS_ID = 'fs-0123456789abcdef0'
GB = 1024 ** 3
TLS_POLICY = ('{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},'
              '"Action":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}')

CHECKS = ['_checkLifecycle_configuration', '_checkFileSystemPolicy', '_checkMountTargetSecurityGroups',
          '_checkAccessPointsConfigured', '_checkComprehensiveSecurity', '_checkTLSRequired',
          '_checkStorageOptimization']
MEMO_OPS = ['describe_lifecycle_configuration', 'describe_file_system_policy',
            'describe_mount_targets', 'describe_access_points']


def _client():
    return boto3.client('efs', region_name='us-east-1', aws_access_key_id='x',
                        aws_secret_access_key='x')


def _fs(size=20 * GB, ia=0):
    return {'FileSystemId': FS_ID, 'Encrypted': True, 'ThroughputMode': 'elastic',
            'PerformanceMode': 'generalPurpose', 'Tags': [],
            'SizeInBytes': {'Value': size, 'ValueInIA': ia, 'ValueInStandard': size - ia}}


def _mt():
    mt = {'MountTargetId': 'fsmt-01234567', 'FileSystemId': FS_ID, 'SubnetId': 'subnet-0123456789abcdef0',
          'LifeCycleState': 'available', 'OwnerId': '123456789012'}
    return {'MountTargets': [mt]}


def test_each_read_called_once_with_stubber():
    """Exactly one queued response per operation: any second call would raise."""
    client = _client()
    st = Stubber(client)
    p = {'FileSystemId': FS_ID}
    st.add_response('describe_lifecycle_configuration',
                    {'LifecyclePolicies': [{'TransitionToIA': 'AFTER_30_DAYS'}]}, p)
    st.add_response('describe_file_system_policy', {'FileSystemId': FS_ID, 'Policy': TLS_POLICY}, p)
    st.add_response('describe_mount_targets', _mt(), p)
    st.add_response('describe_access_points',
                    {'AccessPoints': [{'AccessPointId': 'fsap-1', 'FileSystemId': FS_ID}]}, p)
    with st:
        d = EfsDriver(_fs(), client)
        for c in CHECKS:
            getattr(d, c)()
        st.assert_no_pending_responses()
    r = d.results
    assert 'Lifecycle' not in r and r['EnabledLifecycle'] == [1, 'Enabled']
    assert r['FileSystemPolicy'] == [1, 'Policy configured']
    # The stubbed mount target has no SecurityGroups key -> flagged by both checks
    assert r['MountTargetSecurityGroups'] == [-1, '1 mount target(s) without security groups']
    assert r['AccessPointsConfigured'] == [1, '1 access point(s) configured']
    assert r['ComprehensiveSecurity'] == [-1, 'Missing: security groups']
    assert r['TLSRequired'] == [1, 'TLS required via policy']
    assert r['StorageOptimization'][0] == -1 and 'Lifecycle enabled but no data in IA' in r['StorageOptimization'][1]


def test_policy_not_found_called_once_and_reaches_same_except_blocks():
    client = _client()
    st = Stubber(client)
    p = {'FileSystemId': FS_ID}
    st.add_client_error('describe_file_system_policy', service_error_code='PolicyNotFound',
                        http_status_code=404, expected_params=p)
    st.add_client_error('describe_mount_targets', service_error_code='AccessDeniedException',
                        http_status_code=403, expected_params=p)
    st.add_client_error('describe_access_points', service_error_code='AccessDeniedException',
                        http_status_code=403, expected_params=p)
    with st:
        d = EfsDriver(_fs(), client)
        for c in ['_checkFileSystemPolicy', '_checkTLSRequired', '_checkComprehensiveSecurity',
                  '_checkMountTargetSecurityGroups', '_checkAccessPointsConfigured']:
            getattr(d, c)()
        st.assert_no_pending_responses()
    r = d.results
    assert r['FileSystemPolicy'] == [-1, 'No policy configured']
    assert r['TLSRequired'] == [-1, 'No policy configured']
    assert r['ComprehensiveSecurity'] == [-1, 'Missing: security groups, IAM policy, access points']
    assert r['MountTargetSecurityGroups'] == [-1, 'Error checking mount targets']
    assert r['AccessPointsConfigured'] == [-1, 'No access points configured']


def _original_driver_class():
    """EfsDriver as it was before the de-duplication (commit 5ff30a5)."""
    src = subprocess.run(['git', '-C', ROOT, 'show', '5ff30a5:services/efs/drivers/EfsDriver.py'],
                         capture_output=True, text=True, check=True).stdout
    mod = types.ModuleType('EfsDriver_orig')
    exec(compile(src, 'EfsDriver_orig.py', 'exec'), mod.__dict__)  # nosec B102 - repo's own file
    return mod.EfsDriver


SCENARIOS = {
    'all-good': dict(
        describe_lifecycle_configuration={'LifecyclePolicies': [{'TransitionToIA': 'AFTER_30_DAYS'}]},
        describe_file_system_policy={'FileSystemId': FS_ID, 'Policy': TLS_POLICY},
        describe_mount_targets={'MountTargets': [{'MountTargetId': 'm1', 'SecurityGroups': ['sg-1']}]},
        describe_access_points={'AccessPoints': [{'AccessPointId': 'a1'}]}),
    'no-tls-no-lifecycle': dict(
        describe_lifecycle_configuration={'LifecyclePolicies': []},
        describe_file_system_policy={'FileSystemId': FS_ID, 'Policy': '{"Statement":[]}'},
        describe_mount_targets={'MountTargets': []},
        describe_access_points={'AccessPoints': []}),
    'bad-json-policy': dict(
        describe_lifecycle_configuration={'LifecyclePolicies': []},
        describe_file_system_policy={'FileSystemId': FS_ID, 'Policy': 'not-json'},
        describe_mount_targets={'MountTargets': [{'MountTargetId': 'm1'}]},
        describe_access_points={'AccessPoints': [{'AccessPointId': 'a1'}]}),
    'policy-not-found': dict(
        describe_lifecycle_configuration={'LifecyclePolicies': []},
        describe_file_system_policy='PolicyNotFound',
        describe_mount_targets='AccessDenied',
        describe_access_points='AccessDenied'),
}


def _mocked_client(spec):
    client = _client()
    mocks = {}
    for op, val in spec.items():
        if isinstance(val, str):
            exc_cls = (client.exceptions.PolicyNotFound if val == 'PolicyNotFound'
                       else botocore.exceptions.ClientError)
            err = exc_cls({'Error': {'Code': val, 'Message': 'x'}}, op)
            m = mock.MagicMock(side_effect=err)
        else:
            m = mock.MagicMock(return_value=val)
        setattr(client, op, m)
        mocks[op] = m
    for op in ('describe_backup_policy', 'describe_replication_configurations'):
        m = mock.MagicMock(return_value={'BackupPolicy': {'Status': 'ENABLED'}, 'Replications': []})
        setattr(client, op, m)
        mocks[op] = m
    return client, mocks


def _all_checks(cls):
    return sorted(m for m in dir(cls) if m.startswith('_check'))


def test_results_identical_to_original_and_calls_once_under_threads():
    Orig = _original_driver_class()
    for name, spec in SCENARIOS.items():
        old_client, old_mocks = _mocked_client(spec)
        old = Orig(_fs(), old_client)
        for c in _all_checks(Orig):
            getattr(old, c)()

        new_client, new_mocks = _mocked_client(spec)
        new = EfsDriver(_fs(), new_client)
        # checks of one driver run concurrently in the real scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(lambda c: getattr(new, c)(), _all_checks(EfsDriver)))

        assert _all_checks(Orig) == _all_checks(EfsDriver)
        ## Lifecycle reporting was corrected after the de-duplication: the stray
        ## 'Lifecycle' key (no reporter entry) is gone and EnabledLifecycle always
        ## carries the result. Every other result is unchanged.
        oldR = {k: v for k, v in old.results.items() if k not in ('Lifecycle', 'EnabledLifecycle')}
        newR = {k: v for k, v in new.results.items() if k != 'EnabledLifecycle'}
        assert newR == oldR, name
        assert 'Lifecycle' not in new.results
        assert new.results['EnabledLifecycle'] == old.results.get('EnabledLifecycle', [1, 'Enabled']), name
        for op in MEMO_OPS:
            assert old_mocks[op].call_count >= 1, (name, op)
            assert new_mocks[op].call_count == 1, (name, op, new_mocks[op].call_count)
            new_mocks[op].assert_called_with(FileSystemId=FS_ID)
        # describe_file_system_policy was previously called by three checks
        assert old_mocks['describe_file_system_policy'].call_count == 3, name


def test_cache_is_per_file_system():
    client, mocks = _mocked_client(SCENARIOS['all-good'])
    for _ in range(2):
        d = EfsDriver(_fs(), client)
        d._checkFileSystemPolicy(); d._checkTLSRequired(); d._checkComprehensiveSecurity()
    assert mocks['describe_file_system_policy'].call_count == 2


def test_lifecycle_result_keys_all_have_reporter_entries():
    import json
    reporter = json.load(open(os.path.join(ROOT, 'services', 'efs', 'efs.reporter.json')))
    for policies, expected in (([{'TransitionToIA': 'AFTER_30_DAYS'}], [1, 'Enabled']), ([], [-1, 'Disabled'])):
        client, _ = _mocked_client({'describe_lifecycle_configuration': {'LifecyclePolicies': policies}})
        d = EfsDriver(_fs(), client)
        d._checkLifecycle_configuration()
        assert d.results == {'EnabledLifecycle': expected}
        assert set(d.results) <= set(reporter)


def test_lifecycle_unreadable_is_not_evaluable():
    client, _ = _mocked_client({'describe_lifecycle_configuration': 'AccessDeniedException'})
    d = EfsDriver(_fs(), client)
    d._checkLifecycle_configuration()
    assert d.results == {'EnabledLifecycle': [0, 'Unable to evaluate (AccessDeniedException)']}

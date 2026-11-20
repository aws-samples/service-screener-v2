"""Unit tests for FsxFileSystem.fsxAutomaticBackupDisabled branches the emulator flag/fix
test does not cover (Windows/ONTAP/OpenZFS shapes, Lustre scratch, S3-linked Lustre, missing
fields). The driver only consumes describe_file_systems output, so a real fsx client wrapped
in botocore Stubber supplies real-shaped responses."""
import os
import sys

import boto3
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.fsx.drivers.FsxFileSystem import FsxFileSystem  # noqa: E402

KEY = 'fsxAutomaticBackupDisabled'
CFG = {'WINDOWS': 'WindowsConfiguration', 'LUSTRE': 'LustreConfiguration',
       'ONTAP': 'OntapConfiguration', 'OPENZFS': 'OpenZFSConfiguration'}


def _client():
    return boto3.client('fsx', region_name='us-east-1', aws_access_key_id='x',
                        aws_secret_access_key='x')


def _evaluate(fsType, cfg, lifecycle='AVAILABLE'):
    client = _client()
    fs = {'FileSystemId': 'fs-0123456789abcdef0', 'FileSystemType': fsType, 'Lifecycle': lifecycle,
          CFG[fsType]: cfg}
    with Stubber(client) as st:
        st.add_response('describe_file_systems', {'FileSystems': [fs]})
        fs = client.describe_file_systems()['FileSystems'][0]
    d = FsxFileSystem(fs, client)
    d._checkFsxAutomaticBackupDisabled()
    return d.results[KEY][0]


def test_flag_fix_each_type():
    for t in ('WINDOWS', 'ONTAP', 'OPENZFS'):
        assert _evaluate(t, {'AutomaticBackupRetentionDays': 0}) == -1, t
        assert _evaluate(t, {'AutomaticBackupRetentionDays': 7}) == 1, t
    assert _evaluate('LUSTRE', {'DeploymentType': 'PERSISTENT_1', 'AutomaticBackupRetentionDays': 0}) == -1
    assert _evaluate('LUSTRE', {'DeploymentType': 'PERSISTENT_1', 'AutomaticBackupRetentionDays': 3}) == 1


def test_not_evaluable_cases():
    assert _evaluate('LUSTRE', {'DeploymentType': 'SCRATCH_2', 'AutomaticBackupRetentionDays': 0}) == 0
    assert _evaluate('LUSTRE', {'DeploymentType': 'PERSISTENT_1', 'AutomaticBackupRetentionDays': 0,
                                'DataRepositoryConfiguration': {'ImportPath': 's3://b'}}) == 0
    assert _evaluate('WINDOWS', {}) == 0
    assert _evaluate('WINDOWS', {'AutomaticBackupRetentionDays': 0}, lifecycle='DELETING') == 0


def test_lustre_data_repository_config_without_import_path_is_still_checked():
    """Only legacy ImportPath linking blocks backups; a DataRepositoryConfiguration block
    without ImportPath must not hide AutomaticBackupRetentionDays=0."""
    cfg = {'DeploymentType': 'PERSISTENT_1', 'AutomaticBackupRetentionDays': 0,
           'DataRepositoryConfiguration': {'Lifecycle': 'AVAILABLE', 'AutoImportPolicy': 'NONE'}}
    assert _evaluate('LUSTRE', cfg) == -1
    cfg['AutomaticBackupRetentionDays'] = 7
    assert _evaluate('LUSTRE', cfg) == 1

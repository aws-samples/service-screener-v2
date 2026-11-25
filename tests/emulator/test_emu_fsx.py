"""Flag -> fix -> re-run tests for services/fsx against the local AWS Emulator."""
import time

from tests.emulator.conftest import assertFlagFixCycle


def _waitAvailable(fsx, fid, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        fs = fsx.describe_file_systems(FileSystemIds=[fid])['FileSystems'][0]
        if fs['Lifecycle'] == 'AVAILABLE':
            return
        time.sleep(2)
    raise AssertionError(f'{fid} never became AVAILABLE')


def _network(ec2, uid):
    octet = int(uid[:2], 16) % 200 + 20
    vpc = ec2.create_vpc(CidrBlock=f'10.{octet}.0.0/16')['Vpc']['VpcId']
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock=f'10.{octet}.1.0/24')['Subnet']['SubnetId']
    return vpc, sub


def test_fsx_lustre_automatic_backup_disabled(emu, uid):
    fsx, ec2 = emu.client('fsx'), emu.client('ec2')
    vpc, sub = _network(ec2, uid)
    fid = None
    try:
        fid = fsx.create_file_system(
            FileSystemType='LUSTRE', StorageCapacity=1200, SubnetIds=[sub],
            Tags=[{'Key': 'Name', 'Value': f'ss-test-{uid}'}],
            LustreConfiguration={'DeploymentType': 'PERSISTENT_2', 'PerUnitStorageThroughput': 125,
                                 'AutomaticBackupRetentionDays': 7})['FileSystem']['FileSystemId']
        _waitAvailable(fsx, fid)

        def misconfigure():
            fsx.update_file_system(FileSystemId=fid, LustreConfiguration={'AutomaticBackupRetentionDays': 0})
            _waitAvailable(fsx, fid)

        def fix():
            fsx.update_file_system(FileSystemId=fid, LustreConfiguration={'AutomaticBackupRetentionDays': 7})
            _waitAvailable(fsx, fid)

        assertFlagFixCycle(emu, 'fsx', 'fsxAutomaticBackupDisabled', fid, misconfigure, fix)
    finally:
        if fid:
            try:
                fsx.delete_file_system(FileSystemId=fid)
            except Exception:
                pass
        for fn, kw in ((ec2.delete_subnet, {'SubnetId': sub}), (ec2.delete_vpc, {'VpcId': vpc})):
            try:
                fn(**kw)
            except Exception:
                pass

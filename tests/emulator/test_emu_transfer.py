"""Flag -> fix -> re-run tests for transfer.transferFamilyInsecure."""
from tests.emulator.conftest import assertFlagFixCycle


def test_transfer_outdated_security_policy(emu, uid):
    t = emu.client('transfer')
    sid = t.create_server(Protocols=['SFTP'], Tags=[{'Key': 'ss-test', 'Value': uid}])['ServerId']
    try:
        def misconfigure():
            t.update_server(ServerId=sid, SecurityPolicyName='TransferSecurityPolicy-2018-11')

        def fix():
            t.update_server(ServerId=sid, SecurityPolicyName='TransferSecurityPolicy-2024-01')

        assertFlagFixCycle(emu, 'transfer', 'transferFamilyInsecure', sid, misconfigure, fix)
    finally:
        t.delete_server(ServerId=sid)


def test_transfer_ftp_enabled(emu, uid):
    t = emu.client('transfer')
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.77.0.0/16')['Vpc']['VpcId']
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock='10.77.1.0/24')['Subnet']['SubnetId']
    sid = None
    try:
        ## FTP is only allowed on a VPC endpoint with a custom identity provider.
        sid = t.create_server(
            Protocols=['SFTP'], EndpointType='VPC',
            EndpointDetails={'VpcId': vpc, 'SubnetIds': [sub]},
            IdentityProviderType='AWS_LAMBDA',
            IdentityProviderDetails={'Function': f'arn:aws:lambda:us-east-1:000000000000:function:ss-idp-{uid}'},
            SecurityPolicyName='TransferSecurityPolicy-2024-01',
        )['ServerId']

        def misconfigure():
            t.update_server(ServerId=sid, Protocols=['SFTP', 'FTP'])

        def fix():
            t.update_server(ServerId=sid, Protocols=['SFTP'])

        assertFlagFixCycle(emu, 'transfer', 'transferFamilyInsecure', sid, misconfigure, fix)
    finally:
        if sid:
            t.delete_server(ServerId=sid)
        ec2.delete_subnet(SubnetId=sub)
        ec2.delete_vpc(VpcId=vpc)

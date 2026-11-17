"""DMS endpoint TLS check against the local AWS Emulator.

The emulator implements CreateEndpoint/DescribeEndpoints but ModifyEndpoint and
DeleteEndpoint are scaffolded-only (NotImplemented), so an endpoint cannot be
fixed in place or cleaned up. The "fix" here therefore follows the replace
remediation path: a replacement endpoint created with TLS is scanned and must
not be flagged, while the original stays flagged. The in-place
flag -> modify -> re-run cycle is covered by tests/test_stub_dms.py.
"""
from tests.emulator.conftest import runCheck

CHECK = 'dmsEndpointSslNone'


def _status(emu, name):
    st = runCheck(emu, 'dms', CHECK, name).statuses()
    st = {k: v for k, v in st.items() if k.endswith('::' + name)}
    assert st, f'no result for {name}'
    return list(st.values())[0]


def test_dms_endpoint_ssl_none_flag_fix(emu, uid):
    dms = emu.client('dms')
    bad, good = f'ss-dms-{uid}-plain', f'ss-dms-{uid}-tls'
    common = dict(EndpointType='source', EngineName='postgres', ServerName='db.example.internal',
                  Port=5432, Username='u', Password='p', DatabaseName='d')

    dms.create_endpoint(EndpointIdentifier=bad, SslMode='none', **common)
    assert _status(emu, bad) == -1

    dms.create_endpoint(EndpointIdentifier=good, SslMode='require', **common)
    assert _status(emu, good) == 1
    assert _status(emu, bad) == -1


def test_dms_kafka_plaintext_flag_fix(emu, uid):
    dms = emu.client('dms')
    bad, good = f'ss-dmsk-{uid}-plain', f'ss-dmsk-{uid}-tls'
    dms.create_endpoint(EndpointIdentifier=bad, EndpointType='target', EngineName='kafka',
                        KafkaSettings={'Broker': 'b.example.internal:9092', 'Topic': 't',
                                       'SecurityProtocol': 'plaintext'})
    assert _status(emu, bad) == -1
    dms.create_endpoint(EndpointIdentifier=good, EndpointType='target', EngineName='kafka',
                        KafkaSettings={'Broker': 'b.example.internal:9094', 'Topic': 't',
                                       'SecurityProtocol': 'ssl-encryption'})
    assert _status(emu, good) == 1


def test_dms_s3_endpoint_not_flagged(emu, uid):
    import json
    iam, dms = emu.client('iam'), emu.client('dms')
    role = f'ss-dms-s3-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
        'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                                'Principal': {'Service': 'dms.amazonaws.com'}}]}))['Role']['Arn']
    try:
        name = f'ss-dmss3-{uid}'
        dms.create_endpoint(EndpointIdentifier=name, EndpointType='target', EngineName='s3',
                            S3Settings={'BucketName': f'ss-{uid}', 'ServiceAccessRoleArn': arn})
        assert _status(emu, name) == 0
    finally:
        iam.delete_role(RoleName=role)

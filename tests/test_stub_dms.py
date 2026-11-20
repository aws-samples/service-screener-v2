"""Stubber flag -> fix -> re-run test for dms.dmsEndpointSslNone.

The AWS Emulator does not implement ModifyEndpoint, so the in-place fix
(SslMode none -> require) cannot be exercised there. This test drives the Dms
service and DmsEndpoint driver with a real boto3 DMS client wrapped by
botocore.stub.Stubber, using real DescribeEndpoints response shapes.
"""
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.dms.drivers.DmsEndpoint import DmsEndpoint  # noqa: E402

ARN = 'arn:aws:dms:us-east-1:111122223333:endpoint:ABCDEFGHIJKLMNOP'


def _client():
    return boto3.client('dms', region_name='us-east-1', aws_access_key_id='x',
                        aws_secret_access_key='x')


def _ep(**kw):
    base = {'EndpointIdentifier': 'src-pg', 'EndpointType': 'SOURCE', 'EngineName': 'postgres',
            'EndpointArn': ARN, 'ServerName': 'db.example.internal', 'Port': 5432,
            'Status': 'active'}
    base.update(kw)
    return base


def _evaluate(client, stub, endpoint):
    stub.add_response('describe_endpoints', {'Endpoints': [endpoint]}, {})
    ep = client.describe_endpoints()['Endpoints'][0]
    d = DmsEndpoint(ep, client)
    d._checkDmsEndpointSslNone()
    return d.results['dmsEndpointSslNone'][0]


def _cycle(bad, good):
    client = _client()
    with Stubber(client) as stub:
        assert _evaluate(client, stub, bad) == -1
        assert _evaluate(client, stub, good) != -1
        stub.assert_no_pending_responses()


def test_sslmode_none_then_require():
    _cycle(_ep(SslMode='none'), _ep(SslMode='require'))


@pytest.mark.parametrize('engine', ['mysql', 'oracle', 'sqlserver', 'mongodb', 'docdb'])
def test_sslmode_engines(engine):
    _cycle(_ep(EngineName=engine, SslMode='none'), _ep(EngineName=engine, SslMode='verify-full'))


def test_kafka_plaintext_then_ssl():
    _cycle(_ep(EngineName='kafka', SslMode='none',
               KafkaSettings={'Broker': 'b:9092', 'SecurityProtocol': 'plaintext'}),
           _ep(EngineName='kafka', SslMode='none',
               KafkaSettings={'Broker': 'b:9094', 'SecurityProtocol': 'sasl-ssl'}))


def test_redis_plaintext_then_ssl():
    _cycle(_ep(EngineName='redis', SslMode='none',
               RedisSettings={'ServerName': 'r', 'Port': 6379, 'SslSecurityProtocol': 'plaintext'}),
           _ep(EngineName='redis', SslMode='none',
               RedisSettings={'ServerName': 'r', 'Port': 6379, 'SslSecurityProtocol': 'ssl-encryption'}))


@pytest.mark.parametrize('engine', ['s3', 'dynamodb', 'kinesis', 'redshift', 'neptune', 'db2-zos', 'newengine'])
def test_not_applicable_or_unknown_is_info(engine):
    client = _client()
    with Stubber(client) as stub:
        assert _evaluate(client, stub, _ep(EngineName=engine, SslMode='none')) == 0


def test_kafka_missing_protocol_is_plaintext_fail():
    # A Kafka endpoint with a Broker but no SecurityProtocol uses the plaintext default.
    client = _client()
    with Stubber(client) as stub:
        assert _evaluate(client, stub, _ep(EngineName='kafka', KafkaSettings={'Broker': 'b:9092'})) == -1


def test_kafka_settings_missing_is_info():
    client = _client()
    with Stubber(client) as stub:
        assert _evaluate(client, stub, _ep(EngineName='kafka')) == 0

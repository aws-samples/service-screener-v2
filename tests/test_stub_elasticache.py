"""Stubber flag -> fix -> re-run test for elasticache.EncInTransitAndRest.

Backlog item elasticacheAtRestSplit (tier 3) proposed splitting at-rest encryption into
its own key. It is recorded as covered-by-existing: EncInTransitAndRest already flags a
cluster when either TransitEncryptionEnabled or AtRestEncryptionEnabled is not True and
names which one in the message. This test pins that behaviour, including the at-rest-only
case the split was meant to surface.

Stubber is used instead of the emulator because at-rest encryption is immutable on an
existing ElastiCache cluster (the only "fix" is recreate + wait for 'available'), so the
flag/fix states are driven through real describe_cache_clusters response shapes.
"""
import boto3
from botocore.stub import Stubber

from services.elasticache.drivers.ElasticacheRedis import ElasticacheRedis


def _cluster(client, transit, atRest):
    stub = Stubber(client)
    stub.add_response('describe_cache_clusters', {'CacheClusters': [{
        'CacheClusterId': 'ss-test-enc',
        'ARN': 'arn:aws:elasticache:us-east-1:123456789012:cluster:ss-test-enc',
        'Engine': 'redis', 'EngineVersion': '7.1', 'CacheNodeType': 'cache.r7g.large',
        'CacheClusterStatus': 'available',
        'TransitEncryptionEnabled': transit, 'AtRestEncryptionEnabled': atRest,
    }]})
    with stub:
        return client.describe_cache_clusters(ShowCacheNodeInfo=True)['CacheClusters'][0]


def _evaluate(client, cluster):
    obj = ElasticacheRedis(cluster, client, {})
    obj._checkEncryption()
    return obj.results.get('EncInTransitAndRest')


def test_enc_at_rest_only_missing_flag_fix_cycle():
    client = boto3.client('elasticache', region_name='us-east-1',
                          aws_access_key_id='x', aws_secret_access_key='x')
    res = _evaluate(client, _cluster(client, True, False))
    assert res is not None and res[0] == -1 and 'at rest' in res[1] and 'in transit' not in res[1]

    res = _evaluate(client, _cluster(client, True, True))
    assert res is None or res[0] != -1


def test_enc_in_transit_missing_flag_fix_cycle():
    client = boto3.client('elasticache', region_name='us-east-1',
                          aws_access_key_id='x', aws_secret_access_key='x')
    res = _evaluate(client, _cluster(client, False, True))
    assert res is not None and res[0] == -1 and 'in transit' in res[1]

    res = _evaluate(client, _cluster(client, True, True))
    assert res is None or res[0] != -1

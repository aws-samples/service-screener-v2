"""Emulator flag -> fix -> re-run tests for elasticache.EncInTransitAndRest.

Backlog item elasticacheAtRestSplit is covered by EncInTransitAndRest, which flags a cluster
when in-transit or at-rest encryption is missing and names which one. These tests run the
full Elasticache.advise() path with a node-based Memcached cluster present in the same region.
That pins the fix for the missing ElasticacheMemcached import, which used to raise NameError
and hide every cluster-level finding in the region, including Redis/Valkey encryption.
"""
import time

from tests.emulator.conftest import assertFlagFixCycle, runCheck


def _waitAvailable(ec, ids, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        cc = {c['CacheClusterId']: c.get('CacheClusterStatus')
              for c in ec.describe_cache_clusters()['CacheClusters']}
        if all(cc.get(i) == 'available' for i in ids):
            return
        time.sleep(2)
    raise AssertionError(f'clusters not available: {ids}')


def _waitGone(ec, rgId, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        ids = [g['ReplicationGroupId'] for g in ec.describe_replication_groups()['ReplicationGroups']]
        if rgId not in ids:
            return
        time.sleep(2)


def test_elasticache_encryption_with_memcached_present(emu, uid):
    ec = emu.client('elasticache')
    mc = f'ss-mc-{uid}'
    rg = f'ss-rg-{uid}'
    member = f'{rg}-001'
    ec.create_cache_cluster(CacheClusterId=mc, Engine='memcached',
                            CacheNodeType='cache.t3.micro', NumCacheNodes=1)
    try:
        def misconfigure():
            ec.create_replication_group(ReplicationGroupId=rg, ReplicationGroupDescription='ss test',
                                        Engine='redis', CacheNodeType='cache.t3.micro',
                                        NumCacheClusters=1, AtRestEncryptionEnabled=False,
                                        TransitEncryptionEnabled=False)
            _waitAvailable(ec, [mc, member])

        def fix():
            # at-rest encryption is immutable: recreate the group encrypted
            ec.delete_replication_group(ReplicationGroupId=rg)
            _waitGone(ec, rg)
            ec.create_replication_group(ReplicationGroupId=rg, ReplicationGroupDescription='ss test',
                                        Engine='redis', CacheNodeType='cache.t3.micro',
                                        NumCacheClusters=1, AtRestEncryptionEnabled=True,
                                        TransitEncryptionEnabled=True)
            _waitAvailable(ec, [mc, member])

        assertFlagFixCycle(emu, 'elasticache', 'EncInTransitAndRest', f'cluster:{member}', misconfigure, fix)

        # The Memcached cluster itself is evaluated (no NameError) and flagged with an
        # engine-aware message, since node-based Memcached cannot encrypt at rest.
        res = runCheck(emu, 'elasticache', 'EncInTransitAndRest', f'cluster:{mc}')
        statuses = res.statuses()
        assert statuses and all(s == -1 for s in statuses.values()), (statuses, res.errors[:1])
    finally:
        for fn in (lambda: ec.delete_replication_group(ReplicationGroupId=rg),
                   lambda: ec.delete_cache_cluster(CacheClusterId=mc)):
            try:
                fn()
            except Exception:
                pass

"""Flag -> fix -> re-run tests for the WAFS2027 S3 / Macie / Glacier checks
that the AWS Emulator can drive end to end.

Checks whose APIs the emulator does not implement (macie2
describe_organization_configuration / describe_buckets, s3control access
points, glacier get_vault_access_policy) or cannot produce realistic data for
(Macie only creates *sample* sensitive-data findings, which the check
deliberately ignores) are covered in tests/test_stub_s3_wafs2027.py.
"""
import pytest
from botocore.exceptions import ClientError

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ROLE = 'arn:aws:iam::000000000000:role/ss-test-replication'


def _macieEnabled(macie):
    try:
        return macie.get_macie_session().get('status') == 'ENABLED'
    except ClientError:
        return False


@pytest.fixture
def macie(emu):
    """Macie enabled for the test; original enablement and automated-discovery
    status restored afterwards."""
    m = emu.client('macie2')
    wasEnabled = _macieEnabled(m)
    origAdc = m.get_automated_discovery_configuration().get('status') if wasEnabled else None
    if not wasEnabled:
        m.enable_macie()
    try:
        yield m
    finally:
        if wasEnabled:
            m.update_automated_discovery_configuration(status=origAdc or 'DISABLED')
        else:
            m.disable_macie()


def test_macie_automated_discovery_disabled(emu, macie):
    assertFlagFixCycle(
        emu, 's3', 'macieAutomatedDiscoveryDisabled', 'Macie',
        lambda: macie.update_automated_discovery_configuration(status='DISABLED'),
        lambda: macie.update_automated_discovery_configuration(status='ENABLED'))


def test_macie_checks_not_evaluable_when_macie_disabled(emu):
    m = emu.client('macie2')
    if _macieEnabled(m):
        pytest.skip('Macie already enabled in emulator')
    for key in ('macieAutomatedDiscoveryDisabled', 'macieSensitiveDataFindingsOpen', 'macieOrgAutoEnableOff'):
        res = runCheck(emu, 's3', key, 'Macie')
        assert res.statuses() == {'Macie': 0}, (key, res.results)


def test_macie_sample_findings_are_not_flagged(emu, macie):
    """Emulator-generated findings are always samples (sample=true); the check
    must ignore them. Real (non-sample) findings are covered by the Stubber test."""
    macie.create_sample_findings(findingTypes=['SensitiveData:S3Object/Personal'])
    res = runCheck(emu, 's3', 'macieSensitiveDataFindingsOpen', 'Macie')
    assert res.statuses() == {'Macie': 1}, res.results


def test_macie_org_auto_enable_not_implemented_is_info(emu, macie):
    res = runCheck(emu, 's3', 'macieOrgAutoEnableOff', 'Macie')
    assert res.statuses() == {'Macie': 0}, res.results


def test_s3_replication_without_metrics(emu, uid):
    s3 = emu.client('s3')
    src, dst = f'ss-test-rsrc-{uid}', f'ss-test-rdst-{uid}'
    for b in (src, dst):
        s3.create_bucket(Bucket=b)
        s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={'Status': 'Enabled'})

    def rule(withMetrics):
        dest = {'Bucket': f'arn:aws:s3:::{dst}'}
        if withMetrics:
            dest['Metrics'] = {'Status': 'Enabled', 'EventThreshold': {'Minutes': 15}}
            dest['ReplicationTime'] = {'Status': 'Enabled', 'Time': {'Minutes': 15}}
        return {'ReplicationConfiguration': {'Role': ROLE, 'Rules': [{
            'ID': 'r1', 'Priority': 1, 'Status': 'Enabled', 'Filter': {},
            'DeleteMarkerReplication': {'Status': 'Disabled'}, 'Destination': dest}]}}

    try:
        assertFlagFixCycle(
            emu, 's3', 's3ReplicationNoMetrics', src,
            lambda: s3.put_bucket_replication(Bucket=src, **rule(False)),
            lambda: s3.put_bucket_replication(Bucket=src, **rule(True)))
        # Not applicable without replication: no result at all (never a false PASS/FAIL).
        assert runCheck(emu, 's3', 's3ReplicationNoMetrics', dst).statuses() == {}
    finally:
        try:
            s3.delete_bucket_replication(Bucket=src)
        except ClientError:
            pass
        for b in (src, dst):
            s3.delete_bucket(Bucket=b)


def test_s3_versioned_no_noncurrent_expiry(emu, uid):
    s3 = emu.client('s3')
    bucket = f'ss-test-ncv-{uid}'
    s3.create_bucket(Bucket=bucket)
    try:
        def misconfigure():
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={'Status': 'Enabled'})
            # A lifecycle rule that does not expire noncurrent versions must still be flagged.
            s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={'Rules': [
                {'ID': 'cur', 'Status': 'Enabled', 'Filter': {}, 'Expiration': {'Days': 365}}]})

        def fix():
            s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={'Rules': [
                {'ID': 'nc', 'Status': 'Enabled', 'Filter': {},
                 'NoncurrentVersionExpiration': {'NoncurrentDays': 90}}]})

        assertFlagFixCycle(emu, 's3', 's3VersionedNoNoncurrentExpiry', bucket, misconfigure, fix)

        # Only a prefix-scoped expiry rule: INFO, not a PASS and not a finding.
        s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={'Rules': [
            {'ID': 'nc', 'Status': 'Enabled', 'Filter': {'Prefix': 'logs/'},
             'NoncurrentVersionExpiration': {'NoncurrentDays': 90}}]})
        assert runCheck(emu, 's3', 's3VersionedNoNoncurrentExpiry', bucket).statuses() == {f'Bucket::{bucket}': 0}

        # No lifecycle configuration at all on a versioned bucket is flagged.
        s3.delete_bucket_lifecycle(Bucket=bucket)
        assert runCheck(emu, 's3', 's3VersionedNoNoncurrentExpiry', bucket).statuses() == {f'Bucket::{bucket}': -1}
    finally:
        try:
            s3.delete_bucket_lifecycle(Bucket=bucket)
        except ClientError:
            pass
        s3.delete_bucket(Bucket=bucket)


def test_s3_unversioned_bucket_not_applicable(emu, uid):
    s3 = emu.client('s3')
    bucket = f'ss-test-nov-{uid}'
    s3.create_bucket(Bucket=bucket)
    try:
        assert runCheck(emu, 's3', 's3VersionedNoNoncurrentExpiry', bucket).statuses() == {}
    finally:
        s3.delete_bucket(Bucket=bucket)


def test_glacier_vault_policy_unreadable_is_info(emu, uid):
    """The emulator lists vaults but does not implement get_vault_access_policy;
    the check must record INFO (0), never PASS. Flag/fix is in the Stubber test."""
    g = emu.client('glacier')
    vault = f'ss-test-vault-{uid}'
    g.create_vault(vaultName=vault)
    try:
        res = runCheck(emu, 's3', 'glacierVaultPolicyPublic', vault)
        assert res.statuses() == {f'GlacierVault::{vault}': 0}, res.results
    finally:
        g.delete_vault(vaultName=vault)


def test_account_level_results_are_reported(emu):
    """Regression: S3.advise() used to reset its result dict after the account
    scan, dropping Account::Control (S3AccountPublicAccessBlock, StorageLens)."""
    res = runCheck(emu, 's3', 'S3AccountPublicAccessBlock', 'Account::Control')
    # S3 Control cannot reach the emulator (account-id host prefix): INFO, not FAIL.
    assert res.statuses() == {'Account::Control': 0}, res.results

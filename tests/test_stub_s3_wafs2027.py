"""Flag -> fix -> re-run tests (botocore Stubber) for WAFS2027 S3 checks the
AWS Emulator cannot drive:

- macieOrgAutoEnableOff: macie2.describe_organization_configuration is
  NotImplemented in the emulator, and it needs a Macie delegated-admin account.
- macieSensitiveDataFindingsOpen: the emulator only creates *sample* findings
  (which the check correctly ignores) and get_finding_statistics is
  NotImplemented, so real-finding flag/fix needs real response shapes.
- macieBucketsNotMonitored: macie2.describe_buckets is NotImplemented.
- s3AccessPointPublic: S3 Control puts the account id in the host name
  ({AccountId}.<endpoint>), which cannot reach the emulator's IP endpoint.
- glacierVaultPolicyPublic: glacier get/set_vault_access_policy are
  NotImplemented.

Each test drives the real driver class with real boto3 clients wrapped by
botocore.stub.Stubber (so request/response shapes are validated against the
service model). Clients use dummy credentials and a loopback endpoint; the
Stubber intercepts every call, so nothing is sent anywhere.
"""
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Config import Config  # noqa: E402
from services.s3.drivers.S3Macie import S3Macie  # noqa: E402
from services.s3.drivers.S3Bucket import S3Bucket  # noqa: E402
from services.s3.drivers.S3AccessPoint import S3AccessPoint  # noqa: E402
from services.s3.drivers.S3GlacierVault import S3GlacierVault  # noqa: E402
from services.s3.S3 import S3  # noqa: E402

# Evaluator.__del__ writes to __fork/error.txt, which only exists in a full scan run.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

ACCOUNT = '111122223333'
ALL_ON = {k: True for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')}
ALL_OFF = {k: False for k in ALL_ON}
OPEN_CRITERIA = {'criterion': {'category': {'eq': ['CLASSIFICATION']},
                               'archived': {'eq': ['false']},
                               'sample': {'eq': ['false']}}}


@pytest.fixture(autouse=True)
def _config():
    Config.init()
    Config.set('stsInfo', {'Account': ACCOUNT})
    yield
    Config.init()


def _client(svc):
    return boto3.client(svc, region_name='us-east-1', endpoint_url='https://127.0.0.1:1',
                        aws_access_key_id='testing', aws_secret_access_key='testing',
                        aws_session_token='testing')


def _run(driverFactory, method, key, stubSetup):
    """Build a fresh driver, stub its calls, run one check, return its result."""
    clients, obj = driverFactory()
    stubbers = {name: Stubber(c) for name, c in clients.items()}
    stubSetup(stubbers)
    for s in stubbers.values():
        s.activate()
    try:
        getattr(obj, method)()
    finally:
        for s in stubbers.values():
            s.deactivate()
    for s in stubbers.values():
        s.assert_no_pending_responses()
    return obj.results.get(key)


def _session(st, status='ENABLED'):
    st.add_response('get_macie_session', {'status': status})


# --------------------------------------------------------------------------- #
# Macie
# --------------------------------------------------------------------------- #
def _macie():
    c = _client('macie2')
    return {'macie2': c}, S3Macie(c)


def test_macie_org_auto_enable_flag_fix():
    def bad(s):
        _session(s['macie2'])
        s['macie2'].add_response('describe_organization_configuration',
                                 {'autoEnable': False, 'maxAccountLimitReached': False})

    def good(s):
        _session(s['macie2'])
        s['macie2'].add_response('describe_organization_configuration',
                                 {'autoEnable': True, 'maxAccountLimitReached': False})

    key = 'macieOrgAutoEnableOff'
    assert _run(_macie, '_checkMacieOrgAutoEnable', key, bad)[0] == -1
    assert _run(_macie, '_checkMacieOrgAutoEnable', key, good)[0] == 1


def test_macie_org_auto_enable_member_account_not_evaluable():
    def member(s):
        _session(s['macie2'])
        s['macie2'].add_client_error('describe_organization_configuration', 'AccessDeniedException',
                                     'The request was denied because you are not the Macie administrator')

    assert _run(_macie, '_checkMacieOrgAutoEnable', 'macieOrgAutoEnableOff', member) == \
        [0, 'Not evaluable from member account']


def test_macie_org_auto_enable_macie_disabled_not_evaluable():
    def disabled(s):
        s['macie2'].add_client_error('get_macie_session', 'AccessDeniedException', 'Macie is not enabled.')

    assert _run(_macie, '_checkMacieOrgAutoEnable', 'macieOrgAutoEnableOff', disabled)[0] == 0


def test_macie_sensitive_findings_flag_fix():
    def bad(s):
        _session(s['macie2'])
        s['macie2'].add_response('list_findings', {'findingIds': ['f1']},
                                 {'findingCriteria': OPEN_CRITERIA, 'maxResults': 1})
        s['macie2'].add_response('get_finding_statistics', {'countsByGroup': [
            {'groupKey': 'SensitiveData:S3Object/Personal', 'count': 3},
            {'groupKey': 'SensitiveData:S3Object/Credentials', 'count': 1}]},
            {'findingCriteria': OPEN_CRITERIA, 'groupBy': 'type'})

    def good(s):
        _session(s['macie2'])
        s['macie2'].add_response('list_findings', {'findingIds': []},
                                 {'findingCriteria': OPEN_CRITERIA, 'maxResults': 1})

    key = 'macieSensitiveDataFindingsOpen'
    flagged = _run(_macie, '_checkMacieSensitiveDataFindings', key, bad)
    assert flagged[0] == -1 and '4 finding(s)' in flagged[1]
    assert _run(_macie, '_checkMacieSensitiveDataFindings', key, good)[0] == 1


def test_macie_sensitive_findings_statistics_failure_still_flags():
    def bad(s):
        _session(s['macie2'])
        s['macie2'].add_response('list_findings', {'findingIds': ['f1']})
        s['macie2'].add_client_error('get_finding_statistics', 'AccessDeniedException', 'denied')

    assert _run(_macie, '_checkMacieSensitiveDataFindings', 'macieSensitiveDataFindingsOpen', bad)[0] == -1


def test_macie_sensitive_findings_list_denied_not_evaluable():
    def denied(s):
        _session(s['macie2'])
        s['macie2'].add_client_error('list_findings', 'AccessDeniedException', 'User is not authorized')

    assert _run(_macie, '_checkMacieSensitiveDataFindings', 'macieSensitiveDataFindingsOpen', denied) == \
        [0, 'Unable to evaluate (AccessDeniedException)']


def test_macie_automated_discovery_paused_session_is_info():
    assert _run(_macie, '_checkMacieAutomatedDiscovery', 'macieAutomatedDiscoveryDisabled',
                lambda s: _session(s['macie2'], 'PAUSED'))[0] == 0


def test_macie_automated_discovery_flag_fix_stub():
    def bad(s):
        _session(s['macie2'])
        s['macie2'].add_response('get_automated_discovery_configuration', {'status': 'DISABLED'})

    def good(s):
        _session(s['macie2'])
        s['macie2'].add_response('get_automated_discovery_configuration', {'status': 'ENABLED'})

    key = 'macieAutomatedDiscoveryDisabled'
    assert _run(_macie, '_checkMacieAutomatedDiscovery', key, bad)[0] == -1
    assert _run(_macie, '_checkMacieAutomatedDiscovery', key, good)[0] == 1


# --------------------------------------------------------------------------- #
# macieBucketsNotMonitored (S3Bucket + macie2.describe_buckets)
# --------------------------------------------------------------------------- #
def _bucket(name='my-bucket'):
    def factory():
        Config.set('s3::macieBucketInventory::us-east-1', None)
        s3, m = _client('s3'), _client('macie2')
        return {'s3': s3, 'macie2': m}, S3Bucket(name, s3, m)
    return factory


def _describeBuckets(s, *buckets):
    s['macie2'].add_response('describe_buckets', {'buckets': list(buckets)})


def test_macie_bucket_not_monitored_flag_fix():
    key = 'macieBucketsNotMonitored'
    bad = lambda s: _describeBuckets(s, {  # noqa: E731
        'bucketName': 'my-bucket', 'automatedDiscoveryMonitoringStatus': 'NOT_MONITORED',
        'jobDetails': {'isDefinedInJob': 'FALSE', 'isMonitoredByJob': 'FALSE'}})
    good = lambda s: _describeBuckets(s, {  # noqa: E731
        'bucketName': 'my-bucket', 'automatedDiscoveryMonitoringStatus': 'MONITORED',
        'jobDetails': {'isDefinedInJob': 'FALSE', 'isMonitoredByJob': 'FALSE'}})
    assert _run(_bucket(), '_checkMacieBucketMonitored', key, bad)[0] == -1
    assert _run(_bucket(), '_checkMacieBucketMonitored', key, good)[0] == 1


def test_macie_bucket_recurring_job_counts_as_monitored_one_time_does_not():
    key = 'macieBucketsNotMonitored'
    recurring = lambda s: _describeBuckets(s, {  # noqa: E731
        'bucketName': 'my-bucket', 'automatedDiscoveryMonitoringStatus': 'NOT_MONITORED',
        'jobDetails': {'isDefinedInJob': 'TRUE', 'isMonitoredByJob': 'TRUE'}})
    oneTime = lambda s: _describeBuckets(s, {  # noqa: E731
        'bucketName': 'my-bucket', 'automatedDiscoveryMonitoringStatus': 'NOT_MONITORED',
        'jobDetails': {'isDefinedInJob': 'TRUE', 'isMonitoredByJob': 'FALSE'}})
    assert _run(_bucket(), '_checkMacieBucketMonitored', key, recurring)[0] == 1
    assert _run(_bucket(), '_checkMacieBucketMonitored', key, oneTime)[0] == -1


def test_macie_bucket_inventory_paginated_and_missing_bucket_is_info():
    def pages(s):
        s['macie2'].add_response('describe_buckets', {'buckets': [{'bucketName': 'other'}], 'nextToken': 't'})
        s['macie2'].add_response('describe_buckets', {'buckets': [{'bucketName': 'my-bucket',
                                 'automatedDiscoveryMonitoringStatus': 'MONITORED'}]}, {'nextToken': 't'})
    assert _run(_bucket(), '_checkMacieBucketMonitored', 'macieBucketsNotMonitored', pages)[0] == 1
    assert _run(_bucket('absent'), '_checkMacieBucketMonitored', 'macieBucketsNotMonitored',
                lambda s: _describeBuckets(s, {'bucketName': 'other'}))[0] == 0


def test_macie_bucket_macie_disabled_not_evaluable():
    def disabled(s):
        s['macie2'].add_client_error('describe_buckets', 'AccessDeniedException', 'Macie is not enabled.')
    assert _run(_bucket(), '_checkMacieBucketMonitored', 'macieBucketsNotMonitored', disabled) == \
        [0, 'Macie not enabled in this Region']


# --------------------------------------------------------------------------- #
# s3AccessPointPublic (s3control)
# --------------------------------------------------------------------------- #
def _ap(name='my-ap', listError=None):
    def factory():
        # Account-level BPA is cached per scan; start each run with a cold cache.
        Config.retrieveAllCache().pop(f's3::accountBpaAllOn::{ACCOUNT}', None)
        c = _client('s3control')
        return {'s3control': c}, S3AccessPoint(name, c, ACCOUNT, listError)
    return factory


def _apResponses(s, isPublic, bpa, accountBpa=None, noPolicy=False):
    p = {'AccountId': ACCOUNT, 'Name': 'my-ap'}
    if noPolicy:
        s['s3control'].add_client_error('get_access_point_policy_status', 'NoSuchAccessPointPolicy', 'none', 404, None, p)
    else:
        s['s3control'].add_response('get_access_point_policy_status', {'PolicyStatus': {'IsPublic': isPublic}}, p)
    s['s3control'].add_response('get_access_point', {
        'Name': 'my-ap', 'Bucket': 'b', 'NetworkOrigin': 'Internet',
        'PublicAccessBlockConfiguration': bpa}, p)
    if accountBpa == 'missing':
        s['s3control'].add_client_error('get_public_access_block', 'NoSuchPublicAccessBlockConfiguration',
                                        'none', 404, None, {'AccountId': ACCOUNT})
    elif accountBpa is not None:
        s['s3control'].add_response('get_public_access_block',
                                    {'PublicAccessBlockConfiguration': accountBpa}, {'AccountId': ACCOUNT})


def test_access_point_public_policy_flag_fix():
    key = 's3AccessPointPublic'
    flagged = _run(_ap(), '_checkAccessPointPublic', key,
                   lambda s: _apResponses(s, True, ALL_ON, accountBpa='missing'))
    assert flagged[0] == -1 and 'policy is public' in flagged[1]
    assert _run(_ap(), '_checkAccessPointPublic', key,
                lambda s: _apResponses(s, False, ALL_ON, noPolicy=True))[0] == 1


def test_access_point_bpa_off_flag_and_account_bpa_mitigates():
    key = 's3AccessPointPublic'
    partial = dict(ALL_ON, RestrictPublicBuckets=False)
    assert _run(_ap(), '_checkAccessPointPublic', key,
                lambda s: _apResponses(s, False, ALL_OFF, accountBpa=partial))[0] == -1
    # Fix: account-level Block Public Access fully on overrides access point settings.
    assert _run(_ap(), '_checkAccessPointPublic', key,
                lambda s: _apResponses(s, False, ALL_OFF, accountBpa=ALL_ON))[0] == 1


def test_access_point_unreadable_is_info_and_list_error_is_info():
    def denied(s):
        p = {'AccountId': ACCOUNT, 'Name': 'my-ap'}
        s['s3control'].add_client_error('get_access_point_policy_status', 'AccessDenied', 'denied', 403, None, p)
        s['s3control'].add_client_error('get_access_point', 'AccessDenied', 'denied', 403, None, p)
    assert _run(_ap(), '_checkAccessPointPublic', 's3AccessPointPublic', denied)[0] == 0
    assert _run(_ap('AccessPoints-us-east-1', 'AccessDenied'), '_checkAccessPointPublic',
                's3AccessPointPublic', lambda s: None) == [0, 'Unable to evaluate (AccessDenied)']


def test_s3_service_lists_access_points_with_pagination_and_reports_list_errors():
    serv = S3.__new__(S3)
    serv.region, serv.tags = 'us-east-1', None
    serv.s3Control = _client('s3control')
    with Stubber(serv.s3Control) as st:
        st.add_response('list_access_points', {'AccessPointList': [
            {'Name': 'ap-1', 'NetworkOrigin': 'Internet', 'Bucket': 'b'}], 'NextToken': 'n'}, {'AccountId': ACCOUNT})
        st.add_response('list_access_points', {'AccessPointList': [
            {'Name': 'ap-2', 'NetworkOrigin': 'VPC', 'Bucket': 'b'}]}, {'AccountId': ACCOUNT, 'NextToken': 'n'})
        assert serv.getAccessPoints() == [('ap-1', None), ('ap-2', None)]
        st.add_client_error('list_access_points', 'AccessDenied', 'denied', 403)
        assert serv.getAccessPoints() == [('AccessPoints-us-east-1', 'AccessDenied')]


# --------------------------------------------------------------------------- #
# glacierVaultPolicyPublic
# --------------------------------------------------------------------------- #
def _vault():
    c = _client('glacier')
    return {'glacier': c}, S3GlacierVault('v1', c)


def _vaultPolicy(s, stmt):
    s['glacier'].add_response('get_vault_access_policy', {'policy': {'Policy': json.dumps(
        {'Version': '2012-10-17', 'Statement': [stmt]})}}, {'vaultName': 'v1'})


PUBLIC_STMT = {'Effect': 'Allow', 'Principal': '*', 'Action': 'glacier:InitiateJob',
               'Resource': 'arn:aws:glacier:us-east-1:111122223333:vaults/v1'}


def test_glacier_vault_policy_public_flag_fix():
    key = 'glacierVaultPolicyPublic'
    assert _run(_vault, '_checkVaultPolicyPublic', key, lambda s: _vaultPolicy(s, PUBLIC_STMT))[0] == -1
    fixed = dict(PUBLIC_STMT, Principal={'AWS': f'arn:aws:iam::{ACCOUNT}:root'})
    assert _run(_vault, '_checkVaultPolicyPublic', key, lambda s: _vaultPolicy(s, fixed))[0] == 1
    scoped = dict(PUBLIC_STMT, Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-abc123'}})
    assert _run(_vault, '_checkVaultPolicyPublic', key, lambda s: _vaultPolicy(s, scoped))[0] == 1


def test_glacier_vault_no_policy_passes_and_denied_is_info():
    key = 'glacierVaultPolicyPublic'
    assert _run(_vault, '_checkVaultPolicyPublic', key, lambda s: s['glacier'].add_client_error(
        'get_vault_access_policy', 'ResourceNotFoundException', 'No vault access policy', 404))[0] == 1
    assert _run(_vault, '_checkVaultPolicyPublic', key, lambda s: s['glacier'].add_client_error(
        'get_vault_access_policy', 'AccessDeniedException', 'denied', 403)) == \
        [0, 'Unable to evaluate (AccessDeniedException)']


# --------------------------------------------------------------------------- #
# S3AccountPublicAccessBlock / StorageLens: API errors are INFO, not FAIL.
# (These account-level results were previously dropped from the report by
# S3.advise(); now that they are reported, an unreadable setting must not be
# shown as a finding.)
# --------------------------------------------------------------------------- #
from services.s3.drivers.S3Control import S3Control  # noqa: E402


def _control():
    c = _client('s3control')
    return {'s3control': c}, S3Control(c)


def test_account_bpa_flag_fix_and_denied_is_info():
    key = 'S3AccountPublicAccessBlock'
    run = lambda setup: _run(_control, '_checkAccountPublicAccessBlock', key, setup)  # noqa: E731
    assert run(lambda s: s['s3control'].add_client_error(
        'get_public_access_block', 'NoSuchPublicAccessBlockConfiguration', 'none', 404))[0] == -1
    assert run(lambda s: s['s3control'].add_response(
        'get_public_access_block', {'PublicAccessBlockConfiguration': dict(ALL_ON, BlockPublicAcls=False)}))[0] == -1
    assert run(lambda s: s['s3control'].add_response(
        'get_public_access_block', {'PublicAccessBlockConfiguration': ALL_ON}))[0] == 1
    assert run(lambda s: s['s3control'].add_client_error(
        'get_public_access_block', 'AccessDenied', 'denied', 403)) == [0, 'Unable to evaluate (AccessDenied)']


def test_storage_lens_denied_is_info():
    assert _run(_control, '_checkStorageLens', 'StorageLens', lambda s: s['s3control'].add_client_error(
        'list_storage_lens_configurations', 'AccessDenied', 'denied', 403)) == [0, 'Unable to evaluate (AccessDenied)']

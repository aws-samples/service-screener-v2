"""botocore Stubber tests for CloudTrail WAFS2027 checks.

Why Stubber and not the emulator:
- manualConsoleWritesDetected: the emulator records its own API calls in LookupEvents
  but cannot produce events made from an AWS Management Console session
  (sessionCredentialFromConsole=true), so the FAIL path cannot be set up there.
- trailBucketSameAccount: the emulator is a single account that is always an
  Organizations management account; standalone, member, log-archive and
  cross-account bucket cases need other accounts.
- cloudtrailExcludesKmsEvents: organization shadow trails whose selectors cannot be
  read from a member account (AccessDenied) need a second account.
The drivers are exercised directly with real boto3 clients (real API shapes) wrapped
by Stubber; nothing is sent over the network.
"""
import datetime
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber, ANY

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.cloudtrail.drivers.CloudtrailAccount import CloudtrailAccount  # noqa: E402
from services.cloudtrail.drivers.CloudtrailHelper import selectorCoverage  # noqa: E402

ACCT = '111122223333'
OTHER = '999988887777'
REGION = 'us-east-1'


def _client(svc):
    return boto3.client(svc, region_name=REGION, aws_access_key_id='testing',
                        aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')


@pytest.fixture(autouse=True)
def _cfg():
    Config.init()
    Config.set('stsInfo', {'Account': ACCT})
    yield
    Config.init()


def _trail(name, acct=ACCT, bucket='b', org=False, home=REGION):
    return {'Name': name, 'S3BucketName': bucket, 'HomeRegion': home, 'IsOrganizationTrail': org,
            'IsMultiRegionTrail': True, 'TrailARN': f'arn:aws:cloudtrail:{home}:{acct}:trail/{name}'}


class Clients:
    def __init__(self):
        self.ct, self.s3, self.cfg, self.org = _client('cloudtrail'), _client('s3'), _client('config'), _client('organizations')
        self.st = {k: Stubber(getattr(self, k)) for k in ('ct', 's3', 'cfg', 'org')}

    def driver(self):
        for s in self.st.values():
            s.activate()
        return CloudtrailAccount(self.ct, 1, s3Client=self.s3, cfgClient=self.cfg, orgClient=self.org)

    def done(self):
        for s in self.st.values():
            s.assert_no_pending_responses()


# ---------------------------------------------------------------- selectors

def test_selector_coverage_variants():
    assert selectorCoverage({'EventSelectors': [{'IncludeManagementEvents': True}]})['kms'] is True
    c = selectorCoverage({'EventSelectors': [{'IncludeManagementEvents': True,
                                              'ExcludeManagementEventSources': ['kms.amazonaws.com']}]})
    assert c['management'] and not c['kms']
    c = selectorCoverage({'AdvancedEventSelectors': [{'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Management']},
        {'Field': 'eventSource', 'NotEquals': ['kms.amazonaws.com', 'rdsdata.amazonaws.com']}]}]})
    assert c['management'] and not c['kms']
    c = selectorCoverage({'AdvancedEventSelectors': [{'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Management']},
        {'Field': 'eventSource', 'NotEquals': ['rdsdata.amazonaws.com']}]}]})
    assert c['kms'] is True
    c = selectorCoverage({'AdvancedEventSelectors': [{'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Data']},
        {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']}]}]})
    assert c['data'] and not c['management']
    assert selectorCoverage({'EventSelectors': [{'IncludeManagementEvents': False}]})['management'] is False


# ---------------------------------------------------------------- KMS exclusion

def _kmsStubs(c, selectors, statusErr=None, selErr=None):
    t = _trail('t1', acct=OTHER, org=True)
    c.st['ct'].add_response('describe_trails', {'trailList': [t]}, {'includeShadowTrails': True})
    c.st['ct'].add_response('get_trail_status', {'IsLogging': True}, {'Name': t['TrailARN']})
    if selErr:
        c.st['ct'].add_client_error('get_event_selectors', selErr, expected_params={'TrailName': t['TrailARN']})
    else:
        c.st['ct'].add_response('get_event_selectors', dict(TrailARN=t['TrailARN'], **selectors),
                                {'TrailName': t['TrailARN']})


def test_kms_excluded_then_fixed():
    c = Clients()
    _kmsStubs(c, {'EventSelectors': [{'ReadWriteType': 'All', 'IncludeManagementEvents': True,
                                      'ExcludeManagementEventSources': ['kms.amazonaws.com']}]})
    d = c.driver()
    d._checkCloudtrailExcludesKmsEvents()
    assert d.results['cloudtrailExcludesKmsEvents'][0] == -1
    c.done()

    c = Clients()
    _kmsStubs(c, {'EventSelectors': [{'ReadWriteType': 'All', 'IncludeManagementEvents': True,
                                      'ExcludeManagementEventSources': []}]})
    d = c.driver()
    d._checkCloudtrailExcludesKmsEvents()
    assert d.results['cloudtrailExcludesKmsEvents'][0] == 1
    c.done()


def test_kms_unreadable_org_trail_is_not_pass():
    c = Clients()
    _kmsStubs(c, {}, selErr='AccessDeniedException')
    d = c.driver()
    d._checkCloudtrailExcludesKmsEvents()
    r = d.results['cloudtrailExcludesKmsEvents']
    assert r[0] == 0 and 'Unable to evaluate' in r[1]
    c.done()


# ---------------------------------------------------------------- same-account bucket

def _sameAcctStubs(c, trails, buckets, channels=None, org=True, cfgErr=None, cfg=True):
    if org:
        c.st['org'].add_response('describe_organization', {'Organization': {
            'Id': 'o-abcdefghij', 'MasterAccountId': OTHER}})
    else:
        c.st['org'].add_client_error('describe_organization', 'AWSOrganizationsNotInUseException')
        return
    c.st['s3'].add_response('list_buckets', {'Buckets': [{'Name': b} for b in buckets],
                                             'Owner': {'ID': 'abc'}})
    c.st['ct'].add_response('describe_trails', {'trailList': trails}, {'includeShadowTrails': True})
    if not cfg:
        return
    if cfgErr:
        c.st['cfg'].add_client_error('describe_delivery_channels', cfgErr)
    else:
        c.st['cfg'].add_response('describe_delivery_channels', {'DeliveryChannels': channels or []}, {})


def _runSame(c):
    d = c.driver()
    d._checkTrailBucketSameAccount()
    c.done()
    # bucket list and log-archive verdict are cached per account for the scan
    acct = Config.get('stsInfo')['Account']
    Config.set('CloudTrail_ownedBuckets::' + acct, None)
    Config.set('CloudTrail_logArchive::' + acct, None)
    return d.results['trailBucketSameAccount']


def test_member_trail_to_own_bucket_flagged_then_fixed():
    c = Clients()
    _sameAcctStubs(c, [_trail('local', bucket='my-logs')], ['my-logs', 'other'])
    assert _runSame(c)[0] == -1

    c = Clients()
    _sameAcctStubs(c, [_trail('local', bucket='archive-bucket-in-log-account')], ['my-logs'])
    assert _runSame(c)[0] == 1


def test_config_channel_to_own_bucket_flagged():
    c = Clients()
    _sameAcctStubs(c, [], ['cfg-bucket'], channels=[{'name': 'default', 's3BucketName': 'cfg-bucket'}])
    assert _runSame(c)[0] == -1


def test_config_unreadable_is_not_pass():
    c = Clients()
    _sameAcctStubs(c, [_trail('local', bucket='elsewhere')], ['mine'], cfgErr='AccessDeniedException')
    r = _runSame(c)
    assert r[0] == 0 and 'Unable to evaluate' in r[1]


def test_log_archive_account_not_flagged():
    c = Clients()
    _sameAcctStubs(c, [_trail('org', acct=OTHER, org=True, bucket='org-archive'),
                       _trail('local', bucket='org-archive')], ['org-archive'], cfg=False)
    assert _runSame(c)[0] == 1


def test_log_archive_memo_survives_other_regions():
    """A single-Region org trail is only visible in its home Region. Once the log
    archive role is detected, the account's own Config channel delivering locally in
    another Region must not be flagged."""
    c = Clients()
    _sameAcctStubs(c, [_trail('org', acct=OTHER, org=True, bucket='org-archive')],
                   ['org-archive', 'cfg-local'], cfg=False)
    d = c.driver()
    d._checkTrailBucketSameAccount()
    c.done()
    assert d.results['trailBucketSameAccount'][0] == 1

    c = Clients()  # next Region: org trail not visible, local Config channel
    _sameAcctStubs(c, [], ['org-archive', 'cfg-local'],
                   channels=[{'name': 'default', 's3BucketName': 'cfg-local'}], cfg=False)
    d = c.driver()
    d._checkTrailBucketSameAccount()
    assert d.results['trailBucketSameAccount'][0] == 1


def test_owned_buckets_cache_is_per_account():
    """--sequential multi-account scans share one process: account B must not reuse
    account A's bucket list (false PASS / false FAIL)."""
    c = Clients()
    _sameAcctStubs(c, [_trail('local', bucket='a-logs')], ['a-logs'])
    d = c.driver()
    d._checkTrailBucketSameAccount()
    c.done()
    assert d.results['trailBucketSameAccount'][0] == -1

    B = '444455556666'
    Config.set('stsInfo', {'Account': B})
    c = Clients()
    _sameAcctStubs(c, [_trail('local', acct=B, bucket='b-logs')], ['b-logs'])
    d = c.driver()
    d._checkTrailBucketSameAccount()
    c.done()  # list_buckets was called again for B
    assert d.results['trailBucketSameAccount'][0] == -1


def test_account_flags_reset_between_accounts(monkeypatch):
    """CloudTrail_has* flags are kept across Regions of one account but must be reset
    when a --sequential multi-account scan moves to the next account."""
    import services.cloudtrail.Cloudtrail as mod

    seen = []

    class FakeAccount:
        def __init__(self, *a, **k):
            pass

        def run(self, cls):
            seen.append(Config.get('CloudTrail_hasManagementEventsCaptured'))

        def getInfo(self):
            return {}

    class FakeSession:
        def client(self, *a, **k):
            return None

    monkeypatch.setattr(mod, 'CloudtrailAccount', FakeAccount)
    class Quiet(mod.Cloudtrail):
        def __del__(self):  # skip Service reporting side effects
            pass

    svc = Quiet.__new__(Quiet)
    svc.ssBoto, svc.bConfig, svc.ctClient, svc.snsClient, svc.s3Client = FakeSession(), None, None, None, None
    svc.getTrails = lambda: []

    svc.advise()
    Config.set('CloudTrail_hasManagementEventsCaptured', True)  # a trail in account A
    svc.advise()                                               # next Region, same account
    Config.set('stsInfo', {'Account': '444455556666'})
    svc.advise()                                               # account B, no trails
    assert seen == [False, True, False]
    assert Config.get('CloudTrail_listGlobalServEnabled') == []


def test_kms_ambiguous_selector_is_info():
    c = selectorCoverage({'AdvancedEventSelectors': [{'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Management']},
        {'Field': 'eventSource', 'Equals': ['s3.amazonaws.com'], 'StartsWith': ['kms']}]}]})
    assert c['management'] and not c['kms'] and c['kmsAmbiguous']
    c = Clients()
    _kmsStubs(c, {'AdvancedEventSelectors': [{'Name': 'x', 'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Management']},
        {'Field': 'eventSource', 'Equals': ['s3.amazonaws.com'], 'StartsWith': ['kms']}]}]})
    d = c.driver()
    d._checkCloudtrailExcludesKmsEvents()
    assert d.results['cloudtrailExcludesKmsEvents'][0] == 0
    c.done()


def test_standalone_account_info():
    c = Clients()
    _sameAcctStubs(c, [], [], org=False)
    assert _runSame(c)[0] == 0


# ---------------------------------------------------------------- console writes

def _event(name, console, invokedBy=None, readOnly=False):
    ui = {'type': 'AssumedRole', 'arn': f'arn:aws:sts::{ACCT}:assumed-role/Admin/alice'}
    if invokedBy:
        ui['invokedBy'] = invokedBy
    rec = {'eventType': 'AwsApiCall', 'eventName': name, 'eventSource': 'ec2.amazonaws.com',
           'readOnly': readOnly, 'userIdentity': ui}
    if console:
        rec['sessionCredentialFromConsole'] = 'true'
    return {'EventId': name, 'EventName': name, 'ReadOnly': str(readOnly).lower(),
            'EventTime': datetime.datetime(2026, 11, 1), 'CloudTrailEvent': json.dumps(rec)}


def _runConsole(events):
    c = Clients()
    c.st['ct'].add_response('lookup_events', {'Events': events}, {
        'LookupAttributes': [{'AttributeKey': 'ReadOnly', 'AttributeValue': 'false'}],
        'StartTime': ANY, 'EndTime': ANY, 'MaxResults': 50})
    d = c.driver()
    d._checkManualConsoleWritesDetected()
    c.done()
    return d.results['manualConsoleWritesDetected']


def test_console_writes_flagged_then_fixed():
    r = _runConsole([_event('RunInstances', console=True), _event('CreateTags', console=False)])
    assert r[0] == -1 and 'RunInstances' in r[1]

    r = _runConsole([_event('RunInstances', console=False),
                     _event('CreateStack', console=True, invokedBy='cloudformation.amazonaws.com')])
    assert r[0] == 1


def test_console_lookup_denied_is_not_pass():
    c = Clients()
    c.st['ct'].add_client_error('lookup_events', 'AccessDeniedException')
    d = c.driver()
    d._checkManualConsoleWritesDetected()
    r = d.results['manualConsoleWritesDetected']
    assert r[0] == 0 and 'Unable to evaluate' in r[1]

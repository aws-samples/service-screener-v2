"""De-duplication tests for the iam and cloudtrail drivers.

Each test proves that an API read shared by several _check methods (or by
several drivers of one service run) is now made once, while every affected
check still produces its expected result. Real boto3 clients are wrapped by
botocore Stubber with exactly one queued response per de-duplicated call, so a
second call fails the test (UnStubbedResponseError is not a ClientError and is
not swallowed by the checks' except blocks). Where a check fans out over many
regional services, a small fake client counts paginate() calls instead.
No network calls are made.
"""
import datetime
import json
import os
import sys

import boto3
import botocore
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.cloudtrail.drivers.CloudtrailAccount import CloudtrailAccount  # noqa: E402
from services.cloudtrail.drivers.CloudtrailCommon import CloudtrailCommon  # noqa: E402
from services.iam.drivers.IamAccount import IamAccount  # noqa: E402
from services.iam.drivers.IamOrgData import OrgData  # noqa: E402
from services.iam.drivers.IamTrust import buildTrustContext  # noqa: E402

ACCT = '111122223333'
OTHER = '999988887777'
REGION = 'us-east-1'


def _client(svc, region=REGION):
    c = boto3.session.Session().client(svc, region_name=region, aws_access_key_id='testing',
                                       aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')
    st = Stubber(c)
    st.activate()
    return c, st


@pytest.fixture(autouse=True)
def _cfg():
    Config.init()
    Config.set('stsInfo', {'Account': ACCT, 'Arn': f'arn:aws:iam::{ACCT}:user/x'})
    Config.set('REGIONS_SELECTED', [REGION])
    yield
    Config.init()


# ====================================================================== #
# CloudTrail
# ====================================================================== #
def _trail(name, acct=ACCT, bucket='b', org=False, home=REGION, kms=None):
    t = {'Name': name, 'S3BucketName': bucket, 'HomeRegion': home, 'IsOrganizationTrail': org,
         'IsMultiRegionTrail': True, 'IncludeGlobalServiceEvents': True, 'LogFileValidationEnabled': True,
         'TrailARN': f'arn:aws:cloudtrail:{home}:{acct}:trail/{name}'}
    if kms:
        t['KmsKeyId'] = kms
    return t


ALL_MGMT = {'EventSelectors': [{'ReadWriteType': 'All', 'IncludeManagementEvents': True}]}


def test_cloudtrail_account_describe_trails_once():
    """_checkCloudtrailExcludesKmsEvents, _checkTrailBucketSameAccount and
    _checkOrganizationTrailEnabled share one describe_trails call."""
    ct, ctSt = _client('cloudtrail')
    s3, s3St = _client('s3')
    cfg, cfgSt = _client('config')
    org, orgSt = _client('organizations')
    t = _trail('org', org=True, bucket='my-logs')
    ctSt.add_response('describe_trails', {'trailList': [t]}, {'includeShadowTrails': True})
    ctSt.add_response('get_trail_status', {'IsLogging': True}, {'Name': t['TrailARN']})
    ctSt.add_response('get_event_selectors', dict(TrailARN=t['TrailARN'], **ALL_MGMT), {'TrailName': t['TrailARN']})
    orgSt.add_response('describe_organization', {'Organization': {'Id': 'o-abcdefghij', 'MasterAccountId': ACCT}})
    s3St.add_response('list_buckets', {'Buckets': [{'Name': 'my-logs'}], 'Owner': {'ID': 'abc'}})
    cfgSt.add_response('describe_delivery_channels', {'DeliveryChannels': []}, {})

    # _checkOrganizationTrailEnabled builds its own default-session clients.
    gOrg, gOrgSt = _client('organizations')
    gOrgSt.add_response('describe_organization', {'Organization': {'Id': 'o-abcdefghij', 'MasterAccountId': ACCT}})
    gSts, gStsSt = _client('sts')
    gStsSt.add_response('get_caller_identity', {'Account': ACCT, 'Arn': 'arn:aws:iam::111122223333:user/x',
                                                'UserId': 'test-user-id'})
    realClient = boto3.client
    boto3.client = lambda svc, *a, **k: {'organizations': gOrg, 'sts': gSts}[svc]
    try:
        d = CloudtrailAccount(ct, 1, s3Client=s3, cfgClient=cfg, orgClient=org)
        d._checkCloudtrailExcludesKmsEvents()
        d._checkTrailBucketSameAccount()
        d._checkOrganizationTrailEnabled()
    finally:
        boto3.client = realClient

    assert d.results['cloudtrailExcludesKmsEvents'][0] == 1
    r = d.results['trailBucketSameAccount']
    assert r[0] == -1 and 'my-logs' in r[1]
    assert 'OrganizationTrailEnabled' not in d.results   # org trail present
    for st in (ctSt, s3St, cfgSt, orgSt, gOrgSt, gStsSt):
        st.assert_no_pending_responses()


def test_cloudtrail_describe_trails_error_reaches_every_check():
    ct, ctSt = _client('cloudtrail')
    s3, s3St = _client('s3')
    org, orgSt = _client('organizations')
    ctSt.add_client_error('describe_trails', 'AccessDeniedException', expected_params={'includeShadowTrails': True})
    orgSt.add_response('describe_organization', {'Organization': {'Id': 'o-abcdefghij', 'MasterAccountId': OTHER}})
    s3St.add_response('list_buckets', {'Buckets': [], 'Owner': {'ID': 'abc'}})
    d = CloudtrailAccount(ct, 1, s3Client=s3, orgClient=org)
    d._checkCloudtrailExcludesKmsEvents()
    d._checkTrailBucketSameAccount()
    assert d.results['cloudtrailExcludesKmsEvents'] == [0, 'Unable to evaluate (AccessDeniedException)']
    assert d.results['trailBucketSameAccount'] == [0, 'Unable to evaluate (AccessDeniedException)']
    ctSt.assert_no_pending_responses()


def test_trail_status_and_selectors_shared_between_common_and_account():
    """CloudtrailCommon (per trail) and CloudtrailAccount read get_trail_status
    and get_event_selectors of the same trail once per scan."""
    ct, ctSt = _client('cloudtrail')
    t = _trail('main')
    ctSt.add_response('describe_trails', {'trailList': [t]}, {'trailNameList': [t['TrailARN']]})
    ctSt.add_response('get_event_selectors', dict(TrailARN=t['TrailARN'], **ALL_MGMT), {'TrailName': t['TrailARN']})
    ctSt.add_response('get_trail_status', {'IsLogging': False}, {'Name': t['TrailARN']})
    ctSt.add_response('describe_trails', {'trailList': [t]}, {'includeShadowTrails': True})

    common = CloudtrailCommon(t, ct, None, None)
    common._checkTrailStatus()
    common._checkEvents()
    acc = CloudtrailAccount(ct, 1)
    acc._checkCloudtrailExcludesKmsEvents()

    assert common.results['EnableCloudTrailLogging'] == [-1, '']
    # Trail is not logging -> skipped, so no logging trail captures management events.
    assert acc.results['cloudtrailExcludesKmsEvents'] == [0, 'No logging trail captures management events in this Region']
    ctSt.assert_no_pending_responses()


def test_shared_bucket_and_kms_key_read_once():
    """Two trails delivering to the same bucket with the same KMS key: the
    bucket settings and the key policy are read once."""
    ct, ctSt = _client('cloudtrail')
    s3, s3St = _client('s3')
    kms, kmsSt = _client('kms')
    key = 'arn:aws:kms:us-east-1:000000000000:key/unittestkey-notproduction'
    t1, t2 = _trail('a', bucket='logs', kms=key), _trail('b', bucket='logs', kms=key)
    for t in (t1, t2):
        ctSt.add_response('describe_trails', {'trailList': [t]}, {'trailNameList': [t['TrailARN']]})
        ctSt.add_response('get_event_selectors', dict(TrailARN=t['TrailARN'], **ALL_MGMT), {'TrailName': t['TrailARN']})
    s3St.add_response('get_public_access_block', {'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': True}},
        {'Bucket': 'logs'})
    s3St.add_response('get_bucket_versioning', {'Status': 'Enabled'}, {'Bucket': 'logs'})
    s3St.add_response('get_bucket_logging', {}, {'Bucket': 'logs'})
    s3St.add_client_error('get_bucket_lifecycle', 'NoSuchLifecycleConfiguration', expected_params={'Bucket': 'logs'})
    kmsSt.add_response('get_key_policy', {'Policy': '{"Statement": []}'}, {'KeyId': key, 'PolicyName': 'default'})

    realClient = boto3.client
    boto3.client = lambda svc, *a, **k: {'kms': kms}[svc]
    try:
        out = []
        for t in (t1, t2):
            d = CloudtrailCommon(t, ct, None, s3)
            d._checkS3BucketSettings()
            d._checkKMSPolicySourceArn()
            out.append(d.results)
    finally:
        boto3.client = realClient

    expected = {'EnableS3PublicAccessBlock': [-1, None], 'EnableTrailS3BucketMFADelete': [-1, ''],
                'EnableTrailS3BucketLogging': [-1, ''], 'EnableTrailS3BucketLifecycle': [-1, 'Off'],
                'KMSPolicySourceArn': [-1, f'KMS key {key} lacks aws:SourceArn condition']}
    assert out[0] == expected and out[1] == expected
    for st in (ctSt, s3St, kmsSt):
        st.assert_no_pending_responses()


def test_trail_bucket_describe_organization_once_per_scan():
    """_checkTrailBucketSameAccount runs once per scanned Region; the
    account-level describe_organization answer is read once per scan, and a
    cached error still reaches the same except block in every Region."""
    org, orgSt = _client('organizations')
    orgSt.add_client_error('describe_organization', service_error_code='AWSOrganizationsNotInUseException')
    s3, _ = _client('s3')
    drivers = []
    for region in ('us-east-1', 'eu-west-1'):
        ct, _ = _client('cloudtrail', region)
        d = CloudtrailAccount(ct, 1, s3Client=s3, orgClient=org)
        d._checkTrailBucketSameAccount()
        drivers.append(d)
    for d in drivers:
        assert d.results['trailBucketSameAccount'] == [
            0, 'Standalone account (not in AWS Organizations); log archive separation not evaluated']
    orgSt.assert_no_pending_responses()


# ====================================================================== #
# IAM
# ====================================================================== #
AUTH = {'roles': [], 'users': [{'UserName': 'alice'}], 'groups': [], 'policies': []}


def _account(orgMaster=ACCT, ssBoto=None, orgData=None, credentialReport=None, authDetails=None):
    clients, stubs = {}, {}
    for k, svc in (('iamClient', 'iam'), ('orgClient', 'organizations'), ('accClient', 'account'),
                   ('sppClient', 'support'), ('budgetClient', 'budgets'), ('curClient', 'cur'),
                   ('ctClient', 'cloudtrail'), ('backupClient', 'backup')):
        clients[k], stubs[k] = _client(svc)
    if orgData is None:
        if orgMaster is None:
            stubs['orgClient'].add_client_error('describe_organization', 'AWSOrganizationsNotInUseException')
        else:
            stubs['orgClient'].add_response('describe_organization', {'Organization': {
                'Id': 'o-abcdefghij', 'MasterAccountId': orgMaster, 'FeatureSet': 'ALL',
                'Arn': f'arn:aws:organizations::{orgMaster}:organization/o-abcdefghij'}})
    acc = IamAccount(None, clients, [], [], ssBoto, authDetails if authDetails is not None else dict(AUTH), {},
                     orgData=orgData, credentialReport=credentialReport)
    return acc, stubs


class _FakeClient:
    """Minimal regional client: get_paginator(op).paginate(**kw) yields the
    configured pages and records each paginate() call."""
    def __init__(self, svc, region, pages, calls):
        self.svc, self.pages, self.calls = svc, pages, calls
        self.meta = type('M', (), {'region_name': region,
                                   'service_model': type('S', (), {'service_name': svc})()})()

    def get_paginator(self, op):
        client = self

        class P:
            def paginate(self, **kw):
                client.calls.append((client.svc, client.meta.region_name, op))
                res = client.pages.get((client.svc, op), [{}])
                if isinstance(res, Exception):
                    raise res
                for p in res:
                    if isinstance(p, Exception):
                        raise p
                    yield p
        return P()


class _FakeBoto:
    def __init__(self, pages=None):
        self.pages = pages or {}
        self.calls = []

    def client(self, svc, config=None, **kw):
        region = getattr(config, 'region_name', None) or REGION
        return _FakeClient(svc, region, self.pages, self.calls)

    def count(self, svc, op):
        return len([c for c in self.calls if c[0] == svc and c[2] == op])


def test_identity_providers_and_credential_report_read_once():
    """list_saml_providers / list_open_id_connect_providers: one call each for
    _checkHasExternalProvider, _checkIamUsersWithFederationAvailable and
    _checkPrincipalInventorySummary; the credential report read by
    Iam.getUsers() is reused (no get_credential_report call)."""
    Config.set('REGIONS_SELECTED', ['GLOBAL'])   # no regional probes in the inventory
    fields = 'user,arn,user_creation_time,password_enabled,a,b,c,d,access_key_1_active'
    report = {'Content': (fields + '\nalice,arn,t,true,x,x,x,x,false\n').encode()}
    acc, st = _account(credentialReport=report)
    st['iamClient'].add_response('list_saml_providers', {'SAMLProviderList': [
        {'Arn': f'arn:aws:iam::{ACCT}:saml-provider/okta'}]}, {})
    st['iamClient'].add_response('list_open_id_connect_providers', {'OpenIDConnectProviderList': []}, {})

    acc._checkHasExternalProvider()
    acc._checkIamUsersWithFederationAvailable()
    acc._checkPrincipalInventorySummary()

    assert acc.results['hasExternalIdentityProvider'] == [1, 'IAM identity providers: 1 SAML, 0 OIDC']
    assert acc.results['iamUsersWithFederationAvailable'] == [1, 'alice']
    inv = acc.results['principalInventorySummary']
    assert inv[0] == 0 and 'IAM SAML providers: 1' in inv[1] and 'IAM OIDC providers: 0' in inv[1]
    st['iamClient'].assert_no_pending_responses()


def test_identity_provider_error_reaches_every_check():
    Config.set('REGIONS_SELECTED', ['GLOBAL'])
    acc, st = _account()
    st['iamClient'].add_client_error('list_saml_providers', 'AccessDenied', expected_params={})
    st['iamClient'].add_client_error('list_open_id_connect_providers', 'AccessDenied', expected_params={})
    acc._checkHasExternalProvider()
    acc._checkIamUsersWithFederationAvailable()
    acc._checkPrincipalInventorySummary()
    assert acc.results['hasExternalIdentityProvider'] == [0, 'Unable to evaluate (AccessDenied)']
    assert 'iamUsersWithFederationAvailable' not in acc.results
    inv = acc.results['principalInventorySummary'][1]
    assert 'iam.list_saml_providers: AccessDenied' in inv and 'iam.list_open_id_connect_providers: AccessDenied' in inv
    st['iamClient'].assert_no_pending_responses()


def test_describe_budgets_read_once():
    acc, st = _account()
    st['budgetClient'].add_response('describe_budgets', {'Budgets': [{
        'BudgetName': 'monthly', 'BudgetType': 'COST', 'TimeUnit': 'MONTHLY'}]}, {'AccountId': ACCT})
    st['budgetClient'].add_response('describe_budget_actions_for_account', {'Actions': []}, {'AccountId': ACCT})
    acc._checkHasCostBudget()
    acc._checkBudgetNoActions()
    assert 'enableCostBudget' not in acc.results
    assert acc.results['budgetNoActions'] == [-1, '1 budget(s), none with a budget action']
    st['budgetClient'].assert_no_pending_responses()


def test_list_backup_plans_read_once():
    """_checkAWSBackupPlans and the DR Region detection of
    _checkDrRegionQuotaParity share list_backup_plans in the same Region."""
    acc, st = _account()
    rds, rdsSt = _client('rds')
    rdsSt.add_response('describe_global_clusters', {'GlobalClusters': []})
    st['backupClient'].add_response('list_backup_plans', {'BackupPlansList': []}, {})
    acc._regionalClient = lambda svc, region: {'backup': acc.backupClient, 'rds': rds}[svc]
    acc._checkAWSBackupPlans()
    acc._checkDrRegionQuotaParity()
    assert acc.results['hasAWSBackupPlans'] == [-1, 'No AWS Backup plans configured']
    assert acc.results['drRegionQuotaParity'] == [
        0, 'No DR Region identified (no cross-Region backup copy rule or Aurora global database)']
    st['backupClient'].assert_no_pending_responses()
    rdsSt.assert_no_pending_responses()


def test_backup_plans_other_region_not_shared():
    """The backup client of another Region than the scanned ones keeps its own call."""
    Config.set('REGIONS_SELECTED', ['eu-west-1'])
    acc, st = _account()
    st['backupClient'].add_response('list_backup_plans', {'BackupPlansList': [{'BackupPlanId': 'p'}]}, {})
    acc._checkAWSBackupPlans()
    assert 'hasAWSBackupPlans' not in acc.results
    st['backupClient'].assert_no_pending_responses()


def test_regional_lists_read_once_across_checks():
    """lambda.list_functions (_checkOrgMgmtAccountHostsWorkloads +
    _checkRoleSharedAcrossComponents) and rds.describe_db_instances
    (_checkOrgMgmtAccountHostsWorkloads + _checkDataStoreNoClassificationTag)
    are paginated once per Region."""
    Config.set('REGIONS_SELECTED', ['us-east-1', 'eu-west-1'])
    boto = _FakeBoto({('lambda', 'list_functions'): [{'Functions': [
        {'FunctionName': 'app', 'Role': f'arn:aws:iam::{ACCT}:role/shared'}]}]})
    acc, _ = _account(ssBoto=boto)
    acc._checkOrgMgmtAccountHostsWorkloads()
    acc._checkRoleSharedAcrossComponents()
    acc._checkDataStoreNoClassificationTag()

    r = acc.results['orgMgmtAccountHostsWorkloads']
    assert r[0] == -1 and 'Lambda functions: 2' in r[1]
    assert acc.results['roleSharedAcrossComponents'] == [
        1, '1 role(s) in use by compute components, none shared across components']
    assert acc.results['dataStoreNoClassificationTag'] == [1, 'No data stores found in scanned region(s)']
    assert boto.count('lambda', 'list_functions') == 2      # once per Region
    assert boto.count('rds', 'describe_db_instances') == 2


def test_rolesanywhere_trust_anchors_read_once():
    Config.set('REGIONS_SELECTED', ['us-east-1'])
    boto = _FakeBoto({('rolesanywhere', 'list_trust_anchors'): [{'trustAnchors': [
        {'name': 'ta', 'enabled': False}]}]})
    acc, st = _account(ssBoto=boto, orgMaster=None)
    st['iamClient'].add_response('list_saml_providers', {'SAMLProviderList': []}, {})
    st['iamClient'].add_response('list_open_id_connect_providers', {'OpenIDConnectProviderList': []}, {})
    acc.ssoData.instances = lambda: ([], [])
    acc._checkPrincipalInventorySummary()
    acc._checkRolesAnywhereTrustAnchorCertExpiring()
    assert 'IAM Roles Anywhere trust anchors: us-east-1: 1' in acc.results['principalInventorySummary'][1]
    r = acc.results['rolesAnywhereTrustAnchorCertExpiring']
    assert r[0] == 1 and 'ta (us-east-1): trust anchor disabled' in r[1]
    assert boto.count('rolesanywhere', 'list_trust_anchors') == 1


def test_control_tower_landing_zones_read_once():
    boto = _FakeBoto({('controltower', 'list_landing_zones'): [{'landingZones': []}]})
    acc, _ = _account(ssBoto=boto)
    assert acc._controlTowerEnrolledAccounts() == (set(), False, [])
    acc._checkControlTowerLandingZoneDrift()
    assert acc.results['controlTowerLandingZoneDrift'] == [
        0, 'No AWS Control Tower landing zone found in scanned region(s): us-east-1']
    assert boto.count('controltower', 'list_landing_zones') == 1


def test_sir_memberships_read_once():
    boto = _FakeBoto({('security-ir', 'list_memberships'): [{'items': []}]})
    acc, _ = _account(ssBoto=boto, orgMaster=None)
    acc._checkSirMembershipMissing()
    acc._checkSirTeamTooSmall()
    assert acc.results['sirMembershipMissing'] == [
        -1, 'No active AWS Security Incident Response membership in scanned region(s): us-east-1']
    assert acc.results['sirTeamTooSmall'] == [0, 'No active AWS Security Incident Response membership']
    assert boto.count('security-ir', 'list_memberships') == 1


def test_pages_replay_partial_pages_then_error():
    """A failure on page 2 is seen by every consumer after page 1, exactly as
    when iterating the paginator itself; the API is paginated once."""
    err = botocore.exceptions.ClientError({'Error': {'Code': 'Throttling', 'Message': 'x'}}, 'ListFunctions')
    boto = _FakeBoto({('lambda', 'list_functions'): [{'Functions': [{'FunctionName': 'f'}]}, err]})
    acc, _ = _account(ssBoto=boto)
    c = boto.client('lambda')
    for _ in range(2):
        seen = []
        with pytest.raises(botocore.exceptions.ClientError) as e:
            for page in acc._pages(c, 'list_functions'):
                seen.append(page)
        assert seen == [{'Functions': [{'FunctionName': 'f'}]}] and e.value is err
    assert boto.count('lambda', 'list_functions') == 1


def test_org_children_read_once():
    """OrgData.tree(), OrgData.ous() and _checkOrgOuStructureFlat list the
    children of the same parents once."""
    acc, st = _account()
    org = st['orgClient']
    org.add_response('list_roots', {'Roots': [{'Id': 'r-ab12', 'Name': 'Root', 'Arn': 'arn:aws:organizations::x:root/o/r-ab12'}]})
    org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': [
        {'Id': 'ou-ab12-11111111', 'Name': 'Workloads'}]}, {'ParentId': 'r-ab12'})
    org.add_response('list_accounts_for_parent', {'Accounts': [{'Id': OTHER, 'Name': 'stray'}]}, {'ParentId': 'r-ab12'})
    org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': []}, {'ParentId': 'ou-ab12-11111111'})
    org.add_response('list_accounts_for_parent', {'Accounts': []}, {'ParentId': 'ou-ab12-11111111'})

    tree, err = acc.orgData.tree()
    ous, err2 = acc.orgData.ous()
    acc._checkOrgOuStructureFlat()

    assert err is None and err2 is None
    assert set(tree['nodes']) == {'r-ab12', 'ou-ab12-11111111', OTHER}
    assert ous == {'ou-ab12-11111111': {'Name': 'Workloads', 'Parent': 'r-ab12', 'Path': 'Root/Workloads'}}
    r = acc.results['orgOuStructureFlat']
    assert r[0] == -1 and 'stray ({})'.format(OTHER) in r[1]
    org.assert_no_pending_responses()


def test_org_children_error_reaches_check():
    acc, st = _account()
    org = st['orgClient']
    org.add_response('list_roots', {'Roots': [{'Id': 'r-ab12', 'Name': 'Root'}]})
    org.add_client_error('list_organizational_units_for_parent', 'AccessDeniedException',
                         expected_params={'ParentId': 'r-ab12'})
    assert acc.orgData.ous() == (None, 'AccessDeniedException')
    acc._checkOrgOuStructureFlat()
    assert acc.results['orgOuStructureFlat'] == [0, 'Unable to evaluate (AccessDeniedException)']
    org.assert_no_pending_responses()


def test_org_data_shared_with_trust_context():
    """Iam.advise builds one OrgData for the role trust context and hands it to
    IamAccount: describe_organization and list_accounts are called once."""
    orgClient, orgSt = _client('organizations')
    orgSt.add_response('describe_organization', {'Organization': {
        'Id': 'o-abcdefghij', 'MasterAccountId': ACCT, 'FeatureSet': 'ALL'}})
    orgSt.add_response('list_accounts', {'Accounts': [{'Id': ACCT, 'Name': 'mgmt', 'Status': 'ACTIVE'}]})
    orgData = OrgData(orgClient, ACCT)
    ctx = buildTrustContext(orgData, ACCT)
    assert ctx['orgAccounts'] == {ACCT}

    acc, _ = _account(orgData=orgData)
    assert acc.organizationIsEnabled is True and acc.orgInfo['MasterAccountId'] == ACCT
    assert acc._isOrgManagementAccount() is True
    accounts, err = acc.orgData.accounts()
    assert err is None and [a['Id'] for a in accounts] == [ACCT]
    orgSt.assert_no_pending_responses()


def test_org_data_shared_not_in_org():
    orgClient, orgSt = _client('organizations')
    orgSt.add_client_error('describe_organization', 'AWSOrganizationsNotInUseException')
    orgData = OrgData(orgClient, ACCT)
    assert buildTrustContext(orgData, ACCT)['inOrg'] is False
    acc, _ = _account(orgData=orgData)
    assert acc.organizationIsEnabled is False and acc.orgInfo is None
    acc._checkOrgNotAllFeatures()
    assert acc.results['orgNotAllFeatures'] == [0, 'Not applicable: account is not part of an AWS Organization']
    orgSt.assert_no_pending_responses()


# ---------------------------------------------------------------------- #
# IAM per-resource drivers (API fallback when authorization details were
# not prefetched) and account-level managed policy reads
# ---------------------------------------------------------------------- #
from services.iam.drivers.IamUser import IamUser  # noqa: E402
from services.iam.drivers.IamRole import IamRole  # noqa: E402

MANAGED_ARN = f'arn:aws:iam::{ACCT}:policy/app'
MANAGED_DOC = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}
ADMIN_DOC = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
POLICY = {'Policy': {'PolicyName': 'app', 'Arn': MANAGED_ARN, 'DefaultVersionId': 'v1'}}
def _version():   # fresh dict: boto3 decodes the document in place
    return {'PolicyVersion': {'Document': json.dumps(MANAGED_DOC), 'VersionId': 'v1', 'IsDefaultVersion': True}}
ATTACHED = {'AttachedPolicies': [{'PolicyName': 'app', 'PolicyArn': MANAGED_ARN}]}


def test_iam_user_fallback_lists_and_policies_read_once():
    """Without prefetched details, _checkUserInGroup / _checkUserPolicy and
    _userPolicyDocs share list_groups_for_user, list_attached_user_policies,
    list_user_policies, get_user_policy, get_policy and get_policy_version."""
    iam, st = _client('iam')
    st.add_response('list_groups_for_user', {'Groups': []}, {'UserName': 'bob'})
    st.add_response('list_attached_user_policies', ATTACHED, {'UserName': 'bob'})
    st.add_response('get_policy', POLICY, {'PolicyArn': MANAGED_ARN})
    st.add_response('get_policy_version', _version(), {'PolicyArn': MANAGED_ARN, 'VersionId': 'v1'})
    st.add_response('list_user_policies', {'PolicyNames': ['inl']}, {'UserName': 'bob'})
    st.add_response('get_user_policy', {'UserName': 'bob', 'PolicyName': 'inl', 'PolicyDocument': json.dumps(ADMIN_DOC)},
                    {'UserName': 'bob', 'PolicyName': 'inl'})

    u = IamUser({'user': 'bob'}, iam)
    u._checkUserInGroup()
    u._checkUserPolicy()
    docs, unreadable = u._userPolicyDocs()

    assert u.results['userNotUsingGroup'] == [-1, '-']
    assert u.results['InlinePolicy'] == [-1, 'inl']
    assert u.results['InlinePolicyFullAdminAccess'] == [-1, 'inl']
    assert docs == [ADMIN_DOC, MANAGED_DOC] and unreadable == []
    st.assert_no_pending_responses()


def test_iam_user_fallback_list_error_reaches_both_paths():
    iam, st = _client('iam')
    st.add_client_error('list_attached_user_policies', 'AccessDenied', expected_params={'UserName': 'bob'})
    st.add_client_error('list_user_policies', 'AccessDenied', expected_params={'UserName': 'bob'})
    u = IamUser({'user': 'bob'}, iam)
    u._checkUserPolicy()                       # ClientError caught and printed
    assert u._userPolicyDocs() == (None, ['AccessDenied'])
    assert u.results == {}
    # _userPolicyDocs reads list_user_policies first: that error was cached too.
    st.assert_no_pending_responses()


def _role(name):
    return {'RoleName': name, 'Arn': f'arn:aws:iam::{ACCT}:role/{name}', 'Path': '/',
            'CreateDate': datetime.datetime(2020, 1, 1), 'RoleLastUsed': {}, 'MaxSessionDuration': 3600,
            'AssumeRolePolicyDocument': {'Statement': []}}


def test_iam_role_fallback_lists_and_policies_read_once():
    """_checkRolePolicy and _adminLevelPolicies share list_attached_role_policies,
    list_role_policies, get_role_policy and the managed policy reads; a second
    role attaching the same managed policy does not read it again."""
    iam, st = _client('iam')
    st.add_response('list_attached_role_policies', ATTACHED, {'RoleName': 'r1'})
    st.add_response('get_policy', POLICY, {'PolicyArn': MANAGED_ARN})
    st.add_response('get_policy_version', _version(), {'PolicyArn': MANAGED_ARN, 'VersionId': 'v1'})
    st.add_response('list_role_policies', {'PolicyNames': ['inl']}, {'RoleName': 'r1'})
    st.add_response('get_role_policy', {'RoleName': 'r1', 'PolicyName': 'inl', 'PolicyDocument': json.dumps(ADMIN_DOC)},
                    {'RoleName': 'r1', 'PolicyName': 'inl'})
    st.add_response('list_attached_role_policies', ATTACHED, {'RoleName': 'r2'})
    st.add_response('list_role_policies', {'PolicyNames': []}, {'RoleName': 'r2'})

    r1 = IamRole(_role('r1'), iam)
    r1._checkRolePolicy()
    assert r1._adminLevelPolicies() == (['inl (inline)'], [])
    assert r1.results['InlinePolicyFullAdminAccess'] == [-1, 'inl']
    r2 = IamRole(_role('r2'), iam)
    assert r2._adminLevelPolicies() == ([], [])
    st.assert_no_pending_responses()


def test_customer_policies_listed_once():
    """_getCustomerPolicies and _checkUnnecessaryCustomPolicies share
    list_policies(Scope='Local')."""
    acc, st = _account(authDetails={'users': [], 'roles': [], 'groups': []})
    st['iamClient'].add_response('list_policies', {'Policies': [
        {'PolicyName': 'MyReadOnly', 'Arn': f'arn:aws:iam::{ACCT}:policy/MyReadOnly', 'DefaultVersionId': 'v1'}]},
        {'Scope': 'Local'})
    assert [p['PolicyName'] for p in acc._getCustomerPolicies()] == ['MyReadOnly']
    acc._checkUnnecessaryCustomPolicies()
    assert acc.results['unnecessaryCustomPolicies'] == [1, 'MyReadOnly']
    st['iamClient'].assert_no_pending_responses()


def test_account_managed_policy_doc_shared_with_drivers():
    """IamAccount._managedPolicyDoc reuses get_policy / get_policy_version read
    by another IAM driver in the same scan."""
    iam, st = _client('iam')
    st.add_response('list_attached_role_policies', ATTACHED, {'RoleName': 'r1'})
    st.add_response('get_policy', POLICY, {'PolicyArn': MANAGED_ARN})
    st.add_response('get_policy_version', _version(), {'PolicyArn': MANAGED_ARN, 'VersionId': 'v1'})
    st.add_response('list_role_policies', {'PolicyNames': []}, {'RoleName': 'r1'})
    IamRole(_role('r1'), iam)._adminLevelPolicies()
    acc, _ = _account()
    acc.iamClient = iam
    assert acc._managedPolicyDoc(MANAGED_ARN) == MANAGED_DOC
    st.assert_no_pending_responses()

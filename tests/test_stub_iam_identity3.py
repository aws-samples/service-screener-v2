"""
Stubber-based flag -> fix tests for WAFS2027 IAM identity checks (chunk 3)
that the AWS Emulator cannot drive:

- costAllocationTagsNotActivated: ce.list_cost_allocation_tags is not
  implemented by the emulator.
- drRegionQuotaParity: the emulator is single-Region and cannot raise service
  quota values, so a primary/DR quota difference cannot be produced.
- iamUserLongTermAccessKey / longTermKeyNotContained: both read the IAM
  credential report, which the emulator caches - users/keys created during a
  test never appear in it.
- dataStoreNoClassificationTag (DynamoDB path): the emulator does not persist
  DynamoDB table tags. (S3 and EFS paths are tested against the emulator.)

Real boto3 clients are wrapped by an activated botocore Stubber (real API
shapes, fake credentials, unroutable endpoint), so no network call is made and
any unexpected call fails the test. Pure helper tests are included too.
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
from services.iam.drivers.IamUser import IamUser  # noqa: E402
from services.iam.drivers.IamAccount import IamAccount  # noqa: E402
from services.iam.drivers import IamPolicyHelpers as H  # noqa: E402

ACCOUNT = '111122223333'


def _client(service, region='us-east-1'):
    c = boto3.session.Session().client(service, region_name=region, aws_access_key_id='testing',
                                       aws_secret_access_key='testing', endpoint_url='https://127.0.0.1:1')
    stub = Stubber(c)
    stub.activate()
    return c, stub


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture
def cfg():
    saved = {k: Config.get(k, None) for k in ('stsInfo', 'REGIONS_SELECTED')}
    Config.set('stsInfo', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/x'})
    Config.set('REGIONS_SELECTED', ['us-east-1'])
    yield
    for k, v in saved.items():
        Config.set(k, v)


class _Regional:
    """Replacement for IamAccount._regionalClient handing out stubbed clients."""
    def __init__(self):
        self.clients = {}

    def get(self, service, region='us-east-1'):
        if (service, region) not in self.clients:
            self.clients[(service, region)] = _client(service, region)
        return self.clients[(service, region)]

    def __call__(self, service, region):
        return self.get(service, region)[0]

    def stub(self, service, region='us-east-1'):
        return self.get(service, region)[1]

    def assertDone(self):
        for _, s in self.clients.values():
            s.assert_no_pending_responses()


def _account(orgMaster=ACCOUNT, authDetails=None):
    clients, stubs = {}, {}
    for k, svc in (('iamClient', 'iam'), ('orgClient', 'organizations'), ('accClient', 'account'),
                   ('sppClient', 'support'), ('budgetClient', 'budgets'), ('curClient', 'cur'),
                   ('ctClient', 'cloudtrail'), ('backupClient', 'backup')):
        clients[k], stubs[k] = _client(svc)
    if orgMaster is None:
        stubs['orgClient'].add_client_error('describe_organization', 'AWSOrganizationsNotInUseException')
    else:
        stubs['orgClient'].add_response('describe_organization', {'Organization': {
            'Id': 'o-abcdefghij', 'MasterAccountId': orgMaster,
            'Arn': f'arn:aws:organizations::{orgMaster}:organization/o-abcdefghij'}})
    acc = IamAccount(None, clients, [], [], None,
                     authDetails or {'roles': [], 'users': [], 'groups': [], 'policies': []}, {})
    reg = _Regional()
    acc._regionalClient = reg
    return acc, stubs, reg


# --------------------------------------------------------------------------- #
# costAllocationTagsNotActivated
# --------------------------------------------------------------------------- #
class TestCostAllocationTags:
    K = 'costAllocationTagsNotActivated'

    def _run(self, tags=None, error=None, orgMaster=ACCOUNT, expectCall=True):
        acc, _, reg = _account(orgMaster=orgMaster)
        if expectCall:
            st = reg.stub('ce')
            if error:
                st.add_client_error('list_cost_allocation_tags', error)
            else:
                st.add_response('list_cost_allocation_tags', {'CostAllocationTags': [
                    {'TagKey': t, 'Type': 'UserDefined', 'Status': 'Active'} for t in tags]},
                    {'Status': 'Active', 'Type': 'UserDefined'})
        acc._checkCostAllocationTagsNotActivated()
        reg.assertDone()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        assert self._run([])[0] == -1
        # fix: activate the CostCenter tag
        assert self._run(['CostCenter'])[0] == 1

    def test_standalone_account(self, cfg):
        assert self._run([], orgMaster=None)[0] == -1

    def test_member_account_not_evaluable(self, cfg):
        r = self._run(orgMaster='999988887777', expectCall=False)
        assert r == [0, 'Not evaluable from member account']

    def test_access_denied(self, cfg):
        r = self._run(error='AccessDeniedException')
        assert r[0] == 0 and 'AccessDeniedException' in r[1]


# --------------------------------------------------------------------------- #
# drRegionQuotaParity
# --------------------------------------------------------------------------- #
QUOTA_ARN = 'arn:aws:servicequotas:{}:' + ACCOUNT + ':{}/{}'


def _quota(region, svc, code, value):
    return {'Quota': {'ServiceCode': svc, 'QuotaCode': code, 'Value': value,
                      'QuotaArn': QUOTA_ARN.format(region, svc, code)}}


class TestDrRegionQuotaParity:
    K = 'drRegionQuotaParity'

    def _run(self, drEc2Value, copyDest='us-west-2'):
        acc, _, reg = _account()
        b = reg.stub('backup')
        b.add_response('list_backup_plans', {'BackupPlansList': [
            {'BackupPlanId': 'plan-1', 'BackupPlanName': 'daily'}]})
        rule = {'RuleName': 'r', 'TargetBackupVaultName': 'Default', 'RuleId': 'r1'}
        if copyDest:
            rule['CopyActions'] = [{'DestinationBackupVaultArn':
                                    f'arn:aws:backup:{copyDest}:{ACCOUNT}:backup-vault:dr'}]
        b.add_response('get_backup_plan', {'BackupPlan': {'BackupPlanName': 'daily', 'Rules': [rule]}},
                       {'BackupPlanId': 'plan-1'})
        reg.stub('rds').add_response('describe_global_clusters', {'GlobalClusters': []})
        if copyDest:
            for svc, code, _ in IamAccount.DR_PARITY_QUOTAS:
                for region in ('us-east-1', copyDest):
                    st = reg.stub('service-quotas', region)
                    if svc == 'rds':
                        # quota without an applied value -> AWS default
                        st.add_client_error('get_service_quota', 'NoSuchResourceException')
                        st.add_response('get_aws_default_service_quota', _quota(region, svc, code, 40.0))
                        continue
                    value = 640.0 if (svc, code) == ('ec2', 'L-1216C47A') else 5.0
                    if region == copyDest and (svc, code) == ('ec2', 'L-1216C47A'):
                        value = drEc2Value
                    st.add_response('get_service_quota', _quota(region, svc, code, value))
        acc._checkDrRegionQuotaParity()
        reg.assertDone()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        r = self._run(drEc2Value=32.0)
        assert r[0] == -1 and 'us-west-2 32 < us-east-1 640' in r[1], r
        # fix: request the same vCPU quota in the DR Region
        assert self._run(drEc2Value=640.0)[0] == 1

    def test_no_dr_region_is_info(self, cfg):
        assert self._run(drEc2Value=0, copyDest=None)[0] == 0

    def test_aurora_global_pair(self, cfg):
        acc, _, reg = _account()
        reg.stub('backup').add_response('list_backup_plans', {'BackupPlansList': []})
        reg.stub('rds').add_response('describe_global_clusters', {'GlobalClusters': [{
            'GlobalClusterIdentifier': 'g1', 'GlobalClusterMembers': [
                {'DBClusterArn': f'arn:aws:rds:us-east-1:{ACCOUNT}:cluster:p', 'IsWriter': True},
                {'DBClusterArn': f'arn:aws:rds:eu-west-1:{ACCOUNT}:cluster:s', 'IsWriter': False}]}]})
        assert acc._drRegionPairs([]) == {('us-east-1', 'eu-west-1'): {'global database g1'}}


# --------------------------------------------------------------------------- #
# dataStoreNoClassificationTag - DynamoDB (never tagged -> confirmed via ListTagsOfResource)
# --------------------------------------------------------------------------- #
class TestDataStoreDynamo:
    K = 'dataStoreNoClassificationTag'
    ARN = f'arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders'

    def _run(self, tableTags):
        acc, _, reg = _account()
        reg.stub('resourcegroupstaggingapi').add_response('get_resources', {'ResourceTagMappingList': []},
                                                          {'ResourceTypeFilters': ['s3', 'dynamodb:table']})
        d = reg.stub('dynamodb')
        d.add_response('list_tables', {'TableNames': ['orders']})
        reg.stub('rds').add_response('describe_db_clusters', {'DBClusters': []})
        reg.stub('rds').add_response('describe_db_instances', {'DBInstances': []})
        reg.stub('efs').add_response('describe_file_systems', {'FileSystems': []})
        reg.stub('redshift').add_response('describe_clusters', {'Clusters': []})
        reg.stub('s3').add_response('list_buckets', {'Buckets': []})
        d.add_response('list_tags_of_resource', {'Tags': tableTags}, {'ResourceArn': self.ARN})
        acc._checkDataStoreNoClassificationTag()
        reg.assertDone()
        return acc.results[self.K]

    def test_flag_fix(self, cfg):
        r = self._run([{'Key': 'Owner', 'Value': 'team-a'}])
        assert r[0] == -1 and 'DynamoDB table orders' in r[1]
        # fix: add a classification tag
        assert self._run([{'Key': 'Owner', 'Value': 'team-a'},
                          {'Key': 'DataClassification', 'Value': 'Confidential'}])[0] == 1


# --------------------------------------------------------------------------- #
# iamUserLongTermAccessKey / longTermKeyNotContained
# --------------------------------------------------------------------------- #
def _row(user, password='false', k1='true', k2='false'):
    return {'user': user, 'arn': f'arn:aws:iam::{ACCOUNT}:user/{user}', 'user_creation_time': '2024-01-01T00:00:00+00:00',
            'password_enabled': password, 'password_last_used': 'N/A', 'mfa_active': 'false',
            'access_key_1_active': k1, 'access_key_1_last_rotated': '2026-11-01T00:00:00+00:00',
            'access_key_1_last_used_date': 'N/A', 'access_key_2_active': k2,
            'access_key_2_last_rotated': 'N/A', 'access_key_2_last_used_date': 'N/A'}


def _detail(user, tags=None, inline=None, attached=None, groups=None, boundary=None):
    d = {'UserName': user, 'Path': '/', 'UserId': 'AIDA' + 'X' * 17, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/{user}',
         'CreateDate': _now(), 'UserPolicyList': inline or [], 'AttachedManagedPolicies': attached or [],
         'GroupList': groups or [], 'Tags': tags or []}
    if boundary:
        d['PermissionsBoundary'] = {'PermissionsBoundaryType': 'Policy', 'PermissionsBoundaryArn': boundary}
    return d


def _user(row, detail, groupDetails=None, policyMap=None):
    iam, stub = _client('iam')
    auth = {'users': [detail], 'groups': groupDetails or [], 'roles': [], 'policies': []}
    return IamUser(row, iam, auth, policyMap or {}), stub


ALLOW_S3 = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'}]}
DENY_OUTSIDE = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*',
                'Condition': {'NotIpAddress': {'aws:SourceIp': ['203.0.113.0/24']}}}]}


class TestLongTermAccessKey:
    K = 'iamUserLongTermAccessKey'

    def test_flag_fix(self):
        u, _ = _user(_row('ci-bot'), _detail('ci-bot'))
        u._checkIamUserLongTermAccessKey()
        assert u.results[self.K][0] == -1 and 'machine identity' in u.results[self.K][1]
        # fix: deactivate the key (workload moved to a role)
        u, _ = _user(_row('ci-bot', k1='false'), _detail('ci-bot'))
        u._checkIamUserLongTermAccessKey()
        assert self.K not in u.results

    def test_console_user_detail(self):
        u, _ = _user(_row('alice', password='true'), _detail('alice'))
        u._checkIamUserLongTermAccessKey()
        assert u.results[self.K][0] == -1 and 'console' in u.results[self.K][1]

    def test_exception_tag(self):
        tags = [{'Key': IamUser.LONG_TERM_KEY_EXCEPTION_TAG, 'Value': 'CHG-1234'}]
        u, _ = _user(_row('legacy'), _detail('legacy', tags=tags))
        u._checkIamUserLongTermAccessKey()
        assert u.results[self.K][0] == 0
        tags = [{'Key': IamUser.LONG_TERM_KEY_EXCEPTION_TAG, 'Value': 'false'}]
        u, _ = _user(_row('legacy'), _detail('legacy', tags=tags))
        u._checkIamUserLongTermAccessKey()
        assert u.results[self.K][0] == -1

    def test_root_and_placeholder_skipped(self):
        u, _ = _user(_row('<root_account>'), _detail('x'))
        u._checkIamUserLongTermAccessKey()
        assert self.K not in u.results

    def test_fallback_list_user_tags(self):
        iam, stub = _client('iam')
        stub.add_response('list_user_tags', {'Tags': [], 'IsTruncated': False}, {'UserName': 'bob'})
        u = IamUser(_row('bob'), iam)
        u._checkIamUserLongTermAccessKey()
        stub.assert_no_pending_responses()
        assert u.results[self.K][0] == -1


class TestLongTermKeyNotContained:
    K = 'longTermKeyNotContained'

    def test_flag_fix_inline(self):
        inline = [{'PolicyName': 's3', 'PolicyDocument': ALLOW_S3}]
        u, _ = _user(_row('ci-bot'), _detail('ci-bot', inline=inline))
        u._checkLongTermKeyNotContained()
        assert u.results[self.K][0] == -1
        # fix: add a deny-outside-network guard
        inline.append({'PolicyName': 'net', 'PolicyDocument': DENY_OUTSIDE})
        u, _ = _user(_row('ci-bot'), _detail('ci-bot', inline=inline))
        u._checkLongTermKeyNotContained()
        assert u.results[self.K][0] == 1

    def test_fix_by_boundary(self):
        arn = f'arn:aws:iam::{ACCOUNT}:policy/boundary'
        u, _ = _user(_row('ci-bot'), _detail('ci-bot', attached=[{'PolicyName': 'a', 'PolicyArn': 'arn:aws:iam::aws:policy/AmazonS3FullAccess'}],
                                           boundary=arn))
        u._checkLongTermKeyNotContained()
        assert u.results[self.K][0] == 1

    def test_group_policy_counted(self):
        groups = [{'GroupName': 'devs', 'GroupPolicyList': [{'PolicyName': 'net', 'PolicyDocument': DENY_OUTSIDE}],
                   'AttachedManagedPolicies': [{'PolicyName': 'm', 'PolicyArn': f'arn:aws:iam::{ACCOUNT}:policy/m'}]}]
        u, _ = _user(_row('ci-bot'), _detail('ci-bot', groups=['devs']), groups,
                     {f'arn:aws:iam::{ACCOUNT}:policy/m': ALLOW_S3})
        u._checkLongTermKeyNotContained()
        assert u.results[self.K][0] == 1
        groups[0]['GroupPolicyList'] = []
        u, _ = _user(_row('ci-bot'), _detail('ci-bot', groups=['devs']), groups,
                     {f'arn:aws:iam::{ACCOUNT}:policy/m': ALLOW_S3})
        u._checkLongTermKeyNotContained()
        assert u.results[self.K][0] == -1

    def test_unreadable_managed_policy(self):
        arn = f'arn:aws:iam::{ACCOUNT}:policy/hidden'
        u, stub = _user(_row('ci-bot'), _detail('ci-bot', attached=[{'PolicyName': 'hidden', 'PolicyArn': arn}]))
        stub.add_client_error('get_policy', 'AccessDenied')
        u._checkLongTermKeyNotContained()
        assert u.results[self.K][0] == 0

    def test_no_key_no_result(self):
        u, _ = _user(_row('alice', k1='false'), _detail('alice', inline=[{'PolicyName': 's3', 'PolicyDocument': ALLOW_S3}]))
        u._checkLongTermKeyNotContained()
        assert self.K not in u.results


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
class TestHelpers:
    def test_event_pattern(self):
        m = H.eventPatternMatchesMfaDeactivation
        assert m(json.dumps({'source': ['aws.iam'], 'detail': {'eventName': ['DeactivateMFADevice']}}))
        assert m(json.dumps({'source': ['aws.iam']}))
        assert m(json.dumps({'detail': {'eventName': [{'prefix': 'Deactivate'}]}}))
        assert m(json.dumps({'source': [{'prefix': 'aws.'}], 'detail-type': ['AWS API Call via CloudTrail']}))
        assert not m(json.dumps({'source': ['aws.iam'], 'detail': {'eventName': ['CreateUser']}}))
        assert not m(json.dumps({'source': ['aws.ec2']}))
        assert not m(json.dumps({'source': ['aws.iam'], 'detail-type': ['AWS Console Sign In via CloudTrail']}))
        assert not m(json.dumps({'account': [ACCOUNT]}))
        assert not m(json.dumps({'detail': {'eventName': [{'anything-but': ['DeactivateMFADevice']}]}}))
        assert not m(None) and not m('not json')

    def test_metric_filter(self):
        m = H.metricFilterMatchesMfaDeactivation
        assert m('{ ($.eventName = DeactivateMFADevice) || ($.eventName = DeleteVirtualMFADevice) }')
        assert m('{ $.eventName = "DeactivateMFADevice" }')
        assert m('{ $.eventSource = iam.amazonaws.com }')
        assert not m('{ $.eventName != DeactivateMFADevice }')
        assert not m('{ ($.eventSource = iam.amazonaws.com) && ($.eventName = CreateUser) }')
        assert not m('') and not m(None)

    def test_classification_key(self):
        for k in ('DataClassification', 'data-classification', 'data_classification', 'Sensitivity',
                  'company:data-sensitivity', 'Confidentiality'):
            assert H.isClassificationTagKey(k), k
        for k in ('Owner', 'Name', 'Environment', 'class'):
            assert not H.isClassificationTagKey(k), k

    def test_network_containment(self):
        assert H.networkContainment([ALLOW_S3])[0] is False
        assert H.networkContainment([ALLOW_S3, DENY_OUTSIDE])[0] is True
        cond = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*',
                'Condition': {'StringEquals': {'aws:SourceVpce': 'vpce-1'}}}]}
        assert H.networkContainment([cond])[0] is True
        assert H.networkContainment([])[0] is None

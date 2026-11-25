"""Regression tests for low-severity review findings in codeartifact,
codepipeline, kms and s3 (unit "mix2").

Every test uses real boto3 clients wrapped by botocore.stub.Stubber (real API
shapes; nothing leaves the process) or drives a driver with real response
shapes, because the emulator cannot produce these states (AccessDenied on a
single listing, throttling, a second account in the same process, EventBridge
patterns that narrow on detail.type).
"""
import datetime
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Config import Config  # noqa: E402
from services.codeartifact.Codeartifact import Codeartifact  # noqa: E402
from services.codeartifact.drivers.CodeartifactAccount import CodeartifactAccount  # noqa: E402
from services.codepipeline.Codepipeline import CodepipelineShared, CodepipelineLookupError  # noqa: E402
from services.codepipeline.drivers.CodepipelinePipeline import CodepipelinePipeline  # noqa: E402
from services.kms.drivers.KmsAccount import KmsAccount  # noqa: E402
from services.kms.drivers.KmsCommon import KmsCommon, orgConditionScopes  # noqa: E402
from services.s3.drivers.S3AccessPoint import S3AccessPoint  # noqa: E402
from services.s3.drivers.S3Bucket import S3Bucket  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

ACCT = '111122223333'
OTHER = '444455556666'


@pytest.fixture(autouse=True)
def _config():
    Config.init()
    Config.set('stsInfo', {'Account': ACCT})
    yield
    Config.init()


def _client(svc):
    return boto3.client(svc, region_name='us-east-1', endpoint_url='https://127.0.0.1:1',
                        aws_access_key_id='testing', aws_secret_access_key='testing')  # nosec - Stubber only


# =========================================================================== #
# codepipeline: pipelineNoEventNotification EventBridge pattern matching
# =========================================================================== #
PL_ARN = f'arn:aws:codepipeline:us-east-1:{ACCT}:pl'


class _Shared:
    """Shared lookups with fixed EventBridge rules and no notification rules."""

    def __init__(self, eventRules):
        self._ev = eventRules

    def notificationRules(self):
        return []

    def eventRules(self):
        return self._ev


def _notif(pattern):
    d = CodepipelinePipeline({'name': 'pl', 'stages': []}, {'pipelineArn': PL_ARN},
                             _Shared([('rule1', pattern)]))
    d._checkPipelineNoEventNotification()
    return d.results['pipelineNoEventNotification']


BASE = {'source': ['aws.codepipeline'], 'detail-type': ['CodePipeline Action Execution State Change']}


@pytest.mark.parametrize('detail', [
    {'type': {'category': ['Approval']}, 'state': ['FAILED']},
    {'stage': ['Deploy'], 'state': ['FAILED']},
    {'action': ['build'], 'pipeline': ['pl'], 'state': ['FAILED']},
])
def test_event_pattern_narrowed_by_type_stage_action_is_not_coverage(detail):
    ## Old code ignored these detail keys and returned PASS.
    r = _notif(dict(BASE, detail=detail))
    assert r[0] == -1
    assert 'only match a subset' in r[1] and 'rule1' in r[1]


def test_event_pattern_narrowed_rule_for_other_pipeline_not_listed_as_partial():
    r = _notif(dict(BASE, detail={'pipeline': ['other'], 'stage': ['Deploy'], 'state': ['FAILED']}))
    assert r[0] == -1 and 'subset' not in r[1]


@pytest.mark.parametrize('pipelineFilter', [
    [{'numeric': ['>', 0]}],
    [{'exists': False}],
])
def test_event_pattern_non_matching_operator_on_pipeline_is_not_coverage(pipelineFilter):
    ## Old code treated every unrecognised operator dict as matching (PASS).
    r = _notif(dict(BASE, detail={'pipeline': pipelineFilter, 'state': ['FAILED']}))
    assert r[0] == -1


def test_event_pattern_unknown_operator_is_unable_to_evaluate():
    r = _notif(dict(BASE, detail={'pipeline': [{'cidr': '10.0.0.0/8'}], 'state': ['FAILED']}))
    assert r[0] == 0 and r[1].startswith('Unable to evaluate (') and 'rule1' in r[1]


@pytest.mark.parametrize('detail', [
    {'pipeline': ['pl'], 'state': ['FAILED']},
    {'pipeline': [{'prefix': 'p'}], 'state': [{'anything-but': 'SUCCEEDED'}]},
    {'pipeline': [{'exists': True}], 'state': [{'equals-ignore-case': 'failed'}]},
    {'pipeline': [{'wildcard': 'p*'}], 'state': ['FAILED']},
    {'pipeline': [{'suffix': 'l'}]},
    {},
])
def test_event_pattern_full_coverage_passes(detail):
    r = _notif(dict(BASE, detail=detail))
    assert r[0] == 1 and 'rule1' in r[1]


def test_event_pattern_other_pipeline_or_state_fails():
    assert _notif(dict(BASE, detail={'pipeline': ['other'], 'state': ['FAILED']}))[0] == -1
    assert _notif(dict(BASE, detail={'state': ['SUCCEEDED']}))[0] == -1


# =========================================================================== #
# codepipeline: CodepipelineShared must not cache transient errors
# =========================================================================== #
ROLE = f'arn:aws:iam::{ACCT}:role/pl-role'


def _sharedClients():
    return _client('iam'), _client('codestar-notifications'), _client('events')


def test_role_lookup_throttling_not_cached_access_denied_cached():
    iam, csn, ev = _sharedClients()
    shared = CodepipelineShared(iam, csn, ev)
    with Stubber(iam) as st:
        st.add_client_error('list_attached_role_policies', 'Throttling', http_status_code=400)
        st.add_response('list_attached_role_policies', {'AttachedPolicies': []})
        st.add_response('list_role_policies', {'PolicyNames': []})
        with pytest.raises(CodepipelineLookupError) as e:
            shared.roleAdminFindings(ROLE)
        assert e.value.code == 'Throttling'
        ## Old code re-raised the cached Throttling here without calling IAM.
        assert shared.roleAdminFindings(ROLE) == []
        st.assert_no_pending_responses()

    iam, csn, ev = _sharedClients()
    shared = CodepipelineShared(iam, csn, ev)
    with Stubber(iam) as st:
        st.add_client_error('list_attached_role_policies', 'AccessDenied', http_status_code=403)
        for _ in range(2):
            with pytest.raises(CodepipelineLookupError):
                shared.roleAdminFindings(ROLE)
        st.assert_no_pending_responses()   # second call served from cache


def test_notification_and_event_rule_throttling_not_cached():
    iam, csn, ev = _sharedClients()
    shared = CodepipelineShared(iam, csn, ev)
    ruleArn = f'arn:aws:codestar-notifications:us-east-1:{ACCT}:notificationrule/abc'
    with Stubber(csn) as st:
        st.add_response('list_notification_rules', {'NotificationRules': [{'Id': 'abc', 'Arn': ruleArn}]})
        st.add_client_error('describe_notification_rule', 'ThrottlingException', http_status_code=400)
        st.add_response('list_notification_rules', {'NotificationRules': []})
        with pytest.raises(CodepipelineLookupError):
            shared.notificationRules()
        assert shared.notificationRules() == []
        st.assert_no_pending_responses()

    with Stubber(ev) as st:
        st.add_client_error('list_rules', 'ThrottlingException', http_status_code=400)
        st.add_response('list_rules', {'Rules': []})
        with pytest.raises(CodepipelineLookupError):
            shared.eventRules()
        assert shared.eventRules() == []
        st.assert_no_pending_responses()


# =========================================================================== #
# codepipeline: pipelineNoSecurityTestAction name heuristic
# =========================================================================== #
def _act(name, category, provider, cfg=None):
    a = {'name': name, 'actionTypeId': {'category': category, 'owner': 'AWS',
                                        'provider': provider, 'version': '1'}}
    if cfg:
        a['configuration'] = cfg
    return a


def _secTest(stages):
    d = CodepipelinePipeline({'name': 'pl', 'stages': stages}, {'pipelineArn': PL_ARN}, None)
    d._checkPipelineNoSecurityTestAction()
    return d.results['pipelineNoSecurityTestAction']


SRC = {'name': 'Source', 'actions': [_act('src', 'Source', 'S3')]}
BUILD = {'name': 'Build', 'actions': [_act('compile', 'Build', 'CodeBuild', {'ProjectName': 'app-build'})]}


def test_deploy_to_test_stage_is_not_a_test_step():
    ## Old code matched 'test' in 'DeployToTest' / 'deploy-test' and PASSed.
    stages = [SRC, BUILD,
              {'name': 'DeployToTest', 'actions': [_act('deploy-test', 'Deploy', 'CloudFormation')]},
              {'name': 'DeployToProd', 'actions': [_act('deploy-prod', 'Deploy', 'CloudFormation')]}]
    assert _secTest(stages)[0] == -1
    ## A Build action in a stage named for a test environment is not evidence either.
    stages = [SRC, {'name': 'DeployToTest', 'actions': [_act('cdk-deploy', 'Build', 'CodeBuild',
                                                              {'ProjectName': 'cdk'})]}]
    assert _secTest(stages)[0] == -1
    ## Approval named "test sign-off" is not a test step.
    assert _secTest([SRC, {'name': 'Gate', 'actions': [_act('test-signoff', 'Approval', 'Manual')]}])[0] == -1


def test_real_test_steps_still_pass():
    assert _secTest([SRC, {'name': 'UnitTest', 'actions': [_act('run', 'Build', 'CodeBuild')]}])[0] == 1
    assert _secTest([SRC, {'name': 'Verify', 'actions': [_act('sast-scan', 'Build', 'CodeBuild')]}])[0] == 1
    assert _secTest([SRC, {'name': 'Verify', 'actions': [
        _act('run', 'Build', 'CodeBuild', {'ProjectName': 'checkov'})]}])[0] == 1
    assert _secTest([SRC, {'name': 'Deploy', 'actions': [_act('it', 'Test', 'CodeBuild')]}])[0] == 1
    assert _secTest([SRC, BUILD])[0] == -1


# =========================================================================== #
# s3: s3AccessPointPublic, BPA off everywhere with no public policy
# =========================================================================== #
ALL_OFF = {k: False for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')}


def _apRun(policyError=None):
    c, s3 = _client('s3control'), _client('s3')
    p = {'AccountId': ACCT, 'Name': 'my-ap'}
    with Stubber(c) as sc, Stubber(s3) as ss:
        if policyError:
            sc.add_client_error('get_access_point_policy_status', policyError, 'x', 403, None, p)
        else:
            sc.add_client_error('get_access_point_policy_status', 'NoSuchAccessPointPolicy', 'none', 404, None, p)
        sc.add_response('get_access_point', {'Name': 'my-ap', 'Bucket': 'b', 'NetworkOrigin': 'Internet',
                                             'BucketAccountId': ACCT, 'PublicAccessBlockConfiguration': ALL_OFF}, p)
        sc.add_client_error('get_public_access_block', 'NoSuchPublicAccessBlockConfiguration',
                            'none', 404, None, {'AccountId': ACCT})
        ss.add_client_error('get_public_access_block', 'NoSuchPublicAccessBlockConfiguration',
                            'none', 404, None, {'Bucket': 'b'})
        d = S3AccessPoint('my-ap', c, ACCT, None, s3Client=s3)
        d._checkAccessPointPublic()
    return d.results['s3AccessPointPublic']


def test_access_point_bpa_off_everywhere_without_policy_still_fails_and_says_so():
    """Kept as a FAIL (High): access point BPA off is its own finding in AWS
    Security Hub (S3.19), the reporter describes it, and nothing at any level
    stops a public policy being attached later. The message now says that no
    public access point policy is attached."""
    r = _apRun()
    assert r[0] == -1
    assert 'no public access point policy is attached now' in r[1]
    unread = _apRun('AccessDenied')
    assert unread[0] == -1 and 'policy status unreadable (policy status: AccessDenied)' in unread[1]


# =========================================================================== #
# s3: macieBucketsNotMonitored inventory cache
# =========================================================================== #
def _macieRun(bucket, setup):
    s3, m = _client('s3'), _client('macie2')
    with Stubber(m) as st:
        setup(st)
        d = S3Bucket(bucket, s3, m)
        d._checkMacieBucketMonitored()
        st.assert_no_pending_responses()
    return d.results['macieBucketsNotMonitored']


def test_macie_inventory_cache_is_per_account():
    mon = {'bucketName': 'a-bucket', 'automatedDiscoveryMonitoringStatus': 'MONITORED'}
    assert _macieRun('a-bucket', lambda st: st.add_response('describe_buckets', {'buckets': [mon]}))[0] == 1
    ## Second account in the same (sequential) process: must fetch its own inventory.
    Config.set('stsInfo', {'Account': OTHER})
    notMon = {'bucketName': 'b-bucket', 'automatedDiscoveryMonitoringStatus': 'NOT_MONITORED',
              'jobDetails': {'isDefinedInJob': 'FALSE', 'isMonitoredByJob': 'FALSE'}}
    ## Old code reused account A's inventory: 'Bucket not yet in Macie inventory' (INFO).
    assert _macieRun('b-bucket', lambda st: st.add_response('describe_buckets', {'buckets': [notMon]}))[0] == -1
    ## Account A's cached inventory is still served without another call.
    Config.set('stsInfo', {'Account': ACCT})
    assert _macieRun('a-bucket', lambda st: None)[0] == 1


def test_macie_inventory_throttling_not_cached():
    mon = {'bucketName': 'a-bucket', 'automatedDiscoveryMonitoringStatus': 'MONITORED'}
    r = _macieRun('a-bucket', lambda st: st.add_client_error('describe_buckets', 'ThrottlingException',
                                                             http_status_code=429))
    assert r == [0, 'Unable to evaluate (ThrottlingException)']
    ## Old code cached the throttling error for every later bucket.
    assert _macieRun('a-bucket', lambda st: st.add_response('describe_buckets', {'buckets': [mon]}))[0] == 1


# =========================================================================== #
# kms: KeyPolicyCrossAccount org condition must name a concrete organization
# =========================================================================== #
KEY_ID = '1234abcd-12ab-34cd-56ef-1234567890ab'


def _crossAccount(condition):
    kms = _client('kms')
    policy = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Sid': 'X', 'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::999999999999:root'},
        'Action': 'kms:Decrypt', 'Resource': '*', 'Condition': condition}]})
    md = {'KeyId': KEY_ID, 'Arn': f'arn:aws:kms:us-east-1:{ACCT}:key/{KEY_ID}', 'KeyState': 'Enabled',
          'KeyManager': 'CUSTOMER', 'Origin': 'AWS_KMS', 'KeyRotationEnabled': True,
          'CreationDate': datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)}
    with Stubber(kms) as st:
        st.add_response('get_key_policy', {'Policy': policy, 'PolicyName': 'default'},
                        {'KeyId': KEY_ID, 'PolicyName': 'default'})
        d = KmsCommon(md, kms)
        d._checkPolicyAdminUser()
    return d.results['KeyPolicyCrossAccount']


@pytest.mark.parametrize('condition', [
    {'StringLike': {'aws:PrincipalOrgID': 'o-*'}},
    {'StringLike': {'aws:PrincipalOrgID': 'o-?*'}},
    {'StringLike': {'aws:PrincipalOrgPaths': '*/*'}},
    {'StringLike': {'aws:PrincipalOrgPaths': 'o-*/r-ab12/*'}},
])
def test_wildcard_org_condition_is_not_org_restricted(condition):
    ## Old code: [1, 'Cross-account access restricted by aws:PrincipalOrgID...'].
    assert not orgConditionScopes(condition)
    assert _crossAccount(condition)[0] == -1


def test_concrete_org_condition_still_org_restricted():
    assert orgConditionScopes({'StringEquals': {'aws:PrincipalOrgID': 'o-abcdefghij'}})
    assert orgConditionScopes({'StringLike': {'aws:PrincipalOrgPaths': 'o-abcdefghij/r-ab12/*'}})
    assert _crossAccount({'StringEquals': {'aws:PrincipalOrgID': 'o-abcdefghij'}})[0] == 1


# =========================================================================== #
# kms: SingleKeyBroadUse with unreadable sources
# =========================================================================== #
def _broadUse(denied, refs=None):
    """denied: set of client service names whose listing raises AccessDenied.
    refs: {service: [keyRef, ...]} returned by readable sources."""
    refs = refs or {}
    kms = _client('kms')
    clients, stubs = {}, []
    from services.kms.drivers.KmsAccount import KmsAccount as K

    for label, svc, op, listKey, field in K.KEY_REFERENCE_SOURCES:
        if svc not in clients:
            clients[svc] = _client(svc)
            stubs.append(Stubber(clients[svc]))
        st = [s for s in stubs if s.client is clients[svc]][0]
        if svc in denied:
            st.add_client_error(op, 'AccessDeniedException', http_status_code=403)
        else:
            items = [{field: r} for r in refs.get(label, [])]
            if op == 'describe_volumes':
                items = [dict(i, VolumeId='vol-1') for i in items]
            st.add_response(op, {listKey: items})
    ks = Stubber(kms)
    ks.add_response('list_aliases', {'Aliases': []})
    keyArn = f'arn:aws:kms:us-east-1:{ACCT}:key/{KEY_ID}'
    ks.add_response('describe_key', {'KeyMetadata': {'KeyId': KEY_ID, 'Arn': keyArn, 'KeyManager': 'CUSTOMER'}})
    for s in stubs + [ks]:
        s.activate()
    try:
        d = KmsAccount(kms, lambda svc: clients[svc], keyMetadata={})
        d._checkSingleKeyBroadUse()
    finally:
        for s in stubs + [ks]:
            s.deactivate()
    return d.results['SingleKeyBroadUse']


def test_single_key_broad_use_unreadable_sources_not_pass():
    ## Finding scenario: only ssm and secretsmanager readable. Old code: PASS.
    r = _broadUse({'ec2', 'rds', 'efs', 'logs'})
    assert r[0] == 0 and r[1].startswith('Unable to evaluate (')
    ## A key already in 2 services plus one unreadable service could reach 3.
    keyArn = f'arn:aws:kms:us-east-1:{ACCT}:key/{KEY_ID}'
    r = _broadUse({'logs'}, {'SSM parameters': [keyArn], 'Secrets Manager secrets': [keyArn]})
    assert r[0] == 0


def test_single_key_broad_use_pass_when_unread_sources_cannot_matter():
    ## One unreadable service and no key in 2+ services: no key can reach 3.
    r = _broadUse({'logs'})
    assert r[0] == 1 and 'Not checked: CloudWatch log groups: AccessDeniedException' in r[1]
    ## Everything readable and no references: PASS.
    assert _broadUse(set())[0] == 1


def test_single_key_broad_use_flags_with_partial_errors():
    keyArn = f'arn:aws:kms:us-east-1:{ACCT}:key/{KEY_ID}'
    r = _broadUse({'efs'}, {'SSM parameters': [keyArn], 'Secrets Manager secrets': [keyArn],
                            'CloudWatch log groups': [keyArn]})
    assert r[0] == -1 and 'Not checked' in r[1]


# =========================================================================== #
# codeartifact: codeartifactNotUsed when list_repositories fails
# =========================================================================== #
def _caService(stubSetup):
    svc = Codeartifact.__new__(Codeartifact)
    svc.caClient = _client('codeartifact')
    svc.accountId = ACCT
    svc.tags = None
    with Stubber(svc.caClient) as st:
        stubSetup(st)
        res = svc.getResources()
        st.assert_no_pending_responses()
    a = CodeartifactAccount({'_region': 'us-east-1', '_domains': res['domains'],
                             '_domainError': res['domainError'],
                             '_repositoryError': res['repositoryError'],
                             '_repositoryCount': len(res['repositories'])})
    a._checkCodeartifactNotUsed()
    return a.results['codeartifactNotUsed']


def test_not_used_list_repositories_denied_is_unable_to_evaluate():
    def denied(st):
        st.add_response('list_domains', {'domains': []})
        st.add_client_error('list_repositories', 'AccessDeniedException', http_status_code=403)
    ## Old code swallowed the error: [-1, 'No CodeArtifact domain or repository ...'].
    assert _caService(denied) == [0, 'Unable to evaluate (AccessDeniedException)']

    def empty(st):
        st.add_response('list_domains', {'domains': []})
        st.add_response('list_repositories', {'repositories': []})
    assert _caService(empty)[0] == -1


def test_not_used_driver_honours_repository_error():
    a = CodeartifactAccount({'_region': 'us-east-1', '_domains': [], '_domainError': None,
                             '_repositoryError': 'AccessDeniedException', '_repositoryCount': 0})
    a._checkCodeartifactNotUsed()
    assert a.results['codeartifactNotUsed'] == [0, 'Unable to evaluate (AccessDeniedException)']

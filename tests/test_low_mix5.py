"""Regression tests for low-severity review findings in acm, cloudfront, dms, drs, ecs,
guardduty, inspector and sagemaker. Offline: real boto3 clients wrapped by botocore Stubber
(request/response shapes validated against the API models), or driver objects fed
API-shaped dicts. No network calls are made."""
import datetime
import json
import os
import sys
from datetime import timedelta, timezone

import boto3
import pytest
from botocore.stub import ANY, Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

KW = dict(region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')


def _reporter(svc):
    with open(os.path.join(ROOT, 'services', svc, f'{svc}.reporter.json')) as f:
        return json.load(f)


# --------------------------------------------------------------------------- #
# guardduty: guarddutyS3MalwareProtectionOff in a Region with no S3 buckets
# --------------------------------------------------------------------------- #
from services.guardduty.drivers.GuarddutyDriver import GuarddutyDriver  # noqa: E402

GD_KEY = 'guarddutyS3MalwareProtectionOff'


def _gdRun(buckets=None, s3Error=None, withS3=True):
    Config.set('stsInfo', {'Account': '123456789012'})
    gd, s3 = boto3.client('guardduty', **KW), boto3.client('s3', **KW)
    with Stubber(gd) as gst, Stubber(s3) as sst:
        gst.add_response('list_malware_protection_plans', {'MalwareProtectionPlans': []})
        if withS3:
            if s3Error:
                sst.add_client_error('list_buckets', s3Error, http_status_code=403,
                                     expected_params={'BucketRegion': 'us-east-1', 'MaxBuckets': 1})
            else:
                sst.add_response('list_buckets', {'Buckets': buckets or [], 'Owner': {'ID': 'o'}},
                                 {'BucketRegion': 'us-east-1', 'MaxBuckets': 1})
        d = GuarddutyDriver('a' * 32, gd, 'us-east-1', None, None, None, s3 if withS3 else None)
        d._checkGuarddutyS3MalwareProtectionOff()
        gst.assert_no_pending_responses()
        sst.assert_no_pending_responses()
    return d.results[GD_KEY]


def test_gd_malware_no_plan_no_buckets_is_info_not_fail():
    r = _gdRun(buckets=[])
    assert r[0] == 0 and 'No S3 buckets in this region' in r[1], r


def test_gd_malware_no_plan_with_buckets_fails():
    r = _gdRun(buckets=[{'Name': 'b', 'BucketRegion': 'us-east-1', 'CreationDate': datetime.datetime(2024, 1, 1)}])
    assert r[0] == -1, r


def test_gd_malware_bucket_listing_unreadable_is_unable_to_evaluate():
    assert _gdRun(s3Error='AccessDenied') == [0, 'Unable to evaluate (AccessDenied)']


def test_gd_service_wires_s3_client_into_driver():
    src = open(os.path.join(ROOT, 'services', 'guardduty', 'Guardduty.py')).read()
    assert "client('s3'" in src and 'self.s3_client)' in src


def test_gd_reporter_says_empty_regions_not_flagged():
    assert 'Regions with no S3 buckets are not flagged' in _reporter('guardduty')[GD_KEY]['^description']


# --------------------------------------------------------------------------- #
# drs: describe_jobs page cap must not turn truncated history into a FAIL
# --------------------------------------------------------------------------- #
from services.drs.Drs import Drs  # noqa: E402
from services.drs.drivers.DrsCommon import DrsCommon  # noqa: E402

NOW = datetime.datetime.now(timezone.utc)
SID = 's-1234567890abcdef0'


class _StubDrs(Drs):
    def __del__(self):
        pass


def _drsServer():
    iso = (NOW - timedelta(days=400)).strftime('%Y-%m-%dT%H:%M:%S.000000+00:00')
    recent = (NOW - timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%S.000000+00:00')
    ## lastLaunch is a later RECOVERY, so it does not prove a drill.
    return {'sourceServerID': SID, 'arn': f'arn:aws:drs:us-east-1:111122223333:source-server/{SID}',
            'dataReplicationInfo': {'dataReplicationState': 'CONTINUOUS'}, 'replicationDirection': 'FAILOVER',
            'lifeCycle': {'addedToServiceDateTime': iso,
                          'lastLaunch': {'initiated': {'type': 'RECOVERY', 'apiCallDateTime': recent},
                                         'status': 'LAUNCHED'}},
            'tags': {}}


def _drsJobs(pages, lastHasNext):
    c = boto3.client('drs', **KW)
    with Stubber(c) as st:
        for i in range(pages):
            resp = {'items': [{'jobID': f'drsjob-{i:017d}', 'type': 'LAUNCH', 'initiatedBy': 'START_RECOVERY'}]}
            if i < pages - 1 or lastHasNext:
                resp['nextToken'] = f't{i}'
            st.add_response('describe_jobs', resp, {'filters': {'fromDate': ANY}, **({'nextToken': ANY} if i else {})})
        d = object.__new__(_StubDrs)
        d.drsClient, d.tags, d.region = c, [], 'us-east-1'
        d.JOB_PAGE_CAP = 2
        jobs, err = d._getDrillJobs(NOW)
        st.assert_no_pending_responses()
    common = DrsCommon({'_region': 'us-east-1', '_now': NOW, '_windowDays': 90, '_servers': [_drsServer()],
                        '_serversError': None, '_drillJobs': jobs, '_jobsError': err})
    common._checkNoRecentDrill()
    return err, common.results['drsNoRecentDrill']


def test_drs_page_cap_truncation_is_unable_to_evaluate():
    err, r = _drsJobs(pages=2, lastHasNext=True)
    assert err == 'PageCapReached'
    assert r == [0, 'Unable to evaluate (PageCapReached)'], r


def test_drs_full_history_at_cap_still_fails():
    ## Exactly JOB_PAGE_CAP pages and no more: nothing was truncated, so missing == undrilled.
    err, r = _drsJobs(pages=2, lastHasNext=False)
    assert err is None and r[0] == -1, r


# --------------------------------------------------------------------------- #
# ecs: ecsTaskRoleOverprivileged must not rate resource-scoped '<svc>:*' as admin
# --------------------------------------------------------------------------- #
from services.ecs.drivers.EcsTaskDefinition import EcsTaskDefinition  # noqa: E402

ECS_KEY = 'ecsTaskRoleOverprivileged'


def _ecsRun(statement):
    iam = boto3.client('iam', **KW)
    doc = json.dumps({'Version': '2012-10-17', 'Statement': statement})
    with Stubber(iam) as st:
        st.add_response('list_attached_role_policies', {'AttachedPolicies': [], 'IsTruncated': False},
                        {'RoleName': 'r'})
        st.add_response('list_role_policies', {'PolicyNames': ['p'], 'IsTruncated': False}, {'RoleName': 'r'})
        st.add_response('get_role_policy', {'RoleName': 'r', 'PolicyName': 'p', 'PolicyDocument': doc},
                        {'RoleName': 'r', 'PolicyName': 'p'})
        d = EcsTaskDefinition({'family': 'f', 'revision': 1, 'taskRoleArn': 'arn:aws:iam::111122223333:role/r',
                               'containerDefinitions': []}, None, None, False, iam_client=iam)
        d._checkEcsTaskRoleOverprivileged()
        st.assert_no_pending_responses()
    return d.results[ECS_KEY]


@pytest.mark.parametrize('resource', [
    'arn:aws:s3:::app-bucket/*',
    ['arn:aws:s3:::app-bucket', 'arn:aws:s3:::app-bucket/*'],
])
def test_ecs_scoped_service_wildcard_is_info_not_high_fail(resource):
    r = _ecsRun({'Effect': 'Allow', 'Action': 's3:*', 'Resource': resource})
    assert r[0] == 0, r
    assert 's3:* on arn:aws:s3:::app-bucket' in r[1] and 'review' in r[1]


def test_ecs_scoped_logs_wildcard_is_info():
    r = _ecsRun({'Effect': 'Allow', 'Action': 'logs:*',
                 'Resource': 'arn:aws:logs:us-east-1:111122223333:log-group:/ecs/app:*'})
    assert r[0] == 0, r


@pytest.mark.parametrize('statement', [
    {'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'},
    {'Effect': 'Allow', 'Action': 's3:*', 'Resource': 'arn:aws:s3:::*'},
    {'Effect': 'Allow', 'Action': 's3:*', 'Resource': ['arn:aws:s3:::app-bucket/*', 'arn:aws:s3:::*/*']},
    {'Effect': 'Allow', 'Action': 'dynamodb:*', 'Resource': 'arn:aws:dynamodb:us-east-1:111122223333:table/*'},
    {'Effect': 'Allow', 'Action': 'logs:*', 'Resource': 'arn:aws:logs:*:*:*'},
    {'Effect': 'Allow', 'Action': 's3:*', 'NotResource': 'arn:aws:s3:::secret/*'},
    {'Effect': 'Allow', 'Action': 'iam:*', 'Resource': 'arn:aws:iam::111122223333:role/r'},
    {'Effect': 'Allow', 'Action': 'sts:*', 'Resource': 'arn:aws:iam::111122223333:role/other'},
    {'Effect': 'Allow', 'Action': '*', 'Resource': 'arn:aws:s3:::app-bucket/*'},
    [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': 'arn:aws:s3:::app-bucket/*'},
     {'Effect': 'Allow', 'Action': 'ec2:*', 'Resource': '*'}],
])
def test_ecs_admin_level_still_fails(statement):
    assert _ecsRun(statement)[0] == -1


def test_ecs_reporter_mentions_scoped_wildcards_are_informational():
    d = _reporter('ecs')[ECS_KEY]['^description']
    assert 'on all resources' in d and 'informational' in d


# --------------------------------------------------------------------------- #
# acm: pcaRevocationNotConfigured with RevocationConfiguration absent
# --------------------------------------------------------------------------- #
from services.acm.drivers.AcmPcaCa import AcmPcaCa  # noqa: E402


def _pca(**over):
    now = datetime.datetime.now(timezone.utc)
    ca = {'Arn': 'arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/11111111-2222-3333-4444-555555555555',
          'Type': 'ROOT', 'Status': 'ACTIVE', 'NotBefore': now, 'NotAfter': now + timedelta(days=3650),
          'UsageMode': 'GENERAL_PURPOSE'}
    ca.update(over)
    return ca


def _pcaRun(ca):
    d = AcmPcaCa(ca, None)
    d._checkPcaRevocationNotConfigured()
    return d.results['pcaRevocationNotConfigured']


def test_acm_pca_absent_revocation_configuration_fails():
    ## describe_certificate_authority succeeded (Status ACTIVE was read); the optional
    ## RevocationConfiguration block is absent => revocation was never configured.
    c = boto3.client('acm-pca', **KW)
    with Stubber(c) as st:
        st.add_response('describe_certificate_authority', {'CertificateAuthority': _pca()},
                        {'CertificateAuthorityArn': _pca()['Arn']})
        ca = c.describe_certificate_authority(CertificateAuthorityArn=_pca()['Arn'])['CertificateAuthority']
    assert 'RevocationConfiguration' not in ca
    assert _pcaRun(ca) == [-1, 'Neither CRL nor OCSP revocation is enabled']


def test_acm_pca_revocation_states_locked():
    assert _pcaRun(_pca(RevocationConfiguration={'OcspConfiguration': {'Enabled': True}}))[0] == 1
    assert _pcaRun(_pca(RevocationConfiguration={'CrlConfiguration': {'Enabled': False}}))[0] == -1
    assert _pcaRun(_pca(Status='DISABLED'))[0] == 0


# --------------------------------------------------------------------------- #
# dms: Kafka endpoint with no SecurityProtocol (plaintext default)
# --------------------------------------------------------------------------- #
from services.dms.drivers.DmsEndpoint import DmsEndpoint  # noqa: E402


def _dmsRun(**over):
    ep = {'EndpointIdentifier': 'k', 'EndpointArn': 'arn:aws:dms:us-east-1:111122223333:endpoint:K',
          'EndpointType': 'target', 'EngineName': 'kafka', 'SslMode': 'none'}
    ep.update(over)
    c = boto3.client('dms', **KW)
    with Stubber(c) as st:
        st.add_response('describe_endpoints', {'Endpoints': [ep]}, {})
        ep = c.describe_endpoints()['Endpoints'][0]
    d = DmsEndpoint(ep, None)
    d._checkDmsEndpointSslNone()
    return d.results['dmsEndpointSslNone']


def test_dms_kafka_broker_without_security_protocol_fails():
    r = _dmsRun(KafkaSettings={'Broker': 'b-1.example:9092', 'Topic': 't'})
    assert r[0] == -1 and 'plaintext' in r[1], r


def test_dms_kafka_settings_absent_is_unable_to_evaluate():
    assert _dmsRun()[0] == 0


def test_dms_kafka_tls_protocol_passes():
    assert _dmsRun(KafkaSettings={'Broker': 'b:9094', 'SecurityProtocol': 'ssl-encryption'})[0] == 1


# --------------------------------------------------------------------------- #
# inspector: class-level suppression criteria are broad
# --------------------------------------------------------------------------- #
from services.inspector.drivers.InspectorCommon import InspectorCommon  # noqa: E402

EQ = lambda *v: [{'comparison': 'EQUALS', 'value': x} for x in v]  # noqa: E731


def _insRun(criteria):
    c = boto3.client('inspector2', **KW)
    now = datetime.datetime(2026, 1, 1, tzinfo=timezone.utc)
    with Stubber(c) as st:
        st.add_response('list_filters', {'filters': [{
            'arn': 'arn:aws:inspector2:us-east-1:111111111111:owner/111111111111/filter/1',
            'ownerId': '111111111111', 'name': 'f', 'criteria': criteria, 'action': 'SUPPRESS',
            'createdAt': now, 'updatedAt': now}]}, {'action': 'SUPPRESS'})
        d = InspectorCommon({'_region': 'us-east-1', '_accountStatus': {
            'accountId': '111111111111', 'state': {'status': 'ENABLED'}, 'resourceState': {}}}, c)
        d._checkInspectorSuppressionBroad()
    return d.results['inspectorSuppressionBroad'][0]


@pytest.mark.parametrize('criteria', [
    {'fixAvailable': EQ('NO')},
    {'exploitAvailable': EQ('NO')},
    {'componentType': EQ('jar')},
    {'vulnerabilitySource': EQ('NVD')},
    {'severity': EQ('CRITICAL'), 'fixAvailable': EQ('NO')},
])
def test_inspector_class_level_suppression_is_broad(criteria):
    assert _insRun(criteria) == -1


@pytest.mark.parametrize('criteria', [
    {'fixAvailable': EQ('NO'), 'vulnerabilityId': EQ('CVE-2024-0001')},
    {'exploitAvailable': EQ('NO'), 'resourceId': EQ('i-0123')},
])
def test_inspector_class_level_with_scoping_is_narrow(criteria):
    assert _insRun(criteria) == 1


# --------------------------------------------------------------------------- #
# cloudfront: TLSv1.2_2018/2019 wording
# --------------------------------------------------------------------------- #
from services.cloudfront.drivers.cloudfrontDist import cloudfrontDist  # noqa: E402


def _cfRun(minProto):
    obj = cloudfrontDist.__new__(cloudfrontDist)
    obj.results = {}
    obj.distConfig = {'DistributionConfig': {
        'ViewerCertificate': {'CloudFrontDefaultCertificate': False, 'SSLSupportMethod': 'sni-only',
                              'ACMCertificateArn': 'arn:aws:acm:us-east-1:1:certificate/x',
                              'MinimumProtocolVersion': minProto},
        'Origins': {'Quantity': 0, 'Items': []}}}
    obj._checkViewerMinTlsOld()
    return obj.results['cloudfrontViewerMinTlsOld']


@pytest.mark.parametrize('proto', ['TLSv1.2_2018', 'TLSv1.2_2019'])
def test_cloudfront_tls12_legacy_policy_message_not_older_than_12(proto):
    r = _cfRun(proto)
    assert r[0] == -1
    assert 'TLS 1.2 minimum' in r[1] and 'legacy cipher' in r[1] and 'older than 1.2' not in r[1]


@pytest.mark.parametrize('proto', ['TLSv1', 'TLSv1_2016', 'TLSv1.1_2016'])
def test_cloudfront_pre12_policy_message_says_older(proto):
    r = _cfRun(proto)
    assert r[0] == -1 and 'allows TLS older than 1.2' in r[1]


def test_cloudfront_reporter_covers_legacy_cipher_case():
    d = _reporter('cloudfront')['cloudfrontViewerMinTlsOld']['^description']
    assert 'TLSv1.2_2018 and TLSv1.2_2019 require TLS 1.2 but still offer legacy cipher suites' in d
    assert 'allow TLS versions older than TLS 1.2: either' not in d


# --------------------------------------------------------------------------- #
# sagemaker: checkpoint resume keeps in-use configs/models
# --------------------------------------------------------------------------- #
from unittest.mock import MagicMock  # noqa: E402
from services.sagemaker.Sagemaker import Sagemaker  # noqa: E402


class _Pag:
    def __init__(self, key, items):
        self.key, self.items = key, items

    def paginate(self, **kw):
        yield {self.key: list(self.items)}


def _smService(done):
    """done: set of checkpoint ids already completed in an earlier run."""
    Config.set('_SS_PARAMS', {'others': '{"sagemakerHistoryLimit": 1}'})
    s = Sagemaker.__new__(Sagemaker)
    s.tags, s.region = [], 'us-east-1'
    s.registerItems = lambda objType, items, idFn=None: [x for x in items if idFn(x) not in done]
    t = datetime.datetime(2026, 1, 1)
    data = {
        'list_endpoints': ('Endpoints', [{'EndpointName': 'ep1', 'CreationTime': t}]),
        'list_notebook_instances': ('NotebookInstances', []),
        ## newest first; cap 1 => only cfgNew listed; cfgOld (in use) is older than the cap
        'list_endpoint_configs': ('EndpointConfigs', [{'EndpointConfigName': 'cfgNew', 'CreationTime': t},
                                                      {'EndpointConfigName': 'cfgOld', 'CreationTime': t}]),
        'list_models': ('Models', [{'ModelName': 'mNew', 'CreationTime': t}, {'ModelName': 'mOld', 'CreationTime': t}]),
        'list_training_jobs': ('TrainingJobSummaries', []),
        'list_hyper_parameter_tuning_jobs': ('HyperParameterTuningJobSummaries', []),
    }
    c = MagicMock()
    c.get_paginator.side_effect = lambda op: _Pag(*data[op])
    c.describe_endpoint.side_effect = lambda EndpointName: {
        'EndpointName': EndpointName, 'EndpointArn': 'arn:ep', 'EndpointConfigName': 'cfgOld'}
    c.describe_endpoint_config.side_effect = lambda EndpointConfigName: {
        'EndpointConfigName': EndpointConfigName, 'EndpointConfigArn': 'arn:cfg',
        'ProductionVariants': [{'ModelName': 'mOld' if EndpointConfigName == 'cfgOld' else 'mNew'}]}
    c.describe_model.side_effect = lambda ModelName: {'ModelName': ModelName, 'ModelArn': 'arn:m'}
    s.sagemakerClient = c
    return s


@pytest.fixture
def _smCleanup():
    yield
    Config.set('_SS_PARAMS', {})


def test_sagemaker_fresh_scan_includes_in_use(_smCleanup):
    r = _smService(set()).getResources()
    assert {c['EndpointConfigName'] for c in r['endpointConfigs']} == {'cfgNew', 'cfgOld'}
    assert {m['ModelName'] for m in r['models']} == {'mNew', 'mOld'}


def test_sagemaker_resume_keeps_checkpointed_in_use_config_and_model(_smCleanup):
    ## Earlier run finished the endpoint, the old in-use config and the old in-use model.
    r = _smService({'Endpoint::ep1', 'EndpointConfig::cfgOld', 'Model::mOld'}).getResources()
    assert 'cfgOld' in {c['EndpointConfigName'] for c in r['endpointConfigs']}
    assert 'mOld' in {m['ModelName'] for m in r['models']}


def test_sagemaker_resume_checkpointed_endpoint_still_pulls_in_use_config(_smCleanup):
    ## Only the endpoint was checkpointed: its list summary has no EndpointConfigName,
    ## but its old config and model must still be scanned.
    s = _smService({'Endpoint::ep1'})
    r = s.getResources()
    assert 'cfgOld' in {c['EndpointConfigName'] for c in r['endpointConfigs'] if 'EndpointConfigArn' in c}
    assert 'mOld' in {m['ModelName'] for m in r['models'] if 'ModelArn' in m}

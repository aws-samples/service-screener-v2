"""
Stubber flag -> fix tests for the VPC Lattice checks.

Why Stubber and not the emulator: the AWS Emulator returns NotImplemented for
vpc-lattice ListServiceNetworks, ListAccessLogSubscriptions, GetAuthPolicy,
PutAuthPolicy and UpdateService, so neither latticeAccessLogsDisabled nor the
service-network / auth-policy paths of latticeAuthTypeNone can be driven
there. These tests drive the real driver classes with a real boto3
vpc-lattice client wrapped by botocore.stub.Stubber, so request and response
shapes are validated against the botocore service model. No network calls
are made (any un-stubbed call fails the test).
"""
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.vpclattice.drivers.VpclatticeService import VpclatticeService  # noqa: E402
from services.vpclattice.drivers.VpclatticeServiceNetwork import VpclatticeServiceNetwork  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

ACCT = '111122223333'
SVC_ARN = f'arn:aws:vpc-lattice:us-east-1:{ACCT}:service/svc-0123456789abcdef0'
SN_ARN = f'arn:aws:vpc-lattice:us-east-1:{ACCT}:servicenetwork/sn-0123456789abcdef0'
SN2_ARN = f'arn:aws:vpc-lattice:us-east-1:{ACCT}:servicenetwork/sn-0123456789abcdef1'
LOG_DEST = f'arn:aws:logs:us-east-1:{ACCT}:log-group:lattice'


def _client():
    return boto3.client('vpc-lattice', region_name='us-east-1',
                        aws_access_key_id='testing', aws_secret_access_key='testing')


def _svc(authType='NONE', arn=SVC_ARN):
    return {'id': arn.split('/')[-1], 'name': 'orders', 'arn': arn, 'authType': authType, 'status': 'ACTIVE'}


def _sn(authType='NONE', services=1, arn=SN_ARN):
    return {'id': arn.split('/')[-1], 'name': 'core', 'arn': arn, 'authType': authType,
            'numberOfAssociatedServices': services, 'numberOfAssociatedVPCs': 1}


def _als(resArn, logType=None):
    item = {'id': 'als-0123456789abcdef0',
            'arn': f'arn:aws:vpc-lattice:us-east-1:{ACCT}:accesslogsubscription/als-0123456789abcdef0',
            'resourceId': resArn.split('/')[-1], 'resourceArn': resArn,
            'destinationArn': LOG_DEST,
            'createdAt': '2026-01-01T00:00:00Z', 'lastUpdatedAt': '2026-01-01T00:00:00Z'}
    if logType:
        item['serviceNetworkLogType'] = logType
    return {'items': [item]}


def _assoc(snArn=SN_ARN):
    return {'items': [{'id': 'snsa-0123456789abcdef0', 'status': 'ACTIVE',
                       'serviceArn': SVC_ARN, 'serviceNetworkArn': snArn,
                       'serviceNetworkId': snArn.split('/')[-1]}]}


def _run(driverCls, resource, stubs, method):
    client = _client()
    with Stubber(client) as st:
        for op, resp, params in stubs:
            if isinstance(resp, tuple):
                st.add_client_error(op, service_error_code=resp[0], http_status_code=resp[1],
                                    expected_params=params)
            else:
                st.add_response(op, resp, params)
        obj = driverCls(resource, client, ACCT)
        getattr(obj, method)()
        st.assert_no_pending_responses()
    return obj.results


def _policy(*stmts):
    return json.dumps({'Version': '2012-10-17', 'Statement': list(stmts)})


OPEN_STMT = {'Sid': 'Open', 'Effect': 'Allow', 'Principal': '*', 'Action': 'vpc-lattice-svcs:Invoke', 'Resource': '*'}
ORG_STMT = {'Sid': 'Org', 'Effect': 'Allow', 'Principal': '*', 'Action': 'vpc-lattice-svcs:Invoke', 'Resource': '*',
            'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}}}


# --------------------------------------------------------------------------- #
# latticeAuthTypeNone
# --------------------------------------------------------------------------- #
AUTH = '_checkLatticeAuthTypeNone'
KEY_AUTH = 'latticeAuthTypeNone'


@pytest.mark.parametrize('cls,res,arn', [
    (VpclatticeService, _svc, SVC_ARN), (VpclatticeServiceNetwork, _sn, SN_ARN)])
def test_auth_none_flag_then_iam_policy_fix(cls, res, arn):
    flagged = _run(cls, res('NONE'), [], AUTH)
    assert flagged[KEY_AUTH][0] == -1

    fixed = _run(cls, res('AWS_IAM'), [
        ('get_auth_policy', {'policy': _policy(ORG_STMT), 'state': 'Active'}, {'resourceIdentifier': arn})], AUTH)
    assert fixed[KEY_AUTH][0] == 1


@pytest.mark.parametrize('cls,res,arn', [
    (VpclatticeService, _svc, SVC_ARN), (VpclatticeServiceNetwork, _sn, SN_ARN)])
def test_auth_iam_with_anonymous_policy_flag_then_fix(cls, res, arn):
    flagged = _run(cls, res('AWS_IAM'), [
        ('get_auth_policy', {'policy': _policy(OPEN_STMT), 'state': 'Active'}, {'resourceIdentifier': arn})], AUTH)
    assert flagged[KEY_AUTH][0] == -1

    fixed = _run(cls, res('AWS_IAM'), [
        ('get_auth_policy', {'policy': _policy(dict(OPEN_STMT, Condition={
            'StringNotEqualsIgnoreCase': {'aws:PrincipalType': 'Anonymous'}})), 'state': 'Active'},
         {'resourceIdentifier': arn})], AUTH)
    assert fixed[KEY_AUTH][0] == 1


def _auth(cls, res, arn, stmts):
    return _run(cls, res('AWS_IAM'), [
        ('get_auth_policy', {'policy': _policy(*stmts), 'state': 'Active'}, {'resourceIdentifier': arn})],
        AUTH)[KEY_AUTH][0]


VPC_STMT = dict(OPEN_STMT, Sid='Vpc', Condition={'StringEquals': {'vpc-lattice-svcs:SourceVpc': 'vpc-123'}})


@pytest.mark.parametrize('cls,res,arn', [
    (VpclatticeService, _svc, SVC_ARN), (VpclatticeServiceNetwork, _sn, SN_ARN)])
def test_auth_iam_source_vpc_only_condition_flag_then_fix(cls, res, arn):
    # SourceVpc is satisfiable by unsigned callers in that VPC -> still anonymous.
    assert _auth(cls, res, arn, [VPC_STMT]) == -1
    # Fix: also require an authenticated principal from the org.
    fixed = dict(VPC_STMT, Condition={
        'StringEquals': {'vpc-lattice-svcs:SourceVpc': 'vpc-123', 'aws:PrincipalOrgID': 'o-abc123defg'}})
    assert _auth(cls, res, arn, [fixed]) == 1


@pytest.mark.parametrize('condition', [
    {'StringEquals': {'vpc-lattice-svcs:ServiceNetworkArn': SN_ARN}},
    {'StringEquals': {'vpc-lattice-svcs:SourceVpcOwnerAccount': ACCT}},
    {'IpAddress': {'aws:SourceIp': '10.0.0.0/8'}},
    # negated operators on keys anonymous callers lack evaluate true
    {'StringNotEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}},
    {'ArnNotLike': {'aws:PrincipalArn': 'arn:aws:iam::999999999999:*'}},
    # IfExists / ForAllValues evaluate true when the key is missing
    {'StringEqualsIfExists': {'aws:PrincipalAccount': ACCT}},
    {'ForAllValues:StringLike': {'aws:PrincipalOrgPaths': 'o-abc123defg/*'}},
    {'StringNotEquals': {'aws:PrincipalType': 'anonymous'}},  # case-sensitive: does not match
    {'StringEquals': {'aws:PrincipalType': ['AssumedRole', 'Anonymous']}},
])
def test_auth_conditions_that_still_admit_anonymous(condition):
    assert _auth(VpclatticeService, _svc, SVC_ARN, [dict(OPEN_STMT, Condition=condition)]) == -1


@pytest.mark.parametrize('condition', [
    {'StringEquals': {'aws:PrincipalAccount': ACCT}},
    {'ArnLike': {'aws:PrincipalArn': f'arn:aws:iam::{ACCT}:role/*'}},
    {'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': 'o-abc123defg/*'}},
    {'StringEquals': {'aws:PrincipalTag/team': 'orders'}},
    {'Null': {'aws:PrincipalArn': 'false'}},
    {'StringNotEquals': {'aws:PrincipalType': 'Anonymous'}},
    {'StringEquals': {'aws:PrincipalType': 'AssumedRole'}},
])
def test_auth_conditions_that_exclude_anonymous(condition):
    assert _auth(VpclatticeService, _svc, SVC_ARN, [dict(OPEN_STMT, Condition=condition)]) == 1


@pytest.mark.parametrize('deny_condition,expected', [
    ({'StringEquals': {'aws:PrincipalType': 'Anonymous'}}, 1),
    ({'StringNotEquals': {'aws:PrincipalOrgID': 'o-abc123defg'}}, 1),
    ({'Null': {'aws:PrincipalArn': 'true'}}, 1),
    # Deny scoped by a key anonymous callers may not match does not block them all
    ({'StringNotEquals': {'vpc-lattice-svcs:SourceVpc': 'vpc-123'}}, -1),
])
def test_auth_explicit_deny_of_anonymous(deny_condition, expected):
    deny = {'Sid': 'DenyAnon', 'Effect': 'Deny', 'Principal': '*', 'Action': 'vpc-lattice-svcs:Invoke',
            'Resource': '*', 'Condition': deny_condition}
    assert _auth(VpclatticeService, _svc, SVC_ARN, [VPC_STMT, deny]) == expected


def test_auth_iam_without_policy_is_deny_all_not_flagged():
    r = _run(VpclatticeService, _svc('AWS_IAM'), [
        ('get_auth_policy', ('ResourceNotFoundException', 404), {'resourceIdentifier': SVC_ARN})], AUTH)
    assert r[KEY_AUTH][0] == 1
    r = _run(VpclatticeService, _svc('AWS_IAM'), [
        ('get_auth_policy', {}, {'resourceIdentifier': SVC_ARN})], AUTH)
    assert r[KEY_AUTH][0] == 1


def test_auth_policy_unreadable_is_not_evaluable():
    r = _run(VpclatticeService, _svc('AWS_IAM'), [
        ('get_auth_policy', ('AccessDeniedException', 403), {'resourceIdentifier': SVC_ARN})], AUTH)
    assert r[KEY_AUTH] == [0, 'Unable to evaluate (AccessDeniedException)']


def test_auth_shared_resource_not_evaluated():
    other = 'arn:aws:vpc-lattice:us-east-1:999999999999:service/svc-0123456789abcdef9'
    r = _run(VpclatticeService, _svc('NONE', arn=other), [], AUTH)
    assert r[KEY_AUTH][0] == 0


# --------------------------------------------------------------------------- #
# latticeAccessLogsDisabled
# --------------------------------------------------------------------------- #
LOGS = '_checkLatticeAccessLogsDisabled'
KEY_LOGS = 'latticeAccessLogsDisabled'


def test_sn_access_logs_flag_then_fix():
    flagged = _run(VpclatticeServiceNetwork, _sn(), [
        ('list_access_log_subscriptions', {'items': []}, {'resourceIdentifier': SN_ARN})], LOGS)
    assert flagged[KEY_LOGS][0] == -1

    fixed = _run(VpclatticeServiceNetwork, _sn(), [
        ('list_access_log_subscriptions', _als(SN_ARN, 'SERVICE'), {'resourceIdentifier': SN_ARN})], LOGS)
    assert fixed[KEY_LOGS][0] == 1


def test_sn_resource_only_logs_flag_when_services_associated():
    flagged = _run(VpclatticeServiceNetwork, _sn(services=2), [
        ('list_access_log_subscriptions', _als(SN_ARN, 'RESOURCE'), {'resourceIdentifier': SN_ARN})], LOGS)
    assert flagged[KEY_LOGS][0] == -1
    ok = _run(VpclatticeServiceNetwork, _sn(services=0), [
        ('list_access_log_subscriptions', _als(SN_ARN, 'RESOURCE'), {'resourceIdentifier': SN_ARN})], LOGS)
    assert ok[KEY_LOGS][0] == 1


def test_service_access_logs_flag_then_fix():
    # No own subscription, associated network does not log -> FAIL
    flagged = _run(VpclatticeService, _svc(), [
        ('list_access_log_subscriptions', {'items': []}, {'resourceIdentifier': SVC_ARN}),
        ('list_service_network_service_associations', _assoc(), {'serviceIdentifier': SVC_ARN}),
        ('list_access_log_subscriptions', {'items': []}, {'resourceIdentifier': SN_ARN})], LOGS)
    assert flagged[KEY_LOGS][0] == -1

    # Fix A: subscription on the service itself
    fixed = _run(VpclatticeService, _svc(), [
        ('list_access_log_subscriptions', _als(SVC_ARN), {'resourceIdentifier': SVC_ARN})], LOGS)
    assert fixed[KEY_LOGS][0] == 1

    # Fix B: subscription on the associated service network
    fixed = _run(VpclatticeService, _svc(), [
        ('list_access_log_subscriptions', {'items': []}, {'resourceIdentifier': SVC_ARN}),
        ('list_service_network_service_associations', _assoc(), {'serviceIdentifier': SVC_ARN}),
        ('list_access_log_subscriptions', _als(SN_ARN, 'SERVICE'), {'resourceIdentifier': SN_ARN})], LOGS)
    assert fixed[KEY_LOGS][0] == 1


def test_service_unassociated_without_logs_is_info():
    # An unassociated service receives no Lattice traffic -> INFO, not a finding.
    r = _run(VpclatticeService, _svc(), [
        ('list_access_log_subscriptions', {'items': []}, {'resourceIdentifier': SVC_ARN}),
        ('list_service_network_service_associations', {'items': []}, {'serviceIdentifier': SVC_ARN})], LOGS)
    assert r[KEY_LOGS][0] == 0


def test_service_logs_unreadable_is_not_evaluable():
    r = _run(VpclatticeService, _svc(), [
        ('list_access_log_subscriptions', ('AccessDeniedException', 403), {'resourceIdentifier': SVC_ARN})], LOGS)
    assert r[KEY_LOGS] == [0, 'Unable to evaluate (AccessDeniedException)']
    # Associated network logs unreadable (e.g. cross-account network) -> INFO, not FAIL
    r = _run(VpclatticeService, _svc(), [
        ('list_access_log_subscriptions', {'items': []}, {'resourceIdentifier': SVC_ARN}),
        ('list_service_network_service_associations', _assoc(SN2_ARN), {'serviceIdentifier': SVC_ARN}),
        ('list_access_log_subscriptions', ('AccessDeniedException', 403), {'resourceIdentifier': SN2_ARN})], LOGS)
    assert r[KEY_LOGS][0] == 0


def test_auth_none_update_service_in_place_flag_then_pass():
    """In-place remediation of the SAME service (UpdateService / PutAuthPolicy are
    NotImplemented in the emulator): authType NONE -> FAIL; UpdateService(authType=AWS_IAM) and
    PutAuthPolicy with an org-scoped policy; the re-scan reads GetService (AWS_IAM) and
    GetAuthPolicy -> PASS."""
    flagged = _run(VpclatticeService, _svc('NONE'), [], AUTH)
    assert flagged[KEY_AUTH][0] == -1

    client = _client()
    pol = _policy(ORG_STMT)
    with Stubber(client) as st:
        st.add_response('update_service', {'id': _svc()['id'], 'arn': SVC_ARN, 'name': 'orders',
                                           'authType': 'AWS_IAM'},
                        {'serviceIdentifier': SVC_ARN, 'authType': 'AWS_IAM'})
        st.add_response('put_auth_policy', {'policy': pol, 'state': 'Active'},
                        {'resourceIdentifier': SVC_ARN, 'policy': pol})
        st.add_response('get_service', _svc('AWS_IAM'), {'serviceIdentifier': SVC_ARN})
        client.update_service(serviceIdentifier=SVC_ARN, authType='AWS_IAM')
        client.put_auth_policy(resourceIdentifier=SVC_ARN, policy=pol)
        rescanned = client.get_service(serviceIdentifier=SVC_ARN)
        st.assert_no_pending_responses()
    rescanned.pop('ResponseMetadata', None)
    assert rescanned['authType'] == 'AWS_IAM'

    fixed = _run(VpclatticeService, rescanned, [
        ('get_auth_policy', {'policy': pol, 'state': 'Active'}, {'resourceIdentifier': SVC_ARN})], AUTH)
    assert fixed[KEY_AUTH] == [1, 'AWS_IAM is enforced with an auth policy that does not allow anonymous callers']

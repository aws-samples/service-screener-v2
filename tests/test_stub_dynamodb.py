"""Stubber-based flag -> fix tests for WAFS2027 DynamoDB checks, covering paths the AWS
Emulator cannot drive.

Why not the emulator:
- dynamodbResourcePolicyPublic (wildcard principal paths): the emulator, like DynamoDB block
  public access, rejects PutResourcePolicy for ANY "*" principal, even with scoping conditions,
  so wildcard-with/without-condition, NotPrincipal, AccessDenied and unparseable-policy cases
  cannot be created there.
- dynamodbNoMultiRegionReplica (legacy 2017.11.29 global tables, AccessDenied on tags): legacy
  global tables cannot be created in the emulator, and IAM is not evaluated.

Every client is a real botocore client (real API shapes / parameter validation) wrapped by
botocore.stub.Stubber, pointed at an unroutable loopback endpoint with dummy credentials, so no
request can leave the process.
"""
import json
import os
import sys

import botocore.session
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.dynamodb.drivers.DynamoDbCommon import DynamoDbCommon, resourcePolicyIssues  # noqa: E402

# Evaluator.__del__ writes to __fork/error.txt, which only exists in a full scan run.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

SELF = '111111111111'
OTHER = '222222222222'
TABLE = 'orders'
TABLE_ARN = f'arn:aws:dynamodb:us-east-1:{SELF}:table/{TABLE}'
STREAM_ARN = TABLE_ARN + '/stream/2026-11-17T00:00:00.000'


def _client():
    return botocore.session.get_session().create_client(
        'dynamodb', region_name='us-east-1', endpoint_url='https://127.0.0.1:1',
        aws_access_key_id='testing', aws_secret_access_key='testing')


def _table(**extra):
    t = {'TableName': TABLE, 'TableArn': TABLE_ARN, 'TableStatus': 'ACTIVE'}
    t.update(extra)
    return {'Table': t}


def _doc(*stmts):
    return json.dumps({'Version': '2012-10-17', 'Statement': list(stmts)})


def _stmt(principal=None, condition=None, effect='Allow', notPrincipal=None):
    s = {'Effect': effect, 'Action': 'dynamodb:*', 'Resource': TABLE_ARN}
    if principal is not None:
        s['Principal'] = principal
    if notPrincipal is not None:
        s['NotPrincipal'] = notPrincipal
    if condition is not None:
        s['Condition'] = condition
    return s


def _notFound(st, arn):
    st.add_client_error('get_resource_policy', 'PolicyNotFoundException', 'not found',
                        expected_params={'ResourceArn': arn})


def _runPolicy(responses, table=None):
    """responses: list of (arn, policyDoc | ('error', code))"""
    ddb = _client()
    with Stubber(ddb) as st:
        for arn, resp in responses:
            if isinstance(resp, tuple):
                st.add_client_error('get_resource_policy', resp[1], 'x', expected_params={'ResourceArn': arn})
            elif resp is None:
                _notFound(st, arn)
            else:
                st.add_response('get_resource_policy', {'Policy': resp, 'RevisionId': '1'}, {'ResourceArn': arn})
        drv = DynamoDbCommon(table or _table(), ddb, None, None, None, None, None)
        drv._checkDynamodbResourcePolicyPublic()
        st.assert_no_pending_responses()
    return drv.results['dynamodbResourcePolicyPublic']


# --------------------------------------------------------------------------- #
# dynamodbResourcePolicyPublic
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize('principal', ['*', {'AWS': '*'}, {'AWS': ['*']}, {'AWS': [f'arn:aws:iam::{SELF}:root', '*']}])
def test_wildcard_principal_flag_then_fix(principal):
    bad = _runPolicy([(TABLE_ARN, _doc(_stmt(principal)))])
    assert bad[0] == -1 and 'any principal' in bad[1]
    good = _runPolicy([(TABLE_ARN, _doc(_stmt(principal, {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123def4'}})))])
    assert good[0] == 1


def test_not_principal_allow_flags():
    assert _runPolicy([(TABLE_ARN, _doc(_stmt(notPrincipal={'AWS': f'arn:aws:iam::{SELF}:root'})))])[0] == -1


@pytest.mark.parametrize('condition,expected', [
    ({'StringEqualsIfExists': {'aws:PrincipalOrgID': 'o-abc123def4'}}, -1),
    ({'StringNotEquals': {'aws:PrincipalOrgID': 'o-abc123def4'}}, -1),
    ({'StringLike': {'aws:PrincipalOrgID': '*'}}, -1),
    ({'StringEquals': {'aws:UserAgent': 'x'}}, -1),
    ({'IpAddress': {'aws:SourceIp': '0.0.0.0/0'}}, -1),
    ({'IpAddress': {'aws:SourceIp': '203.0.113.0/24'}}, 1),
    ({'StringEquals': {'aws:SourceVpce': 'vpce-0123456789abcdef0'}}, 1),
    ({'StringEquals': {'aws:PrincipalAccount': SELF}}, 1),
])
def test_wildcard_condition_scoping(condition, expected):
    assert _runPolicy([(TABLE_ARN, _doc(_stmt('*', condition)))])[0] == expected


@pytest.mark.parametrize('principal', [
    {'AWS': f'arn:aws:iam::{OTHER}:root'},
    {'AWS': OTHER},
    {'AWS': [f'arn:aws:iam::{SELF}:role/app', f'arn:aws:iam::{OTHER}:role/reader']},
    {'AWS': f'arn:aws:sts::{OTHER}:assumed-role/r/s'},
])
def test_cross_account_flag_then_fix(principal):
    bad = _runPolicy([(TABLE_ARN, _doc(_stmt(principal)))])
    assert bad[0] == -1 and OTHER in bad[1]
    good = _runPolicy([(TABLE_ARN, _doc(_stmt(principal, {'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': 'o-abc123def4/r-ab12/*'}})))])
    assert good[0] == 1


@pytest.mark.parametrize('stmt', [
    _stmt({'AWS': f'arn:aws:iam::{SELF}:role/app'}),
    _stmt({'Service': 'dynamodb.amazonaws.com'}),
    _stmt('*', effect='Deny'),
    _stmt({'AWS': f'arn:aws:iam::{OTHER}:root'}, effect='Deny'),
])
def test_non_public_statements_pass(stmt):
    assert _runPolicy([(TABLE_ARN, _doc(stmt))])[0] == 1


def test_no_policy_passes():
    assert _runPolicy([(TABLE_ARN, None)]) == [1, '']


def test_stream_policy_flag_then_fix():
    table = _table(LatestStreamArn=STREAM_ARN)
    bad = _runPolicy([(TABLE_ARN, None), (STREAM_ARN, _doc(_stmt({'AWS': OTHER})))], table)
    assert bad[0] == -1 and bad[1].startswith('stream policy')
    good = _runPolicy([(TABLE_ARN, None), (STREAM_ARN, None)], table)
    assert good[0] == 1


def test_access_denied_is_not_pass():
    res = _runPolicy([(TABLE_ARN, ('error', 'AccessDeniedException'))])
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']


def test_finding_wins_over_error():
    table = _table(LatestStreamArn=STREAM_ARN)
    res = _runPolicy([(TABLE_ARN, _doc(_stmt('*'))), (STREAM_ARN, ('error', 'AccessDeniedException'))], table)
    assert res[0] == -1


def test_unparseable_policy_is_not_pass():
    assert _runPolicy([(TABLE_ARN, 'not json')])[0] == 0
    assert resourcePolicyIssues('not json', SELF) is None


# --------------------------------------------------------------------------- #
# dynamodbNoMultiRegionReplica
# --------------------------------------------------------------------------- #
def _runReplica(table, tags=None, tagError=None, globalTable=None, globalError=None):
    ddb = _client()
    with Stubber(ddb) as st:
        if globalTable is not None:
            st.add_response('describe_global_table', {'GlobalTableDescription': globalTable}, {'GlobalTableName': TABLE})
        elif globalError:
            st.add_client_error('describe_global_table', globalError, 'x', expected_params={'GlobalTableName': TABLE})
        if tagError:
            st.add_client_error('list_tags_of_resource', tagError, 'x', expected_params={'ResourceArn': TABLE_ARN})
        elif tags is not None:
            st.add_response('list_tags_of_resource', {'Tags': tags}, {'ResourceArn': TABLE_ARN})
        drv = DynamoDbCommon(table, ddb, None, None, None, None, None)
        drv._checkDynamodbNoMultiRegionReplica()
        st.assert_no_pending_responses()
    return drv.results['dynamodbNoMultiRegionReplica']


@pytest.mark.parametrize('tag', [
    {'Key': 'criticality', 'Value': 'high'},
    {'Key': 'Business-Criticality', 'Value': 'Mission Critical'},
    {'Key': 'Tier', 'Value': 'tier-1'},
    {'Key': 'tier', 'Value': '0'},
])
def test_critical_table_without_replica_flag_then_fix(tag):
    bad = _runReplica(_table(), tags=[{'Key': 'team', 'Value': 'x'}, tag])
    assert bad[0] == -1
    good = _runReplica(_table(GlobalTableVersion='2019.11.21',
                              Replicas=[{'RegionName': 'us-west-2', 'ReplicaStatus': 'ACTIVE'}]))
    assert good[0] == 1 and 'us-west-2' in good[1]


def test_untagged_table_is_info_only():
    assert _runReplica(_table(), tags=[{'Key': 'tier', 'Value': 'web'}])[0] == 0


def test_deleting_replica_does_not_count():
    res = _runReplica(_table(Replicas=[{'RegionName': 'us-west-2', 'ReplicaStatus': 'DELETING'}]),
                      tags=[{'Key': 'criticality', 'Value': 'critical'}])
    assert res[0] == -1


def test_legacy_global_table_replicas_pass():
    res = _runReplica(_table(GlobalTableVersion='2017.11.29'), globalTable={
        'GlobalTableName': TABLE,
        'ReplicationGroup': [{'RegionName': 'us-east-1'}, {'RegionName': 'eu-west-1'}]})
    assert res[0] == 1 and 'eu-west-1' in res[1]


def test_legacy_global_table_error_is_not_pass():
    res = _runReplica(_table(GlobalTableVersion='2017.11.29'), globalError='AccessDeniedException')
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']


def test_tag_access_denied_is_not_pass():
    res = _runReplica(_table(), tagError='AccessDeniedException')
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']

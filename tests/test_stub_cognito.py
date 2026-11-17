"""
Stubber-based tests for WAFS2027 Cognito checks: the paths the emulator cannot
produce (AccessDenied on reads, cross-account guest roles, permissions
boundaries, composite-alarm notification paths, list failures).

They drive the real Cognito service helpers with real boto3 clients wrapped in
botocore.stub.Stubber (so request/response shapes are validated against the
service models) and then the real driver classes. Nothing leaves the process.
"""
import datetime
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Config import Config  # noqa: E402
from services.cognito.Cognito import Cognito  # noqa: E402
from services.cognito.drivers.CognitoIdentityPool import CognitoIdentityPool  # noqa: E402
from services.cognito.drivers.CognitoAccount import CognitoAccount  # noqa: E402
from services.cognito.drivers.CognitoCommon import CognitoCommon  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

ACCOUNT = '111111111111'
IPID = 'us-east-1:11111111-2222-3333-4444-555555555555'
ROLE_ARN = f'arn:aws:iam::{ACCOUNT}:role/guest'
ADMIN = 'arn:aws:iam::aws:policy/AdministratorAccess'
NOW = datetime.datetime(2026, 1, 1)


def _client(name):
    return boto3.session.Session(aws_access_key_id='x', aws_secret_access_key='y',
                                 region_name='us-east-1').client(name)


class _Svc(Cognito):
    def __del__(self):  # Service.__del__ writes scan output files; not wanted here
        pass


@pytest.fixture
def svc():
    Config.set('stsInfo', {'Account': ACCOUNT})
    s = object.__new__(_Svc)         # skip Service.__init__ (needs a scan session)
    s.region = 'us-east-1'
    s.RULESPREFIX = 'Cognito::rules'
    s.tags = None
    s._enumErrors, s._skippedPools, s._listPoolsError = {}, [], None
    s.iamClient = _client('iam')
    s.identityClient = _client('cognito-identity')
    s.cwClient = _client('cloudwatch')
    s.cognitoClient = _client('cognito-idp')
    yield s
    Config.set('stsInfo', {})


def _run(driver, method):
    getattr(driver, method)()
    return next(iter(driver.results.values()))


def _guestPool(**extra):
    p = {'IdentityPoolId': IPID, 'IdentityPoolName': 'p', 'AllowUnauthenticatedIdentities': True,
         '_resourceName': 'p'}
    p.update(extra)
    return p


def _stubRole(st, attached=(), inline=None, boundary=None):
    role = {'Path': '/', 'RoleName': 'guest', 'RoleId': 'ROLEIDFORUNITTEST01', 'Arn': ROLE_ARN,
            'CreateDate': NOW}
    if boundary:
        role['PermissionsBoundary'] = {'PermissionsBoundaryType': 'Policy',
                                       'PermissionsBoundaryArn': boundary[0]}
    st.add_response('get_role', {'Role': role}, {'RoleName': 'guest'})
    st.add_response('list_role_policies', {'PolicyNames': [inline[0]] if inline else []},
                    {'RoleName': 'guest'})
    if inline:
        st.add_response('get_role_policy', {'RoleName': 'guest', 'PolicyName': inline[0],
                                            'PolicyDocument': inline[1]},
                        {'RoleName': 'guest', 'PolicyName': inline[0]})
    st.add_response('list_attached_role_policies', {'AttachedPolicies': [
        {'PolicyName': a[0].split('/')[-1], 'PolicyArn': a[0]} for a in attached]}, {'RoleName': 'guest'})
    for arn, doc in list(attached) + ([boundary] if boundary else []):
        st.add_response('get_policy', {'Policy': {'PolicyName': arn.split('/')[-1], 'Arn': arn,
                                                  'DefaultVersionId': 'v1'}}, {'PolicyArn': arn})
        st.add_response('get_policy_version', {'PolicyVersion': {'Document': doc, 'VersionId': 'v1'}},
                        {'PolicyArn': arn, 'VersionId': 'v1'})


ALLOW_ALL = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
SCOPED = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'


# --------------------------------------------------------------------------- #
# cognitoIdentityPoolGuestRoleBroad
# --------------------------------------------------------------------------- #
def test_guest_role_admin_fails_scoped_passes(svc):
    with Stubber(svc.iamClient) as st:
        _stubRole(st, attached=[(ADMIN, ALLOW_ALL)])
        bad = svc._fetchRoleEvaluation(ROLE_ARN)
    with Stubber(svc.iamClient) as st:
        _stubRole(st, inline=('scoped', SCOPED))
        good = svc._fetchRoleEvaluation(ROLE_ARN)
    m = '_checkCognitoIdentityPoolGuestRoleBroad'
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=bad)), m)[0] == -1
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=good)), m)[0] == 1


def test_guest_role_not_action_fails(svc):
    doc = '{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}'
    with Stubber(svc.iamClient) as st:
        _stubRole(st, inline=('na', doc))
        role = svc._fetchRoleEvaluation(ROLE_ARN)
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=role)),
                '_checkCognitoIdentityPoolGuestRoleBroad')[0] == -1


def test_guest_role_capped_by_boundary_is_info(svc):
    bArn = f'arn:aws:iam::{ACCOUNT}:policy/guest-boundary'
    with Stubber(svc.iamClient) as st:
        _stubRole(st, attached=[(ADMIN, ALLOW_ALL)], boundary=(bArn, SCOPED))
        role = svc._fetchRoleEvaluation(ROLE_ARN)
    with Stubber(svc.iamClient) as st:
        _stubRole(st, attached=[(ADMIN, ALLOW_ALL)], boundary=(bArn, ALLOW_ALL))
        roleOpen = svc._fetchRoleEvaluation(ROLE_ARN)
    m = '_checkCognitoIdentityPoolGuestRoleBroad'
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=role)), m)[0] == 0
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=roleOpen)), m)[0] == -1


def test_guest_role_access_denied_is_unable_to_evaluate(svc):
    with Stubber(svc.iamClient) as st:
        st.add_client_error('get_role', 'AccessDenied', expected_params={'RoleName': 'guest'})
        role = svc._fetchRoleEvaluation(ROLE_ARN)
    r = _run(CognitoIdentityPool(_guestPool(_unauthRole=role)), '_checkCognitoIdentityPoolGuestRoleBroad')
    assert r == [0, 'Unable to evaluate (AccessDenied)']


def test_guest_role_cross_account_is_info(svc):
    role = svc._fetchRoleEvaluation('arn:aws:iam::222222222222:role/guest')
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=role)),
                '_checkCognitoIdentityPoolGuestRoleBroad')[0] == 0


def test_get_identity_pool_roles_denied_is_unable_to_evaluate(svc):
    detail = _guestPool()
    with Stubber(svc.identityClient) as st:
        st.add_client_error('get_identity_pool_roles', 'NotAuthorizedException',
                            expected_params={'IdentityPoolId': IPID})
        svc._hydrateIdentityPool(detail)
    for m in ('_checkCognitoIdentityPoolGuestRoleBroad', '_checkCognitoIdentityPoolNoRoleMapping'):
        assert _run(CognitoIdentityPool(dict(detail)), m) == [0, 'Unable to evaluate (NotAuthorizedException)']


SYNC_PER_IDENTITY = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cognito-sync:*"],'
                     '"Resource":["arn:aws:cognito-sync:us-east-1:111111111111:identitypool/'
                     '${cognito-identity.amazonaws.com:aud}/identity/${cognito-identity.amazonaws.com:sub}/*"]}]}')
SYNC_ALL_IDENTITIES = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cognito-sync:*"],'
                       '"Resource":["arn:aws:cognito-sync:us-east-1:111111111111:identitypool/'
                       '${cognito-identity.amazonaws.com:aud}/*"]}]}')


def test_guest_role_documented_per_identity_sync_policy_not_flagged(svc):
    """The Cognito 'IAM roles' guide grants cognito-sync:* on
    identitypool/${aud}/identity/${sub}/* - least privilege, must not be -1.
    The same wildcard on the whole pool (every identity's data) is -1."""
    m = '_checkCognitoIdentityPoolGuestRoleBroad'
    with Stubber(svc.iamClient) as st:
        _stubRole(st, inline=('sync', SYNC_ALL_IDENTITIES))
        bad = svc._fetchRoleEvaluation(ROLE_ARN)
    with Stubber(svc.iamClient) as st:
        _stubRole(st, inline=('sync', SYNC_PER_IDENTITY))
        good = svc._fetchRoleEvaluation(ROLE_ARN)
    r = _run(CognitoIdentityPool(_guestPool(_unauthRole=bad)), m)
    assert r[0] == -1 and 'shared by all guests' in r[1]
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=good)), m)[0] == 1


def test_policy_scope_rules():
    f = CognitoIdentityPool.policyBroadReasons
    sub = '${cognito-identity.amazonaws.com:sub}'
    # s3:* on a per-identity prefix: documented pattern -> not broad
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3:*',
                             'Resource': f'arn:aws:s3:::b/{sub}/*'}]}) == []
    # dynamodb:* with plain / ForAnyValue LeadingKeys = sub on '*': per-identity -> not broad
    for op in ('StringEquals', 'ForAnyValue:StringEquals', 'StringLike'):
        assert f({'Statement': [{'Effect': 'Allow', 'Action': 'dynamodb:*', 'Resource': '*',
                                 'Condition': {op: {'dynamodb:LeadingKeys': [sub]}}}]}) == [], op
    # ForAllValues is true when LeadingKeys is absent (DeleteTable, Scan...) -> broad
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 'dynamodb:*', 'Resource': '*',
                             'Condition': {'ForAllValues:StringEquals': {'dynamodb:LeadingKeys': [sub]}}}]})
    # ... unless a Null {key: false} companion requires the key to be present
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 'dynamodb:*', 'Resource': '*',
                             'Condition': {'ForAllValues:StringEquals': {'dynamodb:LeadingKeys': [sub]},
                                           'Null': {'dynamodb:LeadingKeys': 'false'}}}]}) == []
    # ...IfExists does not confine
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 'dynamodb:*', 'Resource': '*',
                             'Condition': {'StringEqualsIfExists': {'dynamodb:LeadingKeys': [sub]}}}]})
    # always-true / caller-controlled keys do not confine
    assert f({'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*',
                             'Condition': {'StringLike': {'cognito-identity.amazonaws.com:sub': sub}}}]})
    assert f({'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*',
                             'Condition': {'StringEquals': {'aws:RequestTag/owner': sub}}}]})
    # a value list where one value is not identity-based does not confine
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*',
                             'Condition': {'StringLike': {'s3:prefix': [f'{sub}/*', 'public/*']}}}]})
    # colon-less glob 's3*' matches every s3 action -> broad
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3*', 'Resource': '*'}]}) == ["Action 's3*'"]
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3:**', 'Resource': '*'}]}) == ["Action 's3:**'"]
    # ... and is narrowed by Deny s3:*
    lim = CognitoIdentityPool.denyLimits([{'Statement': [{'Effect': 'Deny', 'Action': 's3:*', 'Resource': '*'}]}])
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3*', 'Resource': '*'}]}, lim) == []
    # negated condition does not confine the caller
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 'dynamodb:*', 'Resource': '*',
                             'Condition': {'StringNotEquals': {'dynamodb:LeadingKeys': [sub]}}}]})
    # arn:aws:s3:::* and NotResource are unscoped
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': 'arn:aws:s3:::*'}]}) == ["Action 's3:*'"]
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'NotResource': 'arn:aws:s3:::x'}]}) == ["Action 's3:*'"]
    # partial wildcard is not broad
    assert f({'Statement': [{'Effect': 'Allow', 'Action': 's3:Get*', 'Resource': '*'}]}) == []


def test_guest_role_dynamodb_forallvalues_leading_keys_flag_then_fix(svc):
    """Review finding: ForAllValues:StringEquals on dynamodb:LeadingKeys is true
    for requests without the key (DeleteTable, UpdateTable, Scan), so dynamodb:*
    on the table is open to every guest -> -1. Plain StringEquals (key required)
    confines each guest to its own partition -> not -1."""
    m = '_checkCognitoIdentityPoolGuestRoleBroad'
    sub = '${cognito-identity.amazonaws.com:sub}'
    table = f'arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/T'
    docs = []
    for op in ('ForAllValues:StringEquals', 'StringEquals'):
        docs.append(__import__('json').dumps({'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'dynamodb:*', 'Resource': table,
            'Condition': {op: {'dynamodb:LeadingKeys': [sub]}}}]}))
    statuses = []
    for doc in docs:
        with Stubber(svc.iamClient) as st:
            _stubRole(st, inline=('ddb', doc))
            statuses.append(_run(CognitoIdentityPool(_guestPool(_unauthRole=svc._fetchRoleEvaluation(ROLE_ARN))), m))
    assert statuses[0][0] == -1 and "dynamodb:*" in statuses[0][1], statuses
    assert statuses[1][0] == 1, statuses
    # same shape on Resource '*'
    star = docs[0].replace(table, '*')
    with Stubber(svc.iamClient) as st:
        _stubRole(st, inline=('ddb', star))
        assert _run(CognitoIdentityPool(_guestPool(_unauthRole=svc._fetchRoleEvaluation(ROLE_ARN))), m)[0] == -1


def test_guest_role_readonlyaccess_flagged(svc):
    m = '_checkCognitoIdentityPoolGuestRoleBroad'
    ro = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","dynamodb:Scan"],"Resource":"*"}]}'
    with Stubber(svc.iamClient) as st:
        _stubRole(st, attached=[(ro, doc)])
        bad = svc._fetchRoleEvaluation(ROLE_ARN)
    r = _run(CognitoIdentityPool(_guestPool(_unauthRole=bad)), m)
    assert r[0] == -1 and 'ReadOnlyAccess' in r[1]
    with Stubber(svc.iamClient) as st:
        _stubRole(st, inline=('scoped', SCOPED))
        good = svc._fetchRoleEvaluation(ROLE_ARN)
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=good)), m)[0] == 1


def test_guest_role_allow_all_narrowed_by_deny_not_action(svc):
    m = '_checkCognitoIdentityPoolGuestRoleBroad'
    narrowed = ('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},'
                '{"Effect":"Deny","NotAction":["mobileanalytics:PutEvents","s3:GetObject"],"Resource":"*"}]}')
    stillWide = ('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},'
                 '{"Effect":"Deny","NotAction":["s3:*"],"Resource":"*"}]}')
    conditional = ('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},'
                   '{"Effect":"Deny","NotAction":["s3:GetObject"],"Resource":"*",'
                   '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}')
    results = []
    for doc in (narrowed, stillWide, conditional):
        with Stubber(svc.iamClient) as st:
            _stubRole(st, inline=('p', doc))
            results.append(_run(CognitoIdentityPool(_guestPool(_unauthRole=svc._fetchRoleEvaluation(ROLE_ARN))), m)[0])
    assert results == [1, -1, -1]


def test_legacy_console_default_guest_role_message(svc):
    legacy = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["mobileanalytics:PutEvents",'
              '"cognito-sync:*"],"Resource":["*"]}]}')
    arn = f'arn:aws:iam::{ACCOUNT}:role/Cognito_appUnauth_Role'
    role = {'roleArn': arn, 'roleName': 'Cognito_appUnauth_Role', 'crossAccount': False, 'error': None,
            'policyErrors': [], 'boundary': None,
            'policies': [{'name': 'oneClick_Cognito_appUnauth_Role_1', 'arn': None, 'managedByAws': False,
                          'document': __import__('json').loads(legacy)}]}
    r = _run(CognitoIdentityPool(_guestPool(_unauthRole=role)), '_checkCognitoIdentityPoolGuestRoleBroad')
    assert r[0] == -1 and 'legacy console-default guest role' in r[1]


def test_unknown_caller_account_is_unable_to_evaluate(svc):
    Config.set('stsInfo', {})
    role = svc._fetchRoleEvaluation(ROLE_ARN)   # no IAM call may be made
    assert _run(CognitoIdentityPool(_guestPool(_unauthRole=role)),
                '_checkCognitoIdentityPoolGuestRoleBroad') == [0, 'Unable to evaluate (CallerAccountUnknown)']


def test_list_identity_pools_denied_records_unable_to_evaluate(svc):
    svc.registerItems = lambda *a, **kw: a[1]
    with Stubber(svc.identityClient) as st:
        st.add_client_error('list_identity_pools', 'AccessDeniedException', expected_params={'MaxResults': 60})
        out = svc.getIdentityPools()
    assert len(out) == 1
    for m in ('_checkCognitoIdentityPoolGuestRoleBroad', '_checkCognitoIdentityPoolNoRoleMapping'):
        assert _run(CognitoIdentityPool(dict(out[0])), m) == [0, 'Unable to evaluate (AccessDeniedException)']


# --------------------------------------------------------------------------- #
# cognitoIdentityPoolNoRoleMapping
# --------------------------------------------------------------------------- #
def _twoProviderPool():
    return {'IdentityPoolId': IPID, 'IdentityPoolName': 'p', 'AllowUnauthenticatedIdentities': False,
            '_resourceName': 'p',
            'CognitoIdentityProviders': [{'ProviderName': 'cognito-idp.us-east-1.amazonaws.com/us-east-1_a',
                                          'ClientId': 'c1'}],
            'SupportedLoginProviders': {'accounts.google.com': 'g'}}


def test_no_role_mapping_flag_then_mapping(svc):
    m = '_checkCognitoIdentityPoolNoRoleMapping'
    providers = sorted(CognitoIdentityPool.loginProviders(_twoProviderPool()))
    bad = _twoProviderPool()
    with Stubber(svc.identityClient) as st:
        st.add_response('get_identity_pool_roles', {'IdentityPoolId': IPID,
                                                    'Roles': {'authenticated': ROLE_ARN}})
        for p in providers:
            st.add_client_error('get_principal_tag_attribute_map', 'ResourceNotFoundException',
                                expected_params={'IdentityPoolId': IPID, 'IdentityProviderName': p})
            if p.startswith('cognito-idp.'):
                ## user pool providers are also tried in the '<provider>:<clientId>' form
                st.add_client_error('get_principal_tag_attribute_map', 'ResourceNotFoundException',
                                    expected_params={'IdentityPoolId': IPID,
                                                     'IdentityProviderName': f'{p}:c1'})
        svc._hydrateIdentityPool(bad)
    assert _run(CognitoIdentityPool(bad), m)[0] == -1

    good = _twoProviderPool()
    with Stubber(svc.identityClient) as st:
        st.add_response('get_identity_pool_roles', {
            'IdentityPoolId': IPID, 'Roles': {'authenticated': ROLE_ARN},
            'RoleMappings': {'accounts.google.com': {'Type': 'Token', 'AmbiguousRoleResolution': 'Deny'}}})
        svc._hydrateIdentityPool(good)
    assert _run(CognitoIdentityPool(good), m)[0] == 1


def test_no_role_mapping_tag_map_denied_is_unable_to_evaluate(svc):
    detail = _twoProviderPool()
    with Stubber(svc.identityClient) as st:
        st.add_response('get_identity_pool_roles', {'IdentityPoolId': IPID,
                                                    'Roles': {'authenticated': ROLE_ARN}})
        for _ in range(3):  # google + user pool (bare and client-qualified forms)
            st.add_client_error('get_principal_tag_attribute_map', 'NotAuthorizedException')
        svc._hydrateIdentityPool(detail)
    assert _run(CognitoIdentityPool(detail), '_checkCognitoIdentityPoolNoRoleMapping') == \
        [0, 'Unable to evaluate (NotAuthorizedException)']


def test_no_role_mapping_client_qualified_tag_map_counts_as_abac(svc):
    """The API docs do not pin down the IdentityProviderName form for user pool
    providers; when only the '<provider>:<clientId>' form returns a map, ABAC is
    still recognised (no false -1)."""
    detail = _twoProviderPool()
    up = 'cognito-idp.us-east-1.amazonaws.com/us-east-1_a'
    with Stubber(svc.identityClient) as st:
        st.add_response('get_identity_pool_roles', {'IdentityPoolId': IPID,
                                                    'Roles': {'authenticated': ROLE_ARN}})
        st.add_client_error('get_principal_tag_attribute_map', 'ResourceNotFoundException',
                            expected_params={'IdentityPoolId': IPID, 'IdentityProviderName': 'accounts.google.com'})
        st.add_client_error('get_principal_tag_attribute_map', 'ResourceNotFoundException',
                            expected_params={'IdentityPoolId': IPID, 'IdentityProviderName': up})
        st.add_response('get_principal_tag_attribute_map',
                        {'IdentityPoolId': IPID, 'IdentityProviderName': f'{up}:c1', 'UseDefaults': True},
                        {'IdentityPoolId': IPID, 'IdentityProviderName': f'{up}:c1'})
        svc._hydrateIdentityPool(detail)
    assert _run(CognitoIdentityPool(detail), '_checkCognitoIdentityPoolNoRoleMapping')[0] == 1


def test_no_role_mapping_two_clients_one_user_pool_is_one_source():
    up = 'cognito-idp.us-east-1.amazonaws.com/us-east-1_a'
    pool = {'IdentityPoolId': IPID, 'IdentityPoolName': 'p', '_resourceName': 'p',
            'CognitoIdentityProviders': [{'ProviderName': up, 'ClientId': 'c1'},
                                         {'ProviderName': up, 'ClientId': 'c2'}],
            '_roles': {'Roles': {'authenticated': ROLE_ARN}, 'RoleMappings': {}}, '_principalTagMaps': {}}
    assert CognitoIdentityPool.loginProviders(pool) == [up]
    assert CognitoIdentityPool.userPoolClientProviders(pool) == {up: [f'{up}:c1', f'{up}:c2']}
    assert _run(CognitoIdentityPool(pool), '_checkCognitoIdentityPoolNoRoleMapping')[0] == 0


# --------------------------------------------------------------------------- #
# cognitoNoAuthMetricAlarm
# --------------------------------------------------------------------------- #
def _alarm(name, pid, actions):
    return {'AlarmName': name, 'Namespace': 'AWS/Cognito', 'MetricName': 'SignInSuccesses',
            'Dimensions': [{'Name': 'UserPool', 'Value': pid}, {'Name': 'UserPoolClient', 'Value': 'c'}],
            'ActionsEnabled': True, 'AlarmActions': actions}


def _poolResult(idx, users=5):
    pool = {'Id': 'us-east-1_a', 'Name': 'a', 'EstimatedNumberOfUsers': users, '_alarmIndex': idx}
    return _run(CognitoCommon(pool, None), '_checkCognitoNoAuthMetricAlarm')


def test_alarm_via_composite_with_actions(svc):
    topic = ['arn:aws:sns:us-east-1:111111111111:t']
    with Stubber(svc.cwClient) as st:
        st.add_response('describe_alarms', {'MetricAlarms': [_alarm('child', 'us-east-1_a', [])],
                                            'CompositeAlarms': []})
        noActions = svc._buildAlarmIndex()
    with Stubber(svc.cwClient) as st:
        st.add_response('describe_alarms', {
            'MetricAlarms': [_alarm('child', 'us-east-1_a', [])],
            'CompositeAlarms': [
                {'AlarmName': 'outer', 'AlarmRule': 'ALARM("inner") OR ALARM(other)',
                 'ActionsEnabled': True, 'AlarmActions': topic},
                {'AlarmName': 'inner', 'AlarmRule': 'ALARM("child")', 'ActionsEnabled': True,
                 'AlarmActions': []}]})
        viaComposite = svc._buildAlarmIndex()
    assert _poolResult(noActions)[0] == -1
    assert _poolResult(viaComposite)[0] == 1


def test_alarm_metric_math_and_denied(svc):
    with Stubber(svc.cwClient) as st:
        st.add_response('describe_alarms', {'MetricAlarms': [{
            'AlarmName': 'math', 'ActionsEnabled': True, 'AlarmActions': ['arn:aws:sns:us-east-1:1:t'],
            'Metrics': [{'Id': 'm1', 'ReturnData': False, 'MetricStat': {
                'Metric': {'Namespace': 'AWS/Cognito', 'MetricName': 'AccountTakeoverRisk',
                           'Dimensions': [{'Name': 'UserPoolId', 'Value': 'us-east-1_a'}]},
                'Period': 300, 'Stat': 'Sum'}}]}], 'CompositeAlarms': []})
        idx = svc._buildAlarmIndex()
    assert _poolResult(idx)[0] == 1
    with Stubber(svc.cwClient) as st:
        st.add_client_error('describe_alarms', 'AccessDenied')
        denied = svc._buildAlarmIndex()
    assert _poolResult(denied) == [0, 'Unable to evaluate (AccessDenied)']
    assert _poolResult({'error': None, 'actioned': set(), 'unactioned': set()}, users=0)[0] == 0


# --------------------------------------------------------------------------- #
# cognitoPerAppIdentitySilos
# --------------------------------------------------------------------------- #
def _silo(i, **kw):
    d = {'id': f'p{i}', 'name': f'p{i}', 'clientCount': 1, 'idpCount': 0, 'error': None}
    d.update(kw)
    return d


def _account(pools, listError=None):
    return _run(CognitoAccount({'_region': 'us-east-1', '_pools': pools, '_listError': listError}),
                '_checkCognitoPerAppIdentitySilos')


def test_silos_thresholds_and_errors():
    assert _account([_silo(i) for i in range(3)])[0] == -1
    assert _account([_silo(0), _silo(1), _silo(2, idpCount=1)])[0] == 1
    assert _account([_silo(0), _silo(1), _silo(2, clientCount=4)])[0] == 1
    assert _account([_silo(0), _silo(1), _silo(2, error='AccessDeniedException')]) == \
        [0, 'Unable to evaluate (AccessDeniedException)']
    assert _account([_silo(0)], listError='AccessDeniedException')[0] == 0
    assert _account([], listError='AccessDeniedException')[0] == 0


def test_silo_summary_checkpointed_pool_counts_and_errors(svc):
    with Stubber(svc.cognitoClient) as st:
        st.add_response('list_user_pool_clients', {'UserPoolClients': [
            {'ClientId': 'c1', 'UserPoolId': 'us-east-1_a', 'ClientName': 'x'}]},
            {'UserPoolId': 'us-east-1_a', 'MaxResults': 60})
        st.add_client_error('list_identity_providers', 'AccessDeniedException')
        out = svc._siloSummary([{'Id': 'us-east-1_a', 'Name': 'a'}])
    assert out[0]['clientCount'] == 1 and out[0]['error'] == 'AccessDeniedException'

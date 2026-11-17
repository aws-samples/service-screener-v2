"""Flag -> fix -> re-run tests for the WAFS2027 Cognito checks, against the local AWS Emulator."""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck

TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Principal': {'Federated': 'cognito-identity.amazonaws.com'},
    'Action': 'sts:AssumeRoleWithWebIdentity'}]})
ADMIN = 'arn:aws:iam::aws:policy/AdministratorAccess'
SCOPED = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Action': ['mobileanalytics:PutEvents', 'cognito-sync:ListDatasets'],
    'Resource': '*'}]})


def _silent(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        pass


def _userPoolWithClient(idp, name):
    pid = idp.create_user_pool(PoolName=name)['UserPool']['Id']
    cid = idp.create_user_pool_client(UserPoolId=pid, ClientName=f'{name}-app')['UserPoolClient']['ClientId']
    return pid, cid


# --------------------------------------------------------------------------- #
# cognitoIdentityPoolGuestRoleBroad
# --------------------------------------------------------------------------- #
def test_identity_pool_guest_role_admin_then_scoped(emu, uid):
    ci, iam = emu.client('cognito-identity'), emu.client('iam')
    role = f'ss-guest-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    ipid = ci.create_identity_pool(IdentityPoolName=f'ss_ip_{uid}',
                                   AllowUnauthenticatedIdentities=True)['IdentityPoolId']
    try:
        def misconfigure():
            iam.attach_role_policy(RoleName=role, PolicyArn=ADMIN)
            ci.set_identity_pool_roles(IdentityPoolId=ipid, Roles={'unauthenticated': arn})

        def fix():
            iam.detach_role_policy(RoleName=role, PolicyArn=ADMIN)
            iam.put_role_policy(RoleName=role, PolicyName='scoped', PolicyDocument=SCOPED)

        before, after = assertFlagFixCycle(emu, 'cognito', 'cognitoIdentityPoolGuestRoleBroad', ipid,
                                           misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        _silent(ci.delete_identity_pool, IdentityPoolId=ipid)
        _silent(iam.detach_role_policy, RoleName=role, PolicyArn=ADMIN)
        _silent(iam.delete_role_policy, RoleName=role, PolicyName='scoped')
        _silent(iam.delete_role_policy, RoleName=role, PolicyName='broad')
        _silent(iam.delete_role, RoleName=role)


def test_identity_pool_guest_role_service_wildcard_then_guest_disabled(emu, uid):
    ci, iam = emu.client('cognito-identity'), emu.client('iam')
    role = f'ss-guest2-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    name = f'ss_ip2_{uid}'
    ipid = ci.create_identity_pool(IdentityPoolName=name, AllowUnauthenticatedIdentities=True)['IdentityPoolId']
    try:
        def misconfigure():
            iam.put_role_policy(RoleName=role, PolicyName='broad', PolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{
                    'Effect': 'Allow', 'Action': 's3:*',
                    'Resource': f'arn:aws:s3:::bucket-{uid}/*'}]}))
            ci.set_identity_pool_roles(IdentityPoolId=ipid, Roles={'unauthenticated': arn})

        def fix():
            ci.update_identity_pool(IdentityPoolId=ipid, IdentityPoolName=name,
                                    AllowUnauthenticatedIdentities=False)

        assertFlagFixCycle(emu, 'cognito', 'cognitoIdentityPoolGuestRoleBroad', ipid, misconfigure, fix)
    finally:
        _silent(ci.delete_identity_pool, IdentityPoolId=ipid)
        _silent(iam.delete_role_policy, RoleName=role, PolicyName='broad')
        _silent(iam.delete_role, RoleName=role)


def test_identity_pool_guest_role_sync_all_identities_then_per_identity(emu, uid):
    """cognito-sync:* on every identity of the pool is flagged; the per-identity
    form recommended by the Cognito 'IAM roles' guide
    (identitypool/${aud}/identity/${sub}/*) is not."""
    ci, iam = emu.client('cognito-identity'), emu.client('iam')
    role = f'ss-guest3-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    ipid = ci.create_identity_pool(IdentityPoolName=f'ss_ip3_{uid}',
                                   AllowUnauthenticatedIdentities=True)['IdentityPoolId']
    base = 'arn:aws:cognito-sync:us-east-1:000000000000:identitypool/${cognito-identity.amazonaws.com:aud}'

    def _put(resource):
        iam.put_role_policy(RoleName=role, PolicyName='sync', PolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Action': ['cognito-sync:*'], 'Resource': [resource]}]}))
    try:
        def misconfigure():
            _put(base + '/*')
            ci.set_identity_pool_roles(IdentityPoolId=ipid, Roles={'unauthenticated': arn})

        def fix():
            _put(base + '/identity/${cognito-identity.amazonaws.com:sub}/*')

        before, after = assertFlagFixCycle(emu, 'cognito', 'cognitoIdentityPoolGuestRoleBroad', ipid,
                                           misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        _silent(ci.delete_identity_pool, IdentityPoolId=ipid)
        _silent(iam.delete_role_policy, RoleName=role, PolicyName='sync')
        _silent(iam.delete_role, RoleName=role)


def test_identity_pool_guest_role_dynamodb_forallvalues_then_plain_condition(emu, uid):
    """dynamodb:* on a table with ForAllValues:StringEquals LeadingKeys = ${sub} is
    flagged (ForAllValues is true for DeleteTable / Scan, which carry no
    LeadingKeys); the plain StringEquals form (key required) is not."""
    ci, iam = emu.client('cognito-identity'), emu.client('iam')
    role = f'ss-guest4-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    ipid = ci.create_identity_pool(IdentityPoolName=f'ss_ip4_{uid}',
                                   AllowUnauthenticatedIdentities=True)['IdentityPoolId']

    def _put(op):
        iam.put_role_policy(RoleName=role, PolicyName='ddb', PolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Action': 'dynamodb:*',
                'Resource': f'arn:aws:dynamodb:us-east-1:000000000000:table/t-{uid}',
                'Condition': {op: {'dynamodb:LeadingKeys': ['${cognito-identity.amazonaws.com:sub}']}}}]}))
    try:
        def misconfigure():
            _put('ForAllValues:StringEquals')
            ci.set_identity_pool_roles(IdentityPoolId=ipid, Roles={'unauthenticated': arn})

        def fix():
            _put('StringEquals')

        before, after = assertFlagFixCycle(emu, 'cognito', 'cognitoIdentityPoolGuestRoleBroad', ipid,
                                           misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        _silent(ci.delete_identity_pool, IdentityPoolId=ipid)
        _silent(iam.delete_role_policy, RoleName=role, PolicyName='ddb')
        _silent(iam.delete_role, RoleName=role)


# --------------------------------------------------------------------------- #
# cognitoIdentityPoolNoRoleMapping
# --------------------------------------------------------------------------- #
def _multiProviderPool(emu, uid):
    ci, iam, idp = emu.client('cognito-identity'), emu.client('iam'), emu.client('cognito-idp')
    pid, cid = _userPoolWithClient(idp, f'ss-rm-{uid}')
    role = f'ss-auth-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    provider = f'cognito-idp.us-east-1.amazonaws.com/{pid}'
    ipid = ci.create_identity_pool(
        IdentityPoolName=f'ss_rm_{uid}', AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[{'ProviderName': provider, 'ClientId': cid}],
        SupportedLoginProviders={'accounts.google.com': f'google-{uid}'})['IdentityPoolId']
    return ipid, pid, cid, provider, role, arn


def _cleanupMultiProvider(emu, ipid, pid, role):
    _silent(emu.client('cognito-identity').delete_identity_pool, IdentityPoolId=ipid)
    _silent(emu.client('cognito-idp').delete_user_pool, UserPoolId=pid)
    _silent(emu.client('iam').delete_role, RoleName=role)


def test_identity_pool_no_role_mapping_then_token_mapping(emu, uid):
    ci = emu.client('cognito-identity')
    ipid, pid, cid, provider, role, arn = _multiProviderPool(emu, uid)
    try:
        def misconfigure():
            ci.set_identity_pool_roles(IdentityPoolId=ipid, Roles={'authenticated': arn})

        def fix():
            ci.set_identity_pool_roles(
                IdentityPoolId=ipid, Roles={'authenticated': arn},
                RoleMappings={f'{provider}:{cid}': {'Type': 'Token', 'AmbiguousRoleResolution': 'Deny'}})

        _, after = assertFlagFixCycle(emu, 'cognito', 'cognitoIdentityPoolNoRoleMapping', ipid, misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        _cleanupMultiProvider(emu, ipid, pid, role)


def test_identity_pool_no_role_mapping_then_principal_tags(emu, uid):
    ci = emu.client('cognito-identity')
    ipid, pid, cid, provider, role, arn = _multiProviderPool(emu, uid)
    try:
        def misconfigure():
            ci.set_identity_pool_roles(IdentityPoolId=ipid, Roles={'authenticated': arn})

        def fix():
            ci.set_principal_tag_attribute_map(IdentityPoolId=ipid, IdentityProviderName=provider,
                                               UseDefaults=True)

        _, after = assertFlagFixCycle(emu, 'cognito', 'cognitoIdentityPoolNoRoleMapping', ipid, misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        _cleanupMultiProvider(emu, ipid, pid, role)


def test_identity_pool_single_provider_not_flagged(emu, uid):
    ci, iam, idp = emu.client('cognito-identity'), emu.client('iam'), emu.client('cognito-idp')
    pid, cid = _userPoolWithClient(idp, f'ss-one-{uid}')
    role = f'ss-auth1-{uid}'
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    ipid = ci.create_identity_pool(
        IdentityPoolName=f'ss_one_{uid}', AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[{'ProviderName': f'cognito-idp.us-east-1.amazonaws.com/{pid}',
                                   'ClientId': cid}])['IdentityPoolId']
    try:
        ci.set_identity_pool_roles(IdentityPoolId=ipid, Roles={'authenticated': arn})
        st = runCheck(emu, 'cognito', 'cognitoIdentityPoolNoRoleMapping', ipid).statuses()
        assert list(st.values()) == [0], st
    finally:
        _cleanupMultiProvider(emu, ipid, pid, role)


# --------------------------------------------------------------------------- #
# cognitoNoAuthMetricAlarm
# --------------------------------------------------------------------------- #
def test_user_pool_no_auth_metric_alarm(emu, uid):
    idp, cw, sns = emu.client('cognito-idp'), emu.client('cloudwatch'), emu.client('sns')
    name = f'ss-alarm-{uid}'
    pid = idp.create_user_pool(PoolName=name)['UserPool']['Id']
    idp.admin_create_user(UserPoolId=pid, Username=f'user-{uid}', MessageAction='SUPPRESS')
    topic = sns.create_topic(Name=f'ss-alarm-{uid}')['TopicArn']
    alarm = f'ss-cognito-risk-{uid}'
    kw = dict(AlarmName=alarm, Namespace='AWS/Cognito', MetricName='CompromisedCredentialsRisk',
              Dimensions=[{'Name': 'UserPoolId', 'Value': pid}], Statistic='Sum', Period=300,
              EvaluationPeriods=1, Threshold=1, ComparisonOperator='GreaterThanOrEqualToThreshold')
    try:
        def misconfigure():
            # An alarm without actions does not alert anyone - still a finding.
            cw.put_metric_alarm(**kw)

        def fix():
            cw.put_metric_alarm(AlarmActions=[topic], **kw)

        _, after = assertFlagFixCycle(emu, 'cognito', 'cognitoNoAuthMetricAlarm', name, misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        _silent(cw.delete_alarms, AlarmNames=[alarm])
        _silent(sns.delete_topic, TopicArn=topic)
        _silent(idp.delete_user_pool, UserPoolId=pid)


# --------------------------------------------------------------------------- #
# cognitoPerAppIdentitySilos (account/region level)
# --------------------------------------------------------------------------- #
def test_per_app_identity_silos(emu, uid):
    idp = emu.client('cognito-idp')
    pools = [_userPoolWithClient(idp, f'ss-silo{i}-{uid}')[0] for i in range(3)]
    try:
        def misconfigure():
            pass  # three single-client, non-federated pools now exist

        def fix():
            for pid in pools[:2]:
                idp.create_identity_provider(
                    UserPoolId=pid, ProviderName='CorpIdP', ProviderType='OIDC',
                    ProviderDetails={'client_id': 'x', 'client_secret': 'y', 'authorize_scopes': 'openid',
                                     'oidc_issuer': 'https://idp.example.com',
                                     'attributes_request_method': 'GET'},
                    AttributeMapping={'email': 'email'})

        _, after = assertFlagFixCycle(emu, 'cognito', 'cognitoPerAppIdentitySilos', 'Account::us-east-1',
                                      misconfigure, fix)
        assert list(after.values()) == [1]
    finally:
        for pid in pools:
            _silent(idp.delete_user_pool, UserPoolId=pid)

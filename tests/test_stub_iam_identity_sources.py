"""
Flag -> fix -> re-run tests (botocore Stubber, real API shapes) for the IAM
identity-source checks added for WAFS2027 chunk 4:
- hasExternalIdentityProvider (extended to cover the proposed
  ssoNoDirectFederationFallback: Identity Center context in the message,
  [0, Unable to evaluate] when the IAM provider lists cannot be read)
- ssoUsersNotScimProvisioned
- trustedIdentityPropagationUnused (informational, never -1)

Why Stubber and not only the AWS Emulator:
- identitystore.create_user cannot set ExternalIds (only SCIM provisioning
  does), so an externally provisioned identity store cannot be built in the
  emulator; the mixed (FAIL) state of ssoUsersNotScimProvisioned needs mocks.
- lakeformation.describe_lake_formation_identity_center_configuration is
  NotImplemented in the emulator and s3control (account-ID host prefix)
  cannot reach an IP endpoint, so the Lake Formation / S3 Access Grants
  evidence of trustedIdentityPropagationUnused needs mocks.
- The emulator only offers an account instance of Identity Center and cannot
  model an AccessDenied caller.
End-to-end emulator runs are in tests/emulator/test_emu_iam_identity_sources.py.

No network is used: clients carry fake credentials and every call is served
by a Stubber (an unexpected call fails the test).
"""
import os
import sys
import uuid
from datetime import datetime, timezone

from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from test_stub_iam_org import Harness, _session, MGMT, MEMBER  # noqa: E402

INST_ARN = 'arn:aws:sso:::instance/ssoins-1111222233334444'
STORE = 'd-1111111111'
INST = {'InstanceArn': INST_ARN, 'IdentityStoreId': STORE, 'Status': 'ACTIVE'}
NOW = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _regional(**responses):
    """{'svc': [(op, resp | 'ErrorCode' | ('ErrorCode', httpStatus), params)]} -> (clients, stubbers)."""
    s = _session()
    clients, stubs = {}, {}
    for svc, calls in responses.items():
        c = s.client(svc)
        st = Stubber(c)
        for op, resp, params in calls:
            if isinstance(resp, (str, tuple)):
                code, status = (resp, 400) if isinstance(resp, str) else resp
                st.add_client_error(op, service_error_code=code, http_status_code=status)
            else:
                st.add_response(op, resp, params)
        st.activate()
        clients[svc], stubs[svc] = c, st
    return clients, stubs


def _ssoInstanceCalls(instances=(INST,)):
    calls = [('list_instances', {'Instances': list(instances)}, {})]
    for i in instances:
        calls.append(('list_permission_sets', {'PermissionSets': []}, {'InstanceArn': i['InstanceArn']}))
    return calls


def _done(stubs):
    for st in stubs.values():
        st.assert_no_pending_responses()


# --------------------------------------------------------------------------- #
class TestExternalIdentityProvider:
    """Covers the proposed ssoNoDirectFederationFallback via the existing key."""
    KEY = 'hasExternalIdentityProvider'

    def _run(self, saml, oidc=0, ssoInstances=(INST,), samlErr=None):
        # Identity Center is only consulted when the check FAILs.
        clients, stubs = _regional(**{'sso-admin': _ssoInstanceCalls(ssoInstances)}) \
            if ssoInstances is not None and not saml and not oidc and not samlErr else ({}, {})
        h = Harness(regionalClients=clients)
        if samlErr:
            h.iam.add_client_error('list_saml_providers', service_error_code=samlErr, http_status_code=403)
        else:
            h.iam.add_response('list_saml_providers', {'SAMLProviderList': [
                {'Arn': f'arn:aws:iam::{MGMT}:saml-provider/idp{i}', 'ValidUntil': NOW, 'CreateDate': NOW}
                for i in range(saml)]})
        h.iam.add_response('list_open_id_connect_providers', {'OpenIDConnectProviderList': [
            {'Arn': f'arn:aws:iam::{MGMT}:oidc-provider/token.actions.githubusercontent.com{i}'} for i in range(oidc)]})
        r = h.run('HasExternalProvider', self.KEY)
        _done(stubs)
        return r

    def test_flag_fix_with_identity_center(self):
        r = self._run(0)
        assert r[0] == -1 and 'IAM Identity Center is in use' in r[1] and 'fall back' in r[1], r
        r = self._run(1)
        assert r[0] == 1 and '1 SAML' in r[1], r

    def test_flag_without_identity_center_has_no_fallback_note(self):
        r = self._run(0, ssoInstances=())
        assert r[0] == -1 and 'Identity Center' not in r[1], r

    def test_unreadable_is_not_silent(self):
        r = self._run(0, samlErr='AccessDenied', ssoInstances=None)
        assert r[0] == 0 and 'Unable to evaluate (AccessDenied)' in r[1], r

    def test_oidc_only_is_not_flagged(self):
        r = self._run(0, oidc=1, ssoInstances=None)
        assert r[0] == 1 and '1 OIDC' in r[1], r


# --------------------------------------------------------------------------- #
def _user(name, external=False, status='ENABLED'):
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, name))
    u = {'IdentityStoreId': STORE, 'UserId': uid, 'UserArn': f'arn:aws:identitystore::{MGMT}:identitystore/{STORE}/user/{uid}', 'Revision': '1',
         'UserName': name, 'UserStatus': status}
    if external:
        u['ExternalIds'] = [{'Issuer': 'https://scim.okta.example.com', 'Id': 'ext-' + name}]
    return u


class TestSsoUsersNotScimProvisioned:
    KEY = 'ssoUsersNotScimProvisioned'

    def _run(self, users=None, usersErr=None, instances=(INST,), caller=MGMT, orgErr=None):
        calls = {'sso-admin': _ssoInstanceCalls(instances)}
        if instances:
            calls['identitystore'] = [('list_users', usersErr or {'Users': users}, {'IdentityStoreId': STORE})]
        clients, stubs = _regional(**calls)
        h = Harness(regionalClients=clients, caller=caller, orgErr=orgErr)
        r = h.run('SsoUsersNotScimProvisioned', self.KEY)
        _done(stubs)
        return r

    def test_flag_fix(self):
        """FLAG: SCIM-provisioned store with a hand-made user. FIX: the user
        is deleted (or provisioned from the IdP)."""
        r = self._run([_user('alice', True), _user('bob', True), _user('local-admin')])
        assert r[0] == -1 and 'local-admin' in r[1] and '1 of 3' in r[1] and STORE in r[1], r
        r = self._run([_user('alice', True), _user('bob', True)])
        assert r[0] == 1 and 'all 2 enabled user(s) are externally provisioned' in r[1], r

    def test_disabled_manual_user_is_not_flagged(self):
        r = self._run([_user('alice', True), _user('old', status='DISABLED')])
        assert r[0] == 1, r

    def test_identity_center_directory_is_info_not_fail(self):
        r = self._run([_user('alice'), _user('bob')])
        assert r[0] == 0 and r[1].startswith('INFO') and 'Identity Center directory' in r[1], r

    def test_unreadable_is_not_silent(self):
        r = self._run(usersErr='AccessDeniedException')
        assert r == [0, 'Unable to evaluate (AccessDeniedException)'], r

    def test_member_account_without_instance(self):
        org = {'Organization': {'Id': 'o-abcdefghij', 'Arn': f'arn:aws:organizations::{MGMT}:organization/o-abcdefghij',
                                'FeatureSet': 'ALL', 'MasterAccountId': MGMT,
                                'MasterAccountArn': f'arn:aws:organizations::{MGMT}:account/o-abcdefghij/{MGMT}'}}
        clients, stubs = _regional(**{'sso-admin': _ssoInstanceCalls(())})
        h = Harness(orgResp=org, caller=MEMBER, regionalClients=clients)
        r = h.run('SsoUsersNotScimProvisioned', self.KEY)
        _done(stubs)
        assert r == [0, 'Not evaluable from member account'], r


# --------------------------------------------------------------------------- #
PROVIDERS = {'ApplicationProviders': [
    {'ApplicationProviderArn': 'arn:aws:sso::aws:applicationProvider/custom', 'FederationProtocol': 'OAUTH'},
    {'ApplicationProviderArn': 'arn:aws:sso::aws:applicationProvider/redshift', 'FederationProtocol': 'OAUTH'},
    {'ApplicationProviderArn': 'arn:aws:sso::aws:applicationProvider/catalog/Salesforce', 'FederationProtocol': 'SAML'}]}


def _app(name, provider):
    return {'ApplicationArn': f'arn:aws:sso::{MGMT}:application/ssoins-1111222233334444/apl-{name}',
            'ApplicationProviderArn': f'arn:aws:sso::aws:applicationProvider/{provider}', 'Name': name,
            'InstanceArn': INST_ARN, 'Status': 'ENABLED'}


class TestTrustedIdentityPropagationUnused:
    KEY = 'trustedIdentityPropagationUnused'

    def _run(self, apps=(), ttis=(), lf=('EntityNotFoundException', 400),
             s3ag=('AccessGrantsInstanceNotExistsError', 404)):
        sso = _ssoInstanceCalls() + [('list_applications', {'Applications': list(apps)}, {'InstanceArn': INST_ARN})]
        if apps:
            sso.append(('list_application_providers', PROVIDERS, {}))
        sso.append(('list_trusted_token_issuers', {'TrustedTokenIssuers': list(ttis)}, {'InstanceArn': INST_ARN}))
        clients, stubs = _regional(**{
            'sso-admin': sso,
            'lakeformation': [('describe_lake_formation_identity_center_configuration', lf, {})],
            's3control': [('get_access_grants_instance', s3ag, {'AccountId': MGMT})],
        })
        h = Harness(regionalClients=clients)
        r = h.run('TrustedIdentityPropagationUnused', self.KEY)
        _done(stubs)
        return r

    def test_unused_then_used_via_oauth_application(self):
        """Informational: 'flag' is INFO (0), never -1. A SAML-only app does
        not count; adding an OAuth (TIP-capable) app flips it to 1."""
        r = self._run(apps=[_app('salesforce', 'catalog/Salesforce')])
        assert r[0] == 0 and r[1].startswith('INFO: no trusted identity propagation'), r
        r = self._run(apps=[_app('salesforce', 'catalog/Salesforce'), _app('analytics', 'redshift')])
        assert r[0] == 1 and 'analytics (redshift)' in r[1], r

    def test_used_via_lake_formation_and_access_grants(self):
        r = self._run(lf={'CatalogId': MGMT, 'InstanceArn': INST_ARN,
                          'ApplicationArn': f'arn:aws:sso::{MGMT}:application/ssoins-1111222233334444/apl-lf'})
        assert r[0] == 1 and 'Lake Formation' in r[1], r
        r = self._run(s3ag={'AccessGrantsInstanceArn': f'arn:aws:s3:us-east-1:{MGMT}:access-grants/default',
                            'AccessGrantsInstanceId': 'default', 'IdentityCenterArn': INST_ARN})
        assert r[0] == 1 and 'S3 Access Grants' in r[1], r

    def test_access_grants_without_identity_center_is_not_tip(self):
        r = self._run(s3ag={'AccessGrantsInstanceArn': f'arn:aws:s3:us-east-1:{MGMT}:access-grants/default',
                            'AccessGrantsInstanceId': 'default'})
        assert r[0] == 0 and r[1].startswith('INFO'), r

    def test_used_via_trusted_token_issuer(self):
        r = self._run(ttis=[{'TrustedTokenIssuerArn': f'arn:aws:sso::{MGMT}:trustedTokenIssuer/ssoins-1111222233334444/tti-1',
                             'Name': 'okta-jwt', 'TrustedTokenIssuerType': 'OIDC_JWT'}])
        assert r[0] == 1 and 'okta-jwt' in r[1], r

    def test_unreadable_is_not_silent(self):
        r = self._run(lf='AccessDeniedException')
        assert r[0] == 0 and r[1].startswith('Unable to evaluate') and 'AccessDeniedException' in r[1], r

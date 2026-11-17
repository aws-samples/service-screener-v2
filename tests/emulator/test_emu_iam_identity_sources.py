"""Emulator tests for the IAM identity-source checks (WAFS2027 chunk 4).

The emulator provides one account with an account instance of IAM Identity
Center. Limits (mocked flag/fix cycles are in
tests/test_stub_iam_identity_sources.py):
- identitystore.create_user cannot set ExternalIds, so the FAIL state of
  ssoUsersNotScimProvisioned (hand-made users in a SCIM-provisioned store)
  cannot be built; here we assert a store without SCIM users is INFO, never
  a false FAIL.
- lakeformation.describe_lake_formation_identity_center_configuration is
  NotImplemented and s3control cannot reach an IP endpoint, so
  trustedIdentityPropagationUnused can only PASS here through Identity
  Center evidence; without it the result must be 0 (never a silent PASS).
  The check is informational and never returns -1.
"""
from tests.emulator.conftest import assertFlagFixCycle, runCheck

RES = 'Account::Config'

# Minimal SAML metadata; IAM requires >= 1000 characters.
SAML_METADATA = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/{uid}">'
    '<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/post"/>'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso/redirect"/>'
    '</md:IDPSSODescriptor></md:EntityDescriptor>'
    '<!-- {pad} -->'
)


def _instance(emu):
    return emu.client('sso-admin').list_instances()['Instances'][0]


def test_external_identity_provider_fallback(emu, uid):
    """FLAG: no IAM SAML/OIDC provider while Identity Center exists (the
    message carries the no-direct-federation-fallback context). FIX: add an
    IAM SAML provider."""
    iam = emu.client('iam')
    created = []

    def misconfigure():
        assert iam.list_saml_providers()['SAMLProviderList'] == []
        assert iam.list_open_id_connect_providers()['OpenIDConnectProviderList'] == []

    def fix():
        r = iam.create_saml_provider(Name=f'ss-test-{uid}', SAMLMetadataDocument=SAML_METADATA.format(uid=uid, pad='x' * 400))
        created.append(r['SAMLProviderArn'])

    try:
        before = runCheck(emu, 'iam', 'hasExternalIdentityProvider', RES)
        misconfigure()
        assert 'IAM Identity Center is in use' in before.results[RES]['hasExternalIdentityProvider'][1], before.results
        _, after = assertFlagFixCycle(emu, 'iam', 'hasExternalIdentityProvider', RES, misconfigure, fix)
        assert after == {RES: 1}
    finally:
        for arn in created:
            iam.delete_saml_provider(SAMLProviderArn=arn)


def test_sso_users_without_scim_are_info_not_fail(emu, uid):
    ids = emu.client('identitystore')
    store = _instance(emu)['IdentityStoreId']
    users = []
    try:
        res = runCheck(emu, 'iam', 'ssoUsersNotScimProvisioned', RES)
        assert res.statuses() == {RES: 0}, res.results
        r = ids.create_user(IdentityStoreId=store, UserName=f'ss-test-{uid}', DisplayName='SS Test',
                            Name={'GivenName': 'SS', 'FamilyName': 'Test'})
        users.append(r['UserId'])
        res = runCheck(emu, 'iam', 'ssoUsersNotScimProvisioned', RES)
        assert res.statuses() == {RES: 0}, res.results
        msg = res.results[RES]['ssoUsersNotScimProvisioned'][1]
        assert msg.startswith('INFO') and store in msg, msg
    finally:
        for u in users:
            ids.delete_user(IdentityStoreId=store, UserId=u)


def test_trusted_identity_propagation_info_then_in_use(emu, uid):
    sso = emu.client('sso-admin')
    inst = _instance(emu)
    apps = []
    try:
        res = runCheck(emu, 'iam', 'trustedIdentityPropagationUnused', RES)
        assert res.statuses() == {RES: 0}, res.results
        # (CreateApplication only creates OAuth apps; the SAML-app exclusion is
        # covered in the Stubber test.)
        # A customer managed OAuth application is.
        r = sso.create_application(InstanceArn=inst['InstanceArn'], Name=f'ss-test-tip-{uid}',
                                   ApplicationProviderArn='arn:aws:sso::aws:applicationProvider/custom')
        apps.append(r['ApplicationArn'])
        res = runCheck(emu, 'iam', 'trustedIdentityPropagationUnused', RES)
        assert res.statuses() == {RES: 1}, res.results
        assert f'ss-test-tip-{uid} (custom)' in res.results[RES]['trustedIdentityPropagationUnused'][1]
    finally:
        for a in apps:
            sso.delete_application(ApplicationArn=a)

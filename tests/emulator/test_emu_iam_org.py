"""Flag -> fix -> re-run tests for the IAM AWS Organizations checks that the
AWS Emulator can drive. The emulator's Organization has the caller
(000000000000) as management account, FeatureSet ALL and a root with no OUs.

Checks whose APIs the emulator does not implement (list_policies,
list_accounts, list_accounts_for_parent, enable_policy_type, IAM
list_organizations_features) are covered in tests/test_stub_iam_org.py.
"""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck

RES = 'Account::Config'


def test_mgmt_account_hosts_workloads(emu, uid):
    ec2 = emu.client('ec2')
    image = ec2.describe_images(Owners=['amazon'], MaxResults=5)['Images'][0]['ImageId']
    created = []

    def misconfigure():
        r = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, InstanceType='t3.micro',
                              TagSpecifications=[{'ResourceType': 'instance',
                                                  'Tags': [{'Key': 'Name', 'Value': f'ss-test-{uid}'}]}])
        created.extend(i['InstanceId'] for i in r['Instances'])

    def fix():
        ec2.terminate_instances(InstanceIds=created)

    try:
        before, _ = assertFlagFixCycle(emu, 'iam', 'orgMgmtAccountHostsWorkloads', RES, misconfigure, fix)
        res = runCheck(emu, 'iam', 'orgMgmtAccountHostsWorkloads', RES)
        assert res.statuses() == {RES: 1}, res.results
    finally:
        if created:
            try:
                ec2.terminate_instances(InstanceIds=created)
            except Exception:
                pass


def test_ou_structure_flat(emu, uid):
    org = emu.client('organizations')
    root = org.list_roots()['Roots'][0]['Id']
    created = []

    def misconfigure():
        # Emulator org starts with no OUs under the root.
        assert org.list_organizational_units_for_parent(ParentId=root)['OrganizationalUnits'] == []

    def fix():
        ou = org.create_organizational_unit(ParentId=root, Name=f'ss-test-{uid}')
        created.append(ou['OrganizationalUnit']['Id'])

    try:
        _, after = assertFlagFixCycle(emu, 'iam', 'orgOuStructureFlat', RES, misconfigure, fix)
        # list_accounts_for_parent is NotImplemented in the emulator, so with an
        # OU present the check must say it cannot evaluate - never a silent PASS.
        assert after == {RES: 0}
    finally:
        for ouId in created:
            org.delete_organizational_unit(OrganizationalUnitId=ouId)


def test_org_all_features_pass(emu):
    """Emulator org is FeatureSet ALL (PASS path); the FAIL path is in the stub test."""
    res = runCheck(emu, 'iam', 'orgNotAllFeatures', RES)
    assert res.statuses() == {RES: 1}, res.results


def test_unimplemented_org_reads_are_not_silent_pass(emu):
    """Org reads the emulator cannot serve must surface as 0 (unable to evaluate)."""
    for check in ('SCPEnabled', 'scpBestPractices', 'scpNoBackupTamperProtection',
                  'orgMemberAlternateContactsMissing', 'rootCentralizedAccessNotEnabled'):
        res = runCheck(emu, 'iam', check, RES)
        st = res.statuses()
        assert st == {RES: 0}, (check, res.results)


def test_new_org_guardrail_checks_not_silent_pass(emu):
    """SCP guardrail and delegated-admin checks: the emulator does not implement
    list_policies / list_delegated_administrators, so they must report 0.
    Flag/fix cycles are in tests/test_stub_iam_org_guardrails.py."""
    for check in ('scpNoDataProtectionGuardrail', 'scpNoIamUserCreationDeny', 'scpNoSecurityServiceProtection',
                  'securityServicesNoDelegatedAdmin'):
        res = runCheck(emu, 'iam', check, RES)
        assert res.statuses() == {RES: 0}, (check, res.results)


def test_sso_checks_account_instance_not_applicable(emu):
    """The emulator only provides an account instance of IAM Identity Center
    (permission-set APIs return ValidationException): checks must say so
    instead of passing. Flag/fix cycles are in the Stubber test."""
    for check in ('ssoAssignmentsToIndividualUsers', 'ssoPermissionSetOverprivileged'):
        res = runCheck(emu, 'iam', check, RES)
        assert res.statuses() == {RES: 0}, (check, res.results)
        assert 'account instance' in res.results[RES][check][1]


def test_third_party_role_unclassifiable_in_emulator(emu, uid):
    """A role trusting another account without ExternalId and with
    AdministratorAccess. organizations.list_accounts is NotImplemented in the
    emulator, so the trusted account cannot be proven external: both checks
    must return 0 (never a silent PASS, never an unproven FAIL). Removing the
    cross-account trust removes the result. Classified flag/fix cycles are in
    tests/test_stub_iam_org_guardrails.py."""
    iam = emu.client('iam')
    name = f'ss-test-vendor-{uid}'
    trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                                     'Principal': {'AWS': 'arn:aws:iam::111122223333:root'}}]}
    selfTrust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                                         'Principal': {'AWS': 'arn:aws:iam::000000000000:root'}}]}
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    try:
        iam.attach_role_policy(RoleName=name, PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        for check in ('thirdPartyRoleNoExternalId', 'thirdPartyRoleOverprivileged'):
            res = runCheck(emu, 'iam', check, name)
            assert res.statuses() == {f'Role::{name}': 0}, (check, res.results)
            assert '111122223333' in res.results[f'Role::{name}'][check][1]

        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(selfTrust))
        for check in ('thirdPartyRoleNoExternalId', 'thirdPartyRoleOverprivileged'):
            res = runCheck(emu, 'iam', check, name)
            assert res.statuses() == {}, (check, res.results)
    finally:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        except Exception:
            pass
        iam.delete_role(RoleName=name)


# --------------------------------------------------------------------------- #
# Organization hygiene heuristics (WAFS2027 tier 3)
# --------------------------------------------------------------------------- #
def _cleanupOus(org, created):
    for ouId in reversed(created):
        try:
            org.delete_organizational_unit(OrganizationalUnitId=ouId)
        except Exception:
            pass


def test_no_sandbox_or_staging_ou(emu, uid):
    org = emu.client('organizations')
    root = org.list_roots()['Roots'][0]['Id']
    created = []

    def misconfigure():
        ou = org.create_organizational_unit(ParentId=root, Name=f'ss-test-{uid}-workloads')
        created.append(ou['OrganizationalUnit']['Id'])

    def fix():
        # Nested under the workloads OU: the whole OU tree is searched.
        ou = org.create_organizational_unit(ParentId=created[0], Name=f'Sandbox-{uid}')
        created.append(ou['OrganizationalUnit']['Id'])

    try:
        _, after = assertFlagFixCycle(emu, 'iam', 'orgNoSandboxOrStagingOu', RES, misconfigure, fix)
        assert after == {RES: 1}
        res = runCheck(emu, 'iam', 'orgNoSandboxOrStagingOu', RES)
        assert f'Sandbox-{uid}' in res.results[RES]['orgNoSandboxOrStagingOu'][1]
    finally:
        _cleanupOus(org, created)


def test_no_forensics_ou(emu, uid):
    """Without a forensics-like OU the check falls back to account names;
    list_accounts is NotImplemented in the emulator, so it must report 0 (not
    PASS, not an unproven FAIL). Adding a Forensics OU makes it PASS. The
    -1 path (no OU and no account match) is in tests/test_stub_iam_org_hygiene.py."""
    org = emu.client('organizations')
    root = org.list_roots()['Roots'][0]['Id']
    created = []
    try:
        ou = org.create_organizational_unit(ParentId=root, Name=f'ss-test-{uid}-security')
        created.append(ou['OrganizationalUnit']['Id'])
        res = runCheck(emu, 'iam', 'orgNoForensicsOu', RES)
        assert res.statuses() == {RES: 0}, res.results

        ou = org.create_organizational_unit(ParentId=created[0], Name=f'Forensics-{uid}')
        created.append(ou['OrganizationalUnit']['Id'])
        res = runCheck(emu, 'iam', 'orgNoForensicsOu', RES)
        assert res.statuses() == {RES: 1}, res.results
    finally:
        _cleanupOus(org, created)


def test_hygiene_checks_unimplemented_reads_not_silent_pass(emu):
    """list_accounts / list_policies are NotImplemented in the emulator:
    these checks must report 0. Flag/fix cycles are Stubber-based."""
    for check in ('accountNotVended', 'orgAccountsMissingOwnershipTags'):
        res = runCheck(emu, 'iam', check, RES)
        assert res.statuses() == {RES: 0}, (check, res.results)


def test_org_policy_types_not_enabled_flag(emu):
    """The emulator root only enables SERVICE_CONTROL_POLICY, so backup and
    declarative policies are genuinely missing (FLAG). enable_policy_type /
    list_policies are NotImplemented, so the FIX half is Stubber-based."""
    org = emu.client('organizations')
    types = {t['Type'] for t in org.list_roots()['Roots'][0].get('PolicyTypes', []) if t.get('Status') == 'ENABLED'}
    for check, ptype in (('orgBackupPolicyMissing', 'BACKUP_POLICY'), ('orgNoDeclarativePolicy', 'DECLARATIVE_POLICY_EC2')):
        assert ptype not in types
        res = runCheck(emu, 'iam', check, RES)
        assert res.statuses() == {RES: -1}, (check, res.results)
        assert 'type is not enabled' in res.results[RES][check][1]


def test_principal_inventory_summary(emu, uid):
    """Informational: never -1. Adding an OIDC provider is reflected on re-run."""
    iam = emu.client('iam')
    url = f'https://ss-test-{uid}.example.com'
    arn = None
    try:
        res = runCheck(emu, 'iam', 'principalInventorySummary', RES)
        assert res.statuses() == {RES: 0}, res.results
        before = res.results[RES]['principalInventorySummary'][1]
        assert before.startswith('INFO: ') and 'IAM users:' in before and 'Cognito user pools:' in before, before
        n = int(before.split('IAM OIDC providers: ')[1].split('<br>')[0])

        arn = iam.create_open_id_connect_provider(Url=url, ClientIDList=['sts.amazonaws.com'],
                                                  ThumbprintList=['a' * 40])['OpenIDConnectProviderArn']
        res = runCheck(emu, 'iam', 'principalInventorySummary', RES)
        assert res.statuses() == {RES: 0}, res.results
        assert f'IAM OIDC providers: {n + 1}' in res.results[RES]['principalInventorySummary'][1]
    finally:
        if arn:
            iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)

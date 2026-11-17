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

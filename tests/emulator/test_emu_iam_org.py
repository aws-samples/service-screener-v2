"""Flag -> fix -> re-run tests for the IAM AWS Organizations checks that the
AWS Emulator can drive. The emulator's Organization has the caller
(000000000000) as management account, FeatureSet ALL and a root with no OUs.

Checks whose APIs the emulator does not implement (list_policies,
list_accounts, list_accounts_for_parent, enable_policy_type, IAM
list_organizations_features) are covered in tests/test_stub_iam_org.py.
"""
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

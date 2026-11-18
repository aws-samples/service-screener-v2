"""Flag -> fix -> re-run tests for the WAFS2027 GuardDuty checks.

All checks are account/region level and are reported on the detector
('Detector::<id>'). Each test reuses an existing detector or creates one, and
restores the original state in finally.
"""
import json
import time
from contextlib import contextmanager

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ORG_FEATURES = ('AI_PROTECTION', 'EBS_MALWARE_PROTECTION', 'EKS_AUDIT_LOGS', 'EKS_RUNTIME_MONITORING',
                'LAMBDA_NETWORK_LOGS', 'RDS_LOGIN_EVENTS', 'RUNTIME_MONITORING', 'S3_DATA_EVENTS')


@contextmanager
def detector(gd):
    ids = gd.list_detectors()['DetectorIds']
    created = not ids
    did = gd.create_detector(Enable=True)['DetectorId'] if created else ids[0]
    try:
        yield did
    finally:
        if created:
            gd.delete_detector(DetectorId=did)


def _deleteDestinations(gd, did):
    for d in gd.list_publishing_destinations(DetectorId=did)['Destinations']:
        gd.delete_publishing_destination(DetectorId=did, DestinationId=d['DestinationId'])


def test_guardduty_no_findings_export(emu, uid):
    gd, s3 = emu.client('guardduty'), emu.client('s3')
    bucket = f'ss-gd-export-{uid}'
    s3.create_bucket(Bucket=bucket)
    with detector(gd) as did:
        try:
            def misconfigure():
                _deleteDestinations(gd, did)

            def fix():
                destId = gd.create_publishing_destination(
                    DetectorId=did, DestinationType='S3',
                    DestinationProperties={
                        'DestinationArn': f'arn:aws:s3:::{bucket}',
                        'KmsKeyArn': 'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000'}
                )['DestinationId']
                ## A new destination starts in PENDING_VERIFICATION (INFO, correctly: GuardDuty
                ## has not yet verified it can write) and becomes PUBLISHING once verified.
                ## The fix is complete only when the destination is PUBLISHING.
                for _ in range(60):
                    if gd.describe_publishing_destination(
                            DetectorId=did, DestinationId=destId)['Status'] == 'PUBLISHING':
                        return
                    time.sleep(1)
                raise AssertionError('publishing destination never reached PUBLISHING')

            assertFlagFixCycle(emu, 'guardduty', 'guardDutyNoFindingsExport', did, misconfigure, fix)
        finally:
            _deleteDestinations(gd, did)
            s3.delete_bucket(Bucket=bucket)


def test_guardduty_no_snapshot_preservation(emu):
    gd = emu.client('guardduty')
    with detector(gd) as did:
        original = gd.get_malware_scan_settings(DetectorId=did).get('EbsSnapshotPreservation', 'NO_RETENTION')
        origFeature = next((f['Status'] for f in gd.get_detector(DetectorId=did).get('Features', [])
                            if f['Name'] == 'EBS_MALWARE_PROTECTION'), 'ENABLED')
        try:
            gd.update_detector(DetectorId=did, Features=[{'Name': 'EBS_MALWARE_PROTECTION', 'Status': 'ENABLED'}])

            def misconfigure():
                gd.update_malware_scan_settings(DetectorId=did, EbsSnapshotPreservation='NO_RETENTION')

            def fix():
                gd.update_malware_scan_settings(DetectorId=did, EbsSnapshotPreservation='RETENTION_WITH_FINDING')

            assertFlagFixCycle(emu, 'guardduty', 'guardDutyNoSnapshotPreservation', did, misconfigure, fix)

            # Malware Protection off -> not applicable (INFO), never a finding
            gd.update_detector(DetectorId=did, Features=[{'Name': 'EBS_MALWARE_PROTECTION', 'Status': 'DISABLED'}])
            misconfigure()
            st = runCheck(emu, 'guardduty', 'guardDutyNoSnapshotPreservation', did).statuses()
            assert st and all(s == 0 for s in st.values()), st
        finally:
            gd.update_malware_scan_settings(DetectorId=did, EbsSnapshotPreservation=original)
            gd.update_detector(DetectorId=did, Features=[{'Name': 'EBS_MALWARE_PROTECTION', 'Status': origFeature}])


def _adminEnabled(gd):
    return any(a.get('AdminStatus') == 'ENABLED' for a in gd.list_organization_admin_accounts().get('AdminAccounts', []))


def test_guardduty_org_auto_enable_incomplete(emu):
    gd = emu.client('guardduty')
    account = emu.client('sts').get_caller_identity()['Account']
    member = '111111111111'
    with detector(gd) as did:
        wasAdmin = _adminEnabled(gd)
        if wasAdmin:
            pytest.skip('emulator account is already a GuardDuty delegated admin; not altering it')
        try:
            # Not the delegated admin -> not evaluable, never a finding
            st = runCheck(emu, 'guardduty', 'guardDutyOrgAutoEnableIncomplete', did).statuses()
            assert st and all(s == 0 for s in st.values()), st

            for _ in range(10):
                try:
                    gd.enable_organization_admin_account(AdminAccountId=account)
                    break
                except gd.exceptions.BadRequestException:
                    time.sleep(1)

            def misconfigure():
                gd.update_organization_configuration(
                    DetectorId=did, AutoEnableOrganizationMembers='NONE',
                    Features=[{'Name': n, 'AutoEnable': 'NONE'} for n in ORG_FEATURES])
                gd.create_members(DetectorId=did, AccountDetails=[{'AccountId': member, 'Email': 'm@example.com'}])

            def fix():
                gd.delete_members(DetectorId=did, AccountIds=[member])
                gd.update_organization_configuration(
                    DetectorId=did, AutoEnableOrganizationMembers='ALL',
                    Features=[{'Name': n, 'AutoEnable': 'NONE' if n == 'RUNTIME_MONITORING' else 'ALL'}
                              for n in ORG_FEATURES])

            assertFlagFixCycle(emu, 'guardduty', 'guardDutyOrgAutoEnableIncomplete', did, misconfigure, fix)
        finally:
            try:
                gd.delete_members(DetectorId=did, AccountIds=[member])
            except Exception:
                pass
            try:
                gd.update_organization_configuration(
                    DetectorId=did, AutoEnableOrganizationMembers='NONE',
                    Features=[{'Name': n, 'AutoEnable': 'NONE'} for n in ORG_FEATURES])
            except Exception:
                pass
            if not wasAdmin:
                try:
                    gd.disable_organization_admin_account(AdminAccountId=account)
                except Exception:
                    pass


def test_detective_not_enabled(emu):
    """The emulator does not implement detective.ListInvitations, so with no graph the
    check correctly reports INFO 'Unable to evaluate (NotImplemented)' rather than FAIL.
    Here we verify that path and the PASS path end to end; the FAIL path (no graph and
    no ENABLED membership) is covered by tests/test_stub_guardduty.py."""
    gd, dt = emu.client('guardduty'), emu.client('detective')
    if dt.list_graphs()['GraphList']:
        pytest.skip('emulator account already has a Detective graph; not deleting it')
    with detector(gd) as did:
        created = []
        try:
            res = runCheck(emu, 'guardduty', 'detectiveNotEnabled', did)
            st = res.statuses()
            assert st and all(s != -1 for s in st.values()), st
            if all(s == 0 for s in st.values()):
                assert 'Unable to evaluate' in str(res.results)
            created.append(dt.create_graph()['GraphArn'])
            st = runCheck(emu, 'guardduty', 'detectiveNotEnabled', did).statuses()
            assert st and all(s == 1 for s in st.values()), st
        finally:
            for arn in created:
                dt.delete_graph(GraphArn=arn)


def test_guardduty_s3_malware_protection_off(emu, uid):
    gd, s3, iam = emu.client('guardduty'), emu.client('s3'), emu.client('iam')
    if gd.list_malware_protection_plans()['MalwareProtectionPlans']:
        pytest.skip('emulator account already has Malware Protection plans; not deleting them')
    bucket, role = f'ss-gd-mp-{uid}', f'ss-gd-mp-{uid}'
    s3.create_bucket(Bucket=bucket)
    roleArn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
        'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Principal': {'Service': 'malware-protection-plan.guardduty.amazonaws.com'},
            'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
    iam.put_role_policy(RoleName=role, PolicyName='p', PolicyDocument=json.dumps({
        'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}))
    plans = []
    with detector(gd) as did:
        try:
            def misconfigure():
                pass  # no Malware Protection plan in the region

            def fix():
                plans.append(gd.create_malware_protection_plan(
                    Role=roleArn, ProtectedResource={'S3Bucket': {'BucketName': bucket}})['MalwareProtectionPlanId'])

            assertFlagFixCycle(emu, 'guardduty', 'guarddutyS3MalwareProtectionOff', did, misconfigure, fix)
        finally:
            for p in plans:
                gd.delete_malware_protection_plan(MalwareProtectionPlanId=p)
            iam.delete_role_policy(RoleName=role, PolicyName='p')
            iam.delete_role(RoleName=role)
            s3.delete_bucket(Bucket=bucket)

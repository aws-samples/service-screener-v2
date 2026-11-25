"""Stubber-based tests for WAFS2027 GuardDuty/Detective checks.

Why Stubber here: the AWS Emulator does not implement detective.ListInvitations
(so the detectiveNotEnabled FAIL path cannot be reached there), and it cannot
put the account into a GuardDuty member relationship, a PENDING_VERIFICATION
destination, or a Malware Protection plan in ERROR state. These tests drive the
driver directly with real boto3 clients wrapped by botocore Stubber, so request
and response shapes are validated against the real API models.
"""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.guardduty.drivers.GuarddutyDriver import GuarddutyDriver  # noqa: E402

DID = 'a' * 32


def _clients():
    s = boto3.session.Session(aws_access_key_id='x', aws_secret_access_key='x', region_name='us-east-1')
    return s.client('guardduty'), s.client('detective')


def _driver(gd, dt=None):
    Config.set('stsInfo', {'Account': '123456789012'})
    return GuarddutyDriver(DID, gd, 'us-east-1', None, None, dt)


def _detector(features):
    return {'Status': 'ENABLED', 'ServiceRole': 'r',
            'Features': [{'Name': n, 'Status': s} for n, s in features.items()]}


# ---- detectiveNotEnabled ------------------------------------------------- #

def test_detective_flag_then_fix():
    gd, dt = _clients()
    with Stubber(dt) as st:
        st.add_response('list_graphs', {'GraphList': []})
        st.add_response('list_invitations', {'Invitations': []})
        d = _driver(gd, dt)
        d._checkDetectiveNotEnabled()
        assert d.results['detectiveNotEnabled'][0] == -1
    with Stubber(dt) as st:
        st.add_response('list_graphs', {'GraphList': [{'Arn': 'arn:aws:detective:us-east-1:123456789012:graph:abc'}]})
        d = _driver(gd, dt)
        d._checkDetectiveNotEnabled()
        assert d.results['detectiveNotEnabled'][0] == 1


def test_detective_member_of_admin_graph_passes():
    gd, dt = _clients()
    with Stubber(dt) as st:
        st.add_response('list_graphs', {'GraphList': []})
        st.add_response('list_invitations', {'Invitations': [{
            'AccountId': '123456789012', 'GraphArn': 'arn:aws:detective:us-east-1:111111111111:graph:abc',
            'Status': 'ENABLED'}]})
        d = _driver(gd, dt)
        d._checkDetectiveNotEnabled()
        assert d.results['detectiveNotEnabled'][0] == 1


def test_detective_access_denied_is_info():
    gd, dt = _clients()
    with Stubber(dt) as st:
        st.add_client_error('list_graphs', 'AccessDeniedException', http_status_code=403)
        d = _driver(gd, dt)
        d._checkDetectiveNotEnabled()
        assert d.results['detectiveNotEnabled'] == [0, 'Unable to evaluate (AccessDeniedException)']


# ---- guardDutyNoFindingsExport -------------------------------------------- #

def _export(adminResp, destinations):
    gd, _ = _clients()
    with Stubber(gd) as st:
        if adminResp is None:  # not a member account
            st.add_client_error('get_administrator_account', 'BadRequestException', http_status_code=400)
        else:
            st.add_response('get_administrator_account', adminResp, {'DetectorId': DID})
        if destinations is not None:
            st.add_response('list_publishing_destinations', {'Destinations': destinations}, {'DetectorId': DID})
        d = _driver(gd)
        d._checkGuardDutyNoFindingsExport()
        return d.results['guardDutyNoFindingsExport']


def test_export_flag_then_fix():
    assert _export(None, [])[0] == -1
    assert _export(None, [{'DestinationId': 'd', 'DestinationType': 'S3', 'Status': 'PUBLISHING'}])[0] == 1


def test_export_member_account_is_info():
    admin = {'Administrator': {'AccountId': '111111111111', 'InvitationId': 'i', 'RelationshipStatus': 'Enabled'}}
    assert _export(admin, None)[0] == 0


def test_export_states():
    assert _export(None, [{'DestinationId': 'd', 'DestinationType': 'S3', 'Status': 'PENDING_VERIFICATION'}])[0] == 0
    assert _export(None, [{'DestinationId': 'd', 'DestinationType': 'S3', 'Status': 'STOPPED'}])[0] == -1


# ---- guardDutyNoSnapshotPreservation -------------------------------------- #

def test_snapshot_preservation_flag_then_fix():
    for value, expected in (('NO_RETENTION', -1), ('RETENTION_WITH_FINDING', 1)):
        gd, _ = _clients()
        with Stubber(gd) as st:
            st.add_response('get_detector', _detector({'EBS_MALWARE_PROTECTION': 'ENABLED'}), {'DetectorId': DID})
            st.add_response('get_malware_scan_settings', {'EbsSnapshotPreservation': value}, {'DetectorId': DID})
            d = _driver(gd)
            d._checkGuardDutyNoSnapshotPreservation()
            assert d.results['guardDutyNoSnapshotPreservation'][0] == expected


# ---- guardDutyOrgAutoEnableIncomplete ------------------------------------- #

def _org(orgResp, members, features=None):
    gd, _ = _clients()
    with Stubber(gd) as st:
        st.add_response('describe_organization_configuration', orgResp, {'DetectorId': DID})
        st.add_response('list_members', {'Members': members}, {'DetectorId': DID, 'OnlyAssociated': 'false'})
        d = _driver(gd)
        d._detector = _detector(features or {'S3_DATA_EVENTS': 'ENABLED'})  # cached get_detector
        d._checkGuardDutyOrgAutoEnableIncomplete()
        return d.results['guardDutyOrgAutoEnableIncomplete']


def _member(status):
    return {'AccountId': '111111111111', 'MasterId': '123456789012', 'Email': 'a@example.com',
            'RelationshipStatus': status, 'UpdatedAt': '2026-01-01T00:00:00Z'}


def test_org_flag_then_fix():
    bad = {'MemberAccountLimitReached': False, 'AutoEnableOrganizationMembers': 'NEW',
           'Features': [{'Name': 'S3_DATA_EVENTS', 'AutoEnable': 'NONE'}]}
    good = {'MemberAccountLimitReached': False, 'AutoEnableOrganizationMembers': 'ALL',
            'Features': [{'Name': 'S3_DATA_EVENTS', 'AutoEnable': 'ALL'}]}
    assert _org(bad, [_member('Enabled')])[0] == -1
    assert _org(good, [_member('Disabled')])[0] == -1
    assert _org(good, [_member('Enabled'), _member('RegionDisabled')])[0] == 1


def test_org_eks_runtime_covered_by_unified_runtime():
    cfg = {'MemberAccountLimitReached': False, 'AutoEnableOrganizationMembers': 'ALL',
           'Features': [{'Name': 'RUNTIME_MONITORING', 'AutoEnable': 'ALL'},
                        {'Name': 'EKS_RUNTIME_MONITORING', 'AutoEnable': 'NONE'}]}
    res = _org(cfg, [], {'RUNTIME_MONITORING': 'ENABLED', 'EKS_RUNTIME_MONITORING': 'ENABLED'})
    assert res[0] == 1, res


def test_org_not_delegated_admin_is_info():
    gd, _ = _clients()
    with Stubber(gd) as st:
        st.add_client_error('describe_organization_configuration', 'BadRequestException', http_status_code=400)
        d = _driver(gd)
        d._checkGuardDutyOrgAutoEnableIncomplete()
        assert d.results['guardDutyOrgAutoEnableIncomplete'] == [0, 'Not evaluable from member account']


# ---- guarddutyS3MalwareProtectionOff -------------------------------------- #

def _plan(status):
    gd, _ = _clients()
    with Stubber(gd) as st:
        st.add_response('list_malware_protection_plans', {'MalwareProtectionPlans': [{'MalwareProtectionPlanId': 'p1'}]})
        st.add_response('get_malware_protection_plan', {
            'Arn': 'arn:aws:guardduty:us-east-1:123456789012:malware-protection-plan/p1', 'Role': 'r',
            'ProtectedResource': {'S3Bucket': {'BucketName': 'uploads'}}, 'Status': status},
            {'MalwareProtectionPlanId': 'p1'})
        d = _driver(gd)
        d._checkGuarddutyS3MalwareProtectionOff()
        return d.results['guarddutyS3MalwareProtectionOff']


def test_s3_malware_plan_error_flag_then_fix():
    assert _plan('ERROR')[0] == -1
    assert _plan('ACTIVE')[0] == 1

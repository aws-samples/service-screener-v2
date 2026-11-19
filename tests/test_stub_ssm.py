"""Stubber-based flag -> fix tests for SSM checks the AWS Emulator cannot
drive end to end.

ssmNoAutomatedPatching needs managed instances (the emulator cannot register
one: there is no EC2 -> SSM agent and activations need an agent), the
AWS-RunPatchBaseline document does not exist in the emulator, and
RegisterTaskWithMaintenanceWindow / DescribeMaintenanceWindowTasks are
NotImplemented there. These tests therefore drive the driver directly with real
boto3 clients wrapped in botocore.stub.Stubber, so every response is validated
against the real API shapes. Error-path tests for the other new checks
(Unable to evaluate, never PASS) are here too. No network calls are made:
Stubber intercepts every request before it is sent.
"""
import json
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber, ANY

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.ssm.drivers.SsmSessionManager import SsmSessionManager  # noqa: E402
from services.ssm.drivers.SsmDocument import SsmDocument  # noqa: E402

FAKE = dict(region_name='us-east-1', aws_access_key_id='testing',
            aws_secret_access_key='testing', aws_session_token='testing')

INSTANCE = {'InstanceId': 'i-0123456789abcdef0', 'PingStatus': 'Online'}
DETAIL = {'_region': 'us-east-1', '_accountId': '111122223333',
          '_sessionPreferences': {}, '_sessionPreferencesFound': False,
          '_dhmcSetting': None, '_sessionPreferencesError': None}


def _clients():
    return boto3.client('ssm', **FAKE), boto3.client('ssm-quicksetup', **FAKE)


def _runPatching(setupSsm, setupQs=None, detail=None):
    ssm, qs = _clients()
    with Stubber(ssm) as s, Stubber(qs) as q:
        setupSsm(s)
        if setupQs:
            setupQs(q)
        drv = SsmSessionManager(detail or DETAIL, ssm, qs)
        drv._checkSsmNoAutomatedPatching()
        s.assert_no_pending_responses()
        q.assert_no_pending_responses()
    return drv.results['ssmNoAutomatedPatching']


def _instances(s, items=(INSTANCE,)):
    s.add_response('describe_instance_information',
                   {'InstanceInformationList': list(items)})


def _assoc(s, params, name='AWS-RunPatchBaseline', assocName='patch-daily'):
    s.add_response('list_associations', {'Associations': [
        {'Name': name, 'AssociationId': '11111111-2222-3333-4444-555555555555',
         'AssociationName': assocName}]})
    s.add_response('describe_association', {'AssociationDescription': {
        'Name': name, 'AssociationId': '11111111-2222-3333-4444-555555555555',
        'Parameters': params}},
        {'AssociationId': '11111111-2222-3333-4444-555555555555'})


def _noWindows(s):
    s.add_response('describe_maintenance_windows', {'WindowIdentities': []})


def _noQuickSetup(q):
    q.add_response('list_configuration_managers', {'ConfigurationManagersList': []})


# ---------------------------------------------------------------------- #
# ssmNoAutomatedPatching
# ---------------------------------------------------------------------- #
def test_patching_flag_then_fix_with_install_association():
    def flag(s):
        _instances(s)
        s.add_response('list_associations', {'Associations': []})
        _noWindows(s)
    before = _runPatching(flag, _noQuickSetup)
    assert before[0] == -1, before

    def fixed(s):
        _instances(s)
        _assoc(s, {'Operation': ['Install']})
    after = _runPatching(fixed)
    assert after[0] == 1, after


def test_patching_scan_only_association_is_flagged():
    def flag(s):
        _instances(s)
        _assoc(s, {'Operation': ['Scan']})
        _noWindows(s)
    res = _runPatching(flag, _noQuickSetup)
    assert res[0] == -1 and 'only scan' in res[1], res


def test_patching_association_without_operation_defaults_to_scan():
    def flag(s):
        _instances(s)
        _assoc(s, {})
        _noWindows(s)
    assert _runPatching(flag, _noQuickSetup)[0] == -1


def test_patching_maintenance_window_task_invocation_parameters_install():
    def flag(s):
        _instances(s)
        s.add_response('list_associations', {'Associations': []})
        s.add_response('describe_maintenance_windows', {'WindowIdentities': [
            {'WindowId': 'mw-0123456789abcdef0', 'Name': 'patch', 'Enabled': True}]})
        s.add_response('describe_maintenance_window_tasks', {'Tasks': [
            {'WindowId': 'mw-0123456789abcdef0',
             'WindowTaskId': '11111111-2222-3333-4444-555555555555',
             'TaskArn': 'AWS-RunPatchBaseline', 'Type': 'RUN_COMMAND'}]})
        s.add_response('get_maintenance_window_task', {
            'WindowId': 'mw-0123456789abcdef0',
            'WindowTaskId': '11111111-2222-3333-4444-555555555555',
            'TaskArn': 'AWS-RunPatchBaseline', 'TaskType': 'RUN_COMMAND',
            'TaskInvocationParameters': {'RunCommand': {
                'Parameters': {'Operation': [operation]}}}})
    operation = 'Scan'
    assert _runPatching(flag, _noQuickSetup)[0] == -1
    operation = 'Install'
    assert _runPatching(flag)[0] == 1


def test_patching_disabled_window_is_ignored():
    def flag(s):
        _instances(s)
        s.add_response('list_associations', {'Associations': []})
        s.add_response('describe_maintenance_windows', {'WindowIdentities': [
            {'WindowId': 'mw-0123456789abcdef0', 'Name': 'patch', 'Enabled': False}]})
    assert _runPatching(flag, _noQuickSetup)[0] == -1


def test_patching_quick_setup_patch_policy():
    def ssmSide(s):
        _instances(s)
        s.add_response('list_associations', {'Associations': []})
        _noWindows(s)

    def qsPolicy(op):
        def setup(q):
            q.add_response('list_configuration_managers', {'ConfigurationManagersList': [
                {'ManagerArn': 'arn:aws:ssm-quicksetup:us-east-1:111122223333:configuration-manager/abc',
                 'Name': 'patching',
                 'ConfigurationDefinitionSummaries': [
                     {'Id': 'def1', 'Type': 'AWSQuickSetupType-PatchPolicy',
                      'FirstClassParameters': {'ConfigurationOptionsPatchOperation': op}}]}]})
        return setup
    assert _runPatching(ssmSide, qsPolicy('Scan'))[0] == -1
    assert _runPatching(ssmSide, qsPolicy('ScanAndInstall'))[0] == 1


def test_patching_quick_setup_non_install_association_is_not_an_installer():
    """A Quick Setup patch-policy association that installs nothing (IAM
    attach) must not turn a missing patch setup into PASS (review fix)."""
    def flag(s):
        _instances(s)
        _assoc(s, {'AutomationAssumeRole': ['arn:aws:iam::111122223333:role/qs']},
               name='AWSQuickSetup-PatchPolicy-AttachIAMToInstance',
               assocName='AWS-QuickSetup-PatchPolicy-AttachIAM-abc')
        _noWindows(s)
    res = _runPatching(flag, _noQuickSetup)
    assert res[0] == -1, res

    def fixed(s):
        _instances(s)
        _assoc(s, {'AutomationAssumeRole': ['arn:aws:iam::111122223333:role/qs']},
               name='AWSQuickSetup-PatchPolicy-InstallPatches',
               assocName='AWS-QuickSetup-PatchPolicy-InstallPatches-abc')
    assert _runPatching(fixed)[0] == 1


def test_patching_quick_setup_policy_targeting_other_region_is_ignored():
    def ssmSide(s):
        _instances(s)
        s.add_response('list_associations', {'Associations': []})
        _noWindows(s)

    def qsPolicy(params):
        def setup(q):
            q.add_response('list_configuration_managers', {'ConfigurationManagersList': [
                {'ManagerArn': 'arn:aws:ssm-quicksetup:us-east-1:111122223333:configuration-manager/abc',
                 'Name': 'patching',
                 'ConfigurationDefinitionSummaries': [
                     {'Id': 'def1', 'Type': 'AWSQuickSetupType-PatchPolicy',
                      'FirstClassParameters': dict(
                          {'ConfigurationOptionsPatchOperation': 'ScanAndInstall'},
                          **params)}]}]})
        return setup
    assert _runPatching(ssmSide, qsPolicy({'TargetRegions': 'eu-west-1,ap-south-1'}))[0] == -1
    assert _runPatching(ssmSide, qsPolicy({'TargetAccounts': '444455556666'}))[0] == -1
    assert _runPatching(ssmSide, qsPolicy({'TargetRegions': 'eu-west-1,us-east-1',
                                          'TargetAccounts': '111122223333'}))[0] == 1


def test_patching_quick_setup_connect_timeout_keeps_result():
    import botocore.exceptions as bex
    from unittest import mock

    def flag(s):
        _instances(s)
        s.add_response('list_associations', {'Associations': []})
        _noWindows(s)
    ssm, qs = _clients()
    with Stubber(ssm) as s, mock.patch.object(
            qs, 'get_paginator',
            side_effect=bex.ConnectTimeoutError(endpoint_url='https://x')):
        flag(s)
        drv = SsmSessionManager(DETAIL, ssm, qs)
        drv._checkSsmNoAutomatedPatching()
    assert drv.results['ssmNoAutomatedPatching'][0] == -1


def test_patching_window_tasks_denied_is_unable_to_evaluate():
    def setup(s):
        _instances(s)
        s.add_response('list_associations', {'Associations': []})
        s.add_response('describe_maintenance_windows', {'WindowIdentities': [
            {'WindowId': 'mw-0123456789abcdef0', 'Name': 'patch', 'Enabled': True}]})
        s.add_client_error('describe_maintenance_window_tasks', 'AccessDeniedException')
    res = _runPatching(setup, _noQuickSetup)
    assert res[0] == 0 and 'AccessDeniedException' in res[1], res


def test_patching_no_instances_not_applicable():
    res = _runPatching(lambda s: _instances(s, ()))
    assert res[0] == 0, res


def test_patching_instances_denied_is_unable_to_evaluate():
    res = _runPatching(lambda s: s.add_client_error(
        'describe_instance_information', 'AccessDeniedException'))
    assert res[0] == 0, res


# ---------------------------------------------------------------------- #
# Error paths of ssmDocumentPublic / ssmSessionPrefsWeak
# ---------------------------------------------------------------------- #
def test_document_permission_denied_is_unable_to_evaluate():
    ssm, _ = _clients()
    with Stubber(ssm) as s:
        s.add_client_error('describe_document_permission', 'AccessDeniedException')
        drv = SsmDocument({'Name': 'doc1'}, ssm)
        drv._checkSsmDocumentPublic()
    assert drv.results['ssmDocumentPublic'][0] == 0


@pytest.mark.parametrize('accounts,expected', [(['all'], -1), (['111122223333'], 1), ([], 1)])
def test_document_permission_flag_fix(accounts, expected):
    ssm, _ = _clients()
    with Stubber(ssm) as s:
        s.add_response('describe_document_permission', {'AccountIds': accounts},
                       {'Name': 'doc1', 'PermissionType': 'Share'})
        drv = SsmDocument({'Name': 'doc1'}, ssm)
        drv._checkSsmDocumentPublic()
    assert drv.results['ssmDocumentPublic'][0] == expected


@pytest.mark.parametrize('value,expected', [('Enable', -1), ('Disable', 1)])
def test_public_sharing_setting(value, expected):
    ssm, _ = _clients()
    with Stubber(ssm) as s:
        s.add_response('get_service_setting', {'ServiceSetting': {
            'SettingId': '/ssm/documents/console/public-sharing-permission',
            'SettingValue': value, 'Status': 'Default'}}, {'SettingId': ANY})
        drv = SsmSessionManager(DETAIL, ssm)
        drv._checkSsmDocumentPublic()
    assert drv.results['ssmDocumentPublic'][0] == expected


def test_public_sharing_setting_denied_is_unable_to_evaluate():
    ssm, _ = _clients()
    with Stubber(ssm) as s:
        s.add_client_error('get_service_setting', 'AccessDeniedException')
        drv = SsmSessionManager(DETAIL, ssm)
        drv._checkSsmDocumentPublic()
    assert drv.results['ssmDocumentPublic'] == [0, 'Unable to evaluate (AccessDeniedException)']


@pytest.mark.parametrize('prefs,expected', [
    ({'idleSessionTimeout': '60', 'maxSessionDuration': '120'}, -1),
    ({'idleSessionTimeout': '20', 'maxSessionDuration': ''}, -1),
    ({'idleSessionTimeout': '20', 'maxSessionDuration': '120'}, 1),
    ({'maxSessionDuration': '60'}, 1),
])
def test_session_prefs_thresholds(prefs, expected):
    detail = dict(DETAIL, _sessionPreferences=prefs, _sessionPreferencesFound=True)
    drv = SsmSessionManager(detail, None)
    drv._checkSsmSessionPrefsWeak()
    assert drv.results['ssmSessionPrefsWeak'][0] == expected


def test_session_prefs_unreadable_is_unable_to_evaluate():
    detail = dict(DETAIL, _sessionPreferencesError='AccessDeniedException')
    drv = SsmSessionManager(detail, None)
    drv._checkSsmSessionPrefsWeak()
    assert drv.results['ssmSessionPrefsWeak'] == [0, 'Unable to evaluate (AccessDeniedException)']


# ---------------------------------------------------------------------- #
# Review finding: an unreadable SSM-SessionManagerRunShell document must be
# "Unable to evaluate" in EVERY preferences check, never the false FAIL
# "No SSM-SessionManagerRunShell document exists in this region".
# ---------------------------------------------------------------------- #
PREFS_CHECKS = [
    ('_checkSsmSessionManagerNoEncryption', 'ssmSessionManagerNoEncryption'),
    ('_checkSsmSessionManagerNoCloudWatchLogs', 'ssmSessionManagerNoCloudWatchLogs'),
    ('_checkSsmSessionManagerNoS3Logs', 'ssmSessionManagerNoS3Logs'),
    ('_checkSsmSessionManagerRunAsDisabled', 'ssmSessionManagerRunAsDisabled'),
    ('_checkSsmSessionPrefsWeak', 'ssmSessionPrefsWeak'),
]

GOOD_PREFS = {'kmsKeyId': 'alias/session', 'cloudWatchLogGroupName': '/ssm/sessions',
              'cloudWatchStreamingEnabled': True, 's3BucketName': 'session-archive',
              'runAsEnabled': True, 'runAsDefaultUser': 'ops',
              'idleSessionTimeout': '15', 'maxSessionDuration': '120'}
WEAK_PREFS = {'kmsKeyId': '', 'cloudWatchLogGroupName': '', 's3BucketName': '',
              'runAsEnabled': False, 'idleSessionTimeout': '60',
              'maxSessionDuration': ''}


@pytest.mark.parametrize('method,key', PREFS_CHECKS)
@pytest.mark.parametrize('code', ['AccessDeniedException', 'ThrottlingException',
                                  'EndpointConnectionError', 'InvalidDocumentContent'])
def test_prefs_unreadable_is_unable_to_evaluate_in_every_check(method, key, code):
    detail = dict(DETAIL, _sessionPreferencesError=code)
    drv = SsmSessionManager(detail, None)
    getattr(drv, method)()
    assert drv.results[key] == [0, f'Unable to evaluate ({code})']


@pytest.mark.parametrize('method,key', PREFS_CHECKS)
def test_prefs_flag_fix(method, key):
    """Missing document and weak preferences FAIL; good preferences PASS."""
    for prefs, found, expected in ((None, False, -1), (WEAK_PREFS, True, -1),
                                   (GOOD_PREFS, True, 1)):
        detail = dict(DETAIL, _sessionPreferences=prefs or {},
                      _sessionPreferencesFound=found)
        drv = SsmSessionManager(detail, None)
        getattr(drv, method)()
        assert drv.results[key][0] == expected, (prefs, drv.results[key])


def _loader(ssm):
    from services.ssm.Ssm import Ssm

    class _BareSsm(Ssm):
        """Skips Service.__init__ (no Config bootstrap) and __del__ reporting."""
        def __del__(self):
            pass
    svc = _BareSsm.__new__(_BareSsm)
    svc.ssmClient = ssm
    svc._logClientError = lambda *a, **k: None
    return svc


def _content(inputs, raw=None):
    if raw is not None:
        return raw
    return json.dumps({'schemaVersion': '1.0', 'sessionType': 'Standard_Stream',
                       'inputs': inputs})


@pytest.mark.parametrize('setup,found,error', [
    (lambda s: s.add_client_error('get_document', 'InvalidDocument'), False, None),
    (lambda s: s.add_client_error('get_document', 'AccessDeniedException'),
     False, 'AccessDeniedException'),
    (lambda s: s.add_client_error('get_document', 'ThrottlingException'),
     False, 'ThrottlingException'),
    (lambda s: s.add_response('get_document', {'Name': 'SSM-SessionManagerRunShell',
                                               'Content': 'not json {'}),
     False, 'InvalidDocumentContent'),
    (lambda s: s.add_response('get_document', {'Name': 'SSM-SessionManagerRunShell',
                                               'Content': '{"schemaVersion": "1.0"}'}),
     False, 'InvalidDocumentContent'),
    (lambda s: s.add_response('get_document', {'Name': 'SSM-SessionManagerRunShell',
                                               'Content': '[1, 2]'}),
     False, 'InvalidDocumentContent'),
    (lambda s: s.add_response('get_document', {'Name': 'SSM-SessionManagerRunShell',
                                               'Content': _content(GOOD_PREFS)},
                              {'Name': 'SSM-SessionManagerRunShell',
                               'DocumentFormat': 'JSON'}),
     True, None),
])
def test_session_preferences_loader(setup, found, error):
    ssm, _ = _clients()
    svc = _loader(ssm)
    with Stubber(ssm) as s:
        setup(s)
        prefs = svc._getSessionPreferences()
        s.assert_no_pending_responses()
    assert svc._sessionPreferencesFound is found
    assert svc._sessionPreferencesError == error
    assert prefs == (GOOD_PREFS if found else {})


def test_unparseable_document_end_to_end_not_a_false_fail():
    """Loader + all five checks: a document that exists but cannot be parsed
    must not be reported as 'no document exists' (old behaviour: 5 FAILs)."""
    ssm, _ = _clients()
    svc = _loader(ssm)
    with Stubber(ssm) as s:
        s.add_response('get_document', {'Name': 'SSM-SessionManagerRunShell',
                                        'Content': 'not json {'})
        prefs = svc._getSessionPreferences()
    detail = dict(DETAIL, _sessionPreferences=prefs,
                  _sessionPreferencesFound=svc._sessionPreferencesFound,
                  _sessionPreferencesError=svc._sessionPreferencesError)
    for method, key in PREFS_CHECKS:
        drv = SsmSessionManager(detail, None)
        getattr(drv, method)()
        assert drv.results[key] == [0, 'Unable to evaluate (InvalidDocumentContent)']

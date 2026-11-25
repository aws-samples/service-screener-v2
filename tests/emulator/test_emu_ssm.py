"""Flag -> fix -> re-run tests for the WAFS2027 SSM checks that the AWS
Emulator supports: ssmDocumentPublic (per-document and region setting) and
ssmSessionPrefsWeak. ssmNoAutomatedPatching needs managed instances, which the
emulator cannot register, so it is covered in tests/test_stub_ssm.py."""
import json

import pytest
from botocore.exceptions import ClientError

from tests.emulator.conftest import assertFlagFixCycle, runCheck

PUBLIC_SHARING = '/ssm/documents/console/public-sharing-permission'
SESSION_DOC = 'SSM-SessionManagerRunShell'

COMMAND_DOC = json.dumps({
    'schemaVersion': '2.2',
    'description': 'service-screener test document',
    'mainSteps': [{'action': 'aws:runShellScript', 'name': 'echo',
                   'inputs': {'runCommand': ['echo hello']}}],
})


def _sessionDoc(idle, maxDuration):
    return json.dumps({
        'schemaVersion': '1.0',
        'description': 'Session Manager preferences',
        'sessionType': 'Standard_Stream',
        'inputs': {
            's3BucketName': '', 's3KeyPrefix': '', 's3EncryptionEnabled': True,
            'cloudWatchLogGroupName': '', 'cloudWatchEncryptionEnabled': True,
            'cloudWatchStreamingEnabled': True, 'kmsKeyId': '',
            'runAsEnabled': False, 'runAsDefaultUser': '',
            'idleSessionTimeout': str(idle),
            'maxSessionDuration': str(maxDuration),
            'shellProfile': {'windows': '', 'linux': ''},
        },
    })


def test_ssm_document_shared_publicly(emu, uid):
    ssm = emu.client('ssm')
    name = f'ss-test-doc-{uid}'
    ssm.create_document(Name=name, DocumentType='Command', Content=COMMAND_DOC)
    try:
        def misconfigure():
            ssm.modify_document_permission(Name=name, PermissionType='Share',
                                           AccountIdsToAdd=['all'])

        def fix():
            ssm.modify_document_permission(Name=name, PermissionType='Share',
                                           AccountIdsToRemove=['all'])

        assertFlagFixCycle(emu, 'ssm', 'ssmDocumentPublic',
                           f'SSM Document::{name}', misconfigure, fix)
    finally:
        try:
            ssm.modify_document_permission(Name=name, PermissionType='Share',
                                           AccountIdsToRemove=['all'])
        except ClientError:
            pass
        ssm.delete_document(Name=name)


def test_ssm_public_sharing_setting_not_blocked(emu):
    ssm = emu.client('ssm')
    original = ssm.get_service_setting(SettingId=PUBLIC_SHARING)['ServiceSetting']
    try:
        def misconfigure():
            ssm.update_service_setting(SettingId=PUBLIC_SHARING, SettingValue='Enable')

        def fix():
            ssm.update_service_setting(SettingId=PUBLIC_SHARING, SettingValue='Disable')

        assertFlagFixCycle(emu, 'ssm', 'ssmDocumentPublic', 'SSM::Account',
                           misconfigure, fix)
    finally:
        if original.get('Status') == 'Default':
            ssm.reset_service_setting(SettingId=PUBLIC_SHARING)
        else:
            ssm.update_service_setting(SettingId=PUBLIC_SHARING,
                                       SettingValue=original['SettingValue'])


def test_ssm_session_prefs_weak(emu):
    ssm = emu.client('ssm')
    try:
        prior = ssm.get_document(Name=SESSION_DOC)['Content']
    except ClientError:
        prior = None
    try:
        def misconfigure():
            if prior is not None:
                ssm.delete_document(Name=SESSION_DOC)
            ## 60 minute idle timeout, no maximum session duration.
            ssm.create_document(Name=SESSION_DOC, DocumentType='Session',
                                Content=_sessionDoc(60, ''))

        def fix():
            ssm.delete_document(Name=SESSION_DOC)
            ssm.create_document(Name=SESSION_DOC, DocumentType='Session',
                                Content=_sessionDoc(15, 120))

        before, after = assertFlagFixCycle(emu, 'ssm', 'ssmSessionPrefsWeak',
                                           'SSM::Account', misconfigure, fix)
        assert all(s == 1 for s in after.values()), after
    finally:
        try:
            ssm.delete_document(Name=SESSION_DOC)
        except ClientError:
            pass
        if prior is not None:
            ssm.create_document(Name=SESSION_DOC, DocumentType='Session',
                                Content=prior)


def _prefsDoc(**inputs):
    return json.dumps({'schemaVersion': '1.0', 'description': 'prefs',
                       'sessionType': 'Standard_Stream', 'inputs': inputs})


@pytest.mark.parametrize('key,weak,good', [
    ('ssmSessionManagerNoEncryption', {'kmsKeyId': ''},
     {'kmsKeyId': 'alias/ss-session'}),
    ('ssmSessionManagerNoCloudWatchLogs',
     {'cloudWatchLogGroupName': '/ss/sessions', 'cloudWatchStreamingEnabled': False},
     {'cloudWatchLogGroupName': '/ss/sessions', 'cloudWatchStreamingEnabled': True}),
    ('ssmSessionManagerNoS3Logs', {'s3BucketName': ''},
     {'s3BucketName': 'ss-session-archive'}),
    ('ssmSessionManagerRunAsDisabled', {'runAsEnabled': False},
     {'runAsEnabled': True, 'runAsDefaultUser': 'ops'}),
])
def test_ssm_session_manager_prefs_flag_fix(emu, key, weak, good):
    ssm = emu.client('ssm')
    try:
        prior = ssm.get_document(Name=SESSION_DOC)['Content']
    except ClientError:
        prior = None
    try:
        def misconfigure():
            if prior is not None:
                ssm.delete_document(Name=SESSION_DOC)
            ssm.create_document(Name=SESSION_DOC, DocumentType='Session',
                                Content=_prefsDoc(**weak))

        def fix():
            ssm.delete_document(Name=SESSION_DOC)
            ssm.create_document(Name=SESSION_DOC, DocumentType='Session',
                                Content=_prefsDoc(**good))

        assertFlagFixCycle(emu, 'ssm', key, 'SSM::Account', misconfigure, fix)
    finally:
        try:
            ssm.delete_document(Name=SESSION_DOC)
        except ClientError:
            pass
        if prior is not None:
            ssm.create_document(Name=SESSION_DOC, DocumentType='Session',
                                Content=prior)


def test_ssm_session_prefs_missing_document_flags(emu):
    """No preferences document = AWS defaults = no max session duration."""
    ssm = emu.client('ssm')
    try:
        ssm.get_document(Name=SESSION_DOC)
        return  # preferences exist in this emulator; covered above
    except ClientError:
        pass
    res = runCheck(emu, 'ssm', 'ssmSessionPrefsWeak', 'SSM::Account').statuses()
    assert res and all(s == -1 for s in res.values()), res


def test_ssm_no_automated_patching_without_instances_is_not_a_finding(emu):
    """The emulator has no managed instances: the check must not FAIL."""
    res = runCheck(emu, 'ssm', 'ssmNoAutomatedPatching', 'SSM::Account').statuses()
    assert res and all(s != -1 for s in res.values()), res

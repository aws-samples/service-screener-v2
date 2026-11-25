"""Flag -> fix -> re-run tests for Amazon Verified Permissions checks."""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck

SCHEMA = {'cedarJson': json.dumps({'App': {'entityTypes': {'User': {}, 'Doc': {}},
                                          'actions': {'read': {'appliesTo': {
                                              'principalTypes': ['User'], 'resourceTypes': ['Doc']}}}}})}


def _store(avp, uid, mode):
    return avp.create_policy_store(validationSettings={'mode': mode},
                                   description=f'ss-test-{uid}')['policyStoreId']


def test_avp_validation_off_flag_fix(emu, uid):
    avp = emu.client('verifiedpermissions')
    psid = _store(avp, uid, 'STRICT')
    try:
        avp.put_schema(policyStoreId=psid, definition=SCHEMA)

        def misconfigure():
            avp.update_policy_store(policyStoreId=psid, validationSettings={'mode': 'OFF'})

        def fix():
            avp.update_policy_store(policyStoreId=psid, validationSettings={'mode': 'STRICT'})

        assertFlagFixCycle(emu, 'verifiedpermissions', 'avpPolicyStoreValidationOff', psid,
                           misconfigure, fix)
    finally:
        avp.delete_policy_store(policyStoreId=psid)


def test_avp_validation_off_without_schema_flags(emu, uid):
    avp = emu.client('verifiedpermissions')
    psid = _store(avp, uid, 'OFF')
    try:
        res = runCheck(emu, 'verifiedpermissions', 'avpPolicyStoreValidationOff', psid)
        assert list(res.statuses().values()) == [-1], res.results
        msg = list(res.results.values())[0]['avpPolicyStoreValidationOff'][1]
        assert 'no schema' in msg
    finally:
        avp.delete_policy_store(policyStoreId=psid)

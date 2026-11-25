"""Flag -> fix -> re-run for VPC Lattice latticeAuthTypeNone against the emulator.

The emulator implements create/get/list/delete for services but not
UpdateService, GetAuthPolicy, PutAuthPolicy or ListServiceNetworks, so it
cannot produce the PASS state (PASS requires reading the auth policy of an
AWS_IAM service). The emulator test therefore asserts:
  - misconfigure = create a service with authType NONE  -> FAIL (-1)
  - fix          = replace it with an AWS_IAM service    -> exactly
    [0, 'Unable to evaluate (NotImplemented)']: the auth policy cannot be read,
    so the check must neither PASS nor FAIL (accuracy tenet).
FAIL -> PASS on the SAME service (UpdateService authType=AWS_IAM +
PutAuthPolicy, then re-scan) is proven with real API shapes by
tests/test_stub_vpclattice.py::test_auth_none_update_service_in_place_flag_then_pass,
and the remaining PASS / service-network paths by the other Stubber tests there.
latticeAccessLogsDisabled cannot be exercised here at all
(ListAccessLogSubscriptions is NotImplemented) - see the Stubber test.
"""
from tests.emulator.conftest import runCheck

KEY = 'latticeAuthTypeNone'


def _msgs(res):
    return [m for r in res.results.values() for k, m in r.items() if k.lower() == KEY.lower()]


def test_lattice_service_auth_type_none(emu, uid):
    c = emu.client('vpc-lattice')
    prefix = f'ss-lat-{uid}'
    created = []
    try:
        created.append(c.create_service(name=f'{prefix}-a', authType='NONE')['id'])
        before = runCheck(emu, 'vpclattice', KEY, f'{prefix}-a').statuses()
        assert before and all(v == -1 for v in before.values()), before

        c.delete_service(serviceIdentifier=created[0])
        created.append(c.create_service(name=f'{prefix}-b', authType='AWS_IAM')['id'])

        gone = runCheck(emu, 'vpclattice', KEY, f'{prefix}-a').statuses()
        assert not gone, gone  # the deleted NONE service is no longer reported

        msgs = _msgs(runCheck(emu, 'vpclattice', KEY, f'{prefix}-b'))
        assert msgs and all(m == [0, 'Unable to evaluate (NotImplemented)'] for m in msgs), msgs
    finally:
        for sid in created:
            try:
                c.delete_service(serviceIdentifier=sid)
            except Exception:
                pass

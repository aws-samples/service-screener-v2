"""Flag -> fix -> re-run for VPC Lattice latticeAuthTypeNone against the emulator.

The emulator implements create/get/list/delete for services but not
UpdateService, GetAuthPolicy or ListServiceNetworks, so:
  - misconfigure = create a service with authType NONE  -> expect -1
  - fix          = delete it and create a replacement with AWS_IAM -> expect not -1
    (GetAuthPolicy is NotImplemented, so the fixed service reports 0
    'Unable to evaluate'; the PASS path with a real auth policy and all
    service-network paths are covered by tests/test_stub_vpclattice.py).
latticeAccessLogsDisabled cannot be exercised here at all
(ListAccessLogSubscriptions is NotImplemented) - see the Stubber test.
"""
from tests.emulator.conftest import assertFlagFixCycle


def test_lattice_service_auth_type_none(emu, uid):
    c = emu.client('vpc-lattice')
    prefix = f'ss-lat-{uid}'
    created = []
    try:
        def misconfigure():
            created.append(c.create_service(name=f'{prefix}-a', authType='NONE')['id'])

        def fix():
            c.delete_service(serviceIdentifier=created[0])
            created.append(c.create_service(name=f'{prefix}-b', authType='AWS_IAM')['id'])

        assertFlagFixCycle(emu, 'vpclattice', 'latticeAuthTypeNone', prefix, misconfigure, fix)
    finally:
        for sid in created:
            try:
                c.delete_service(serviceIdentifier=sid)
            except Exception:
                pass

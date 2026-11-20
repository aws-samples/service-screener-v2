"""VPC Lattice: list_services / list_service_networks also return resources
shared in through AWS RAM. A shared resource with the same name as a local
one must not overwrite the local result (objs key) or share its checkpoint
id (_resourceName).

Why not the emulator: it cannot create cross-account RAM-shared Lattice
resources. The drivers are real; check-level API calls are not needed for
latticeAuthTypeNone with authType NONE."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.vpclattice.Vpclattice import Vpclattice  # noqa: E402
from services.vpclattice.drivers.VpclatticeService import VpclatticeService  # noqa: E402
from services.vpclattice.drivers.VpclatticeServiceNetwork import VpclatticeServiceNetwork  # noqa: E402
from utils.Config import Config  # noqa: E402

ACCT = '111122223333'
OTHER = '999999999999'


class _Lattice(Vpclattice):
    """Vpclattice without Service.__init__/__del__ (no session, no scan bookkeeping)."""
    def __del__(self):
        pass


def _svc(acct, sid):
    return {'id': sid, 'name': 'payments', 'authType': 'NONE', 'status': 'ACTIVE',
            'arn': f'arn:aws:vpc-lattice:us-east-1:{acct}:service/{sid}'}


def _sn(acct, sid):
    return {'id': sid, 'name': 'core', 'authType': 'NONE', 'numberOfAssociatedServices': 1,
            'arn': f'arn:aws:vpc-lattice:us-east-1:{acct}:servicenetwork/{sid}'}


def test_driver_resource_names_distinct_for_shared_same_name():
    local = VpclatticeService(_svc(ACCT, 'svc-0123456789abcdef0'), None, ACCT)
    shared = VpclatticeService(_svc(OTHER, 'svc-0123456789abcdef9'), None, ACCT)
    assert local._resourceName == 'payments'
    assert shared._resourceName == f'payments@{OTHER}'
    snShared = VpclatticeServiceNetwork(_sn(OTHER, 'sn-0123456789abcdef9'), None, ACCT)
    assert snShared._resourceName == f'core@{OTHER}'


@pytest.mark.parametrize('order', ['local-first', 'shared-first'])
def test_shared_same_name_does_not_overwrite_local_fail(monkeypatch, order):
    Config.init()
    Config.set('stsInfo', {'Account': ACCT})
    services = [_svc(ACCT, 'svc-0123456789abcdef0'), _svc(OTHER, 'svc-0123456789abcdef9')]
    networks = [_sn(ACCT, 'sn-0123456789abcdef0'), _sn(OTHER, 'sn-0123456789abcdef9')]
    if order == 'shared-first':
        services.reverse()
        networks.reverse()

    def onlyAuth(self, serviceName):
        self._checkLatticeAuthTypeNone()
    monkeypatch.setattr(VpclatticeService, 'run', onlyAuth)
    monkeypatch.setattr(VpclatticeServiceNetwork, 'run', onlyAuth)

    svc = _Lattice.__new__(_Lattice)
    svc.latticeClient = None
    svc.getResources = lambda: {'serviceNetworks': networks, 'services': services}
    objs = svc.advise()

    assert objs['Service::payments']['results']['latticeAuthTypeNone'][0] == -1, objs
    assert objs[f'Service::payments@{OTHER}']['results']['latticeAuthTypeNone'][0] == 0, objs
    assert objs['ServiceNetwork::core']['results']['latticeAuthTypeNone'][0] == -1, objs
    assert objs[f'ServiceNetwork::core@{OTHER}']['results']['latticeAuthTypeNone'][0] == 0, objs

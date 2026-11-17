"""Emulator end-to-end test for services/drs.

The emulator cannot create a DRS source server (needs the replication agent; CreateExtendedSourceServer
and DescribeJobs are NotImplemented), so the flag -> fix -> re-run cycles for drsReplicationUnhealthy
and drsNoRecentDrill live in tests/test_stub_drs.py. This test drives the real service path
(Drs.advise via CheckRunner) against an initialized, empty region and asserts nothing is falsely
flagged and the drill check reports INFO rather than PASS.
"""
from tests.emulator.conftest import runCheck


def test_drs_empty_region_end_to_end(emu, uid):
    emu.client('drs').initialize_service()
    rep = runCheck(emu, 'drs', 'drsReplicationUnhealthy')
    assert all(s != -1 for s in rep.statuses().values()), rep.results
    drill = runCheck(emu, 'drs', 'drsNoRecentDrill', 'DRS::Account')
    st = drill.statuses()
    assert st and all(s == 0 for s in st.values()), drill.results

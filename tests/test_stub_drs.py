"""Stubber flag -> fix -> re-run tests for services/drs (no AWS, no emulator).

Why Stubber and not the emulator: the AWS Emulator implements drs.describe_source_servers but
offers no way to create a source server (that needs the AWS Replication Agent; the only API path,
CreateExtendedSourceServer, is NotImplemented), and drs.describe_jobs is NotImplemented. So a
misconfigured -> fixed source server cannot be produced there. tests/emulator/test_emu_drs.py
covers the emulator end-to-end path (empty, initialized region).

Responses go through real boto3 'drs' clients wrapped by botocore.stub.Stubber, so the API
shapes are validated against the real service model, including the service-level paginators.
"""
import datetime
import os
import sys

import boto3
from botocore.stub import Stubber, ANY

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.drs.Drs import Drs  # noqa: E402
from services.drs.drivers.DrsSourceServer import DrsSourceServer, parseIsoDuration  # noqa: E402
from services.drs.drivers.DrsCommon import DrsCommon  # noqa: E402

ACCT = '111122223333'
SID = 's-1234567890abcdef0'
SID2 = 's-0fedcba0987654321'
NOW = datetime.datetime.now(datetime.timezone.utc)


def _iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000000+00:00')


def _client():
    return boto3.client('drs', region_name='us-east-1',
                        aws_access_key_id='stub', aws_secret_access_key='stub')


def _server(sid=SID, state='CONTINUOUS', lag='PT2S', error=None, addedDaysAgo=400, lastLaunch=None, **over):
    dri = {'dataReplicationState': state,
           'replicatedDisks': [{'deviceName': '/dev/xvda', 'totalStorageBytes': 10, 'replicatedStorageBytes': 10,
                                'backloggedStorageBytes': 0, 'rescannedStorageBytes': 0}]}
    if lag:
        dri['lagDuration'] = lag
    if error:
        dri['dataReplicationError'] = {'error': error, 'rawError': 'agent not seen for 1 hour'}
    lc = {'addedToServiceDateTime': _iso(NOW - datetime.timedelta(days=addedDaysAgo))}
    if lastLaunch:
        lc['lastLaunch'] = lastLaunch
    s = {'sourceServerID': sid, 'arn': f'arn:aws:drs:us-east-1:{ACCT}:source-server/{sid}',
         'dataReplicationInfo': dri, 'lifeCycle': lc, 'replicationDirection': 'FAILOVER',
         'sourceProperties': {'identificationHints': {'hostname': f'host-{sid[-4:]}'}}, 'tags': {}}
    s.update(over)
    return s


def _job(sid=SID, daysAgo=10, initiatedBy='START_DRILL', launchStatus='LAUNCHED'):
    return {'jobID': 'drsjob-1234567890abcdef0', 'arn': f'arn:aws:drs:us-east-1:{ACCT}:job/drsjob-1',
            'type': 'LAUNCH', 'initiatedBy': initiatedBy, 'status': 'COMPLETED',
            'creationDateTime': _iso(NOW - datetime.timedelta(days=daysAgo)),
            'endDateTime': _iso(NOW - datetime.timedelta(days=daysAgo)),
            'participatingServers': [{'sourceServerID': sid, 'launchStatus': launchStatus,
                                      'recoveryInstanceID': 'i-1234567890abcdef0'}]}


class _StubDrs(Drs):
    """Drs without Service.__init__/__del__ (those need a full scan Config)."""
    def __del__(self):
        pass


def _drs(client):
    """A Drs service object wired to a stubbed client."""
    d = object.__new__(_StubDrs)
    d.drsClient = client
    d.tags = []
    d.region = 'us-east-1'
    return d


def _scan(servers, jobs=None, jobsError=None, serversError=None):
    """Drive Drs.getResources/_getDrillJobs through Stubber, then evaluate both drivers."""
    c = _client()
    with Stubber(c) as st:
        if serversError:
            st.add_client_error('describe_source_servers', serversError, http_status_code=403,
                                expected_params={'filters': {}})
        else:
            st.add_response('describe_source_servers', {'items': servers}, {'filters': {}})
        if not serversError and servers:
            if jobsError:
                st.add_client_error('describe_jobs', jobsError, http_status_code=403,
                                    expected_params={'filters': {'fromDate': ANY}})
            else:
                st.add_response('describe_jobs', {'items': jobs or []}, {'filters': {'fromDate': ANY}})
        d = _drs(c)
        got, err = d.getResources()
        jobsGot, jErr = (None, None)
        if err is None and got:
            jobsGot, jErr = d._getDrillJobs(NOW)
        st.assert_no_pending_responses()

    per = {}
    for s in got:
        drv = DrsSourceServer(s)
        drv._checkReplicationUnhealthy()
        per[s['sourceServerID']] = drv.results['drsReplicationUnhealthy']
    common = DrsCommon({'_region': 'us-east-1', '_now': NOW, '_windowDays': 90, '_servers': got,
                        '_serversError': err, '_drillJobs': jobsGot, '_jobsError': jErr})
    common._checkNoRecentDrill()
    return per, common.results['drsNoRecentDrill']


# ---------------------------------------------------------------- drsReplicationUnhealthy
def test_replication_flag_fix_stalled():
    per, _ = _scan([_server(state='STALLED', error='AGENT_NOT_SEEN')], jobs=[_job()])
    assert per[SID][0] == -1 and 'AGENT_NOT_SEEN' in per[SID][1]
    per, _ = _scan([_server(state='CONTINUOUS')], jobs=[_job()])
    assert per[SID][0] == 1


def test_replication_flag_fix_states():
    for state in ('DISCONNECTED', 'STOPPED', 'PAUSED'):
        per, _ = _scan([_server(state=state, lag=None)], jobs=[])
        assert per[SID][0] == -1, state
    for state in ('BACKLOG', 'CREATING_SNAPSHOT', 'RESCAN'):
        per, _ = _scan([_server(state=state)], jobs=[_job()])
        assert per[SID][0] == 1, state


def test_replication_flag_fix_lag():
    per, _ = _scan([_server(state='CONTINUOUS', lag='PT3H5M')], jobs=[_job()])
    assert per[SID][0] == -1 and 'lag' in per[SID][1]
    per, _ = _scan([_server(state='CONTINUOUS', lag='PT45M')], jobs=[_job()])
    assert per[SID][0] == 1


def test_replication_error_without_bad_state_fails():
    per, _ = _scan([_server(state='INITIATING', lag=None, error='FAILED_TO_LAUNCH_REPLICATION_SERVER')], jobs=[])
    assert per[SID][0] == -1


def test_replication_initial_sync_is_info_not_pass():
    per, _ = _scan([_server(state='INITIAL_SYNC', lag=None, addedDaysAgo=1)])
    assert per[SID][0] == 0


def test_iso_duration_parser():
    assert parseIsoDuration('PT1H2M3.5S') == 3723.5
    assert parseIsoDuration('P1DT1H') == 90000
    assert parseIsoDuration('garbage') is None
    assert parseIsoDuration('P') is None


# ---------------------------------------------------------------- drsNoRecentDrill
def test_drill_flag_fix_cycle():
    # Flag: only a 120-day-old drill (outside the window would not be returned by fromDate; also
    # filtered client-side) and a recent *recovery* launch, which is not a drill.
    _, r = _scan([_server()], jobs=[_job(daysAgo=120), _job(initiatedBy='START_RECOVERY')])
    assert r[0] == -1 and SID in r[1]
    # Fix: a drill 10 days ago that launched.
    _, r = _scan([_server()], jobs=[_job(daysAgo=10)])
    assert r[0] == 1


def test_drill_terminated_instance_counts_failed_launch_does_not():
    _, r = _scan([_server()], jobs=[_job(launchStatus='TERMINATED')])
    assert r[0] == 1
    _, r = _scan([_server()], jobs=[_job(launchStatus='FAILED')])
    assert r[0] == -1


def test_drill_partial_coverage_fails():
    _, r = _scan([_server(SID), _server(SID2)], jobs=[_job(SID)])
    assert r[0] == -1 and SID2 in r[1] and '1 of 2' in r[1]


def test_drill_lastlaunch_evidence_when_jobs_denied():
    recent = {'initiated': {'apiCallDateTime': _iso(NOW - datetime.timedelta(days=5)),
                            'jobID': 'drsjob-1234567890abcdef0', 'type': 'DRILL'}, 'status': 'TERMINATED'}
    _, r = _scan([_server(lastLaunch=recent)], jobsError='AccessDeniedException')
    assert r[0] == 1
    # Without lastLaunch evidence and describe_jobs denied: never PASS, never FAIL.
    _, r = _scan([_server()], jobsError='AccessDeniedException')
    assert r == [0, 'Unable to evaluate (AccessDeniedException)']


def test_drill_new_and_disconnected_servers_not_due():
    _, r = _scan([_server(addedDaysAgo=10), _server(SID2, state='DISCONNECTED', lag=None)], jobs=[])
    assert r[0] == 0


def test_access_denied_on_source_servers_is_unable_to_evaluate():
    per, r = _scan([], serversError='AccessDeniedException')
    assert per == {} and r == [0, 'Unable to evaluate (AccessDeniedException)']


def test_no_servers_is_info():
    per, r = _scan([])
    assert per == {} and r[0] == 0

import datetime
import re

from services.Evaluator import Evaluator


def parseDrsDate(value):
    """DRS returns ISO-8601 date strings. Return an aware datetime or None."""
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        try:
            dt = datetime.datetime.fromisoformat(str(value).strip().replace('Z', '+00:00'))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


_DURATION_RE = re.compile(
    r'^P(?:(?P<d>\d+(?:\.\d+)?)D)?(?:T(?:(?P<h>\d+(?:\.\d+)?)H)?(?:(?P<m>\d+(?:\.\d+)?)M)?(?:(?P<s>\d+(?:\.\d+)?)S)?)?$'
)


def parseIsoDuration(value):
    """Parse an ISO-8601 duration such as 'PT1H2M3.5S' or 'P1DT2H' into seconds (None if unparseable)."""
    if not value:
        return None
    m = _DURATION_RE.match(str(value).strip().upper())
    if not m or not any(m.groupdict().values()):
        return None
    g = {k: float(v) if v else 0.0 for k, v in m.groupdict().items()}
    return g['d'] * 86400 + g['h'] * 3600 + g['m'] * 60 + g['s']


def serverLabel(server):
    sid = server.get('sourceServerID') or 'unknown'
    hints = (server.get('sourceProperties') or {}).get('identificationHints') or {}
    host = hints.get('hostname') or hints.get('fqdn') or hints.get('awsInstanceID')
    return f"{sid} ({host})" if host else sid


class DrsSourceServer(Evaluator):
    """
    Per source server AWS Elastic Disaster Recovery checks.

    Input: one item from drs.describe_source_servers.
    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ## Replication states where the server has no current recovery point being kept up to date.
    UNHEALTHY_STATES = {
        'STALLED': 'replication is stalled',
        'DISCONNECTED': 'the replication agent is disconnected from the service',
        'STOPPED': 'replication is stopped (existing recovery snapshots were removed)',
        'PAUSED': 'replication is paused',
    }
    ## States reached while replication is still being set up; protection is not yet established.
    SETUP_STATES = ('INITIATING', 'INITIAL_SYNC')
    HEALTHY_STATES = ('CONTINUOUS', 'BACKLOG', 'CREATING_SNAPSHOT', 'RESCAN')

    ## Continuous replication normally keeps lag at seconds; over an hour means the
    ## achievable RPO is already far outside what DRS is deployed for.
    LAG_FAIL_SECONDS = 3600

    def __init__(self, server):
        super().__init__()
        self.server = server
        self.dri = server.get('dataReplicationInfo') or {}
        self._resourceName = server.get('sourceServerID') or 'unknown'

        self.addII('sourceServerArn', server.get('arn') or 'N/A')
        self.addII('hostname', ((server.get('sourceProperties') or {}).get('identificationHints') or {}).get('hostname') or 'N/A')
        self.addII('dataReplicationState', self.dri.get('dataReplicationState') or 'N/A')
        self.addII('lagDuration', self.dri.get('lagDuration') or 'N/A')
        self.addII('replicationDirection', server.get('replicationDirection') or 'N/A')

    def _checkReplicationUnhealthy(self):
        key = 'drsReplicationUnhealthy'
        label = serverLabel(self.server)
        state = self.dri.get('dataReplicationState')
        err = self.dri.get('dataReplicationError') or {}
        errCode = err.get('error')
        rawErr = err.get('rawError')

        problems = []
        if state in self.UNHEALTHY_STATES:
            problems.append(f"state {state}: {self.UNHEALTHY_STATES[state]}")
        if errCode:
            problems.append(f"replication error {errCode}" + (f" ({rawErr[:200]})" if rawErr else ''))

        steps = ((self.dri.get('dataReplicationInitiation') or {}).get('steps')) or []
        failedSteps = [s.get('name') for s in steps if s.get('status') == 'FAILED' and s.get('name')]
        if failedSteps and not errCode:
            problems.append('replication initiation step(s) failed: ' + ', '.join(failedSteps))

        lagSec = parseIsoDuration(self.dri.get('lagDuration'))
        if state in self.HEALTHY_STATES and lagSec is not None and lagSec > self.LAG_FAIL_SECONDS:
            problems.append(f"replication lag {self.dri.get('lagDuration')} exceeds 1 hour")

        if problems:
            self.results[key] = [-1, f"Source server {label}: " + '; '.join(problems)]
        elif state in self.SETUP_STATES:
            self.results[key] = [0, f"Source server {label}: replication still being established ({state}) - not yet evaluable"]
        elif state in self.HEALTHY_STATES:
            lag = self.dri.get('lagDuration')
            self.results[key] = [1, f"Source server {label}: replication {state}" + (f", lag {lag}" if lag else '')]
        else:
            self.results[key] = [0, f"Source server {label}: Unable to evaluate (replication state {state or 'not reported'})"]

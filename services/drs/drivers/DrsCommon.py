import datetime

from services.Evaluator import Evaluator
from services.drs.drivers.DrsSourceServer import parseDrsDate, serverLabel


class DrsCommon(Evaluator):
    """
    Account/region-scoped AWS Elastic Disaster Recovery checks.

    Input (from services/drs/Drs.py.advise):
      '_region', '_now' (aware datetime), '_windowDays', '_servers' (describe_source_servers items),
      '_serversError', '_drillJobs' (START_DRILL LAUNCH jobs from describe_jobs since now-window,
      or None), '_jobsError'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ## A server whose replication is disconnected/stopped cannot be drilled and is reported by
    ## drsReplicationUnhealthy instead; FAILBACK-direction servers are reverse replication.
    NOT_DRILLABLE_STATES = ('DISCONNECTED', 'STOPPED')
    ## A drill launch counts when the drill instance launched (TERMINATED = launched, then cleaned up).
    LAUNCHED = ('LAUNCHED', 'TERMINATED')

    def __init__(self, detail):
        super().__init__()
        self.detail = detail
        self._resourceName = 'Account'
        self.servers = detail.get('_servers') or []
        self.now = detail.get('_now') or datetime.datetime.now(datetime.timezone.utc)
        self.windowDays = detail.get('_windowDays') or 90

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('sourceServerCount', str(len(self.servers)))

    def _drilledServerIds(self):
        """Source server IDs with a successful drill launch inside the window."""
        cutoff = self.now - datetime.timedelta(days=self.windowDays)
        drilled = set()
        for job in self.detail.get('_drillJobs') or []:
            if job.get('initiatedBy') != 'START_DRILL':
                continue
            created = parseDrsDate(job.get('creationDateTime'))
            if created is not None and created < cutoff:
                continue
            for p in job.get('participatingServers') or []:
                if p.get('launchStatus') in self.LAUNCHED and p.get('sourceServerID'):
                    drilled.add(p['sourceServerID'])
        ## lifeCycle.lastLaunch is a second source (covers job history beyond the page cap).
        for s in self.servers:
            last = (s.get('lifeCycle') or {}).get('lastLaunch') or {}
            init = last.get('initiated') or {}
            when = parseDrsDate(init.get('apiCallDateTime'))
            if init.get('type') == 'DRILL' and last.get('status') in self.LAUNCHED and when and when >= cutoff:
                drilled.add(s.get('sourceServerID'))
        return drilled

    # REL13-BP03: DR implementation must be tested regularly.
    def _checkNoRecentDrill(self):
        key = 'drsNoRecentDrill'
        if self.detail.get('_serversError'):
            self.results[key] = [0, f"Unable to evaluate ({self.detail['_serversError']})"]
            return
        if not self.servers:
            self.results[key] = [0, 'No Elastic Disaster Recovery source servers in this region - not evaluated']
            return

        cutoff = self.now - datetime.timedelta(days=self.windowDays)
        due, notYetDue = [], []
        for s in self.servers:
            state = (s.get('dataReplicationInfo') or {}).get('dataReplicationState')
            if state in self.NOT_DRILLABLE_STATES or s.get('replicationDirection') == 'FAILBACK':
                continue
            added = parseDrsDate((s.get('lifeCycle') or {}).get('addedToServiceDateTime'))
            if added is not None and added > cutoff:
                notYetDue.append(s)
            else:
                due.append(s)

        if not due:
            self.results[key] = [
                0, f"No source server has been protected for more than {self.windowDays} days "
                   f"({len(notYetDue)} recently added) - drill not yet due"
            ]
            return

        drilled = self._drilledServerIds()
        missing = [s for s in due if s.get('sourceServerID') not in drilled]
        jobsErr = self.detail.get('_jobsError')

        if missing and jobsErr:
            self.results[key] = [0, f"Unable to evaluate ({jobsErr})"]
            return
        if missing:
            shown = ', '.join(serverLabel(s) for s in missing[:5]) + (' ...' if len(missing) > 5 else '')
            self.results[key] = [
                -1, f"{len(missing)} of {len(due)} DRS source server(s) have had no successful recovery drill "
                    f"in the last {self.windowDays} days: {shown}"
            ]
            return
        self.results[key] = [
            1, f"All {len(due)} DRS source server(s) had a successful recovery drill in the last {self.windowDays} days"
        ]

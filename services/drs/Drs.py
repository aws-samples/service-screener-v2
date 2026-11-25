import datetime

import botocore

from utils.Tools import _pi
from services.Service import Service

from services.drs.drivers.DrsSourceServer import DrsSourceServer
from services.drs.drivers.DrsCommon import DrsCommon


class Drs(Service):
    """
    AWS Elastic Disaster Recovery (DRS) scanner.

    Per source server (DrsSourceServer):
      - drsReplicationUnhealthy  (describe_source_servers dataReplicationInfo)
    Per account/region (DrsCommon):
      - drsNoRecentDrill         (describe_jobs START_DRILL launches in the last
                                  90 days, plus lifeCycle.lastLaunch)

    Read-only calls only: describe_source_servers, describe_jobs (both paginated).
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )
    ## DRS raises this in a region where the service was never initialized.
    UNINITIALIZED_CODES = ('UninitializedAccountException',)

    DRILL_WINDOW_DAYS = 90
    ## Hard cap on describe_jobs pages so a busy account cannot stall the scan.
    JOB_PAGE_CAP = 50

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.drsClient = ssBoto.client('drs', config=self.bConfig)

    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def getResources(self):
        """Return (servers, errorCode). errorCode is None on success."""
        servers = []
        try:
            paginator = self.drsClient.get_paginator('describe_source_servers')
            for page in paginator.paginate(filters={}):
                servers += page.get('items', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_source_servers', e)
            return [], self._errCode(e)

        if self.tags:
            servers = [s for s in servers
                       if self.resourceHasTags(self.convertKeyPairTagToTagFormat(s.get('tags') or {}))]
        return servers, None

    def _getDrillJobs(self, now):
        """START_DRILL launch jobs created in the drill window. Returns (jobs, errorCode)."""
        fromDate = (now - datetime.timedelta(days=self.DRILL_WINDOW_DAYS)).strftime('%Y-%m-%dT%H:%M:%SZ')
        jobs = []
        try:
            paginator = self.drsClient.get_paginator('describe_jobs')
            pages = 0
            for page in paginator.paginate(filters={'fromDate': fromDate}):
                for job in page.get('items', []) or []:
                    if job.get('initiatedBy') == 'START_DRILL' and job.get('type', 'LAUNCH') == 'LAUNCH':
                        jobs.append(job)
                pages += 1
                if pages >= self.JOB_PAGE_CAP and page.get('nextToken'):
                    ## Older jobs were not read: a server missing from `jobs` may still
                    ## have been drilled, so the caller must not report it as undrilled.
                    return jobs, 'PageCapReached'
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_jobs', e)
            return None, self._errCode(e)
        return jobs, None

    def advise(self):
        objs = {}
        try:
            servers, serversError = self.getResources()
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Elastic Disaster Recovery not available in region {self.region}: {e}")
            return objs

        for server in servers:
            sid = server.get('sourceServerID') or 'unknown'
            _pi('Drs', f"SourceServer: {sid}")
            try:
                obj = DrsSourceServer(server)
                obj.run(self.__class__)
                objs[f"SourceServer::{sid}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing DRS source server {sid}: {e}")

        ## Not initialized in this region == DRS is not in use here; nothing to report.
        if serversError in self.UNINITIALIZED_CODES:
            return objs

        now = datetime.datetime.now(datetime.timezone.utc)
        jobs, jobsError = (None, None)
        if serversError is None and servers:
            jobs, jobsError = self._getDrillJobs(now)

        detail = {
            '_region': self.region,
            '_now': now,
            '_windowDays': self.DRILL_WINDOW_DAYS,
            '_servers': servers,
            '_serversError': serversError,
            '_drillJobs': jobs,
            '_jobsError': jobsError,
        }
        try:
            obj = DrsCommon(detail)
            obj.run(self.__class__)
            objs['DRS::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing DRS account checks in {self.region}: {e}")
        return objs

    def _logClientError(self, where, error):
        code = self._errCode(error)
        if code in self.ACCESS_DENIED_CODES or code in self.UNINITIALIZED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Drs {where}: {code} - {msg}")

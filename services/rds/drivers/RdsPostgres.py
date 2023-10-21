
from .RdsCommon import RdsCommon

class RdsPostgres(RdsCommon):
    def __init__(self, db, rdsClient, ctClient, cwClient):
        super().__init__(db, rdsClient, ctClient, cwClient)
        self.loadParameterInfo()

    def _checkPostgresParam(self):
        params = self.dbParams

        idleTimeout = params.get('idle_in_transaction_session_timeout', False)
        if idleTimeout in (False, None) or int(idleTimeout) < 30000 or int(idleTimeout) > 86400001:
            self.results['PG__param_idleTransTimeout'] = [-1, "Configured: {}, Recommended: {}".format(idleTimeout, '30000-86400001')]

        statementTimeout = params.get('statement_timeout', False)
        if statementTimeout in (False, None) or int(statementTimeout) < 1 or int(statementTimeout) > 1800001:
            self.results['PG__param_statementTimeout'] = [-1, "Configured: {}, Recommended: {}".format(idleTimeout, '1-1800001')]

        logTempFiles = params.get('log_temp_files', False)
        if logTempFiles in (False, None) or int(logTempFiles) > 5242880:
            self.results['PG__param_logTempFiles'] = [-1, "Configured: {}, Recommended: {}".format(idleTimeout, '0-5242880')]

        ## seems no such things
        tempFileLimit = params.get('temp_file_limit', False)
        if tempFileLimit in (False, None) or tempFileLimit < 10:
            self.results['PG__param_tempFileLimit'] = [-1, "Configured: {}, Recommended: {}".format(tempFileLimit, '10-500000001')]

        alevel = params.get('rds.force_autovacuum_logging_level', False)
        alevel = alevel.upper()
        if not alevel in (False, 'INFO', 'DEBUG1'):
            self.results['PG__param_rdsAutoVacuum'] = [-1, "Configured: {}, Recommended: {}".format(alevel, 'INFO or DEBUG1')]

        adlevel = params.get('log_autovacuum_min_duration', False)
        if adlevel in (False, None) or int(adlevel) > 120000:
            self.results['PG__param_autoVacDuration'] = [-1, "Configured: {}, Recommended: {}".format(alevel, '0-120000')]

        trackIo = params.get('track_io_timing', False)
        if not trackIo in ('on', '1', 1):
            self.results['PG__param_trackIoTime'] = [-1, "Configured: {}, Recommended: {}".format(trackIo, '1')]

        logStatement = params.get('log_statement', False)
        if not logStatement in ('none', 'ddl', False):
            self.results['PG__param_logStatement'] = [-1, "Configured: {}, Recommended: {}".format(logStatement, 'none or ddl')]
            
        ## TODO Reporter
        track_activities = params.get('track_activities', False)
        if not track_activities in ('on', '1', 1, False):
            self.results['PG__param_trackActivities'] = [-1, "Configured: {}, Recommended: {}".format(track_activities, '1')]
            
        track_counts = params.get('track_counts', False)
        if not track_activities in ('on', '1', 1, False):
            self.results['PG__param_trackCounts'] = [-1, "Configured: {}, Recommended: {}".format(track_counts, '1')]
            
        synchronous_commit = params.get('synchronous_commit', False)
        if not synchronous_commit in ('on', '1', 1, False):
            self.results['PG__param_synchronousCommit'] = [-1, "Configured: {}, Recommended: {}".format(synchronous_commit, '1')]
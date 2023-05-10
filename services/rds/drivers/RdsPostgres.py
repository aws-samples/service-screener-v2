
from .RdsCommon import RdsCommon

class RdsPostgres(RdsCommon):
    def __init__(self, db, rdsClient):
        super().__init__(db, rdsClient)
        self.loadParameterInfo()

    def _checkPostgresParam(self):
        params = self.dbParams

        idleTimeout = params.get('idle_in_transaction_session_timeout', False)
        if idleTimeout in (False, 0):
            self.results['PG__param_idleTransTimeout'] = [-1, 'null' if idleTimeout is False else idleTimeout]

        statementTimeout = params.get('statement_timeout', False)
        if statementTimeout in (False, 0, ''):
            self.results['PG__param_statementTimeout'] = [-1, 'null' if statementTimeout is False else statementTimeout]

        logTempFiles = params.get('log_temp_files', False)
        if logTempFiles in (False, 0, ''):
            self.results['PG__param_logTempFiles'] = [-1, 'null' if logTempFiles is False else logTempFiles]

        tempFileLimit = params.get('temp_file_limit', False)
        if tempFileLimit in (False, 0, ''):
            self.results['PG__param_tempFileLimit'] = [-1, 'null' if tempFileLimit is False else tempFileLimit]

        alevel = params.get('rds.force_autovacuum_logging_level', False)
        if alevel in (False, '', 'warning'):
            self.results['PG__param_rdsAutoVacuum'] = [-1, 'null' if alevel is False else alevel]

        adlevel = params.get('log_autovacuum_min_duration', False)
        if adlevel in (False, 0, ''):
            self.results['PG__param_autoVacDuration'] = [-1, 'null' if adlevel is False else adlevel]

        trackIo = params.get('track_io_timing', False)
        if trackIo in (False, 0, ''):
            self.results['PG__param_trackIoTime'] = [-1, 'null' if trackIo is False else adlevel]

        logStatement = params.get('log_statement', False)
        if logStatement in ('mod', 'all'):
            self.results['PG__param_logStatement'] = [-1, 'none' if logStatement is False else logStatement]

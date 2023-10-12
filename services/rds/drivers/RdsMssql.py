
from utils.Tools import _pr

from .RdsCommon import RdsCommon

class RdsMssql(RdsCommon):
    def __init__(self, db, rdsClient, ctClient):
        super().__init__(db, rdsClient, ctClient)
        self.loadParameterInfo()
    
    # check if MSSQL engine is Express Edition / Web Edition
    def _checkEngineHasMultiAZSupport(self):
        flaggedEngines = ['sqlserver-ex','sqlserver-web']
        engine = self.db['Engine']
        
        if engine in flaggedEngines:
            # print("instance flagged: multiAZ not supported")
            self.results['MSSQL__EngineHasMultiAZSupport'] = [-1,engine]

    def _checkSSLParams(self):
        if 'rds.force_ssl' in self.dbParams and self.dbParams['rds.force_ssl'] == '0':
            self.results['MSSQL__TransportEncrpytionDisabled'] = [-1, 'rds.force_ssl==0']
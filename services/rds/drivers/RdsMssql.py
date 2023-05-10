
from utils.Tools import _pr

from .RdsCommon import RdsCommon

class RdsMssql(RdsCommon):
    def __init__(self, db, rdsClient):
        super().__init__(db, rdsClient)
        self.loadParameterInfo()
    
    # check if MSSQL engine is Express Edition / Web Edition
    def _checkEngineHasMultiAZSupport(self):
        flaggedEngines = ['sqlserver-ex','sqlserver-web']
        engine = self.db['Engine']
        
        if engine in flaggedEngines:
            # print("instance flagged: multiAZ not supported")
            self.results['MSSQL__EngineHasMultiAZSupport'] = [-1,engine]


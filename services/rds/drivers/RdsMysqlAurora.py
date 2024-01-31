
from .RdsMysql import RdsMysql

class RdsMysqlAurora(RdsMysql):
    def __init__(self, db, rdsClient, ctClient, cwClient):
        super().__init__(db, rdsClient, ctClient, cwClient)
        self.loadParameterInfo()
        
    def _checkAuroraStorage64TBLimit(self):
        if self.isCluster == False:
            return
        
        engVersion = self.db['EngineVersion']
        info = engVersion.split('.')
        sz = len(info)
        
        majorV = int(info[(sz-3)])
        minorV = int(info[(sz-2)])
        if majorV > 2:
            return
        
        needFlag = False
        if majorV < 2:
            needFlag = True
        elif majorV == 2 and minorV < 9:
            needFlag = True
                    
        if needFlag:
            self.results['AuroraStorage64TBLimit'] = [-1, engVersion]
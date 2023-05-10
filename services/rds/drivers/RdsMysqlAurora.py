
from .RdsMysql import RdsMysql

class RdsMysqlAurora(RdsMysql):
    def __init__(self, db, rdsClient):
        super().__init__(db, rdsClient)
        self.loadParameterInfo()
        
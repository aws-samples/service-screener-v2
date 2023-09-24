
from .RdsMysql import RdsMysql

class RdsMysqlAurora(RdsMysql):
    def __init__(self, db, rdsClient, ctClient):
        super().__init__(db, rdsClient, ctClient)
        self.loadParameterInfo()
        
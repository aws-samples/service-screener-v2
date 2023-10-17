
from .RdsMysql import RdsMysql

class RdsMysqlAurora(RdsMysql):
    def __init__(self, db, rdsClient, ctClient, cwClient):
        super().__init__(db, rdsClient, ctClient, cwClient)
        self.loadParameterInfo()
        
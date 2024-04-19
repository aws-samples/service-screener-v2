from .RdsMysql import RdsMysql

class RdsMariadb(RdsMysql):
    def __init__(self, db, rdsClient, ctClient, cwClient):
        super().__init__(db, rdsClient, ctClient, cwClient)
        self.loadParameterInfo()


from .RdsPostgres import RdsPostgres

class RdsPostgresAurora(RdsPostgres):
    def __init__(self, db, rdsClient):
        super().__init__(db, rdsClient)
        self.loadParameterInfo()
        
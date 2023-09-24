
from .RdsPostgres import RdsPostgres

class RdsPostgresAurora(RdsPostgres):
    def __init__(self, db, rdsClient, ctClient):
        super().__init__(db, rdsClient, ctClient)
        self.loadParameterInfo()
        
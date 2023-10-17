
from .RdsPostgres import RdsPostgres

class RdsPostgresAurora(RdsPostgres):
    def __init__(self, db, rdsClient, ctClient, cwClient):
        super().__init__(db, rdsClient, ctClient, cwClient)
        self.loadParameterInfo()
        
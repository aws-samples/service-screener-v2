from utils.Config import Config
from utils.CustomPage.CustomObject import CustomObject

class Modernize(CustomObject):
    ResourcesToTrack = {
        'rds': {
            'rdsmariadb': {'MoveToGraviton', 'ConsiderAurora'},
            'rdsmysql': {'MoveToGraviton', 'ConsiderAurora'},
            'rdsmssql': {'ConsiderOpenSource'},
            'rdspostgres': {'MoveToGraviton', 'ConsiderAurora'},
            'rdsmysqlaurora': {},
            'rdspostgresaurora': {}
        },
        'ec2': {
            'ec2instance': {}
        },
        'eks': {
            'ekscommon': {}
        },
        'lambda': {
            'lambdacommon': {}
        }
    }
    
    def __init__(self):
        super().__init__()
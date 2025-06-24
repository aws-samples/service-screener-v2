import botocore

from utils.Config import Config
from services.Evaluator import Evaluator

class CloudtrailAccount(Evaluator):
    def __init__(self, ctClient, sizeofTrail):
        super().__init__()
        self.ctClient = ctClient
        self.sizeofTrail = sizeofTrail
        
        self._resourceName = 'General'

        self.init()
    
    ## For General Trail purpose
    def _checkHasOneTrailConfiguredCorrectly(self):
        if self.sizeofTrail == 0:
            self.results['NeedToEnableCloudTrail'] = [-1, '']
        
        if Config.get('CloudTrail_hasOneMultiRegion') == False:
            self.results['HasOneMultiRegionTrail'] = [-1, '']
            
        if Config.get('CloudTrail_hasGlobalServEnabled') == False:
            self.results['HasCoverGlobalServices'] = [-1, '']
            
        if Config.get('CloudTrail_hasManagementEventsCaptured') == False:
            self.results['HasManagementEventsCaptured'] = [-1, '']
        
        if Config.get('CloudTrail_hasDataEventsCaptured') == False:
            self.results['HasDataEventsCaptured'] = [-1, '']
            
        lists = Config.get('CloudTrail_listGlobalServEnabled')
        if len(lists) > 1:
            self.results['DuplicateGlobalTrail'] = [-1, '<br>'.join(lists)]
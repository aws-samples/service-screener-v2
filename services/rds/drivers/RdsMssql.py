import math

from utils.Tools import _pr
from .RdsCommon import RdsCommon

class RdsMssql(RdsCommon):
    def __init__(self, db, rdsClient, ctClient):
        super().__init__(db, rdsClient, ctClient)
        self.loadParameterInfo()
        
        self.getMSSQLEdition()
    
    def getMSSQLEdition(self):
        self.sqlEdition = self.db['Engine'][10:]
        
    
    # check if MSSQL engine is Express Edition / Web Edition
    def _checkEngineHasMultiAZSupport(self):
        flaggedEngines = ['sqlserver-ex','sqlserver-web']
        engine = self.db['Engine']
        
        if engine in flaggedEngines:
            # print("instance flagged: multiAZ not supported")
            self.results['MSSQL__EngineHasMultiAZSupport'] = [-1,engine]

    def _checkEntSpecs(self):
        if self.sqlEdition == 'ee':
            if self.instInfo['specification']['vcpu'] <= 48 or self.instInfo['specification']['memoryInGiB'] <= 128:
                self.results['MSSQL__EEUnderSize'] = [-1, self.db['DBInstanceClass']]
            
    def _checkNonEntSpecs(self):
        if not self.sqlEdition == 'ee':
            if self.instInfo['specification']['vcpu'] > 48 or self.instInfo['specification']['memoryInGiB'] > 128:
                self.results['MSSQL__EditionOversize'] = [-1, self.db['DBInstanceClass'] + ' :: ' + self.sqlEdition]
                
    def _checkEnt2017OrAbove(self):
        if self.sqlEdition == 'ee':
            y = self.enginePatches['DBEngineVersionDescription'][11:15]
            if int(y) >= 2017:
                self.results['MSSQL__EE2017'] = [-1, self.enginePatches['DBEngineVersionDescription']]
    
    def _checkParamCostThresholdParallelism(self):
        costT = self.dbParams['cost threshold for parallelism']
        recommendedThreshold = 50
        if int(costT) < recommendedThreshold:
            self.results['MSSQL__ParamCostThresholdTooLow'] = [-1, "Recommended: >{}<br>Current:{}".format(recommendedThreshold, costT)]
    
    def _checkParamMaxServerMemory(self):
        ## Calculate max server memory:
        GbToKbRatio = 1024*1024
        # total_RAM - (memory_for_the_OS + MemoryToLeave)
        memTotal = self.instInfo['specification']['memoryInGiB']
        memOS = 1 # 1GB
        memMTL = 0
        
        if memTotal <= 16:
            memMTL = math.floor(memTotal / 4)
        else: # > 16
            fix = 4 # 16/4
            memRemain = math.floor((memTotal - 16) / 8)
            memMTL = fix + memRemain
        
        memRecommend = memTotal - (memOS + memMTL)
        
        memInKBytes = self.instInfo['specification']['memoryInGiB'] * GbToKbRatio
        
        maxMemorySettings = self.dbParams['max server memory (mb)']
        if 'DBInstanceClassMemory' in maxMemorySettings:
            maxMemorySettings = maxMemorySettings.replace("{", "")
            maxMemorySettings = maxMemorySettings.replace("}", "")
            maxMemorySettings = eval(maxMemorySettings, {"DBInstanceClassMemory": memInKBytes})
        
        ## Need to be review
        diff = (memRecommend - maxMemorySettings)/maxMemorySettings
        if maxMemorySettings > memRecommend and diff < -0.1:
            self.results['MSSQL__ParamMaxMemoryTooHigh'] = [-1, "Recommended: {}<br>current: {}<br>diff: {}%".format(memRecommend, maxMemorySettings, round(diff*100, 2))]
        elif (memTotal <= 16 and diff > 0.2) or (memTotal > 16 and diff > 0.3):
            self.results['MSSQL__ParamMaxMemoryTooLow'] = [-1, "Recommended: {}<br>current: {}<br>diff: {}%".format(memRecommend, maxMemorySettings, round(diff*100, 2))]
            
    def _checkParamMaxWorkerThreads(self):
        print(None)
        # print(self.dbParams['max worker threads'])    
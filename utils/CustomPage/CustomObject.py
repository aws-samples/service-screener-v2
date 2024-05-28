from utils.Config import Config
from utils.Tools import _pr, _warn
import json

class CustomObject():
    ResourcesToTrack = {}
    ResourcesStat = {}
    
    ### REDO THIS AS STRUCTURE CHANGE FROM 2 LEVELS to 3 LEVELS
    def __init__(self):
        for serv, groups in self.ResourcesToTrack.items():
            self.ResourcesStat[serv] = {}
            for res, rules in groups.items():
                tRules = {'total': 0, 'items': [], 'rules': {}}
                for rule in rules:
                    tRules['rules'][rule] = []
                
                self.ResourcesStat[serv][res] = tRules
        
        s = json.dumps(self.ResourcesStat)
        _pr(s)
            
    def recordItem(self, driver, name, results, inventoryInfo):
        for serv, groups in self.ResourcesToTrack.items():
            if driver in groups:
                rules = self.ResourcesToTrack[serv][driver]
                
                cnt = self.ResourcesStat[serv][driver]['total']
                self.ResourcesStat[serv][driver]['total'] = cnt + 1
                
                
                # tmpInfo = inventoryInfo
                tmpInfo = inventoryInfo.copy()
                tmpInfo['id'] = name
                self.ResourcesStat[serv][driver]['items'].append(tmpInfo)
                
                for rule in rules:
                    if rule in results and results[rule][0] == -1:
                        self.ResourcesStat[serv][driver]['rules'][rule].append(name)
                        
    def printInfo(self, service):
        if not service in self.ResourcesStat:
            return None
        
        s = json.dumps(self.ResourcesStat[service])
        _pr(s)
        
        return s
        
    def setData(self, json):
        self.dataSets = json
        
    def build(self):
        _warn("CustomObject [{}] does not contains _build_ function".format(self.__class__.__name__))
        
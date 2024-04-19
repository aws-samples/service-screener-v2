from utils.Config import Config
from utils.Tools import _pr
import json

class CustomObject():
    ResourcesToTrack = {}
    ResourcesStat = {}
    
    ### REDO THIS AS STRUCTURE CHANGE FROM 2 LEVELS to 3 LEVELS
    def __init__(self):
        for serv, groups in self.ResourcesToTrack.items():
            self.ResourcesStat[serv] = {}
            for res, rules in groups.items():
                tRules = {'total': 0}
                for rule in rules:
                    tRules[rule] = []
            
                self.ResourcesStat[serv][res] = tRules
        
        s = json.dumps(self.ResourcesStat)
        _pr(s)
            
    def recordItem(self, driver, name, results):
        for serv, groups in self.ResourcesToTrack.items():
            if driver in groups:
                rules = self.ResourcesToTrack[serv][driver]
                
                cnt = self.ResourcesStat[serv][driver]['total']
                self.ResourcesStat[serv][driver]['total'] = cnt + 1
                
                for rule in rules:
                    if rule in results and results[rule][0] == -1:
                        self.ResourcesStat[serv][driver][rule].append(name)
                        
    def printInfo(self, service):
        s = json.dumps(self.ResourcesStat[service])
        _pr(s)
        
        return s
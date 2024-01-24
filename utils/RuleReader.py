import os
import json

class RuleReader:
    def __init__(self, serviceFolderPath, service=None):
        self.serviceFolderPath = serviceFolderPath
        self.service = service
        # self.reporterPathDict = {}
        
        # self.setReporterPathDict()
        return
    
    def getReporterPathList(self):
        service = self.service
        folderPathList = []
        reporterPathList = []
        if service is None:
            with os.scandir(self.serviceFolderPath) as dir:
                directories = list(dir)
            directories.sort(key=lambda x: x.name)
            
            for item in directories:
                if item.is_dir():
                    folderPath = self.serviceFolderPath + '/' + item.name + '/'
                    folderPathList.append(folderPath)
        else:
            folderPath = self.serviceFolderPath + '/' + service + '/'
            if os.path.isdir(folderPath):
                folderPathList.append(folderPath)
            else:
                print("Service folder " + folderPath + " not found")
            
        for path in folderPathList:
            folderItems = os.scandir(path)
            for item in folderItems:
                if item.is_file() and item.name.endswith('reporter.json'):
                    reporterPathList.append(path + item.name)
            
        return reporterPathList
    
    def getRulesFromReporter(self):
        service = self.service
        pathList = self.getReporterPathList()
        rules = {}
        for path in pathList:
            reporterFile = open(path, 'r')
            ruleJSON = reporterFile.read()
            reporterFile.close()
            ruleDict = json.loads(ruleJSON)
            rules.update(ruleDict)
        
        return rules
        
    def getRulesAttr(self, attrName):
        service = self.service
        rules = self.getRulesFromReporter()
        
        attr = {}
        
        for rule in rules:
            attr[rule] = {}
            if attrName in rules[rule]:
                attr[rule][attrName] = rules[rule][attrName]
                # attr.append(rules[rule][attrName])
            else:
                print(attrName + ' not found in rule ' + rule)
        
        return attr
        

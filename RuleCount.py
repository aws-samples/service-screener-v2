import os
import sys
import json

try:
    from prettytable import PrettyTable
except ModuleNotFoundError as err:
    sys.exit('PrettyTable module not found, run \"pip install prettytable\"')

SERVICE_FOLDER_PATH = os.getcwd() + '/services'

def getReporterPaths(serviceFolderPath):
    reporterPath = {}

    with os.scandir(serviceFolderPath) as dir:
        directories = list(dir)
    directories.sort(key=lambda x: x.name)

    for item in directories :
        if item.is_dir():
            servicePath = serviceFolderPath + '/' + item.name
            serviceItems = os.scandir(servicePath)
            for service in serviceItems:
                if service.is_file() and service.name.endswith('reporter.json'):
                    reporterPath[item.name] = servicePath + '/' + service.name

            serviceItems.close()

    return reporterPath

def getRulesFromJSON(reporterPath):
    reporterFile = open(reporterPath, 'r')
    ruleJSON = reporterFile.read()
    reporterFile.close()

    rules = json.loads(ruleJSON)
    return rules

def getTableFormat(cntType):
    if cntType == 'PILLAR':
        tableFormat = {
            'C': 0,
            'P': 0,
            'S': 0,
            'R': 0,
            'O': 0,
            'T': 0
        }
    else:
        tableFormat = {
            'I': 0,
            'L': 0,
            'M': 0,
            'H': 0
        }
    return tableFormat

def getCntSummary(reporterPath, cntType):
    cntTable = getTableFormat(cntType)

    rules = getRulesFromJSON(reporterPath)
    for ruleName in rules:
        if cntType == 'PILLAR':
            allCategory = rules[ruleName]['category']
            category = allCategory[0]
            
        else:
            category = rules[ruleName]['criticality']

        cntTable[category] += 1
    return cntTable

def formSummaryPrettyTable(tableType):
    totalCategoryTable = getTableFormat(tableType)

    reporterPaths = getReporterPaths(SERVICE_FOLDER_PATH)
    totalService = len(reporterPaths)
    totalRules = 0
    table = []

    ## Form per service row and calculate total number of rules
    info = {}
    for service in reporterPaths:
        path = reporterPaths[service]
        cntResult = getCntSummary(path, tableType)
        serviceRow = [service]
        totalPerService = 0
        
        for category in cntResult:
            serviceRow.append(cntResult[category])
            totalPerService = totalPerService + cntResult[category]
            totalCategoryTable[category] = totalCategoryTable[category] + cntResult[category]
        serviceRow.append(totalPerService)
        table.append(serviceRow)

        totalRules = totalRules + totalPerService
        
        ## Does not matter, just need it to run once
        sname = service
        if(tableType == 'PILLAR'):
            if sname == 'lambda_':
                sname = 'lambda'
            info[sname] = totalPerService

    if len(info) > 0:
        f = open("info.json", "w+")
        f.write(json.dumps(info))
        f.close()

    ## Form splitter row
    splitRow = ['-------']
    for i in range (len(totalCategoryTable) + 1):
        splitRow.append('')
    table.append(splitRow)

    ## Form total Row
    totalRow = ['Total']
    totalRow = totalRow + list(totalCategoryTable.values())
    totalRow.append(totalRules)
    table.append(totalRow)

    ## Form mean and header row
    meanRow = ['Mean']
    titleRow = ['Services']
    for category in totalCategoryTable:
        meanRow.append(round(totalCategoryTable[category]/totalService, 2))
        titleRow.append(category.center(7,'_'))
    meanRow.append(round(totalRules/totalService, 2))
    titleRow.append('_TOTAL_')
    table.append(meanRow)

    prettyTable = PrettyTable()
    prettyTable.field_names = titleRow
    prettyTable.add_rows(table)

    return prettyTable



if __name__ == "__main__":
    print('Service Rules Pillar Count:')
    print(formSummaryPrettyTable('PILLAR'))
    print('Service Rules Criticality Count:')
    print(formSummaryPrettyTable('SEVERITY'))
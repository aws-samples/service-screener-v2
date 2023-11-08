import importlib.util
import json
import os

import time
from utils.Config import Config
from services.Cloudwatch import Cloudwatch
from services.Reporter import Reporter
from services.PageBuilder import PageBuilder
from services.dashboard.DashboardPageBuilder import DashboardPageBuilder

from frameworks.FrameworkPageBuilder import FrameworkPageBuilder
from utils.ExcelBuilder import ExcelBuilder
import shutil
# import zlib

import constants as _C

class Screener:
    def __init__(self):
        pass
    
    @staticmethod
    def scanByService(service, regions, filters):
        _zeroCount = {
            'resources': 0,
            'rules': 0,
            'exceptions': 0,
            'timespent': 0
        }
        
        contexts = {}
        time_start = time.time()
        
        tempCount = 0
        service = service.split('::')
        
        _regions = ['GLOBAL'] if service[0] in Config.GLOBAL_SERVICES else regions
        
        scannedKey = 'scanned_'+service[0]
        globalKey = 'GLOBALRESOURCES_'+service[0]
        Config.set(scannedKey, _zeroCount)

        for region in _regions:
            reg = region
            if region == 'GLOBAL':
                reg = 'us-east-1'
                # reg = regions[0]
            
            
            CURRENT_REGION = reg
            cw = Cloudwatch(reg)
            
            ServiceClass = Screener.getServiceModuleDynamically(service[0])    
            serv = ServiceClass(reg)
            
            ## Support --filters
            if filters != []:
                serv.setTags(filters)
                
            if len(service) > 1 and service[1] != []:
                serv.setRules(service[1])
            
            if not service[0] in contexts:
                contexts[service[0]] = {}
            
            Config.set('CWClient', cw.getClient())
                
            contexts[service[0]][region] = serv.advise()
            tempCount += len(contexts[service[0]][region])
            del serv
        
        GLOBALRESOURCES = Config.get(globalKey, [])
        if len(GLOBALRESOURCES) > 0:
            contexts[service[0]]['GLOBAL'] = GLOBALRESOURCES
        
        time_end = time.time()
        scanned = Config.get(scannedKey)
        # print(scannedKey)
        
        scanned['timespent'] = time_end - time_start
        
        with open(_C.FORK_DIR + '/' + service[0] + '.json', 'w') as f:
            json.dump(contexts[service[0]], f)
        
        with open(_C.FORK_DIR + '/' + service[0] + '.stat.json', 'w') as f:
            json.dump(scanned, f)

    @staticmethod
    def getServiceModuleDynamically(service):
        # .title() captilise the first character
        # e.g: services.iam.Iam
        folder = service
        if service in Config.KEYWORD_SERVICES:
            folder = service + '_'
        
        className = service.title()
        module = 'services.' + folder + '.' + className
        
        ServiceClass = getattr(importlib.import_module(module), className)
        return ServiceClass
    
    @staticmethod 
    def getServicePagebuilderDynamically(service):
        # ServiceClass = getattr(importlib.import_module('services.guardduty.GuarddutypageBuilder'), 'GuarddutypageBuilder')
        # return ServiceClass
        ServiceClass = getattr(importlib.import_module('services.PageBuilder'), 'PageBuilder')
        
        folder = service
        if service in Config.KEYWORD_SERVICES:
            folder = service + '_'
        
        className = service.title() + 'pageBuilder'
        module = 'services.' + folder + '.' + className
        
        try:
            ServiceClass = getattr(importlib.import_module(module), className)
        except:
            print(className + ' class not found, using default pageBuilder')
        
        # print(module, className)
        # print(ServiceClass)
        return ServiceClass
    
    
    @staticmethod    
    def generateScreenerOutput(runmode, contexts, hasGlobal, regions, uploadToS3, bucket):
        stsInfo = Config.get('stsInfo')
        if runmode == 'api-raw':
            with open(_C.API_JSON, 'w') as f:
                json.dump(contexts, f)
        else:
            apiResultArray = {}
            if hasGlobal:
                regions.append('GLOBAL')
            
            rawServices = []
            
            if runmode == 'report':
                params = []
                for key, val in Config.get('_SS_PARAMS').items():
                    if val != '':
                        tmp = '--' + key + ' ' + str(val)
                        params.append(tmp)
                        
                summary = Config.get('SCREENER-SUMMARY')
                excelObj = ExcelBuilder(stsInfo['Account'], ' '.join(params))
            
            for service, resultSets in contexts.items():
                rawServices.append(service)
                
                reporter = Reporter(service)
                reporter.process(resultSets).getSummary().getDetails()
                
                if runmode == 'report':
                    ## <TODO> -- verification
                    ## Maybe need to import module, to validate later
                    pageBuilderClass = Screener.getServicePagebuilderDynamically(service)
                    pb = pageBuilderClass(service, reporter)
                    pb.buildPage()
                    
                    ## <TODO>
                    if service not in ['guardduty']:
                        excelObj.generateWorkSheet(service, reporter.cardSummary)
                
                if runmode == 'report' or runmode == 'api-full':
                    if not service in apiResultArray:
                        apiResultArray[service] = {'summary': {}, 'detail': {}}
                    
                    apiResultArray[service]['summary'] = reporter.getCard()
                    apiResultArray[service]['detail'] = reporter.getDetail()
            
            if runmode == 'report':
                # serviceStat = Config.get('cli_services')
                # print(serviceStat)
                dashPB = DashboardPageBuilder('index', [])
                dashPB.buildPage()
                
                # <TODO>
                ## dashPB will gather summary info, hence rearrange the sequences
                excelObj.buildSummaryPage(summary)
                excelObj._save()
                
                ## Enhancement - Framework
                frameworks = Config.get('cli_frameworks')
                if len(frameworks) > 0:
                    for framework in frameworks:
                        o = FrameworkPageBuilder(framework, apiResultArray)
                        if o.getGateCheckStatus() == True:
                            p = o.buildPage()
                        else:
                            print(framework + " GATECHECK==FALSE")
                
                # <TODO>
                ## Upload to S3
                ## Not implement yet, low priority
            else:
                with open(_C.API_JSON, 'w') as f:
                    json.dump(apiResultArray, f)

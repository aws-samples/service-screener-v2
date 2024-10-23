import traceback
import botocore
import time
import os
import math

import concurrent.futures as cf

from utils.Config import Config
from utils.Tools import _warn, _info
from utils.CustomPage.CustomPage import CustomPage
import constants as _C

def runSingleCheck(tmp_obj, method_name):
    debugFlag = Config.get('DEBUG')
    obj = tmp_obj
    try:
        startTime = time.time()
        if debugFlag:
            print('--- --- fn: ' + method_name)
            
        getattr(obj, method_name)()
        if debugFlag:
            timeSpent = round(time.time() - startTime, 3)
            if timeSpent >= 0.2:
                _warn("Long running checks {}s".format(timeSpent))

        getattr(obj, method_name)()
        return 'OK'
    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        msg = e.response['Error']['Message']
        print(code, msg)
        print(traceback.format_exc())
        traceback.format_exc()
    except Exception:
        print(traceback.format_exc())
        traceback.format_exc()

    return traceback.format_exc()

class Evaluator():
    def __init__(self):
        self.init()
        
    def init(self):
        self.results = {}
        self.InventoryInfo = {}
        self.classname = type(self).__name__
    
    def addII(self, k, v):
        self.InventoryInfo[k] = v
        
    def getII(self, k):
        if k in self.InventoryInfo:
            return self.InventoryInfo[k]
        else:
            _warn("{} is not found in drivers/{}.InventoryInfo".format(k, self.classname), forcePrint=False)
            return None

    def run(self, serviceName):
        servClass = self.classname
        rulePrefix = serviceName.__name__ + '::rules'
        servMethods = servClass + '::methods'
        rules = Config.get(rulePrefix, [])
        
        debugFlag = Config.get('DEBUG')
        
        ecnt = cnt = 0
        emsg = []

        #Improve of methods scanning
        methods = Config.get(servMethods, [])
        if methods == []:
            methods = [method for method in dir(self) if method.startswith('__') is False and method.startswith('_check') is True]
            Config.set(servMethods, methods)

        filteredMethods = [method for method in methods if not rules or method[6:].lower() in rules]

        cnt = len(filteredMethods)

        isBeta = Config.get('beta', False)
        if isBeta:
            with cf.ThreadPoolExecutor() as executor:
                futures = [executor.submit(runSingleCheck, self, method) for method in filteredMethods]
                
                for future in cf.as_completed(futures):
                    for fr in future.result():
                        if fr == 'OK': 
                            continue 
                        else:
                            emsg.append(fr)
                            ecnt += 1
                            
        else:
            for method in methods:
                if not rules or str.lower(method[6:]) in rules:
                    try:
                        
                        startTime = time.time()
                        if debugFlag:
                            print('--- --- fn: ' + method)
                            
                        getattr(self, method)()
                        if debugFlag:
                            timeSpent = round(time.time() - startTime, 3)
                            if timeSpent >= 0.2:
                                _warn("Long running checks {}s".format(timeSpent))
                        
                    except botocore.exceptions.ClientError as e:
                        code = e.response['Error']['Code']
                        msg = e.response['Error']['Message']
                        print(code, msg)
                        print(traceback.format_exc())
                        emsg.append(traceback.format_exc())
                    except Exception:
                        ecnt += 1
                        print(traceback.format_exc())
                        emsg.append(traceback.format_exc())
            
        if emsg:
            with open(_C.FORK_DIR + '/error.txt', 'a+') as f:
                f.write('\n\n'.join(emsg))
                f.close()
        
        scannedKey = 'scanned_'+serviceName.__name__.lower()
        # print(scannedKey)
        
        scanned = Config.get(scannedKey)
        Config.set(scannedKey, {
            'resources': scanned['resources'] + 1,
            'rules': scanned['rules'] + cnt,
            'exceptions': scanned['exceptions'] + ecnt
        })
        
        if debugFlag:
            self.showInfo()
            print()
        
    def showInfo(self):
        print("Class: {}".format(self.classname))
        print(self.getInfo())
        # __pr(self.getInfo())
        
    def getInfo(self):
        return {'results': self.results, 'info': self.InventoryInfo}
    
    ## Enhancement 20240117 - Capture all scanned resources    
    def __del__(self):
        driver = type(self).__name__.lower()
        classPrefix = Config.getDriversClassPrefix(driver)
        
        ConfigKey = 'AllScannedResources.' + classPrefix
        scanned = Config.get(ConfigKey, [])
        
        # print(classPrefix, Config.get(classPrefix))
        
        if not driver in Config.SERVICES_IDENTIFIER_MAPPING:
            _warn("driver: '{}' is not exists in Config.SERVICES_IDENTIFIER_MAPPING".format(driver))
            return
        else:
            rule = Config.SERVICES_IDENTIFIER_MAPPING[driver]
            if rule[0] == 'SKIP':
                return 1
            elif rule[0] == 'TEXT':
                name = rule[1]
            elif rule[0] in ['DICT', 'ATTR']:
                var = eval('self.'+rule[1])
                
                if rule[0] == 'DICT':
                    name = 'NOTFOUND*'
                    
                    if (type(rule[2]).__name__) == 'str':
                        name = var[rule[2]]
                    else:    
                        for dictname in rule[2]:
                            if dictname in var:
                                name = var[dictname]
                                break
                else:
                    name = var
            
            hasError = '1'
            for check, find in self.results.items():
                if find[0] == -1:
                    hasError = '-1'
                    break
            
            if name == None:
                return
            
            scanned.append(';'.join([Config.get(classPrefix), driver, name, hasError]))
            Config.set(ConfigKey, scanned)
            
            
        ## Handle custom page requirement
        cp = CustomPage()
        
        emsg = []
        try:
            cp.trackInfo(driver, name, self.results, self.InventoryInfo)
        except Exception:
            print(traceback.format_exc())
            emsg.append(traceback.format_exc())
        
        if emsg:
            with open(_C.FORK_DIR + '/error.txt', 'a+') as f:
                f.write('\n\n'.join(emsg))
                f.close()
        
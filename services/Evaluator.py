import traceback
import botocore

from utils.Config import Config
import constants as _C

class Evaluator():
    def __init__(self):
        self.results = {}
        self.init()
        
    def init(self):
        self.classname = type(self).__name__
        
    def run(self, serviceName):
        servClass = self.classname
        rulePrefix = serviceName.__name__ + '::rules'
        rules = Config.get(rulePrefix, [])
        
        ecnt = cnt = 0
        emsg = []
        methods = [method for method in dir(self) if method.startswith('__') is False and method.startswith('_check') is True]
        for method in methods:
            if not rules or str.lower(method[6:]) in rules:
                try:
                    print('--- --- fn: ' + method)
                    getattr(self, method)()
                    cnt += 1
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
        
    def showInfo(self):
        print("Class: {}".format(self.classname))
        print(self.getInfo())
        # __pr(self.getInfo())
        
    def getInfo(self):
        return self.results
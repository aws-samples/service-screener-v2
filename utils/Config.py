import traceback
import os
import boto3
import constants as _C

class Config:
    
    AWS_SDK = {
        'signature_version': 'v4'
    }

    ADVISOR = {
        'TITLE': 'Service Screener',
        'VERSION': '2.3.0',
        'LAST_UPDATE': '02-Dec-2024'
    }

    ADMINLTE = {
        'VERSION': '3.1.0',
        'DATERANGE': '2014-2021',
        'URL': 'https://adminlte.io',
        'TITLE': 'AdminLTE.io'
    }

    GLOBAL_SERVICES = [
        'iam',
        'cloudfront'
    ]
    
    KEYWORD_SERVICES = [
        'lambda'    
    ]
    
    CURRENT_REGION = 'us-east-1'
    
    @staticmethod
    def init():
        global cache
        cache = {}
    
    @staticmethod
    def setAccountInfo(__AWS_CONFIG):
        print(" -- Acquiring identify info...")
        
        ssBoto = Config.get('ssBoto', None)
        
        stsClient = ssBoto.client('sts')
        
        resp = stsClient.get_caller_identity()
        stsInfo = {
            'UserId': resp.get('UserId'),
            'Account': resp.get('Account'),
            'Arn': resp.get('Arn')
        }

        Config.set('stsInfo', stsInfo)
        acctId = stsInfo['Account']
        
        adir = 'adminlte/aws/' + acctId
        
        Config.set('HTML_ACCOUNT_FOLDER_FULLPATH', _C.ROOT_DIR + '/' + adir)
        Config.set('HTML_ACCOUNT_FOLDER_PATH', adir)
       
    @staticmethod 
    def set(key, val):
        cache[key] = val

    @staticmethod
    def get(key, defaultValue = False):
        ## <TODO>, fix the DEBUG variable
        DEBUG = False
        if key in cache:
            return cache[key]
        
        if defaultValue == False:
            if DEBUG:
                traceback.print_exc()
        
        return defaultValue
        
    @staticmethod
    def retrieveAllCache():
        return cache
        
    
    ## do checking for prefix=cloud, if found, use first 8character instead
    ## other than that, first 3 prefix should be unique
    @staticmethod
    def getDriversClassPrefix(driver):
        name = Config.extractDriversClassPrefix(driver)
        return 'regionInfo::' + name
    
    @staticmethod
    def extractDriversClassPrefix(driver):
        ## handling for S3
        if driver[:2].lower() == 's3':
            return 's3'
            
        if driver[:7].lower() == 'elastic':
            classPrefix = driver[:10]
        else:
            classPrefix = driver[:3]
            if len(driver) > 3 and driver[:5] == 'cloud':
                classPrefix = driver[:8]
            
        return classPrefix

try:
    if configHasInit:
        pass
except NameError:
    dashboard = {}
    Config.init()
    configHasInit = True

if __name__ == "__main__":
    print(os.getcwd())

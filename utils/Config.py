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
        'VERSION': '2.0.1',
        'LAST_UPDATE': '26-Sep-2023'
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
        stsClient = boto3.client('sts')
        
        resp = stsClient.get_caller_identity()
        stsInfo = {
            'UserId': resp.get('UserId'),
            'Account': resp.get('Account'),
            'Arn': resp.get('Arn')
        }

        Config.set('stsInfo', stsInfo)
        acctId = stsInfo['Account']
        
        adir = 'adminlte/aws/' + acctId[0:-2] + 'XX'
        
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

try:
    if configHasInit:
        pass
except NameError:
    dashboard = {}
    Config.init()
    configHasInit = True

if __name__ == "__main__":
    print(os.getcwd())
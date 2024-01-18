import time
import os
import shutil
import json
import locale
from multiprocessing import Pool

import boto3

from utils.Config import Config
from utils.ArguParser import ArguParser
from utils.CfnTrail import CfnTrail
from utils.CrossAccountsValidator import CrossAccountsValidator
from utils.Tools import _info, _warn
import constants as _C
from utils.AwsRegionSelector import AwsRegionSelector
from Screener import Screener

def number_format(num, places=2):
    return locale.format_string("%.*f", (places, num), True)

scriptStartTime = time.time()
_cli_options = ArguParser.Load()

debugFlag = _cli_options['debug']
# feedbackFlag = _cli_options['feedback']
# testmode = _cli_options['dev']
testmode = _cli_options['ztestmode']
bucket = _cli_options['bucket']
runmode = _cli_options['mode']
filters = _cli_options['tags']
crossAccounts = _cli_options['crossAccounts']
workerCounts = _cli_options['workerCounts']

# print(crossAccounts)

DEBUG = True if debugFlag in _C.CLI_TRUE_KEYWORD_ARRAY or debugFlag is True else False
testmode = True if testmode in _C.CLI_TRUE_KEYWORD_ARRAY or testmode is True else False
crossAccounts = True if crossAccounts in _C.CLI_TRUE_KEYWORD_ARRAY or crossAccounts is True else False
_cli_options['crossAccounts'] = crossAccounts

runmode = runmode if runmode in ['api-raw', 'api-full', 'report'] else 'report'

# <TODO>, yet to convert to python
# S3 upload specific variables 
# uploadToS3 = Uploader.getConfirmationToUploadToS3(bucket)

# <TODO> analyse the impact profile switching
profile = _cli_options['profile']
if not profile == False:
    boto3.setup_default_session(profile_name=profile)

_AWS_OPTIONS = {
    'signature_version': Config.AWS_SDK['signature_version']
}

Config.init()
Config.set('_AWS_OPTIONS', _AWS_OPTIONS)
Config.set('DEBUG', DEBUG)

_AWS_OPTIONS = {
    'signature_version': Config.AWS_SDK['signature_version']
}

Config.set("_SS_PARAMS", _cli_options)
Config.set("_AWS_OPTIONS", _AWS_OPTIONS)

defaultSessionRegion = 'us-east-1'
defaultBoto3 = boto3.Session(region_name=defaultSessionRegion)

rolesCred = {}
if crossAccounts == True:
    _info('Cross Accounts requested, validating necessary configurations...')
    cav = CrossAccountsValidator()
    cav.setIamGlobalEndpointTokenVersion()
    cav.runValidation()
    cav.resetIamGlobalEndpointTokenVersion()
    if cav.isValidated() == False:
        print('CrossAccountsFlag=True but failed to validate, exit...')
        exit()
    
    if cav.checkIfIncludeThisAccount() == True:
        rolesCred['default'] = {}
    
    tmp = cav.getCred()
    rolesCred.update(tmp)
else:
    rolesCred = {'default': {}}

## Cleanup existing static resources if any
for file in os.listdir(_C.ADMINLTE_DIR):
    if file.isnumeric() == True:
        shutil.rmtree(_C.ADMINLTE_DIR + '/' + file)

acctLoop = 0
CfnTrailObj = CfnTrail()
for acctId, cred in rolesCred.items():
    acctLoop = acctLoop + 1
    flagSkipPromptForRegionConfirmation = True
    if acctLoop == 1:
        flagSkipPromptForRegionConfirmation = False
    
    tcred = cred.copy()
    tcred['region_name'] = defaultSessionRegion
    aid = acctId
    if acctId == 'default':
        aid = 'Current Account'
    
    
    if acctId != 'default':
        newSess = boto3.session.Session(**tcred)
        Config.set('ssBoto', newSess)
    else:
        Config.set('ssBoto', defaultBoto3)

    
    Config.set('scanned', {'resources': 0, 'rules': 0, 'exceptions': 0})
    if _cli_options['regions'] == None:
        print("--regions option is not present. Generating region list...")
        
        regions = AwsRegionSelector.prompt_for_region(flagSkipPromptForRegionConfirmation)
        if not regions or len(regions.split(',')) == 0:
            print("No valid region(s) selected. Exiting.")
            exit()
        
        # Set back to cli options
        _cli_options['regions'] = regions
    
    services = _cli_options['services'].split(',')
    regions = _cli_options['regions'].split(',')
    
    Config.set('PARAMS_REGION_ALL', False)
    if regions[0] == 'ALL':
        Config.set('PARAMS_REGION_ALL', True)
        # regions = AwsRegionSelector.get_all_enabled_regions(True)
        ## Can pass in True for RegionSelector to skip prompt
        regions = AwsRegionSelector.get_all_enabled_regions(flagSkipPromptForRegionConfirmation)
    
    frameworks = []
    if len(_cli_options['frameworks']) > 0:
        frameworks = _cli_options['frameworks'].split(',')
    
    tempConfig = _AWS_OPTIONS.copy();
    tempConfig['region'] = regions[0]
    
    Config.setAccountInfo(tempConfig)
    acctInfo = Config.get('stsInfo')
    print("")
    print("=================================================")
    print("Processing the following account id: " + acctInfo['Account'])
    print("=================================================")
    print("")
    ## Build List of Accounts for dropdown...
    if acctLoop == 1:
        listOfAccts = []
        if acctId == 'default':
            listOfAccts.append(acctInfo['Account'])
        
        for tacctId, tcred in rolesCred.items():
            if tacctId != 'default':
                listOfAccts.append(tacctId)
            
        Config.set('ListOfAccounts', listOfAccts)
    
    contexts = {}
    serviceStat = {}
    # GLOBALRESOURCES = []
    
    oo = Config.get('_AWS_OPTIONS')
    
    if testmode == False:
        CfnTrailObj.boto3init()
        CfnTrailObj.createStack()
    
    overallTimeStart = time.time()
    # os.chdir('__fork')
    directory = '__fork'
    if not os.path.exists(directory):
        os.mkdir(directory)
    
    files_in_directory = os.listdir(directory)
    filtered_files = [file for file in files_in_directory if (file.endswith(".json") or file=='all.csv')]
    for file in filtered_files:
    	path_to_file = os.path.join(directory, file)
    	os.remove(path_to_file)
    
    with open(directory + '/tail.txt', 'w') as fp:
        pass
    
    input_ranges = []
    for service in services:
        input_ranges = [(service, regions, filters) for service in services]
    
    pool = Pool(processes=int(workerCounts))
    pool.starmap(Screener.scanByService, input_ranges)
    
    if testmode == False:
        CfnTrailObj.deleteStack()
    
    ## <TODO>
    ## parallel logic to be implement in Python
    scanned = {
        'resources': 0,
        'rules': 0,
        'exceptions': 0,
        'timespent': 0
    }
    
    inventory = {}
    
    hasGlobal = False
    for file in os.listdir(_C.FORK_DIR):
        if file[0] == '.' or file == _C.SESSUID_FILENAME or file == 'tail.txt' or file == 'error.txt' or file == 'empty.txt' or file == 'all.csv':
            continue
        f = file.split('.')
        if len(f) == 2:
            contexts[f[0]] = json.loads(open(_C.FORK_DIR + '/' + file).read())
        else:
            cnt, rules, exceptions, timespent = list(json.loads(open(_C.FORK_DIR + '/' + file).read()).values())
            
            serviceStat[f[0]] = cnt
            scanned['resources'] += cnt
            scanned['rules'] += rules
            scanned['exceptions'] += exceptions
            scanned['timespent'] += timespent
            if f[0] in Config.GLOBAL_SERVICES:
                hasGlobal = True
    
    if testmode == True:
        exit("Test mode enable, script halted")
    
    timespent = round(time.time() - overallTimeStart, 3)
    scanned['timespent'] = timespent
    Config.set('SCREENER-SUMMARY', scanned)
    
    print("Total Resources scanned: " + str(number_format(scanned['resources'])) + " | No. Rules executed: " + str(number_format(scanned['rules'])))
    print("Time consumed (seconds): " + str(timespent))
    
    # Cleanup
    # os.chdir(_C.HTML_DIR)
    ACCTDIR = Config.get('HTML_ACCOUNT_FOLDER_FULLPATH')
    
    filetodel = ACCTDIR + '/error.txt'
    if os.path.exists(filetodel):
        os.remove(filetodel)
        
    filetodel = ACCTDIR + '/all.csv'
    if os.path.exists(filetodel):
        os.remove(filetodel)
    
    directory = _C.ADMINLTE_DIR
    files_in_directory = os.listdir(directory)
    filtered_folders = [folder for folder in files_in_directory if folder.endswith("XX")]
    for folder in filtered_folders:
    	path_to_folder = os.path.join(directory, folder)
    	shutil.rmtree(path_to_folder)

    os.chdir(_C.ROOT_DIR)
    filetodel = _C.ROOT_DIR + '/output.zip'
    if os.path.exists(filetodel):
        os.remove(filetodel)
    
    
    ## Generate output
    uploadToS3 = False
    
    ## <TODO>
    ## Might be able breakdown the function further to leverage on multi-processing
    
    Config.set('cli_services', serviceStat)
    Config.set('cli_regions', regions)
    Config.set('cli_frameworks', frameworks)
    
    Screener.generateScreenerOutput(runmode, contexts, hasGlobal, regions, uploadToS3, bucket)
    
    # os.chdir(_C.FORK_DIR)
    filetodel = _C.FORK_DIR + '/tail.txt'
    if os.path.exists(filetodel):
        os.remove(filetodel)
    # os.system('rm -f tail.txt')
    
    src = _C.FORK_DIR + '/error.txt'
    if os.path.exists(src):
        dest = ACCTDIR + '/error.txt'
        os.rename(src, dest)
        
    src = _C.FORK_DIR + '/all.csv'
    if os.path.exists(src):
        dest = ACCTDIR + '/all.csv'
        os.rename(src, dest)
    

adminlteDir = _C.ADMINLTE_ROOT_DIR
shutil.make_archive('output', 'zip', adminlteDir)

print("Pages generated, download \033[1;42moutput.zip\033[0m to view")
print("CloudShell user, you may use this path: \033[1;42m =====> \033[0m ~/service-screener-v2/output.zip \033[1;42m <===== \033[0m")

scriptTimeSpent = round(time.time() - scriptStartTime, 3)
print("@ Thank you for using {}, script spent {}s to complete @".format(Config.ADVISOR['TITLE'], scriptTimeSpent))
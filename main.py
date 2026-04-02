import time
import os
import shutil
import json
import locale
import logging
import sys
from datetime import datetime
from sys import platform

if platform == 'darwin':
    from multiprocess import Pool
else:
    from multiprocessing import Pool

import boto3

from utils.Config import Config
from utils.ArguParser import ArguParser
from utils.CfnTrail import CfnTrail
from utils.CrossAccountsValidator import CrossAccountsValidator
from utils.SuppressionsManager import SuppressionsManager
from utils.Tools import _info, _warn
import constants as _C
from utils.AwsRegionSelector import AwsRegionSelector
from Screener import Screener
from utils.CustomPage.CustomPage import CustomPage

def setup_logging():
    """Setup logging to capture all output to a timestamped log file"""
    # Create timestamp for log filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    log_filename = f"ssv2-{timestamp}.log"
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    log_filepath = os.path.join('logs', log_filename)
    
    # Create a custom logger that captures print statements without buffering
    class TeeOutput:
        def __init__(self, original_stdout, log_file_path):
            self.original_stdout = original_stdout
            self.log_file_path = log_file_path
            
        def write(self, message):
            # Write to original stdout immediately (console)
            self.original_stdout.write(message)
            self.original_stdout.flush()
            
            # Also write to log file immediately (no buffering)
            if message.strip():  # Only log non-empty messages
                try:
                    with open(self.log_file_path, 'a', encoding='utf-8') as log_file:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        log_file.write(f"{timestamp} - {message.strip()}\n")
                        log_file.flush()  # Force immediate write to disk
                except Exception as e:
                    # If logging fails, don't break the main process
                    pass
                
        def flush(self):
            self.original_stdout.flush()
    
    # Redirect stdout to capture print statements
    sys.stdout = TeeOutput(sys.stdout, log_filepath)
    
    # Write initial log entries
    print(f"=== Service Screener v2 - Scan Started ===")
    print(f"Log file: {log_filepath}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    return log_filepath

def number_format(num, places=2):
    return locale.format_string("%.*f", (places, num), True)

def collect_fork_results(contexts, serviceStat, scanned):
    """Collect scan results from __fork directory files into contexts and stats"""
    hasGlobal = False
    for file in os.listdir(_C.FORK_DIR):
        if file[0] == '.' or file == _C.SESSUID_FILENAME or file == 'tail.txt' or file == 'error.txt' or file == 'empty.txt' or file == 'all.csv' or file[0:10] == 'CustomPage':
            continue
        f = file.split('.')
        if len(f) == 2:
            if f[0] not in contexts:
                contexts[f[0]] = {}
            contexts[f[0]]['results'] = json.loads(open(_C.FORK_DIR + '/' + file).read())
        elif f[1] == "charts":
            if f[0] not in contexts:
                contexts[f[0]] = {}
            contexts[f[0]]['charts'] = json.loads(open(_C.FORK_DIR + '/' + file).read())
        else:
            cnt, rules, exceptions, timespent = list(json.loads(open(_C.FORK_DIR + '/' + file).read()).values())
            serviceStat[f[0]] = cnt
            scanned['resources'] += cnt
            scanned['rules'] += rules
            scanned['exceptions'] += exceptions
            scanned['timespent'] += timespent
            if f[0] in Config.GLOBAL_SERVICES:
                hasGlobal = True
    return hasGlobal

def process_custom_pages(customPage, services, disable_custom_pages):
    """Process CustomPage data collection (TA, COH) and store results in Config"""
    if disable_custom_pages:
        _info("CustomPage processing disabled via --disable-custom-pages flag")
        Config.set('custom_page_data', {})
        return
    
    _info("Processing CustomPage data collection...")
    try:
        _info("Building CustomPage data (TA, COH) - this happens after all service scans are complete")
        customPage.buildPage()
        _info("CustomPage processing completed successfully")
        
        customPageData = customPage.getCustomPageData()
        if customPageData:
            _info(f"CustomPage data available for: {list(customPageData.keys())}")
            Config.set('custom_page_data', customPageData)
    except Exception as e:
        _warn(f"CustomPage processing failed: {str(e)}")
        Config.set('custom_page_data', {})

def run_content_enrichment(enable_enrichment, enrichment_categories, enrichment_timeout, serviceStat, contexts):
    """Fetch and process AWS content enrichment data for beta UI"""
    if not enable_enrichment:
        _info("Content enrichment disabled (not in beta mode)")
        Config.set('enriched_content_data', '{"contentData": {}, "metadata": {}, "userPreferences": {}}')
        Config.set('content_enrichment_enabled', False)
        return
    
    try:
        from utils.ContentEnrichment import ContentAggregator, ContentProcessor, RelevanceEngine
        from utils.ContentEnrichment.models import UserContext
        
        detected_services = list(serviceStat.keys()) if serviceStat else []
        
        scan_findings = []
        for service, data in contexts.items():
            if 'results' in data:
                for result in data['results']:
                    if isinstance(result, dict) and result.get('status') in ['FAIL', 'WARN']:
                        scan_findings.append({
                            'service': service,
                            'category': result.get('category', 'general'),
                            'severity': result.get('status', 'INFO')
                        })
        
        user_context = UserContext(
            detected_services=detected_services,
            scan_findings=scan_findings
        )
        
        _info(f"Fetching AWS best practices and security insights (this may take 10-15 seconds)...")
        _info(f"Content enrichment: Processing {len(detected_services)} detected services...")
        
        requested_categories = [cat.strip() for cat in enrichment_categories.split(',')]
        
        content_aggregator = ContentAggregator(timeout=int(enrichment_timeout), max_retries=2)
        content_processor = ContentProcessor()
        relevance_engine = RelevanceEngine()
        
        raw_content = content_aggregator.fetch_aws_content()
        
        processed_content = {}
        total_items = 0
        
        for category, items in raw_content.items():
            if category not in requested_categories:
                continue
            
            processed_items = []
            for item in items:
                processed_item = content_processor.process_single_item(item)
                if processed_item:
                    relevance_score = relevance_engine.calculate_relevance(processed_item, user_context)
                    processed_item.relevance_score = relevance_score
                    processed_items.append(processed_item)
            
            filtered_items = content_aggregator.filter_by_services(processed_items, detected_services)
            prioritized_items = relevance_engine.prioritize_content(filtered_items, user_context)
            
            processed_content[category] = prioritized_items[:10]
            total_items += len(processed_content[category])
        
        enriched_content_data = content_aggregator.serialize_for_html(processed_content, detected_services)
        
        _info(f"✓ Content enrichment complete: {total_items} relevant items found")
        Config.set('enriched_content_data', enriched_content_data)
        Config.set('content_enrichment_enabled', True)
        
    except Exception as e:
        _warn(f"Content enrichment failed: {str(e)}")
        try:
            from utils.ContentEnrichment.error_handler import ContentEnrichmentErrorHandler
            error_handler = ContentEnrichmentErrorHandler()
            enriched_content_data = error_handler.create_empty_enrichment_data(detected_services)
            Config.set('enriched_content_data', enriched_content_data)
            Config.set('content_enrichment_enabled', False)
        except Exception as fallback_error:
            _warn(f"Failed to create fallback enrichment data: {str(fallback_error)}")
            Config.set('enriched_content_data', '{"contentData": {}, "metadata": {}, "userPreferences": {}}')
            Config.set('content_enrichment_enabled', False)

scriptStartTime = time.time()
_cli_options = ArguParser.Load()

# Setup logging to capture all output to timestamped log file
log_filepath = setup_logging()

debugFlag = _cli_options['debug']
# feedbackFlag = _cli_options['feedback']
# testmode = _cli_options['dev']
testmode = _cli_options['ztestmode']
filters = _cli_options['tags']
crossAccounts = _cli_options['crossAccounts']
workerCounts = _cli_options['workerCounts']
beta = _cli_options['beta']
suppress_file = _cli_options['suppress_file']
sequential = _cli_options['sequential']
disable_custom_pages = _cli_options['disable_custom_pages']

# print(crossAccounts)
DEBUG = True if debugFlag in _C.CLI_TRUE_KEYWORD_ARRAY or debugFlag is True else False
testmode = True if testmode in _C.CLI_TRUE_KEYWORD_ARRAY or testmode is True else False
crossAccounts = True if crossAccounts in _C.CLI_TRUE_KEYWORD_ARRAY or crossAccounts is True else False
beta = True if beta in _C.CLI_TRUE_KEYWORD_ARRAY or beta is True else False
disable_custom_pages = True if disable_custom_pages in _C.CLI_TRUE_KEYWORD_ARRAY or disable_custom_pages is True else False
_cli_options['crossAccounts'] = crossAccounts

# Content enrichment is automatically enabled with beta features
enable_enrichment = beta
enrichment_categories = "security-reliability,ai-ml-genai,best-practices"
enrichment_timeout = 30

# <TODO> analyse the impact profile switching
_AWS_OPTIONS = {
    'signature_version': Config.AWS_SDK['signature_version']
}

Config.init()
Config.set('_AWS_OPTIONS', _AWS_OPTIONS)
Config.set('DEBUG', DEBUG)

# Load suppressions if a file is provided (AFTER Config.init())
if suppress_file:
    suppressions_manager = SuppressionsManager()
    if suppressions_manager.load_suppressions(suppress_file):
        Config.set('suppressions_manager', suppressions_manager)
Config.set('beta', beta)
Config.set('disable_custom_pages', disable_custom_pages)
Config.set("_SS_PARAMS", _cli_options)

defaultSessionRegion = 'us-east-1'

boto3args = {'region_name': defaultSessionRegion}
profile = _cli_options['profile']
if not profile == False:
    boto3args['profile_name'] = profile
    # boto3.setup_default_session(profile_name=profile)

defaultBoto3 = boto3.Session(**boto3args)

rolesCred = {}
if crossAccounts == True:
    _info('Cross Accounts requested, validating necessary configurations...')
    cav = CrossAccountsValidator()
    cav.checkIfNonDefaultRegionsInParams(_cli_options['regions'])
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
    
    
    if acctLoop == 1:
        Config.set('REGIONS_SELECTED', regions)
        
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
    charts = {}
    serviceStat = {}
    # GLOBALRESOURCES = []
    
    oo = Config.get('_AWS_OPTIONS')
    
    ## Added mpeid to CFStack
    mpeid = None
    otherParams = _cli_options.get('others', None)
    if otherParams is not None:
        try:
            oparams = json.loads(otherParams)
            mpeInfo = oparams.get('mpe', None)
            if mpeInfo is not None:
                mpeid = mpeInfo.get('id', None)
        except json.JSONDecodeError as e:
            print("Unable to read --others parameters, invalid JSON format provided")
            print(f"Error decoding JSON: {e}")
            exit()

    if testmode == False:
        cfnAdditionalStr = None
        if mpeid is not None: 
            cfnAdditionalStr = " --mpeid:{}".format(mpeid)
        CfnTrailObj.boto3init(cfnAdditionalStr)
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
    
    special_services = {'iam', 's3'}
    input_ranges = {}

    ## Make IAM and S3 to be separate pool
    if 'iam' in services:
        input_ranges['iam'] = ('iam', regions, filters)

    input_ranges.update({service: (service, regions, filters) for service in services if service not in special_services})

    if 's3' in services:
        input_ranges['s3'] = ('s3', regions, filters)

    input_ranges = list(input_ranges.values())

    if sequential:
        # Run sequentially to avoid macOS hanging issues
        for input_range in input_ranges:
            Screener.scanByService(*input_range)
    else:
        # Run in parallel (default behavior)
        pool = Pool(processes=int(workerCounts))
        pool.starmap(Screener.scanByService, input_ranges)
        pool.close()

    # if testmode == False:
        # CfnTrailObj.deleteStack()
    
    # Initialize CustomPage for cost optimization and other custom features
    customPage = CustomPage()
    _info(f"CustomPage initialized with pages: {customPage.getRegistrar()}")
    
    # Reset CustomPage output for clean start
    for service in services:
        customPage.resetOutput(service)
    
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
    hasGlobal = collect_fork_results(contexts, serviceStat, scanned)
    
    timespent = round(time.time() - overallTimeStart, 3)
    scanned['timespent'] = timespent
    Config.set('SCREENER-SUMMARY', scanned)
    
    print("Total Resources scanned: " + str(number_format(scanned['resources'])) + " | No. Rules executed: " + str(number_format(scanned['rules'])))
    print("Time consumed (seconds): " + str(timespent))
    
    process_custom_pages(customPage, services, disable_custom_pages)
    
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
    
    run_content_enrichment(enable_enrichment, enrichment_categories, enrichment_timeout, serviceStat, contexts)

    # Generate output using OutputGenerator (handles both legacy and Cloudscape)
    from utils.OutputGenerator import OutputGenerator
    from utils.Tools import _info, _warn
    
    beta_mode = Config.get('beta', False)
    generator = OutputGenerator(beta_mode=beta_mode)
    
    if beta_mode:
        _info("Beta mode enabled - Generating both AdminLTE (legacy) and Cloudscape UI...")
    else:
        _info("Generating AdminLTE HTML output...")
    
    try:
        generator.generate(contexts, regions, frameworks)
        
        if beta_mode:
            _info("Both AdminLTE (index-legacy.html) and Cloudscape (index.html) generated successfully!")
        else:
            _info("AdminLTE HTML generated successfully!")
            
    except Exception as e:
        _warn(f"Output generation failed: {e}")
        # Fallback to old method if OutputGenerator fails
        _warn("Falling back to legacy output generation...")
        Screener.generateScreenerOutput(contexts, hasGlobal, regions, uploadToS3)
    
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
print("CloudShell user, you may use this path: \033[1;42m =====> \033[0m /tmp/service-screener-v2/output.zip \033[1;42m <===== \033[0m")

scriptTimeSpent = round(time.time() - scriptStartTime, 3)
print("@ Thank you for using {}, script spent {}s to complete @".format(Config.ADVISOR['TITLE'], scriptTimeSpent))

if beta:
    print("")
    print("\033[93m[-- ..... --] BETA MODE ENABLED [-- ..... --] \033[0m")
    print("Current Beta Features:")
    print("\033[96m  01/ API Buttons on each service html (Interactive GenAI functionality) \033[0m")
    print("\033[92m  02/ AWS Cloudscape Design System UI (Modern React-based interface) \033[0m")
    print("\033[95m  03/ Content Enrichment (AWS best practices & security insights) \033[0m")
    print("\033[93m[-- ..... --] THANK YOU FOR TESTING BETA FEATURES [-- ..... --] \033[0m")
    print("")
    print("\033[94mStandard Features (Always Enabled):\033[0m")
    print("\033[94m  • Concurrent Mode: Parallel check execution for better performance\033[0m")
    print("\033[94m  • Enhanced TA Data: Advanced Trusted Advisor data generation\033[0m")
    print("\033[94m  • Use --sequential to disable concurrent mode if needed\033[0m")

# Log completion
print("=" * 50)
print(f"=== Service Screener v2 - Scan Completed ===")
print(f"Total execution time: {scriptTimeSpent}s")
print(f"Log saved to: {log_filepath}")
print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 50)

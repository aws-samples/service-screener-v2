import importlib.util
import json
import os
import botocore
import traceback

import time
from utils.Config import Config
from services.Cloudwatch import Cloudwatch
from services.Reporter import Reporter
from services.PageBuilder import PageBuilder
from services.dashboard.DashboardPageBuilder import DashboardPageBuilder
from utils.CustomPage.CustomPage import CustomPage
from utils.Tools import _warn, _info

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
        _cli_options = Config.get('_SS_PARAMS', {})
        
        _zeroCount = {
            'resources': 0,
            'rules': 0,
            'exceptions': 0,
            'timespent': 0
        }
        
        contexts = {}
        charts = {}
        time_start = time.time()
        
        tempCount = 0
        service = service.split('::')
        
        _regions = ['GLOBAL'] if service[0] in Config.GLOBAL_SERVICES else regions
        
        scannedKey = 'scanned_'+service[0]
        globalKey = 'GLOBALRESOURCES_'+service[0]
        Config.set(scannedKey, _zeroCount)
        
        ## CustomPage Enhancement
        cp = CustomPage()
        cp.resetOutput(service[0])
        
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

            if not service[0] in charts:
                charts[service[0]] = {}
            
            Config.set('CWClient', cw.getClient())
            try:
                ## Enhancement 20240117 - Capture all scanned resources
                classPrefix = Config.getDriversClassPrefix(service[0])
                Config.set(classPrefix, reg)
                
                resp = serv.advise()
                arr = {}
                info = {}
                for identifier, obj in resp.items():
                    arr[identifier] = obj['results']
                    info[identifier] = obj['info']
                    
                contexts[service[0]][region] = arr
                charts[service[0]][region] = serv.getChart()
                
            except botocore.exceptions.ClientError as e:
                contexts[service[0]][region] = {}
                eCode = e.response['Error']['Code']
                eMsg = e.response['Error']['Message']
                print("Screener.py error: {}, {}".format(eCode, eMsg))
                print("Screener.py isCrossAccounts: {}".format(_cli_options['crossAccounts']))
                if eCode == 'InvalidClientTokenId' and _cli_options['crossAccounts'] == True:
                    _warn('Impacted Region: [{}], Services: {}... Cross Account limitation, encounted errors: {}'.format(reg, service[0], e))

            except botocore.exceptions.EndpointConnectionError as e:
                contexts[service[0]][region] = {}
                _warn("(Not showstopper: Service <{}> not available: {}".format(service[0], e))
                
            tempCount += len(contexts[service[0]][region])
            del serv
            
            Config.set(classPrefix, None)

        
        GLOBALRESOURCES = Config.get(globalKey, [])
        if len(GLOBALRESOURCES) > 0:
            garr = {}
            ginfo = {}
            for identifier, obj in GLOBALRESOURCES.items():
                garr[identifier] = obj['results']
                ginfo[identifier] = obj['info']
                
            contexts[service[0]]['GLOBAL'] = arr
        
        time_end = time.time()
        scanned = Config.get(scannedKey)
        # print(scannedKey)
        
        scanned['timespent'] = time_end - time_start
        
        with open(_C.FORK_DIR + '/' + service[0] + '.json', 'w') as f:
            json.dump(contexts[service[0]], f)
        
        with open(_C.FORK_DIR + '/' + service[0] + '.stat.json', 'w') as f:
            json.dump(scanned, f)

        ## write the charts data per region
        with open(_C.FORK_DIR + '/' + service[0] + '.charts.json', 'w') as f:
            json.dump(charts[service[0]], f)
            
        cp.writeOutput(service[0].lower())


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
    def generateScreenerOutput(contexts, hasGlobal, regions, uploadToS3):
        htmlFolder = Config.get('HTML_ACCOUNT_FOLDER_FULLPATH')
        if not os.path.exists(htmlFolder):
            os.makedirs(htmlFolder)
        
        stsInfo = Config.get('stsInfo')

        # generate raw findings json file
        with open(htmlFolder + '/api-raw.json', 'w') as f:
            json.dump(contexts, f)

        cp = CustomPage()
        pages = cp.getRegistrar()
        Config.set("CustomPage::Pages", pages)

        apiResultArray = {}
        if hasGlobal:
            regions.append('GLOBAL')

        params = []
        for key, val in Config.get('_SS_PARAMS').items():
            if val != '':
                tmp = '--' + key + ' ' + str(val)
                params.append(tmp)

        summary = Config.get("SCREENER-SUMMARY")
        excelObj = ExcelBuilder(stsInfo["Account"], " ".join(params))

        for service, dataSets in contexts.items():
            resultSets = dataSets['results']
            chartSets = dataSets['charts']

            reporter = Reporter(service)
            reporter.process(resultSets).processCharts(chartSets).getSummary().getDetails()

            ## <TODO> -- verification
            ## Maybe need to import module, to validate later
            pageBuilderClass = Screener.getServicePagebuilderDynamically(service)
            pb = pageBuilderClass(service, reporter)
            pb.buildPage()

            ## <TODO>
            if service not in ['guardduty']:
                suppressedCardSummary = reporter.getSuppressedCardSummary()
                excelObj.generateWorkSheet(service, reporter.cardSummary, suppressedCardSummary)

            if not service in apiResultArray:
                apiResultArray[service] = {'summary': {}, 'detail': {}, 'stats': {}}
            
            apiResultArray[service]['summary'] = reporter.getCard()
            apiResultArray[service]['detail'] = reporter.getDetail()
            
            # Add service statistics from stat.json file
            stat_file = os.path.join(_C.FORK_DIR, f'{service}.stat.json')
            if os.path.exists(stat_file):
                try:
                    with open(stat_file, 'r') as f:
                        stat_data = json.load(f)
                        # Add suppressed count from reporter
                        stat_data['suppressed'] = reporter.suppressedCount
                        # Add checksCount (unique rules) from reporter
                        stat_data['checksCount'] = reporter.stats.get('checksCount', 0)
                        apiResultArray[service]['stats'] = stat_data
                except Exception as e:
                    print(f"Failed to load stats for {service}: {e}")
                    apiResultArray[service]['stats'] = {
                        'resources': 0,
                        'rules': 0,
                        'exceptions': 0,
                        'timespent': 0,
                        'suppressed': reporter.suppressedCount,
                        'checksCount': 0
                    }
            else:
                apiResultArray[service]['stats'] = {
                    'resources': 0,
                    'rules': 0,
                    'exceptions': 0,
                    'timespent': 0,
                    'suppressed': reporter.suppressedCount,
                    'checksCount': 0
                }

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

        emsg = []
        try:
            _cli_options = Config.get('_SS_PARAMS', {})
            if _cli_options['ztestmode'] == '1':
                print('skip page build, testmode ON')
            else:
                cp.buildPage()
        except Exception:
            print(traceback.format_exc())
            emsg.append(traceback.format_exc())

        if emsg:
            with open(_C.FORK_DIR + '/error.txt', 'a+') as f:
                f.write('\n\n'.join(emsg))
                f.close()

        # Add custom page data to API result array
        try:
            custom_page_data = cp.getCustomPageData()
            
            # If custom page data is empty, generate basic data from service findings
            if not custom_page_data or not any(custom_page_data.values()):
                custom_page_data = Screener.generateBasicCustomPageData(apiResultArray)
            
            apiResultArray.update(custom_page_data)
        except Exception as e:
            print(f"Error adding custom page data: {e}")
            # Generate basic custom page data as fallback
            try:
                custom_page_data = Screener.generateBasicCustomPageData(apiResultArray)
                apiResultArray.update(custom_page_data)
            except Exception as e2:
                print(f"Error generating basic custom page data: {e2}")

        reporter.resetDashboard()
        cp.resetPages()
        del cp

        # Generate TA data for enhanced UI features
        Screener.generateTAData(htmlFolder)

        # generate the full results in JSON format
        with open(htmlFolder + "/api-full.json", "w") as f:
            json.dump(apiResultArray, f)

    @staticmethod
    def generateTAData(htmlFolder):
        """Generate TA data for Cloudscape UI"""
        try:
            import os
            import json
            
            # Check if ta.json already exists (from CustomPage build)
            ta_file_path = os.path.join(htmlFolder, 'ta.json')
            if os.path.exists(ta_file_path):
                from utils.Tools import _pr
                _pr(f"TA data already exists: {ta_file_path}")
                return
            
            from utils.CustomPage.Pages.TA.TA import TA
            
            # Create TA instance and build data
            ta_instance = TA()
            ta_instance.build()
            
            # Prepare TA data for Cloudscape UI
            ta_data = {
                'error': ta_instance.taError,
                'pillars': {}
            }
            
            # Process each pillar's findings
            for pillar_name, pillar_data in ta_instance.taFindings.items():
                if len(pillar_data) >= 3:
                    rows = pillar_data[0]  # Row data
                    headers = pillar_data[1]  # Table headers
                    totals = pillar_data[2]  # Summary totals
                    
                    # Convert rows to structured data
                    structured_rows = []
                    for row in rows:
                        if len(row) >= len(headers):
                            row_dict = {}
                            for i, header in enumerate(headers):
                                if i < len(row):
                                    row_dict[header] = row[i]
                            # Add description (last item)
                            if len(row) > len(headers):
                                row_dict['Description'] = row[-1]
                            structured_rows.append(row_dict)
                    
                    ta_data['pillars'][pillar_name] = {
                        'headers': headers,
                        'rows': structured_rows,
                        'totals': totals
                    }
            
            # Write TA data to separate JSON file
            ta_file_path = os.path.join(htmlFolder, 'ta.json')
            with open(ta_file_path, 'w') as f:
                json.dump(ta_data, f, indent=2)
            
            print(f"TA data generated: {ta_file_path}")
            
        except Exception as e:
            print(f"Error generating TA data: {str(e)}")

    @staticmethod
    def generateBasicCustomPageData(apiResultArray):
        """Generate basic custom page data from service findings"""
        custom_data = {}
        
        # Generate findings data for Cross-Service Findings page
        findings_list = []
        suppressed_list = []
        
        for service_name, service_data in apiResultArray.items():
            if not isinstance(service_data, dict) or 'summary' not in service_data:
                continue
                
            for rule_name, rule_data in service_data.get('summary', {}).items():
                if not isinstance(rule_data, dict):
                    continue
                    
                # Count affected resources
                affected_resources = rule_data.get('__affectedResources', {})
                total_resources = sum(len(resources) for resources in affected_resources.values())
                
                # Map criticality to severity
                criticality_map = {'H': 'High', 'M': 'Medium', 'L': 'Low', 'I': 'Informational'}
                severity = criticality_map.get(rule_data.get('criticality', 'L'), 'Low')
                
                # Map category
                category_map = {
                    'S': 'Security', 'R': 'Reliability', 'P': 'Performance', 
                    'C': 'Cost', 'O': 'Operational Excellence'
                }
                category = category_map.get(rule_data.get('__categoryMain', 'O'), 'Operational Excellence')
                
                finding = {
                    'service': service_name.upper(),
                    'Check': rule_name,
                    'Severity': severity,
                    'Type': category,
                    'Description': rule_data.get('shortDesc', ''),
                    'Resources': total_resources,
                    'Regions': list(affected_resources.keys())
                }
                
                findings_list.append(finding)
        
        custom_data['customPage_findings'] = {
            'findings': findings_list,
            'suppressed': suppressed_list  # TODO: Add suppressed findings if needed
        }
        
        # Generate basic modernize data (placeholder)
        custom_data['customPage_modernize'] = {
            'Computes': {
                'nodes': ['Resources (100)', 'Computes (80)', 'EC2 (75)'],
                'links': [{'source': 0, 'target': 1, 'value': 80}, {'source': 1, 'target': 2, 'value': 75}]
            }
        }
        
        return custom_data

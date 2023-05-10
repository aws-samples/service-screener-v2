import os
import json
import re

from utils.Config import Config, dashboard
import constants as _C

class Reporter:
    def __init__(self, service):
        self.summary = {}
        self.summaryRegion = {}
        self.detail = {}
        self.config = {}
        self.service = service
        
        folder = service
        if service in Config.KEYWORD_SERVICES:
            folder = service + '_'
        
        serviceReporterJsonPath = _C.SERVICE_DIR + '/' + folder + '/' + service + '.reporter.json'
        
        if not os.path.exists(serviceReporterJsonPath):
            print("[Fatal] " + serviceReporterJsonPath + " not found")
        self.config = json.loads(open(serviceReporterJsonPath).read())
        if not self.config:
            raise Exception(serviceReporterJsonPath + " does not contain valid JSON")
        generalConfig = json.loads(open(_C.GENERAL_CONF_PATH).read())
        self.config = {**self.config, **generalConfig}

    def process(self, serviceObjs):
        for region, objs in serviceObjs.items():
            for identifier, results in objs.items():
                self._process(region, identifier, results)
                
            if 'SERV' not in dashboard:
                dashboard['SERV'] = {self.service: {region: {}}}
                
            if self.service not in dashboard['SERV']:
                dashboard['SERV'][self.service] = {region: {}}
                
            dashboard['SERV'][self.service][region] = {'Total': len(objs), 'H': 0}
        return self
        
    def getDetail(self):
        return self.detail
    
    def getCard(self):
        return self.cardSummary
    
    def _process(self, region, identifier, results):
        for key, info in results.items():
            if info[0] == -1:
                ## Register summary info
                if key not in self.summaryRegion:
                    self.summaryRegion[key] = {}
                    self.summary[key] = []
                    
                if region not in self.summaryRegion[key]:
                    self.summaryRegion[key][region] = []
                
                self.summaryRegion[key][region].append(identifier)
                self.summary[key].append(identifier)
                
                if region not in self.detail:
                    self.detail[region] = {}
                
                if identifier not in self.detail[region]:
                    self.detail[region][identifier] = {}
                    
                # print(identifier, key, info[1])
                self.detail[region][identifier][key] = info[1]

    def _getConfigValue(self, check, field):
        if check not in self.config:
            print("<{}> not exists in {}.reporter.json".format(check, self.service))
            return None
        
        if field == 'category' and field not in self.config[check]:
            field = '__categoryMain'
        
        if field not in self.config[check]:
            print("<{}>::<{}> not exists in {}.reporter.json".format(check, field, self.service))
            return None
        
        return self.config[check][field]
    
    def _checkCriticality(self, check):
        return self._getConfigValue(check, 'criticality') or 'X'
    
    def _checkCategory(self, check):
        return self._getConfigValue(check, 'category') or 'X'
        
    def getSummary(self):
        # Enhance for MAP summary
        # _ : refers to HIGH category
        if 'MAP' not in dashboard:
            dashboard['MAP'] = {}
            
        dashboard['MAP'][self.service] = {
            '_': {
                'S': 0,
                'C': 0,
                'R': 0,
                'P': 0,
                'O': 0    
            },
            'H': 0,
            'M': 0,
            'L': 0,
            'I': 0,
            'S': 0,
            'C': 0,
            'R': 0,
            'P': 0,
            'O': 0    
        }

        for check, dataSet in self.summaryRegion.items():
            for region, obj in dataSet.items():
                itemSize = len(obj)

                #check criticality
                critical = self._checkCriticality(check)
                if 'CRITICALITY' not in dashboard:
                    dashboard['CRITICALITY'] = {}
                if region not in dashboard['CRITICALITY']:
                    dashboard['CRITICALITY'][region] = {}
                if critical not in dashboard['CRITICALITY'][region]:
                    dashboard['CRITICALITY'][region][critical] = 0
                    
                dashboard['CRITICALITY'][region][critical] += itemSize

                if critical == 'H':
                    dashboard['SERV'][self.service][region]['H'] += itemSize

                #check category
                category = self._checkCategory(check)
                mainCategory = category[0]
                
                if 'CATEGORY' not in dashboard:
                    dashboard['CATEGORY'] = {}
                if region not in dashboard['CATEGORY']:
                    dashboard['CATEGORY'][region] = {}
                if mainCategory not in dashboard['CATEGORY'][region]:
                    dashboard['CATEGORY'][region][mainCategory] = 0
                
                dashboard['CATEGORY'][region][mainCategory] += itemSize

                # Enhance for MAP summary
                if mainCategory == 'T':
                    continue

                if critical == 'H':
                    dashboard['MAP'][self.service]['_'][mainCategory] += itemSize
                else:
                    pass
                dashboard['MAP'][self.service][critical] += itemSize
                dashboard['MAP'][self.service][mainCategory] += itemSize

        self.cardSummary = {}
        service = self.service
        
        sorted(self.summary)
        for check, items in self.summary.items():
            if check not in self.config:
                print("<{}> not exists in {}.reporter.json".format(check, service))
                continue
            
            self.cardSummary[check] = self.config[check]
            
            # Process Field by Field:
            # Process description
            desc = self._getConfigValue(check, '^description')
            if desc:
                COUNT = len(items)
                COUNT = "<strong><u>{}</u></strong>".format(COUNT)
                self.cardSummary[check]['^description'] = desc.replace('{$COUNT}', COUNT)
            
            # Process category
            category = self._getConfigValue(check, 'category')
            if category:
                self.cardSummary[check]['__categoryMain'] = category[0]
                if len(category) > 1:
                    self.cardSummary[check]['__categorySub'] = category[1:]
                
                del self.cardSummary[check]['category']
            
            # Process ref
            ref = self._getConfigValue(check, 'ref')
            if ref and isinstance(ref, list):
                links = []
                for link in ref:
                    output = re.search(r'\[(.*)\]<(.*)>', link)
                    if not output:
                        continue
                    
                    links.append("<a href='{}'>{}</a>".format(output.group(2), output.group(1)))
                
                self.cardSummary[check]['__links'] = links
                del self.cardSummary[check]['ref']
                
            resourceByRegion = {}
            for region, insts in self.summaryRegion[check].items():
                resourceByRegion[region] = insts
                
            self.cardSummary[check]['__affectedResources'] = resourceByRegion
            
        del self.summaryRegion
        del self.summary
        
        return self
        
    def getDetails(self):
        tmp = {}
        for region, detail in self.detail.items():
            for identifier, checks in detail.items():
                # htmlAttribute = "data-resource='" + identifier + "' data-region='" + region + "'"
                sorted(checks)
                # del tmp[region][identifier]
                for key, info in checks.items():
                    arr = self.getDetailAttributeByKey(key)
                    arr['value'] = info
                    # self.detail[region][identifier][key] = arr
                    if region not in tmp:
                        tmp[region] = {}
                    
                    if identifier not in tmp[region]:
                        tmp[region][identifier] = {}
                        #tmp[region][identifier] = {key: arr}
                    
                    if key not in tmp[region][identifier]:
                        tmp[region][identifier][key] = arr
                    
        self.detail = tmp.copy()
        # print(self.detail)
        
        del self.config
        
    def getDetailAttributeByKey(self, key):
        config = {}
        if not key in config:
            arr = {
                'category': self._getConfigValue(key, 'category'),
                'criticality': self._getConfigValue(key, 'criticality'),
                'shortDesc': self._getConfigValue(key, 'shortDesc')
            }
            
            category = arr['category']
            if category:
                arr['__categoryMain'] = category[0]
                if len(category) > 1:
                    arr['__categorySub'] = category[1:]
                
                del arr['category']
            
            config[key] = arr
        
        return config[key]
        
    # backward-compatible for PHP global $DASHBOARD concept
    def getDashboard(self):
        return dashboard
        
if __name__ == "__main__":
    from services.PageBuilder import PageBuilder
    
    regions = ['ap-southeast-1']
    services = {'rds': 2, 'ec2': 3, 'iam': 20}
    obj = {
        'ap-southeast-1': {
            'postgres::g2gtest': {
                'MultiAZ': [-1, 'Off'],
                'EngineVersionMajor': [1, 'On']
            },
            'mysql::mysql-5': {
                'MultiAZ': [-1, 'Off'],
                'EngineVersionMajor': [-1, 'Off']
            },
            'mysql::mysql-bad': {
                'MultiAZ': [-1, 'Off'],
                'EngineVersionMajor': [-1, 'Off']
            }
        },
        'us-east-1': {
            'oracle::oracletest': {
                'MultiAZ': [-1, 'Off'],
                'EngineVersionMajor': [1, 'On']
            }
        }
    }
    reporter = Reporter('rds')
    reporter.process(obj).getSummary().getDetails()
    
    # o = reporter.getCard()
    o = reporter.getDetail()
    # o = reporter.getDashboard()
    # o = dashboard
    # print(json.dumps(o, indent=4))
    
    pb = PageBuilder('rds', reporter, services, regions)
    pb.buildPage()
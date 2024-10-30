import time

import boto3
from botocore.config import Config as bConfig
from utils.Config import Config
import constants as _C

class Service:
    _AWS_OPTIONS = {}
    chartsType = {}
    RULESPREFIX = None
    tags = []
    chartsConfig = {}

    TAGS_SEPARATOR = '%'
    KEYVALUE_SEPARATOR = '='
    VALUES_SEPARATOR = ','

    def __init__(self, region):
        self.overallTimeStart = time.time()

        classname = self.__class__.__name__

        suffix = "" if classname in Config.GLOBAL_SERVICES else " on region <" + region + ">"

        self.RULESPREFIX = classname + '::rules'
        self.region = region
        self.bConfig = bConfig(
            region_name = region    
        )
        
        self.charts = {}
        self.chartData = {}
        
        self.ssBoto = Config.get('ssBoto', None)
        if self.ssBoto == None:
            print('BOTO3 SESSION IS MISSING')
        
        print('\x1b[1;37;43mPREPARING\x1b[0m -- \x1b[1;31;43m' + classname.upper()+ '::'+region + '\x1b[0m')

    def setChartConfig(self, title, chartType, legends, data):
        if title not in self.chartsConfig:
            self.chartsConfig[title] = {}
        self.chartsConfig[title] = {
            'chartType' : chartType,
            'legends': legends
        }
        
        self.charts[title] = data


    def setChartsType(self, chartsType):
        self.chartsType = chartsType
    

    def setChartData(self,chartData):
        for title in chartData:
            if title not in self.chartData:
                self.chartData[title] = {}
            
            for cat in chartData[title]:
                if cat not in self.chartData[title]:
                    self.chartData[title][cat] = chartData[title][cat]
                else:
                    self.chartData[title][cat] += chartData[title][cat]
        
    def getChart(self):
        result = {
            'config': self.chartsConfig,
            'data': self.charts
        }
        return result

    def setRules(self, rules):
        ## Class method is case insensitive, lower to improve accessibilities
        rules = rules.lower().split('^')
        Config.set(self.RULESPREFIX, rules)
        
    def __del__(self):
        self.processChartData()
        timespent = round(time.time() - self.overallTimeStart, 3)
        print('\033[1;42mCOMPLETED\033[0m -- \x1b[4;30;47m' + self.__class__.__name__.upper() + '::'+self.region+'\x1b[0m (' + str(timespent) + 's)')
        
        items = Config.retrieveAllCache()
        key = [k for k in items.keys() if 'AllScannedResources' in k]
        f = open(_C.FORK_DIR + '/' + 'all.csv', 'a+')
        for ke in key:
            f.write('\r\n'.join(items[ke]) + '\r\n')
        f.close()
            
        
        Config.set(self.RULESPREFIX, [])
        
    def setTags(self, tags):
        rawTags = {}
        if not tags:
            return
        
        result = []
        t = tags.split(self.TAGS_SEPARATOR)
        for tag in t:
            k, v = tag.split(self.KEYVALUE_SEPARATOR)
            rawTags[k] = v.split(self.VALUES_SEPARATOR)
            result.append({"Name": "tag:" + k, "Values": v.split(self.VALUES_SEPARATOR)})
        
        self._tags = rawTags
        self.tags = result
        
        # print(self._tags, self.tags)
        
    def resourceHasTags(self, tags):
        if not self._tags:
            return True
        
        if not tags:
            return False
        
        formattedTags = {}
        for tag in tags:
            formattedTags[tag['Key']] = tag['Value']
        
        filteredTags = self._tags
        
        for key, value in filteredTags.items():
            if key not in formattedTags:
                return False
            
            cnt = 0
            for val in value:
                if formattedTags[key] == val:
                    cnt += 1
                    break
            
            if cnt == 0:
                return False
        
        return True    
        
    # convert normal keypair to tag format
    # {env: prod, costcenter: hr} => [{'Key': 'env', 'Value': 'prod'}, {'Key': 'costcenter', 'Value': 'hr'}] 
    def convertKeyPairTagToTagFormat(self, tags):
        nTags = []
        for k, v in tags.items():
            nTags.append({'Key': k, 'Value': v})
            
        return nTags
        
    def convertTagKeyTagValueIntoKeyValue(self, tags):
        nTags = []
        for i in tags:
            nTags.append({'Key': i['TagKey'], 'Value': i['TagValue']})
            
        return nTags
    
    def processChartData(self):
        if len(self.chartData) > 0:
            for title, data in self.chartData.items():
                legends = list(data.keys())
                values = list(data.values())
                chartType = self.chartsType[title]

                self.setChartConfig(title, chartType, legends, values)


if __name__ == "__main__":
    Config.init()
    Config.set('_AWS_OPTIONS', {'signature': 'ok'})
    r = 'ap-southeast-1'
    o = Service(r)
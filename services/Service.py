import time

import boto3
from botocore.config import Config as bConfig
from utils.Config import Config

class Service:
    _AWS_OPTIONS = {}
    RULESPREFIX = None
    tags = []

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
        
        # param = Config.get('_SS_PARAMS')
        # profile = param['profile']
        # if not profile == False:
        #    boto3.setup_default_session(profile_name=profile)
        
        print('PREPARING -- ' + classname.upper()+ '::'+region)
        
    def setRules(self, rules):
        ## Class method is case insensitive, lower to improve accessibilities
        rules = rules.lower().split('^')
        Config.set(self.RULESPREFIX, rules)
        
    def setTags(self, tags):
        rawTags = []
        if not tags:
            return
        
        result = []
        t = tags.split(self.TAGS_SEPARATOR)
        for tag in t:
            k, v = tag.split(self.KEYVALUE_SEPARATOR)
            rawTags = {k: v.split(self.VALUES_SEPARATOR) for k, v in tag.items()}
            result.append({"Name": "tag:" + k, "Values": v.split(self.VALUES_SEPARATOR)})
        
        self._tags = rawTags
        self.tags = result
        
    def __del__(self):
        timespent = round(time.time() - self.overallTimeStart, 3)
        print('\033[1;42mCOMPLETED\033[0m -- ' + self.__class__.__name__.upper() + '::'+self.region+' (' + str(timespent) + 's)')
        Config.set(self.RULESPREFIX, [])
        
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

if __name__ == "__main__":
    Config.init()
    Config.set('_AWS_OPTIONS', {'signature': 'ok'})
    r = 'ap-southeast-1'
    o = Service(r)
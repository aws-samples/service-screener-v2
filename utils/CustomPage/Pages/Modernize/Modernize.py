import json
from utils.Config import Config
from utils.CustomPage.CustomObject import CustomObject

class Modernize(CustomObject):
    ResourcesToTrack = {
        'rds': {
            'rdsmariadb': {'MoveToGraviton', 'ConsiderAurora'},
            'rdsmysql': {'MoveToGraviton', 'ConsiderAurora'},
            'rdsmssql': {'ConsiderOpenSource'},
            'rdspostgres': {'MoveToGraviton', 'ConsiderAurora'},
            'rdsmysqlaurora': {},
            'rdspostgresaurora': {}
        },
        'dynamodb': {
            'dynamodbcommon': {}
        },
        'ec2': {
            'ec2instance': {'WindowsOSOutdated', 'WindowsOSNotLatest', 'MoveToGraviton'}
        },
        'eks': {
            'ekscommon': {}
        },
        'lambda': {
            'lambdacommon': {}
        }
    }
    
    ModernizePath = [
        {
            "Computes": {
                "EC2": {
                    "Windows": {
                        "MSSQL": {
                            "_MoveToManagedDB": None
                        },
                        "OutdatedOS": {
                            "_UpgradeLatestOS": None
                        },
                        "NotLatestOS": {
                            "_UpgradeLatestOS": None
                        },
                        "_MoveToAMD": None,
                        "_MoveToContainer": None
                    },
                    "NoneGravitonLinux": {
                        "_MoveToGraviton": None
                    },
                    "Linux":{
                        "_MoveToContainer": None
                    },
                    "TagsKeyWords": {
                        "_MoveToManagedServices": None
                    }
                },
                "Lambda": {
                    "_Modernized": None
                },
                "EKS_ECS": {
                    "_Modernized": None
                }
            },
        },
        {
            "Databases": {
                "RDS": {
                    "OpenSources": {
                        "_MoveToAurora": None
                    },
                    "Enterprise": {
                        "_MoveToOpenSourceDB": None
                    },
                    "Aurora": {
                        "_Modernized": None
                    }
                },
                "DynamoDB": {
                    "_Modernized": None
                }
            }
        }
    ]
    
    def __init__(self):
        super().__init__()
        self.ds = {}
        self.IndexMap = []
        self.ConnectMap = []
        self.RelMapValue = {}
        # print( json.dumps(self.ModernizePath, indent=2))
    
    def getRelValue(self, source, target, isPath=False):
        prefix = source + "==>" + target
        
        res = 0
        if prefix in self.RelMapValue and (target[0:1] == '_' and isPath==True): 
            res = self.RelMapValue[prefix]
        elif target[0:1] == '_': 
            kstr = "==>" + target
            for k, v in self.RelMapValue.items():
                if kstr in k:
                    res = res + v 
            
            ## to cater those _ which has no number populated        
            if res == 0:
                kstr = "==>" + source
                for k, v in self.RelMapValue.items():
                    if kstr in k:
                        res = res + v 
                        break
                    
        else: 
            res = 0
            
        # print(target, res)
        return res
        
    
    def indexMapping(self, arr, p = None):
        for k, ar in arr.items():
            if not k in self.IndexMap:
                ## add nodes
                val = self.d3ResourceCount(k)
                if val == 0:
                    continue 
                
                if val != '':
                    val = " ({})".format(str(val))
                else:
                    val = self.getRelValue(p, k)
                    if val == 0:
                        continue
                    
                    val = " ({})".format(str(val))
                
                # print('===', val, k)
                self.d3nodes.append("{}{}".format(k, val))
                self.IndexMap.append(k)
            
            if p:
                val = self.getRelValue(p, k, isPath=True)
                
                print(val, p, k)
                pIdx = self.IndexMap.index(p)
                kIdx = self.IndexMap.index(k)
                
                # print(p, pIdx, kIdx, k)
                
                self.ConnectMap.append([pIdx, kIdx, val])
            
            if isinstance(ar, dict):
                self.indexMapping(ar, k)
            
    def d3LinksSetup(self):
        links = []
        for rel in self.ConnectMap:
            tmp = {}
            # tmp["source"] = self.d3nodes[rel[0]]
            # tmp["target"] = self.d3nodes[rel[1]]
            tmp["source"] = rel[0]
            tmp["target"] = rel[1]
            tmp["value"] = rel[2]
            
            if rel[2] == 0:
                continue
            
            links.append(tmp)
            
        self.d3links = links
    
    def d3ResourceCount(self, keyw):
        comboToSkip = ['EC2==>TagsKeyWords']
        
        if keyw[0:1] == '_':
            return ''
        
        kpref = keyw + "==>"
        ksuff = "==>" + keyw
        cnt = 0
        for k, v in self.RelMapValue.items():
            if k in comboToSkip:
                continue
            
            if kpref in k:
                cnt = cnt + v
        
        if cnt == 0:
            for k, v in self.RelMapValue.items():
                if ksuff in k:
                    cnt = cnt + v
                
        return cnt
    
    def build(self):
        ds = self.dataSets
        
        compTotal = 0
        compWindowsTotal = 0
        compLinuxTotal = 0
        compLinuxNonGTotal = 0
        winNotLatestOS = 0
        winOutdateOS = 0
        winMSSQL = 0
        winToContainer = 0
        winToAMD = 0
        compHasTag = 0
        
        dbTotal = 0
        rdsTotal = 0
        ddbTotal = 0
        dbOpen = 0
        dbMSSQL = 0
        dbOracle = 0
        dbAurora = 0
        
        compute = {}
        database = {}
        if 'ec2' in ds:
            compute['ec2'] = ds['ec2']['ec2instance']
            for ec2info in compute['ec2']['items']:
                if ec2info['platform'] == 'windows':
                    compWindowsTotal = compWindowsTotal + 1
                    if 'SQLServer' in ec2info:
                        winMSSQL = winMSSQL + 1
                else:
                    compLinuxTotal = compLinuxTotal + 1
                    
                if 'keyTags' in ec2info:
                    compHasTag = compHasTag + 1
            
            if 'rules' in compute['ec2']:
                ru = compute['ec2']['rules']
                if 'EC2Graviton' in ru:
                    compLinuxNonGTotal = len(ru['EC2Graviton'])
                
                if 'WindowsOSOutdated' in ru:
                    winOutdateOS = len(ru['WindowsOSOutdated'])
                
                if 'WindowsOSNotLatest' in ru:
                    winNotLatestOS = len(ru['WindowsOSNotLatest'])
                
                if 'EC2AMD' in ru:
                    winToAMD = len(ru['EC2AMD'])
                
            winToContainer = compWindowsTotal - winOutdateOS - winNotLatestOS - winMSSQL
                    
        if 'eks' in ds:
            compute['container'] = ds['eks']['ekscommon']
            
        if 'lambda' in ds:
            compute['lambda'] = ds['lambda']['lambdacommon']
        
        if 'rds' in ds:
            for engine, rules in self.ResourcesToTrack['rds'].items():
                # print(engine, engine in ds)
                if engine in ds['rds']:
                    database[engine] = ds['rds'][engine]
            
            # print(database)
        ## total compute
        for comp, detail in compute.items():
            compTotal = compTotal + detail['total']
        
        ## total database
        for db, detail in database.items():
            rdsTotal = rdsTotal + detail['total']
            
            if db in ['rdsmariadb', 'rdsmysql', 'rdspostgres']:
                dbOpen = dbOpen + database[db]['total']
            elif db in ['rdsmssql']:
                dbMSSQL = dbMSSQL + database[db]['total']
            elif db in ['rdsoracle']:       ## currently, oracle is not supported in SSv2
                dbOracle = dbOracle + database[db]['total']
            elif db in ['rdsmysqlaurora', 'rdspostgresaurora']:
                if database[db]['total'] > 0:
                    dbAurora = dbAurora + database[db]['total'] - 1 ## cluster logic. remove it from list
            else :
                print('-- Modernize Page: unsupported DB Engine: {}'.format(db))
            
            if detail['items']:
                for dbInfo in detail['items']:
                    if dbInfo['IsCluster'] == True:
                        rdsTotal = rdsTotal - 1
        
        if 'dynamodb' in ds:
            ddbTotal = ds['dynamodb']['dynamodbcommon']['total']
        
        dbTotal = ddbTotal + rdsTotal
        
        resourcesTotal = compTotal + dbTotal    
        
        ## Manual Mapping
        self.RelMapValue['Resources==>Computes'] = compTotal
        self.RelMapValue['Computes==>EC2'] = 0 if not 'ec2' in compute else compute['ec2']['total']
        self.RelMapValue['EC2==>Windows'] = compWindowsTotal
        self.RelMapValue['Windows==>MSSQL'] = winMSSQL
        self.RelMapValue['Windows==>OutdatedOS'] = winOutdateOS
        self.RelMapValue['Windows==>NotLatestOS'] = winNotLatestOS
        self.RelMapValue['Windows==>_MoveToContainer'] = winToContainer
        self.RelMapValue['Windows==>_MoveToAMD'] = winToAMD
        self.RelMapValue['EC2==>TagsKeyWords'] = compHasTag
        
        self.RelMapValue['EC2==>NoneGravitonLinux'] = compLinuxNonGTotal
        self.RelMapValue['Linux==>_MoveToContainer'] = self.RelMapValue['EC2==>Linux'] = compLinuxTotal - compLinuxNonGTotal
        self.RelMapValue['Computes==>Lambda'] = 0 if not 'lambda' in compute else compute['lambda']['total']
        self.RelMapValue['Computes==>EKS_EC2'] = 0 if not 'container' in compute else compute['container']['total']
        
        self.RelMapValue['Resources==>Databases'] = dbTotal
        self.RelMapValue['Databases==>RDS'] = rdsTotal
        self.RelMapValue['RDS==>OpenSources'] = dbOpen
        self.RelMapValue['RDS==>Enterprise'] = dbMSSQL + dbOracle
        self.RelMapValue['RDS==>Aurora'] = dbAurora
        self.RelMapValue['Databases==>DynamoDB'] = ddbTotal
        
        # print(self.RelMapValue)
        for va in self.ModernizePath:
            currentParent = list(va.keys())[0]
            
            self.ConnectMap = []
            self.IndexMap = []
            self.d3nodes = []
            self.indexMapping(va)
            # self.d3NodesSetup()
            self.d3LinksSetup()
            
            self.ds[currentParent] = {
                'nodes':self.d3nodes, 
                'links':self.d3links
            }
import botocore

from utils.Config import Config
from utils.Tools import _pr, _warn
from services.Service import Service
##import drivers here
from services.rds.drivers.RdsCommon import RdsCommon
from services.rds.drivers.RdsMysql import RdsMysql
from services.rds.drivers.RdsMariadb import RdsMariadb
from services.rds.drivers.RdsMysqlAurora import RdsMysqlAurora
from services.rds.drivers.RdsPostgres import RdsPostgres
from services.rds.drivers.RdsPostgresAurora import RdsPostgresAurora
from services.rds.drivers.RdsMssql import RdsMssql
from services.rds.drivers.RdsSecretsManager import RdsSecretsManager
from services.rds.drivers.RdsSecretsVsDB import RdsSecretsVsDB
from services.rds.drivers.RdsSecurityGroup import RdsSecurityGroup

from utils.Tools import _pi

class Rds(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.rdsClient = ssBoto.client('rds', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self.ctClient = ssBoto.client('cloudtrail', config=self.bConfig)
        self.smClient = ssBoto.client('secretsmanager', config=self.bConfig)
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        
        self.secrets = []

    engineDriver = {
        'mariadb': 'Mariadb',
        'mysql': 'Mysql',
        'aurora-mysql': 'MysqlAurora',
        'postgres': 'Postgres',
        'aurora-postgresql': 'PostgresAurora',
        'sqlserver': 'Mssql'
    }
    
    def getResources(self):
        p = {}
        
        results = self.rdsClient.describe_db_instances(**p)
        
        arr = results.get('DBInstances')
        while results.get('Maker') is not None:
            p['Maker'] = results.get('Maker')
            results = self.rdsClient.describe_db_instances(**p)
            arr = arr + results.get('DBInstances')
        
        for k, v in enumerate(arr):
            if v['DBInstanceStatus'].lower() in ['deleting', 'failed', 'restore-error', 'failed'] or v['DBInstanceStatus'].lower().startswith('incompatible'):
                del arr[k]
        
        if not self.tags:
            return arr
        
        finalArr = []
        for i, detail in enumerate(arr):
            if self.resourceHasTags(detail['TagList']):
                finalArr.append(arr[i])
        
        return finalArr    
        
    def getClusters(self):
        p = {}
        results = self.rdsClient.describe_db_clusters(**p)
        
        arr = results.get('DBClusters')
        while results.get('Maker') is not None:
            p['Maker'] = results.get('Maker')
            results = self.rdsClient.describe_db_clusters(**p)
            
            arr = arr + results.get('DBClusters')

        if not self.tags:
            return arr
        
        finalArr = []
        for i, detail in enumerate(arr):
            if self.resourceHasTags(detail['TagList']):
                finalArr.append(arr[i])
            
        return finalArr
            
    def getSecrets(self):
        p = {"IncludePlannedDeletion": False, "MaxResults": 10}
        
        results = self.smClient.list_secrets(**p)
        self.registerSecrets(results)
        
        NextToken = results.get('NextToken')
        while NextToken != None:
            p['NextToken'] = NextToken
            results = self.smClient.list_secrets(**p)
            NextToken = results.get('NextToken')
            
            self.registerSecrets(results)
            
    def registerSecrets(self, results):
        for secret in results.get('SecretList'):
            if self.tags:
                if not 'Tags' in secret:
                    print('Tags not supported in this region: [{}], ignoring tags filter'.format(self.region))
                    continue
                
                if self.resourceHasTags(secret['Tags']) == False:
                    continue
            
            resp = self.smClient.describe_secret(SecretId=secret['ARN'])
            self.secrets.append(resp)
        
    def advise(self):
        objs = {}
        instances = self.getResources()
        securityGroupArr = {}
        
        clusters = self.getClusters()
        
        groupedResources = instances + clusters
        
        for instance in groupedResources:
            dbKey = 'DBClusterIdentifier'
            dbInfo = 'Cluster'
            if 'DBInstanceIdentifier' in instance:
                dbInfo = 'Instance'
                dbKey = 'DBInstanceIdentifier'
            
            _pi('RDS', '{}::{}'.format(dbInfo, instance[dbKey]))
            
            if 'VpcSecurityGroups' in instance:
                for sg in instance['VpcSecurityGroups']:
                    if 'Status' in sg and (sg['Status'] == 'active' or sg['Status'] == 'adding'):
                        if sg['VpcSecurityGroupId'] in securityGroupArr:
                            securityGroupArr[sg['VpcSecurityGroupId']].append(instance[dbKey])
                        else:
                            securityGroupArr[sg['VpcSecurityGroupId']] = [instance[dbKey]]
                
            engine = instance['Engine']
            
            # grouping mssql versions together
            if engine.find('sqlserver') != -1:
                engine = 'sqlserver'
            
            if engine not in self.engineDriver:
                _warn("{}, unsupported RDS Engine: [{}]".format(instance[dbKey], engine))
                continue
            
            driver_ = self.engineDriver[engine]
            driver = 'Rds' + driver_
            if driver in globals():
                obj = globals()[driver](instance, self.rdsClient, self.ctClient, self.cwClient)
                obj.setEngine(engine)
                obj.run(self.__class__)
                
                objs[instance['Engine'] + '::' + dbInfo + '=' + instance[dbKey]] = obj.getInfo()
                del obj
        
        for sg, rdsList in securityGroupArr.items():
            _pi('RDS-SG', sg)
            obj = RdsSecurityGroup(sg, self.ec2Client, rdsList)
            obj.run(self.__class__)
            objs['RDS_SG::' + sg] = obj.getInfo()
            del obj

        self.getSecrets()
        for secret in self.secrets:
            _pi('SecretsManager', secret['Name'])
            obj = RdsSecretsManager(secret, self.smClient, self.ctClient)
            obj.run(self.__class__)
            
            objs['SecretsManager::'+ secret['Name']] = obj.getInfo()
            del obj
        
        obj = RdsSecretsVsDB(len(self.secrets), len(instances))
        obj.run(self.__class__)
        objs['SecretsRDS::General'] = obj.getInfo()
        del obj
        
        return objs
    
if __name__ == "__main__":
    Config.init()
    o = Rds('ap-southeast-1')
    out = o.advise()

import botocore

from utils.Config import Config
from utils.Tools import _pr, _warn, _pi
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

from datetime import datetime, timedelta, time, timezone

class Rds(Service):
    CHARTSTYPE = {
        'RDS Price': 'bar',
        'RDS Price per Instance Type': 'bar',
        'RDS Price per Engine': 'bar',
        'RDS Price per Deployment Option': 'bar'
    }
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.rdsClient = ssBoto.client('rds', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self.ctClient = ssBoto.client('cloudtrail', config=self.bConfig)
        self.smClient = ssBoto.client('secretsmanager', config=self.bConfig)
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        self.ceClient = ssBoto.client('ce', config=self.bConfig)
        self.setChartsType(self.CHARTSTYPE)
        
        self.secrets = []
        self.hasCEPermission = True

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
    
    def getCEResults(self, groupBy, filter):
        ## Fix for 30 days data
        endDate = datetime.now().date()
        startDate = endDate - timedelta(days=30)
        response = {}

        if self.hasCEPermission == True:
            try:
                response = self.ceClient.get_cost_and_usage(
                    TimePeriod={"Start": str(startDate), "End": str(endDate)},
                    Granularity="MONTHLY",
                    Metrics=["UnblendedCost"],
                    GroupBy=[{"Type": "DIMENSION", "Key": groupBy}],
                    Filter=filter,
                )
            except botocore.exceptions.ClientError as e:
                self.hasCEPermission = False
                eCode = e.response['Error']['Code']
                eMsg = e.response['Error']['Message']
                print("Rds.py error: {}, {}".format(eCode, eMsg))
                print("[Skipped] RDS Cost Breakdown Charts")

        return response
    
    
    def getRDSCost(self, dimension, unuse_group=[]):
        results = {}
        filter = {
            "And": [
                {"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Relational Database Service"]}},
                {"Dimensions": {"Key": "REGION", "Values": [self.region]}}
            ]
        }
        response = self.getCEResults(dimension, filter)
        if response == {}:
            return results

        for item in response.get('ResultsByTime'):
            for group in item.get("Groups"):
                if 'Keys' in group:
                    key = group.get("Keys")[0]
                    if key in unuse_group:
                        continue
                    amt = group.get("Metrics").get("UnblendedCost").get("Amount")
                    if float(amt) == 0:
                        continue                    

                    if key in results:
                        results[key] = results[key] + float(amt)
                    else:
                        results[key] = float(amt)
        
        return results
    
    def setRDSChartData(self):
        chart_data = {}
        service_result = self.getRDSCost("SERVICE")
        if service_result:
            chart_data['RDS Price'] = service_result

        instance_type_result = self.getRDSCost("INSTANCE_TYPE",["NoInstanceType"])
        if instance_type_result:
            chart_data['RDS Price per Instance Type'] = instance_type_result

        engine_result = self.getRDSCost("DATABASE_ENGINE",["NoDatabaseEngine"])
        if engine_result:
            chart_data['RDS Price per Engine'] = engine_result

        deploy_option_result = self.getRDSCost("DEPLOYMENT_OPTION",["NoDeploymentOption"])
        if deploy_option_result:
            chart_data['RDS Price per Deployment Option'] = deploy_option_result
        
        self.setChartData(chart_data)

        return
    
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
        
        ## Set RDS CO Chart
        self.setRDSChartData()

        return objs
    
if __name__ == "__main__":
    Config.init()
    o = Rds('ap-southeast-1')
    out = o.advise()

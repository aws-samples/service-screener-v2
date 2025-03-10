import boto3, botocore

import time
import datetime
from datetime import timezone

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import aws_parseInstanceFamily
from utils.Tools import _warn
from services.Evaluator import Evaluator

class RdsCommon(Evaluator):
    def __init__(self, db, rdsClient, ctClient, cwClient):
        self.dbParams = {}
        self.results = {}
        self.db = db
        self.rdsClient = rdsClient
        self.cwClient = cwClient
        self.ctClient = ctClient
        self.certInfo = None
        
        self.__configPrefix = 'rds::' + db['Engine'] + '::' + db['EngineVersion'] + '::'
        self.isCluster = True
        if 'DBInstanceIdentifier' in db:
            self.isCluster = False
            
        self.init()
        self.getInstInfo()
        self.getCAInfo()
        self.loadParameterInfo()
        
        
    def setEngine(self, engine):
        self.engine = engine
        self.addII('engine', engine)
        
        self.isAurora = False
        if engine[0:6]=='aurora':
            self.isAurora = True
        
    def getCAInfo(self):
        if self.isCluster == True:
            return
    
        if not 'CACertificateIdentifier'in self.db:
            _warn("Unable to locate CACertificateIdentifier")
            return
            
        ca = self.db['CACertificateIdentifier']
        k = 'RDSCaInfo::' + ca
        
        myCert = Config.get(k, None)
        if myCert == None:
            try:
                resp = self.rdsClient.describe_certificates(CertificateIdentifier=ca)
                certInfo = resp.get('Certificates')
                
                for cert in certInfo:
                    diff = cert['ValidTill'].replace(tzinfo=None) - datetime.datetime.now()
                    
                    cert['expiredInDays'] = diff.days
                    cert['isExpireIn365days'] = False
                    if diff.days < 365:
                        cert['isExpireIn365days'] = True
                    
                    myCert = cert
                    Config.set(k, cert)
                    break
            except botocore.exceptions.ClientError as e:
                ecode = e.response['Error']['Code']
                emsg = e.response['Error']['Message']
                print("[{}] {}".format(ecode, emsg))
        
        self.certInfo = myCert
        
    def showInfo(self):
        identifier = self.db['DBInstanceIdentifier'] if self.isCluster == False else self.db['DBClusterIdentifier']
        print("Identifier: " + identifier + "\n")
        _pr(self.results)

    def getInstInfo(self):
        self.isServerless = False
        self.addII('isServerless', False)
        self.addII('IsCluster', True)
        
        if self.isCluster == False:
            if 'serverless' in self.db['DBInstanceClass']:
                self.isServerless = True
                self.addII('isServerless', True)
                return
            
            self.instInfo = aws_parseInstanceFamily(self.db['DBInstanceClass'], region=self.rdsClient.meta.region_name)
            self.addII('instInfo', self.instInfo)
            self.addII('IsCluster', False)
        
        
        engine = self.db['Engine']
        engineVersion = self.db['EngineVersion']
        
        key = self.__configPrefix + 'engineVersions'
        details = Config.get(key, {})
        
        if not details:
            versions = self.rdsClient.describe_db_engine_versions(
                Engine=engine,
                EngineVersion=engineVersion
            )
            version = versions.get('DBEngineVersions')
            if not version:
                self.results['EngineVersionMinor'] = [-1, "**DEPRECIATED**"]
                self.results['EngineVersionMajor'] = [-1, "**DEPRECIATED**"]
                return
            details = version[0]
            Config.set(key, details)
        
        self.addII('EngineVersion', engineVersion)
        self.enginePatches = details
        
    def loadParameterInfo(self):
        arr = {}
        
        if self.isCluster == False:
            paramGroupName = self.db['DBParameterGroups'][0]['DBParameterGroupName']
            results = self.rdsClient.describe_db_parameters(
                DBParameterGroupName = paramGroupName
            )

            for param in results.get('Parameters'):
                if param['IsModifiable'] == 1 and 'ParameterValue' in param:
                    arr[param['ParameterName']] = param['ParameterValue']
            
            while results.get('Marker') is not None:
                results = self.rdsClient.describe_db_parameters(
                    DBParameterGroupName = paramGroupName,
                    Marker = results.get('Marker')
                )

                for param in results.get('Parameters'):
                    #__pr(param['ParameterName'] + ' = ' + param['ParameterValue'] + ' || ' + param['IsModifiable'])
                    if param['IsModifiable'] == 1 and 'ParameterValue' in param:
                        arr[param['ParameterName']] = param['ParameterValue']
            
        else: 
            paramGroupName = self.db['DBClusterParameterGroup']
            results = self.rdsClient.describe_db_cluster_parameters(
                DBClusterParameterGroupName = paramGroupName
            )

            for param in results.get('Parameters'):
                if param['IsModifiable'] == 1 and 'ParameterValue' in param:
                    arr[param['ParameterName']] = param['ParameterValue']
            
            while results.get('Marker') is not None:
                results = self.rdsClient.describe_db_cluster_parameters(
                    DBClusterParameterGroupName = paramGroupName,
                    Marker = results.get('Marker')
                )

                for param in results.get('Parameters'):
                    #__pr(param['ParameterName'] + ' = ' + param['ParameterValue'] + ' || ' + param['IsModifiable'])
                    if param['IsModifiable'] == 1 and 'ParameterValue' in param:
                        arr[param['ParameterName']] = param['ParameterValue']
            

        self.dbParams = arr
        del arr

    ##Common Logic Belows
    ##All checks start from __check;
    def _checkPublicSnapshot(self):
        if self.engine[0:6] == 'aurora':
            if self.db.get('DBClusterIdentifier', None) == None:
                return

            resp = self.rdsClient.describe_db_cluster_snapshots(
                DBClusterIdentifier=self.db['DBClusterIdentifier'],
                SnapshotType='public',
                IncludePublic=True,
                MaxRecords=20
            )
            publicSnapshots = resp.get('DBClusterSnapshots')
        else:
            if self.db.get('DBInstanceIdentifier', None) == None:
                return

            resp = self.rdsClient.describe_db_snapshots(
                DBInstanceIdentifier=self.db['DBInstanceIdentifier'],
                SnapshotType='public',
                IncludePublic=True,
                MaxRecords=20
            )
            
            publicSnapshots = resp.get('DBSnapshots')
            
        if len(publicSnapshots) > 0:
            self.results['SnapshotRDSIsPublic'] = [-1, "At least " + str(len(publicSnapshots))]
    
    ## Move from MSSQL to Common as Postgres has similar settings
    def _checkSSLParams(self):
        validEngine = ['aurora-postgresql', 'postgres', 'sqlserver']
        
        if not self.engine in validEngine:
            return
        
        if 'rds.force_ssl' in self.dbParams and self.dbParams['rds.force_ssl'] == '0':
            self.results['MSSQLorPG__TransportEncrpytionDisabled'] = [-1, 'rds.force_ssl==0']
    
    def _checkMasterUsername(self):
        defaultMasterUser = {
            'mysql': 'admin',
            'aurora-mysql': 'admin',
            'postgres': 'postgres',
            'aurora-postgresql': 'postgres',
            'sqlserver': 'admin',
            'mariadb': 'admin'
        }
        
        if not self.engine in defaultMasterUser:
            _warn("New Engine not being tracked (RDS-MasterUser), please submit an issue to github --> " + self.engine)
            return
        
        if defaultMasterUser[self.engine] == self.db['MasterUsername']:
            self.results['DefaultMasterAdmin'] = [-1, self.engine + "::" + self.db["MasterUsername"]]
    
    def _checkHasStorageAutoscaling(self):
        if not 'MaxAllocatedStorage' in self.db:
            self.results['EnableStorageAutoscaling'] = [-1, None]
    
    def _checkHasMultiAZ(self):
        multiAZ = -1 if self.db['MultiAZ'] == False else 1
        self.results['MultiAZ'] = [multiAZ, 'Off' if multiAZ == -1 else 'On']
    
    def _checkAutoMinorVersionUpgrade(self):
        flag = -1 if self.db['AutoMinorVersionUpgrade'] == False else 1
        self.results['AutoMinorVersionUpgrade'] = [flag, 'Off' if flag == -1 else 'On']
    
    def _checkHasStorageEncrypted(self):
        flag = -1 if self.db['StorageEncrypted'] == False else 1
        self.results['StorageEncrypted'] = [flag, 'Off' if flag == -1 else 'On']
    
    def _checkHasPerformanceInsightsEnabled(self):
        if self.isCluster == True:
            return
        
        flag = -1 if self.db['PerformanceInsightsEnabled'] == False else 1
        self.results['PerformanceInsightsEnabled'] = [flag, 'Off' if flag == -1 else 'On']
        
    def _checkHasBackup(self):
        backupDay = self.db['BackupRetentionPeriod']
        if backupDay == 0:
            kk = 'Backup'
        elif backupDay < 7:
            kk = 'BackupTooLow'
            
        if backupDay < 7:
            self.results[kk] = [-1, backupDay]

    def _checkIsUsingDefaultParameterGroups(self):
        if self.isCluster == False:
            params = self.db['DBParameterGroups']
            for param in params:
                if 'default.' in param['DBParameterGroupName']:
                    self.results['DefaultParams'] = [-1, param['DBParameterGroupName']]
        else:
            param = self.db['DBClusterParameterGroup']
            if param[0:7] == 'default.':
                self.results['DefaultParams'] = [-1, param['DBClusterParameterGroup']]
            
    def _checkMonitoringIntervals(self):
        if self.isCluster == True:
            return
        
        if self.db['MonitoringInterval'] > 30 or self.db['MonitoringInterval'] == 0:
            self.results['MonitoringIntervalTooLow'] = [-1, self.db['MonitoringInterval']]

    def _checkHasEnhancedMonitoring(self):
        flag = 1 if 'EnhancedMonitoringResourceArn' in self.db else -1
        self.results['EnhancedMonitor'] = [flag, 'On' if flag == -1 else 'Off']

    def _checkDeleteProtection(self):
        key = 'DeleteProtection'
        if self.isCluster == True:
            key = 'DeleteProtectionCluster'
        
        flag = -1 if self.db['DeletionProtection'] == False else 1
        self.results[key] = [flag, 'Off' if flag == -1 else 'On']

    def _checkIsPublicAccessible(self):
        if self.isCluster == True:
            return
        
        flag = -1 if self.db['PubliclyAccessible'] == True else 1
        self.results['PubliclyAccessible'] = [flag, 'Off' if flag == -1 else 'On']

    def _checkSubnet3Az(self):
        if self.isCluster == False:
            subnets = self.db['DBSubnetGroup']['Subnets']
            
            subnetName = []
            for subnet in subnets:
                subnetName.append(subnet['SubnetAvailabilityZone']['Name'])
            
            flag = 1
            if len(subnets) < 3:
                flag = -1
                
            self.results['Subnets3Az'] = [flag, ', '.join(subnetName)]
        else:
            subnets = self.db['AvailabilityZones']
            if len(subnets) < 3:
                self.results['Subnets3Az'] = [-1, ', '.join(subnets)]
        
    def _checkIsInstanceLatestGeneration(self):
        if self.isCluster == True or self.isServerless == True:
            return
        
        key = self.__configPrefix + 'orderableInstanceType'
        instTypes = Config.get(key, [])
        
        if not instTypes:
            try:
                results = self.rdsClient.describe_orderable_db_instance_options(
                    # DBInstanceClass = self.db['DBInstanceClass'],
                    Engine = self.db['Engine'],
                    EngineVersion = self.db['EngineVersion'],
                    MaxRecords = 20
                )
                
                arr = []
                for instClass in results.get('OrderableDBInstanceOptions'):
                    arr.append(instClass['DBInstanceClass'])
                
                while results.get('Marker') is not None:
                    results = self.rdsClient.describe_orderable_db_instance_options(
                        Engine = self.db['Engine'],
                        EngineVersion = self.db['EngineVersion'],
                        Marker = results.get('Marker')
                    )
                    
                    for instClass in results.get('OrderableDBInstanceOptions'):
                        arr.append(instClass['DBInstanceClass'])
                
                instTypes = list(set(arr))
                Config.set(key, instTypes)
                
                compressedLists = {}
                for instType in instTypes:
                    temp = instType.split('.')
                    compressedLists[temp[1][0]] = temp[1][1]
                
                Config.set(key + '::zip', compressedLists)
            except self.rdsClient.exceptions as e:
                _warn("Unable to identify potential latest engine version")
                if e.getAwsErrorCode() == 'InvalidParameterCombination':
                    self.results['LatestInstanceGeneration'] = [-1, '**DEPRECIATED**' + self.db['DBInstanceClass']]
                self.results['LatestInstanceGeneration'] = [-1, '_ERROR_']
                return
        else:
            compressedLists = Config.get(key + '::zip')
            
        dbInstClass = self.db['DBInstanceClass'].split('.')
        instInfo = self.instInfo
        dbInstFamily = instInfo['prefixDetail']['family']
        dbInstGeneration = instInfo['prefixDetail']['version']
        
        if dbInstFamily == 't':
            self.results['BurstableInstance'] = [-1, self.db['DBInstanceClass']]   
        
        if compressedLists[dbInstFamily] > dbInstGeneration:
            self.results['LatestInstanceGeneration'] = [-1, self.db['DBInstanceClass']]
    
    def _checkIsOpenSource(self):
        if self.isCluster == True:
            return
        
        validEngine = ['mariadb', 'postgres', 'mysql', 'aurora-mysql', 'aurora-postgresql']
        if not self.engine in validEngine:
            self.results['ConsiderOpenSource'] = [-1, self.engine]
            
    def _checkIfAurora(self):
        if self.isCluster == True:
            return
        
        validEngine = ['mariadb', 'postgres', 'mysql']
        if self.engine in validEngine:
            self.results['ConsiderAurora'] = [-1, self.engine]
    
    def _checkHasGravitonOption(self):
        if self.isCluster == True or self.isServerless == True:
            return
        
        ## valid Graviton List
        validEngine = ['mariadb', 'postgres', 'mysql', 'aurora-mysql', 'aurora-postgresql']
        if self.engine in validEngine:
            if not 'g' in self.instInfo['prefixDetail']['attributes']:
                self.results['MoveToGraviton'] = [-1, self.instInfo['prefix']]
            
    
    def _checkHasPatches(self):
        if self.isServerless == True:
            return
        
        engineVersion = self.db['EngineVersion']
        
        details = self.enginePatches
        
        upgrades = details['ValidUpgradeTarget']
        if not upgrades:
            self.results['EngineVersion'] = [1, engineVersion]
            return
        
        if upgrades[0]['IsMajorVersionUpgrade'] == False:
            self.results['EngineVersionMinor'] = [-1, engineVersion]
        
        lastInfo = upgrades[-1]
        if lastInfo['IsMajorVersionUpgrade'] == True:
            self.results['EngineVersionMajor'] = [-1, engineVersion]
       
    def _checkClusterSize(self):
        cluster = self.db.get('DBClusterIdentifier', None)
        if not cluster:
            return
        
        resp = self.rdsClient.describe_db_clusters(
            DBClusterIdentifier=cluster
        )
        
        clusters = resp.get('DBClusters')
        if len(clusters) < 2 or len(clusters) > 7:
            self.results['Aurora__ClusterSize'] = [-1, len(clusters)]
            
    def _checkHasTags(self):
        if len(self.db['TagList']) == 0:
            self.results['DBInstanceWithoutTags'] = [-1, None]
            
    def _checkOldSnapshots(self):
        if self.db.get('DBClusterIdentifier'):
            identifier = self.db['DBClusterIdentifier']
            result = self.rdsClient.describe_db_cluster_snapshots(
                DBClusterIdentifier=identifier,
                SnapshotType='manual'
            )
            
            snapshots = result.get('DBClusterSnapshots')
            while result.get('Marker') is not None:
                result = self.rdsClient.describe_db_cluster_snapshots(
                    DBClusterIdentifier=identifier,
                    SnapshotType='manual',
                    Marker=result.get('Marker')
                )
                
                snapshots = snapshots + result.get('DBSnapshots')
        else:
            identifier = self.db['DBInstanceIdentifier']
            result = self.rdsClient.describe_db_snapshots(
                DBInstanceIdentifier=identifier,
                SnapshotType='manual'
            )
            
            snapshots = result.get('DBSnapshots')
            while result.get('Marker') is not None:
                result = self.rdsClient.describe_db_snapshots(
                    DBInstanceIdentifier=identifier,
                    SnapshotType='manual',
                    Marker=result.get('Marker')
                )
                
                snapshots = snapshots + result.get('DBSnapshots')
        
        if not snapshots:
            return
                
        oldest_copy = snapshots[-1]
        
        oldest_copy_date = oldest_copy['SnapshotCreateTime']
        
        now = datetime.datetime.now(timezone.utc)
        
        diff = now - oldest_copy_date
        days = diff.days
        
        if len(snapshots) > 5:
            self.results['ManualSnapshotTooMany'] = [-1, len(snapshots)]
    
        if days > 180:
            self.results['ManualSnapshotTooOld'] = [-1, days]
            
    def _checkCAExpiry(self):
        if self.certInfo == None:
            return
        
        if self.isCluster == False and self.certInfo['isExpireIn365days'] == True:
            exp = self.certInfo['ValidTill'].strftime("%Y-%m-%d")
            self.results['CACertExpiringIn365days'] = [-1, "Expired on {}, ({} days left)".format(exp, self.certInfo['expiredInDays'])]
    
    def _checkFreeStorage(self):
        cw_client = self.cwClient
    
        if 'DBClusterIdentifier' in self.db:
            # Aurora Volume auto increase until 128TB as of 23/Sep/2021
            return
        else:
            metric = 'FreeStorageSpace'
            dimensions = [
                {
                    'Name': 'DBInstanceIdentifier',
                    'Value': self.db['DBInstanceIdentifier']
                }
            ]
    
        results = cw_client.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/RDS',
            MetricName=metric,
            StartTime=int(time.time()) - 300,
            EndTime=int(time.time()),
            Period=300,
            Statistics=['Average']
        )
    
        GBYTES = 1024 * 1024 * 1024
        dp = results['Datapoints']
        if len(dp) == 0:
            return
        
        freesize = round(dp[0]['Average'] / GBYTES, 4)
    
        ratio = freesize / self.db['AllocatedStorage']
        if ratio < 0.2:
            self.results['FreeStorage20pct'] = [-1, str(ratio * 100) + ' / ' + str(freesize) + '(GB)']

    def _checkHasDatabaseConnection(self):
        if self.isCluster == True:
            return
        
        metric = 'DatabaseConnections'
        dimensions = [
            {
                'Name': 'DBInstanceIdentifier',
                'Value': self.db['DBInstanceIdentifier']
            }   
        ]
        
        day7 = 60 * 60 * 24 * 7
        
        cw_client = self.cwClient
        results = cw_client.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/RDS',
            MetricName=metric,
            StartTime=int(time.time()) - day7,
            EndTime=int(time.time()),
            Period=day7,
            Statistics=['Sum']
        )
        
        dp = results['Datapoints']
        if dp and dp[0]['Sum'] == 0:
            self.results['RdsIsIdle7days'] = [-1, None]

    def _checkClusterIOvsStorage(self):
        if self.isCluster == False:
            return
        
        storageType = 'aurora'
        if 'StorageType' in self.db:
            storageType = self.db['StorageType']
        
        MILLION = 1000*1000
        ByteToGigaBytesRatio = 1024*1024*1024
        cwClient = self.cwClient
        metrics = ['VolumeReadIOPs', 'VolumeWriteIOPs']
        
        volumeMetric = 'VolumeBytesUsed'
        dimensions = [
            {
                'Name': 'DBClusterIdentifier',
                'Value': self.db['DBClusterIdentifier']
            }
        ]
        
        dayInSecond=(60*60*24)
        monthInSecond=dayInSecond*30
        
        statsParams = {
            'Dimensions':dimensions,
            'Namespace':'AWS/RDS',
            'StartTime':int(time.time()) - monthInSecond,
            'EndTime':int(time.time()),
            'Period':monthInSecond,
            'Statistics':['Sum']
        }
        
        ioCnt = 0
        volumeSize = 0
        for metric in metrics:
            statsParams['MetricName'] = metric
            resp = cwClient.get_metric_statistics(**statsParams)
            data = resp.get('Datapoints')
            
            if data:
                ioCnt = ioCnt + int(data[0]['Sum'])/MILLION
            
        statsParams['MetricName'] = volumeMetric
        statsParams['Statistics'] = ['Maximum']
        resp = cwClient.get_metric_statistics(**statsParams)
        data = resp.get('Datapoints')
        
        if data:
            volumeSize = data[0]['Maximum']/ByteToGigaBytesRatio
        
        if volumeSize == 0:
            return
        ratio = ioCnt / volumeSize
        
        ratioInfo = "Type: {}<br>[Ratio=ioCnt(million)/volumeSize(GB)]<br>[{}={}/{}]".format(storageType, round(ratio, 1), round(ioCnt, 1), round(volumeSize, 1))
        
        if ratio > 0.7 and storageType == 'aurora':
            self.results['AuroraStorageTypeToUseIOOpt'] = [-1, ratioInfo]
        elif ratio <= 0.7 and storageType == 'aurora-iopt1':
            self.results['AuroraStorageTypeToUseStnd'] = [-1, ratioInfo]
        else:
            self.results['AuroraStorageTypeOK'] = [-1, ratioInfo]
            return

    def _checkCPUUtilization(self):
        if self.isCluster == True or self.isServerless == True:
            return
        
        cwClient = self.cwClient
        serverVCPU = self.instInfo['specification']['vcpu']
        
        metric = 'CPUUtilization'
        dimensions = [
            {
                'Name': 'DBInstanceIdentifier',
                'Value': self.db['DBInstanceIdentifier']
            }    
        ]
        
        dayInSecond=(60*60*24)
        monthInSecond=dayInSecond*30
        resp = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/RDS',
            MetricName=metric,
            StartTime=int(time.time()) - monthInSecond,
            EndTime=int(time.time()),
            Period=dayInSecond,
            Statistics=['Minimum', 'Maximum', 'Average']
        )
        dailyDp = resp.get('Datapoints')
        
        resp = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/RDS',
            MetricName=metric,
            StartTime=int(time.time()) - monthInSecond,
            EndTime=int(time.time()),
            Period=monthInSecond,
            Statistics=['Minimum', 'Maximum', 'Average']
        )
        monthDp = resp.get('Datapoints')
        if len(monthDp) == 0:
            return
        
        monthAverage = monthDp[0]['Average']
        monthMax = monthDp[0]['Maximum']
        
        ## check for right sizing
        if monthMax <= 50:
            self.results['RightSizingCpuMonthMaxLT50pct'] = [-1, "Monthly Max CPU Util: {}%".format(round(monthMax, 100))]
            return 
        
        ## if not, trying to build manual rules for reviewing
        maxCnt = 0
        avgCnt = 0
        minCnt = 0
        for dp in dailyDp:
            if dp['Maximum'] > 70:
                maxCnt = maxCnt + 1
            if dp['Average'] < 30:
                avgCnt = avgCnt + 1
            if dp['Minimum'] < 3:
                minCnt = minCnt + 1
        
        ## High CPU
        if avgCnt < 10 and maxCnt > 10:
            #do ntg
            maxCnt 
        ## Low CPU on average
        elif minCnt >= 25 and avgCnt >= 20:
            self.results['RightSizingCpuLowUsageDetected'] = [-1, "MinCPU < 5% for {} days<br>AvgCPU < 30% for {}days".format(minCnt, avgCnt)]
        ## weekly spike once
        elif maxCnt >= 4 and maxCnt <= 7 and minCnt >= 20 and avgCnt >= 15:
            self.results['RightSizingCpuLowUsageDetectedWithWeeklySpike'] = [-1, "MinCPU < 5% for {} days<br>AvgCPU < 30% for {}days<br>MaxCPU > 70%  for {}days".format(minCnt, avgCnt, maxCnt)]

    def _checkFreeMemory(self):
        if self.isCluster == True or self.isServerless == True:
            return
        
        cwClient = self.cwClient
        metric = 'FreeableMemory'
        dimensions = [
            {
                'Name': 'DBInstanceIdentifier',
                'Value': self.db['DBInstanceIdentifier']
            }    
        ]
        
        rawToGBRatio=1024*1024*1024
        
        ## Past 24 hours, might recovers back
        dayInSecond=(60*60*24)
        resp = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/RDS',
            MetricName=metric,
            StartTime=int(time.time()) - dayInSecond,
            EndTime=int(time.time()),
            Period=dayInSecond,
            Statistics=['Minimum', 'Maximum', 'Average']
        )
        
        dp = resp.get('Datapoints')
        if len(dp) == 0:
            return
        
        serverGB = self.instInfo['specification']['memoryInGiB']
        
        freeMemoryMin = dp[0]['Minimum'] / rawToGBRatio
        freeMemoryMax = dp[0]['Maximum'] / rawToGBRatio
        freeMemoryAvg = dp[0]['Average'] / rawToGBRatio
        
        freeMemoryMinRatio = freeMemoryMin/serverGB
        freeMemoryMaxRatio = freeMemoryMax/serverGB
        freeMemoryAvgRatio = freeMemoryAvg/serverGB
        
        monthInSecond = dayInSecond*30
        resp = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/RDS',
            MetricName=metric,
            StartTime=int(time.time()) - monthInSecond,
            EndTime=int(time.time()),
            Period=monthInSecond,
            Statistics=['Minimum', 'Maximum', 'Average']
        )
        
        dp = resp.get('Datapoints')
        freeMemoryMthMin = dp[0]['Minimum'] / rawToGBRatio
        freeMemoryMthMax = dp[0]['Maximum'] / rawToGBRatio
        freeMemoryMthAvg = dp[0]['Average'] / rawToGBRatio
        freeMemoryMthMinRatio = freeMemoryMthMin/serverGB
        freeMemoryMthMaxRatio = freeMemoryMthMax/serverGB
        freeMemoryMthAvgRatio = freeMemoryMthAvg/serverGB
        
        # Less than 10%
        if freeMemoryMinRatio < 0.1:
            self.results['FreeMemoryLessThan10pct'] = [-1, "FreeableMemory: {}GB, %remains: {}".format(freeMemoryMin, round(freeMemoryMinRatio*100))]
            
            if freeMemoryMaxRatio - freeMemoryMinRatio > 0.5:
                self.results['FreeMemoryDropMT50pctIn24hours'] = [-1, "Max FreeMemory: {}GB, Min FreeMemory {}GB".format(freeMemoryMax, freeMemoryMin)]
        elif freeMemoryMthMinRatio > 0.60 and freeMemoryMthAvgRatio > 0.60:
            self.results['RightSizingMemoryMonthMinMT60pct'] = [-1, "Monthly<br>Min FreeMemory: {}%, Avg FreeMemory {}%".format(round(freeMemoryMinRatio*100, 1), round(freeMemoryAvgRatio*100, 1))]

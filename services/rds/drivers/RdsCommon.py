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
            self._resourceName = self.db['DBInstanceIdentifier']
        else:
            self._resourceName = self.db['DBClusterIdentifier']
            
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
                if param.get('IsModifiable', True) == 1 and 'ParameterValue' in param:
                    arr[param['ParameterName']] = param['ParameterValue']
            
            while results.get('Marker') is not None:
                results = self.rdsClient.describe_db_parameters(
                    DBParameterGroupName = paramGroupName,
                    Marker = results.get('Marker')
                )

                for param in results.get('Parameters'):
                    #__pr(param['ParameterName'] + ' = ' + param['ParameterValue'] + ' || ' + param['IsModifiable'])
                    if param.get('IsModifiable', True) == 1 and 'ParameterValue' in param:
                        arr[param['ParameterName']] = param['ParameterValue']
            
        else: 
            paramGroupName = self.db['DBClusterParameterGroup']
            results = self.rdsClient.describe_db_cluster_parameters(
                DBClusterParameterGroupName = paramGroupName
            )

            for param in results.get('Parameters'):
                if param.get('IsModifiable', True) == 1 and 'ParameterValue' in param:
                    arr[param['ParameterName']] = param['ParameterValue']
            
            while results.get('Marker') is not None:
                results = self.rdsClient.describe_db_cluster_parameters(
                    DBClusterParameterGroupName = paramGroupName,
                    Marker = results.get('Marker')
                )

                for param in results.get('Parameters'):
                    #__pr(param['ParameterName'] + ' = ' + param['ParameterValue'] + ' || ' + param['IsModifiable'])
                    if param.get('IsModifiable', True) == 1 and 'ParameterValue' in param:
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
        
        val = self.dbParams.get('rds.force_ssl', None)
        if val is not None:
            if str(val).strip() == '0':
                self.results['MSSQLorPG__TransportEncrpytionDisabled'] = [-1, 'rds.force_ssl==0']
            elif str(val).strip() == '1':
                self.results['MSSQLorPG__TransportEncrpytionDisabled'] = [1, 'rds.force_ssl==1']
            return

        # rds.force_ssl not returned by the parameter group: fall back to the
        # engine default only where AWS documents it per major version. Aurora / Multi-AZ cluster member instances
        # take the setting from the cluster parameter group (evaluated on the
        # cluster object), so they are skipped here.
        if self._isClusterMemberInstance():
            return
        # Documented engine defaults: RDS for PostgreSQL 15+ -> 1 (14 and
        # older -> 0); Aurora PostgreSQL 17+ -> 1 (16 and older -> 0).
        defaultOnFrom = {'postgres': 15, 'aurora-postgresql': 17}
        if self.engine in defaultOnFrom:
            try:
                major = int(str(self.db.get('EngineVersion', '')).split('.')[0])
            except ValueError:
                major = None
            minOn = defaultOnFrom[self.engine]
            if major is None:
                self.results['MSSQLorPG__TransportEncrpytionDisabled'] = [0, 'Unable to evaluate (rds.force_ssl not set; engine version unknown)']
            elif major >= minOn:
                self.results['MSSQLorPG__TransportEncrpytionDisabled'] = [1, 'rds.force_ssl not set (engine default 1 for {} {}+)'.format(self.engine, minOn)]
            else:
                self.results['MSSQLorPG__TransportEncrpytionDisabled'] = [-1, 'rds.force_ssl not set (engine default 0 before {} {})'.format(self.engine, minOn)]
            return
        # SQL Server: no version-specific default to rely on; never PASS (or
        # FAIL) on an unknown value.
        self.results['MSSQLorPG__TransportEncrpytionDisabled'] = [0, 'Unable to evaluate (rds.force_ssl not returned by the parameter group)']
    
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
            except botocore.exceptions.ClientError as e:
                _warn("Unable to identify potential latest engine version")
                if e.response['Error']['Code'] == 'InvalidParameterCombination':
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
        
        # Fix for AttributeError: 'RdsMysql' object has no attribute 'enginePatches'
        if not hasattr(self, 'enginePatches'):
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

        # When self.db is the cluster's own dict (from Rds.getClusters()'s bulk
        # describe_db_clusters() fetch), DBClusterMembers is already present -
        # no need to re-describe it. When self.db is an instance dict (this
        # driver also runs per-instance for cluster members), that field
        # isn't there, so fall back to the original per-call lookup.
        if 'DBClusterMembers' in self.db:
            members = self.db['DBClusterMembers']
        else:
            resp = self.rdsClient.describe_db_clusters(
                DBClusterIdentifier=cluster
            )
            members = resp.get('DBClusters')[0].get('DBClusterMembers', [])

        if len(members) < 2 or len(members) > 7:
            self.results['Aurora__ClusterSize'] = [-1, len(members)]
            
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
    
    def _checkCrossRegionBackup(self):
        if self.isCluster == True:
            return
        
        try:
            resp = self.rdsClient.describe_db_instance_automated_backups(
                DBInstanceIdentifier=self.db['DBInstanceIdentifier']
            )
            
            automated_backups = resp.get('DBInstanceAutomatedBackups', [])
            has_cross_region = False
            
            for backup in automated_backups:
                if backup.get('Region') != self.rdsClient.meta.region_name:
                    has_cross_region = True
                    break
            
            if not has_cross_region:
                self.results['CrossRegionBackupNotEnabled'] = [-1, 'No cross-region backup']
                
        except botocore.exceptions.ClientError as e:
            _warn(f"Unable to check cross-region backup: {e}")
            
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

    def _checkRDSRecommendationsActive(self):
        # Check if the resource has active (non-dismissed) RDS recommendations
        # API may not be available in all regions, so wrap in try/except.
        # The recommendations list is account/region-wide, not per-resource -
        # cache it once (same Config pattern as _checkEventSubscriptionNotConfigured
        # below) instead of every instance/cluster re-fetching the whole list.
        try:
            resourceArn = self.db.get('DBInstanceArn') or self.db.get('DBClusterArn')
            if not resourceArn:
                return

            cacheKey = 'rds::DBRecommendations'
            recommendations = Config.get(cacheKey, None)

            if recommendations is None:
                resp = self.rdsClient.describe_db_recommendations(
                    Filters=[
                        {
                            'Name': 'status',
                            'Values': ['active']
                        }
                    ]
                )
                recommendations = resp.get('DBRecommendations', [])
                Config.set(cacheKey, recommendations)

            # Filter recommendations for this specific resource
            resourceRecommendations = []
            for rec in recommendations:
                recResourceArn = rec.get('ResourceArn', '')
                if recResourceArn == resourceArn:
                    resourceRecommendations.append(rec)

            if len(resourceRecommendations) > 0:
                self.results['RDSRecommendationsActive'] = [-1, len(resourceRecommendations)]

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            _warn("Unable to describe RDS recommendations: [{}] {}".format(ecode, emsg))

    def _checkEventSubscriptionNotConfigured(self):
        # Account/region-level check: verify if any active event subscriptions exist
        # Use Config caching to avoid repeated API calls across instances
        cacheKey = 'rds::EventSubscriptions'
        hasSubscriptions = Config.get(cacheKey, None)
        
        if hasSubscriptions is None:
            try:
                resp = self.rdsClient.describe_event_subscriptions()
                subscriptions = resp.get('EventSubscriptionsList', [])
                
                # Check for active subscriptions
                activeSubscriptions = [s for s in subscriptions if s.get('Enabled', False)]
                hasSubscriptions = len(activeSubscriptions) > 0
                Config.set(cacheKey, hasSubscriptions)
                
            except botocore.exceptions.ClientError as e:
                ecode = e.response['Error']['Code']
                emsg = e.response['Error']['Message']
                _warn("Unable to describe RDS event subscriptions: [{}] {}".format(ecode, emsg))
                return
        
        if not hasSubscriptions:
            self.results['EventSubscriptionNotConfigured'] = [-1, 'No event subscriptions configured']

    ## ---- WAFS2027 checks ----
    def _isClusterMemberInstance(self):
        # Aurora and Multi-AZ DB cluster members inherit log exports and the
        # cluster parameter group from the cluster; evaluate them once on the
        # cluster object instead of on every member instance.
        return self.isCluster == False and bool(self.db.get('DBClusterIdentifier'))

    def _hasAuditPluginOption(self):
        # MySQL/MariaDB audit log only exists when MARIADB_AUDIT_PLUGIN is
        # added to the instance's option group. Returns (found, errorCode);
        # errorCode is set (and found is None) when an option group cannot
        # be read.
        found = False
        for og in self.db.get('OptionGroupMemberships', []) or []:
            name = og.get('OptionGroupName')
            if not name:
                continue
            cacheKey = 'rds::optionGroupOptions::' + self.rdsClient.meta.region_name + '::' + name
            options = Config.get(cacheKey, None)
            if options is None:
                try:
                    resp = self.rdsClient.describe_option_groups(OptionGroupName=name)
                    options = []
                    for grp in resp.get('OptionGroupsList', []):
                        options += [o.get('OptionName') for o in grp.get('Options', [])]
                    Config.set(cacheKey, options)
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', 'ClientError')
                    _warn("Unable to describe option group {}: {}".format(name, code))
                    return None, code
            if 'MARIADB_AUDIT_PLUGIN' in options:
                found = True
        return found, None

    def _checkRdsLogExportsDisabled(self):
        if self._isClusterMemberInstance():
            return

        auditUnknown = None
        if self.engine in ('postgres', 'aurora-postgresql'):
            required = ['postgresql']
        elif self.engine == 'aurora-mysql':
            required = ['audit']
        elif self.engine in ('mysql', 'mariadb'):
            required = ['error']
            if self.isCluster == False:
                hasAudit, auditUnknown = self._hasAuditPluginOption()
                if hasAudit == True:
                    required.append('audit')
        elif self.engine == 'sqlserver':
            required = ['error']
        else:
            # Oracle ('audit') is not evaluated: Rds.engineDriver has no Oracle
            # driver, so Oracle instances never reach RdsCommon.
            return

        exported = self.db.get('EnabledCloudwatchLogsExports', []) or []
        missing = [t for t in required if t not in exported]
        if missing:
            self.results['rdsLogExportsDisabled'] = [-1, 'Not exported to CloudWatch Logs: {} (exported: {})'.format(
                ', '.join(missing), ', '.join(exported) if exported else 'none')]
        elif auditUnknown and 'audit' not in exported:
            # Option group unreadable: cannot tell whether an audit log export
            # is also required, so do not PASS.
            self.results['rdsLogExportsDisabled'] = [0, 'Unable to evaluate ({}) - option group unreadable; audit plugin status unknown'.format(auditUnknown)]
        else:
            self.results['rdsLogExportsDisabled'] = [1, 'Exported: ' + ', '.join(exported)]

    def _checkRdsSecureTransportNotRequired(self):
        # PostgreSQL / Aurora PostgreSQL / SQL Server rds.force_ssl is already
        # reported by MSSQLorPG__TransportEncrpytionDisabled (_checkSSLParams).
        if self.engine not in ('mysql', 'mariadb', 'aurora-mysql'):
            return
        if self._isClusterMemberInstance():
            return
        # Aurora MySQL sets require_secure_transport in the cluster parameter group.
        if self.engine == 'aurora-mysql' and self.isCluster == False:
            return

        val = self.dbParams.get('require_secure_transport', None)
        if val is None:
            ver = self._engineVersionTuple()
            if self.engine == 'mariadb' and ver is not None and ver < (10, 5):
                # Parameter only exists on RDS for MariaDB 10.5 and higher.
                self.results['rdsSecureTransportNotRequired'] = [0, 'require_secure_transport not supported on MariaDB ' + self.db.get('EngineVersion', '')]
                return
            if self.engine == 'mariadb' and ver is not None and ver >= (11, 8):
                # RDS for MariaDB 11.8+ defaults require_secure_transport to ON.
                self.results['rdsSecureTransportNotRequired'] = [1, 'require_secure_transport not set (engine default ON for MariaDB 11.8+)']
                return
            if self.engine == 'mariadb' and ver is None:
                self.results['rdsSecureTransportNotRequired'] = [0, 'Unable to evaluate (engine version unknown; default depends on MariaDB version)']
                return
            # Engine default is OFF for RDS MySQL, Aurora MySQL and MariaDB 10.5 - 11.4.
            self.results['rdsSecureTransportNotRequired'] = [-1, 'require_secure_transport not set (engine default OFF)']
            return

        if str(val).strip().lower() in ('1', 'on', 'true'):
            self.results['rdsSecureTransportNotRequired'] = [1, 'require_secure_transport=' + str(val)]
        else:
            self.results['rdsSecureTransportNotRequired'] = [-1, 'require_secure_transport=' + str(val)]

    def _engineVersionTuple(self):
        # '10.11.6' -> (10, 11); None when unparsable / missing.
        try:
            parts = str(self.db.get('EngineVersion', '')).split('.')
            return (int(parts[0]), int(parts[1]))
        except (ValueError, IndexError):
            return None

    def _checkAuroraNoGlobalDatabase(self):
        if self.isCluster == False or self.engine not in ('aurora-mysql', 'aurora-postgresql'):
            return
        if self.db.get('EngineMode', 'provisioned') not in ('provisioned', None):
            # Aurora Serverless v1 / parallel query modes cannot join a global database.
            return

        if self.db.get('GlobalClusterIdentifier'):
            self.results['auroraNoGlobalDatabase'] = [1, 'Member of global database ' + self.db['GlobalClusterIdentifier']]
            return

        cacheKey = 'rds::GlobalClusterMemberArns::' + self.rdsClient.meta.region_name
        memberArns = Config.get(cacheKey, None)
        if memberArns is None:
            try:
                memberArns = []
                paginator = self.rdsClient.get_paginator('describe_global_clusters')
                for page in paginator.paginate():
                    for gc in page.get('GlobalClusters', []):
                        memberArns += [m.get('DBClusterArn') for m in gc.get('GlobalClusterMembers', [])]
                Config.set(cacheKey, memberArns)
            except botocore.exceptions.ClientError as e:
                self.results['auroraNoGlobalDatabase'] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
                return

        if self.db.get('DBClusterArn') in memberArns:
            self.results['auroraNoGlobalDatabase'] = [1, 'Member of a global database']
        else:
            self.results['auroraNoGlobalDatabase'] = [-1, 'Not part of an Aurora global database']

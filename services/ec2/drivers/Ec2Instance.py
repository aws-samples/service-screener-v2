import boto3
import botocore
import datetime
import re
import time
from utils.Config import Config
from services.ec2.acctCache import acctKey

from datetime import timedelta
from utils.Tools import aws_parseInstanceFamily, _warn
from services.Evaluator import Evaluator
from services.ec2.drivers.Ec2UserDataScan import decodeUserData, findSecrets
from services.ec2.drivers.Ec2NetworkInterface import getSubnetRouting, evaluatePlacement
from services.ec2.drivers.Ec2EbsVolume import volumeSnapshots

import constants as _C

import json

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

        # print(json.dumps(self.ec2InstanceData, indent=4, cls=DateTimeEncoder))


class Ec2Instance(Evaluator):
    def __init__(self, ec2InstanceData,ec2Client, cwClient):
        super().__init__()
        self.ec2Client = ec2Client
        self.cwClient = cwClient
        self.ec2InstanceData = ec2InstanceData
        self.setTimeDeltaInDays()

        self._resourceName = ec2InstanceData['InstanceId']

        self.init()
        
        self.getImageInfo()
    
        self.addII('platform', ec2InstanceData['Platform'] if 'Platform' in ec2InstanceData else 'linux')
        self.addII('instanceType', ec2InstanceData['InstanceType'])
    
    # supporting functions
    def getCPUUtil(self):
        return self.ec2Util
    
    def getEC2UtilizationMetrics(self, metricName, verifyDay, statistics=['Average']):
        """Daily datapoints of one AWS/EC2 metric over verifyDay days. Memoized per
        instance: e.g. CPUUtilization/Average/14d is used by both the low- and the
        high-utilization check."""
        cwClient = self.cwClient
        instance = self.ec2InstanceData
        
        dimensions = [
            {
                'Name': 'InstanceId',
                'Value': instance['InstanceId']
            },
        ]
        
        def fetch():
            return cwClient.get_metric_statistics(
                Dimensions=dimensions,
                Namespace='AWS/EC2',
                MetricName=metricName,
                StartTime=datetime.datetime.utcnow() - timedelta(days=verifyDay),
                EndTime=datetime.datetime.utcnow(),
                Period=24 * 60 * 60,
                Statistics=statistics,
            )
        
        return self._memo(('get_metric_statistics', metricName, verifyDay, tuple(statistics)), fetch)
    
    def checkMetricsLowUsage(self, metricName, verifyDay, thresholdDay, thresholdValue):
        result = self.getEC2UtilizationMetrics(metricName, verifyDay)
        cnt = 0
        if len(result['Datapoints']) < verifyDay:
            ## Handling if EC2 is stopped
            cnt = verifyDay - len(result['Datapoints'])
        for datapoint in result['Datapoints']:
            if datapoint['Average'] < thresholdValue:
                cnt += 1
        if cnt < thresholdDay:
            return False
        else:
            return True
        
    def checkMetricsHighUsage(self, metricName, verifyDay, thresholdDay, thresholdValue):
        result = self.getEC2UtilizationMetrics(metricName, verifyDay)
        
        if len(result['Datapoints']) < verifyDay:
            return False
        
        cnt = 0
        for datapoint in result['Datapoints']:
            if datapoint['Average'] > thresholdValue:
                cnt += 1
        
        if cnt < thresholdDay:
            return False
        else:
            return True

    def checkMetricsSpikyUsage(self, metricName, verifyDay, thresholdDay, maxThresholdValue, avgThresholdValue, statistics):
        result = self.getEC2UtilizationMetrics(metricName, verifyDay, statistics)
        
        if len(result['Datapoints']) < verifyDay:
            return False
        
        cnt = 0
        for datapoint in result['Datapoints']:
            if (datapoint['Average'] < avgThresholdValue) and (datapoint['Maximum'] > maxThresholdValue):
                cnt += 1
        
        if cnt < thresholdDay:
            return False
        else:
            return True
    
    def setTimeDeltaInDays(self):
        launchTimeData = self.ec2InstanceData['LaunchTime']
        
        timeDelta = datetime.datetime.now().timestamp() - launchTimeData.timestamp()
        launchDay = int(timeDelta / (60*60*24))
        
        self.launchTimeDeltaInDays = launchDay
        
    # describe_images error codes meaning "this AMI no longer exists / is not visible"
    IMAGE_NOT_FOUND_CODES = ('InvalidAMIID.NotFound', 'InvalidAMIID.Unavailable')

    def getImageInfo(self):
        """Source AMI of the instance (cached per image).
        self.ec2ImageInfo   - the image dict, or None
        self.ec2ImageStatus - 'found' | 'missing' (deregistered / no longer shared) | 'error:<code>'
        Deprecated and disabled AMIs are included so they can be reported."""
        imageId = self.ec2InstanceData['ImageId']
        cacheKey = acctKey('ec2::image::' + imageId)
        statusKey = acctKey('ec2::imagestatus::' + imageId)
        cached = Config.get(cacheKey, "__unset__")
        if cached != "__unset__":
            self.ec2ImageInfo = cached
            self.ec2ImageStatus = Config.get(statusKey, 'found' if cached else 'missing')
            return

        self.ec2ImageInfo = None
        try:
            resp = self.ec2Client.describe_images(ImageIds=[imageId], IncludeDeprecated=True, IncludeDisabled=True)
            for image in resp.get('Images', []):
                self.ec2ImageInfo = image
            self.ec2ImageStatus = 'found' if self.ec2ImageInfo else 'missing'
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'ClientError')
            self.ec2ImageStatus = 'missing' if code in self.IMAGE_NOT_FOUND_CODES else 'error:' + code

        Config.set(cacheKey, self.ec2ImageInfo)
        Config.set(statusKey, self.ec2ImageStatus)

    def _getInstanceTypeInfo(self, instanceTypeStr):
        """Cached describe_instance_types lookup - shared across every instance
        of the same type, and across this instance's own multiple checks that
        query its own type. Returns the InstanceTypes[0] dict, None if the API
        returned no match, or 'INVALID' if the type doesn't exist (mirrors the
        InvalidInstanceType ClientError callers use as a signal, not an error).
        Any other exception propagates uncaught - callers keep their own
        try/except around calls to this method.
        """
        # _memo guards the concurrent checks of this instance that ask for the
        # same type (EBS-optimized / instance store) - without it both could
        # miss the Config cache and call the API.
        return self._memo(('describe_instance_types', instanceTypeStr),
                          lambda: self._fetchInstanceTypeInfo(instanceTypeStr))

    def _fetchInstanceTypeInfo(self, instanceTypeStr):
        cacheKey = acctKey('ec2::instancetype::' + instanceTypeStr)
        cached = Config.get(cacheKey, "__unset__")
        if cached != "__unset__":
            return cached

        try:
            resp = self.ec2Client.describe_instance_types(InstanceTypes=[instanceTypeStr])
            types = resp.get('InstanceTypes', [])
            result = types[0] if types else None
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceType':
                result = 'INVALID'
            else:
                raise

        Config.set(cacheKey, result)
        return result
    
    # checks
    def _checkSQLServerEdition(self):
        EolVersion = Config.get('SQLEolVersion', 2012)

        if self.ec2ImageInfo == None:
            return 
            
        image = self.ec2ImageInfo
        
        if 'PlatformDetails' in image and image['PlatformDetails'].find('SQL Server') > 0:
            pos = image['Name'].find('SQL')
            if pos > 0:
                sqlVers = image['Name'][pos+4:pos+8]
                self.addII('SQLServer', sqlVers)
                if EolVersion >= sqlVers:
                    self.results['SQLServerEOL'] = [-1, image['Name']]
    
    def _checkWindowsServerEdition(self):
        if self.ec2ImageInfo == None:
            return
        
        image = self.ec2ImageInfo
        
        if 'Platform' in image and not image['Platform'] == 'windows':
            return
        
        if 'Name' in image and 'Windows_Server' in image['Name']:
            nameInfo = image['Name'].split('-')
            if len(nameInfo) <= 2:
                ## Unable to detect OS version from name, skip
                return
            
            if len(nameInfo[1]) == 4:
                EolVersion = Config.get('WindowsEolVersion', 2012)
                
                if not nameInfo[1] in EolVersion:
                    _warn("Windows Edition not found in EOL Lookup: {}".format(nameInfo[1]))
                else:
                    eolInfo = EolVersion[nameInfo[1]]
                    if eolInfo['isOutdate']:
                        self.results['WindowsOSOutdated'] = [-1, nameInfo[1]]
                    elif eolInfo['isLatest'] == False:
                        self.results['WindowsOSNotLatest'] = [-1, nameInfo[1]]
                    else:
                        return
        
    def _checkInstanceTypeGeneration(self):
        instanceArr = aws_parseInstanceFamily(self.ec2InstanceData['InstanceType'], region=self.ec2Client.meta.region_name)
        instancePrefixArr = instanceArr['prefixDetail']
        
        instancePrefixArr['version'] = int(instancePrefixArr['version'])+1
        size = instanceArr['suffix']
        newFamily = instancePrefixArr['family'] + str(instancePrefixArr['version']) + instancePrefixArr['attributes']
       
        result = self._getInstanceTypeInfo(newFamily + '.' + size)

        if result == 'INVALID':
            self.results['EC2NewGen'] = [1, self.ec2InstanceData['InstanceType']]
            return

        self.results['EC2NewGen'] = [-1, self.ec2InstanceData['InstanceType']]
        return
        
    def _checkDetailedMonitoringEnabled(self):

        if self.ec2InstanceData['Monitoring']['State'] == 'disabled':
            self.results['EC2DetailedMonitor'] = [-1, 'Disabled']
        else:
            self.results['EC2DetailedMonitor'] = [1, 'Enabled']
        
        return
        
    def _checkIamProfileAssociated(self):
        if "IamInstanceProfile" not in self.ec2InstanceData:
            self.results['EC2IamProfile'] = [-1, '']
        return
    
    def _checkCWMemoryMetrics(self):
        cw_client = self.cwClient
        instance = self.ec2InstanceData
    
        dimensions = [
            {
                'Name': 'InstanceId',
                'Value': instance['InstanceId']
            }
        ]
    
        result = cw_client.list_metrics(
            MetricName='mem_used_percent',
            Namespace='CWAgent',
            Dimensions=dimensions
        )
    
        if result['Metrics']:
            return
    
        result = cw_client.list_metrics(
            MetricName='Memory % Committed Bytes In Use',
            Namespace='CWAgent',
            Dimensions=dimensions
        )
    
        if result['Metrics']:
            return
    
        self.results['EC2MemoryMonitor'] = [-1, 'Disabled']
        return
        
    def _checkCWDiskMetrics(self):
        cwClient = self.cwClient
        instance = self.ec2InstanceData
        
        dimensions = [
            {
                'Name': 'InstanceId',
                'Value': instance['InstanceId']
            }
        ]
        
        result = cwClient.list_metrics(
            MetricName='disk_used_percent',
            Namespace='CWAgent',
            Dimensions=dimensions
        )
        
        if result['Metrics']:
            return
        
        result = cwClient.list_metrics(
            MetricName='LogicalDisk % Free Space',
            Namespace='CWAgent',
            Dimensions=dimensions
        )
        
        if result['Metrics']:
            return
        
        self.results['EC2DiskMonitor'] = [-1, 'Disabled']
        return
        
    # def _checkEC2Active(self):
    #     verifyDay = 7
    
    #     cwClient = self.cwClient
    #     instance = self.ec2InstanceData
    #     launchDay = self.launchTimeDeltaInDays
        
    #     if launchDay < verifyDay:
    #         return
    
    #     dimensions = [
    #         {
    #             'Name': 'InstanceId',
    #             'Value': instance['InstanceId']
    #         }
    #     ]
    
    #     results = cwClient.get_metric_statistics(
    #         Dimensions=dimensions,
    #         Namespace='AWS/EC2',
    #         MetricName='CPUUtilization',
    #         StartTime=datetime.datetime.utcnow() - datetime.timedelta(days=verifyDay),
    #         EndTime=datetime.datetime.utcnow(),
    #         Period=verifyDay * 24 * 60 * 60,
    #         Statistics=['Average']
    #     )
    
    #     if not results['Datapoints']:
    #         results['Datapoints'] = [{'Average': 0.0}]
    #     if results['Datapoints'][0]['Average'] < 5.0:
    #         self.results['EC2Active'] = [-1, 'Inactive']
        
    #     return
        
    def _checkSecurityGroupsAttached(self):
        instance = self.ec2InstanceData
    
        if len(instance['SecurityGroups']) > 50:
            self.results['EC2SGNumber'] = [-1, len(instance['SecurityGroups'])]
    
    def _checkEC2LowUtilization(self):
        instance = self.ec2InstanceData
        launchDay = self.launchTimeDeltaInDays
    
        verifyDay = 14
        thresholdDay = 4
        
        if launchDay < verifyDay:
            return
        
        cpuThresholdPercent = 10
        cpuLowUsage = self.checkMetricsLowUsage('CPUUtilization', verifyDay, thresholdDay, cpuThresholdPercent)
        
        if not cpuLowUsage:
            return
        
        networkThresholdByte = 5 * 1024 * 1024
        networkOutLowUsage = self.checkMetricsLowUsage('NetworkOut', verifyDay, thresholdDay, networkThresholdByte)
        
        if not networkOutLowUsage:
            return
        
        networkInLowUsage = self.checkMetricsLowUsage('NetworkIn', verifyDay, thresholdDay, networkThresholdByte)
        
        if not networkInLowUsage:
            return
        
        self.results['EC2LowUtilization'] = [-1, '']
        self.setChartData("EC2 Instance Utilization", 'Over Provisioned', 1)
        return


    def _checkEC2HighUtilization(self):
        instance = self.ec2InstanceData
        launchDay = self.launchTimeDeltaInDays
    
        verifyDay = 14
        thresholdDay = 4
        
        if launchDay < verifyDay:
            return
        
        cpuThresholdPercent = 90
        cpuHighUsage = self.checkMetricsHighUsage('CPUUtilization', verifyDay, thresholdDay, cpuThresholdPercent)
        if not cpuHighUsage:
            return
    
        self.results['EC2HighUtilization'] = [-1, '']
        self.setChartData("EC2 Instance Utilization", 'Under Provisioned', 1)
        return
    
    def _checkEC2SpikyUtilization(self):
        instance = self.ec2InstanceData
        launchDay = self.launchTimeDeltaInDays

        verifyDay = 14
        thresholdDay = 4

        if launchDay < verifyDay:
            return

        cpuMaxThresholdPercent = 90
        cpuAvgThresholdPercent = 30
        cpuSpikyUsage = self.checkMetricsSpikyUsage('CPUUtilization', verifyDay, thresholdDay, cpuMaxThresholdPercent, cpuAvgThresholdPercent,  statistics=['Average', 'Maximum'])
        if not cpuSpikyUsage:
            return

        self.results['EC2SpikyUtilization'] = [-1, '']
        self.setChartData("EC2 Instance Utilization", 'Spiky', 1)
        return
    
    def _checkEC2PublicIP(self):
        instance = self.ec2InstanceData
        
        if instance.get('PublicIpAddress') is None:
            return
        
        self.results['EC2InstancePublicIP'] = [-1, instance.get('PublicIpAddress')]
        
        try:
            addrResp = self.ec2Client.describe_addresses(
                PublicIps=[instance.get('PublicIpAddress')]
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAddress.NotFound':
                self.results['EC2InstanceAutoPublicIP'] = [-1, instance.get('PublicIpAddress')]
            else:
                raise(e)
        
        return
    
    def _checkEC2SubnetAutoPublicIP(self):
        instance = self.ec2InstanceData
        subnetId = instance.get('SubnetId')

        cacheKey = acctKey('ec2::subnet::' + str(subnetId))
        subnets = Config.get(cacheKey, "__unset__")
        if subnets == "__unset__":
            results = self.ec2Client.describe_subnets(
                SubnetIds = [subnetId]
            )
            subnets = results.get('Subnets')
            Config.set(cacheKey, subnets)

        for subnet in subnets:
            if subnet.get('MapPublicIpOnLaunch'):
                self.results['EC2SubnetAutoPublicIP'] = [-1, subnet.get('SubnetId')]

        return
    
    def _checkEC2HasTag(self):
        if self.ec2InstanceData.get('Tags') is None:
            self.results['EC2HasTag'] = [-1, '']
        return

    def _checkIMDSv2(self):
        """Check if instance enforces IMDSv2 (HttpTokens = required)"""
        instance = self.ec2InstanceData
        metadataOptions = instance.get('MetadataOptions', {})
        httpTokens = metadataOptions.get('HttpTokens', 'optional')
        
        if httpTokens != 'required':
            self.results['EC2IMDSv2'] = [-1, 'Not enforced']
        return

    def _checkStoppedTooLong(self):
        """Flag instances stopped for more than 30 days (still incurring EBS cost)"""
        instance = self.ec2InstanceData
        if instance['State']['Name'] != 'stopped':
            return
        
        reason = instance.get('StateTransitionReason', '')
        # Format: "User initiated (2024-01-15 10:30:00 GMT)"
        if '(' in reason and ')' in reason:
            match = re.search(r'\((\d{4}-\d{2}-\d{2})', reason)
            if match:
                stopped_date = datetime.datetime.strptime(match.group(1), '%Y-%m-%d').date()
                days_stopped = (datetime.date.today() - stopped_date).days
                if days_stopped > 30:
                    self.results['EC2StoppedTooLong'] = [-1, f'{days_stopped} days']
        return

    def _checkTerminationProtection(self):
        """Check if instance has termination protection enabled.

        Stopped instances are intentionally included: they can be critical
        (e.g. reserved for DR failover) and still benefit from deletion
        protection. Only terminated/shutting-down instances are skipped.

        This uses describe_instance_attribute, which has no batch form and
        is therefore called once per instance. The shared boto client is
        configured with standard retry mode (max_attempts=5), so transient
        throttling is retried automatically by botocore. If throttling still
        surfaces after retries, the check is skipped (with a warning) rather
        than emitting a misleading result.
        """
        instance = self.ec2InstanceData
        
        # Skip terminated/shutting-down instances (nothing left to protect)
        if instance['State']['Name'] in ('terminated', 'shutting-down'):
            return
        
        try:
            resp = self.ec2Client.describe_instance_attribute(
                InstanceId=instance['InstanceId'],
                Attribute='disableApiTermination'
            )
            protected = resp.get('DisableApiTermination', {}).get('Value', False)
            if not protected:
                self.results['EC2NoTerminationProtection'] = [-1, 'Disabled']
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code in ('RequestLimitExceeded', 'Throttling', 'ThrottlingException'):
                _warn("Throttled while checking termination protection for {}; skipping.".format(instance['InstanceId']), forcePrint=False)
            # Other client errors (e.g. permission) are skipped silently to
            # avoid emitting a false 'Disabled' result.
            return
        except Exception:
            return
        return

    def checkInstanceTypeAvailable(self, instanceType):
        region = self.ec2Client.meta.region_name
        cacheKey = acctKey('ec2::instancetypeoffering::' + region + '::' + instanceType)
        available = Config.get(cacheKey, None)

        if available is None:
            resp = self.ec2Client.describe_instance_type_offerings(
                LocationType='region',
                Filters=[
                    {
                        'Name': 'instance-type',
                        'Values': [
                            instanceType,
                        ]
                    },
                    {
                        'Name': 'location',
                        'Values': [
                            region,
                        ]
                    }
                ]
            )
            available = len(resp['InstanceTypeOfferings']) > 0
            Config.set(cacheKey, available)

        if available:
            return True
    
    def _checkEC2AMD(self):
        osType = self.getII('platform')
        if osType == 'linux':
            return
        
        instanceArr = aws_parseInstanceFamily(self.ec2InstanceData['InstanceType'], region=self.ec2Client.meta.region_name)
        prefixDetail = instanceArr['prefixDetail']

        if 'a' not in prefixDetail['attributes']:
            amdInstanceType = prefixDetail['family'] + prefixDetail['version'] + 'a.' + instanceArr['suffix']
            nextVersion = str(int(prefixDetail['version']) + 1)
            nextVerInstanceType = prefixDetail['family'] + nextVersion + 'a.' + instanceArr['suffix']
            
            if self.checkInstanceTypeAvailable(amdInstanceType) or self.checkInstanceTypeAvailable(nextVerInstanceType):
                self.results['EC2AMD'] = [-1, self.ec2InstanceData['InstanceType']]
                
        return
    
    def _checkEC2Graviton(self):
        osType = self.getII('platform')
        if osType != 'linux':
            return
        
        instanceArr = aws_parseInstanceFamily(self.ec2InstanceData['InstanceType'], region=self.ec2Client.meta.region_name)
        prefixDetail = instanceArr['prefixDetail']

        if 'g' not in prefixDetail['attributes']:
            gInstanceType = prefixDetail['family'] + prefixDetail['version'] + 'g.' + instanceArr['suffix']
            nextVersion = str(int(prefixDetail['version']) + 1)
            nextVerInstanceType = prefixDetail['family'] + nextVersion + 'g.' + instanceArr['suffix']
            
            if self.checkInstanceTypeAvailable(gInstanceType) or self.checkInstanceTypeAvailable(nextVerInstanceType):
                self.results['EC2Graviton'] = [-1, self.ec2InstanceData['InstanceType']]
                
        return
    
    
    def _checkTags(self):    
        ## Prevent error when 'Tags' not found in the dict
        if 'Tags' not in self.ec2InstanceData:
            return
        
        tags = self.ec2InstanceData['Tags']
        
        keyTags = []
        for tag in tags:
            if tag['Key'].lower() in _C.EC2_TAGS_KEYWORDS and tag['Value'].lower() not in _C.EC2_TAG_VALUE_FALSE_KEYWORDS:
                keyTags.append(tag['Key'].lower())
                continue
                
            if tag['Value'].lower() in _C.EC2_TAGS_KEYWORDS:
                keyTags.append(tag['Value'].lower())
                continue

        if len(keyTags) > 0:
            self.addII('keyTags', keyTags)
            
        return
    

    def _checkEC2EbsOptimized(self):
        """Check if EBS optimization is available but not enabled"""
        instance = self.ec2InstanceData
        instanceType = instance['InstanceType']
        
        # Check if instance type supports EBS optimization
        try:
            instanceTypeInfo = self._getInstanceTypeInfo(instanceType)

            if not instanceTypeInfo or instanceTypeInfo == 'INVALID':
                return

            ebsInfo = instanceTypeInfo.get('EbsInfo', {})
            
            # Check if EBS optimization is supported
            ebsOptimizedSupport = ebsInfo.get('EbsOptimizedSupport')
            
            if ebsOptimizedSupport == 'unsupported':
                # Instance type doesn't support EBS optimization
                return
            
            # Check if EBS optimization is enabled on the instance
            ebsOptimized = instance.get('EbsOptimized', False)
            
            if not ebsOptimized:
                # EBS optimization is supported but not enabled
                self.results['EC2EbsOptimized'] = [-1, instanceType]
        
        except Exception as e:
            # If we can't determine, skip the check
            return
    
    def _checkEC2RootVolumeImplications(self):
        """Check root volume backup strategy"""
        instance = self.ec2InstanceData
        
        # Get root device name
        rootDeviceName = instance.get('RootDeviceName')
        if not rootDeviceName:
            return
        
        # Find root volume in block device mappings
        blockDeviceMappings = instance.get('BlockDeviceMappings', [])
        rootVolume = None
        
        for mapping in blockDeviceMappings:
            if mapping.get('DeviceName') == rootDeviceName:
                rootVolume = mapping
                break
        
        if not rootVolume or 'Ebs' not in rootVolume:
            return
        
        # Check if DeleteOnTermination is enabled
        deleteOnTermination = rootVolume['Ebs'].get('DeleteOnTermination', True)
        
        if not deleteOnTermination:
            # Root volume persists after termination, no issue
            return
        
        # Root volume will be deleted on termination, check for recent snapshots
        volumeId = rootVolume['Ebs'].get('VolumeId')
        if not volumeId:
            return
        
        try:
            # Check for snapshots of this volume
            snapshotResp = volumeSnapshots(self, self.ec2Client, volumeId)
            
            snapshots = snapshotResp.get('Snapshots', [])
            
            if not snapshots:
                # No snapshots exist for root volume with DeleteOnTermination=True
                self.results['EC2RootVolumeImplications'] = [-1, volumeId]
                return
            
            # Check if most recent snapshot is within 7 days
            latestSnapshot = max(snapshots, key=lambda x: x['StartTime'])
            timeDelta = datetime.datetime.now(datetime.timezone.utc) - latestSnapshot['StartTime']
            daysSinceSnapshot = timeDelta.days
            
            if daysSinceSnapshot > 7:
                # Latest snapshot is outdated
                self.results['EC2RootVolumeImplications'] = [-1, volumeId]
        
        except Exception as e:
            # If we can't check snapshots, skip
            return
    def _checkSeparateOSDataVolumes(self):
        """Check if instance has separate OS and data volumes"""
        instance = self.ec2InstanceData
        blockDeviceMappings = instance.get('BlockDeviceMappings', [])

        # Only flag if instance has exactly 1 block device (root only) or none
        if len(blockDeviceMappings) <= 1:
            self.results['EC2SeparateOSDataVolumes'] = [-1, f"{len(blockDeviceMappings)} volume(s)"]
        return

    def _checkInstanceStoreUsage(self):
        """Check if instance type has instance store and validate usage"""
        instance = self.ec2InstanceData
        instanceType = instance.get('InstanceType', '')

        try:
            instanceTypeInfo = self._getInstanceTypeInfo(instanceType)

            if not instanceTypeInfo or instanceTypeInfo == 'INVALID':
                return

            instanceStorageInfo = instanceTypeInfo.get('InstanceStorageInfo')

            if not instanceStorageInfo:
                # Instance type doesn't support instance store, nothing to check
                return

            # Instance type supports instance store - check if ephemeral mappings exist
            blockDeviceMappings = instance.get('BlockDeviceMappings', [])
            hasEphemeral = False
            for mapping in blockDeviceMappings:
                if 'Ebs' not in mapping:
                    # Non-EBS mapping = ephemeral/instance store
                    hasEphemeral = True
                    break

            if not hasEphemeral:
                totalSizeGb = instanceStorageInfo.get('TotalSizeInGB', 0)
                self.results['EC2InstanceStoreUsage'] = [-1, f"{totalSizeGb}GB available"]

        except Exception:
            return

    # ------------------------------------------------------------------ #
    # WAFS2027
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parseTime(value):
        if isinstance(value, datetime.datetime):
            dt = value
        else:
            try:
                dt = datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            except ValueError:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    def _checkEc2AmiUntrustedOrStale(self):
        """Running instance launched from an AMI that is deregistered (or no longer
        shared), deprecated, disabled, or a public AMI from an owner that is neither
        this account nor Amazon / AWS Marketplace / a verified provider (no ImageOwnerAlias)."""
        key = 'ec2AmiUntrustedOrStale'
        instance = self.ec2InstanceData
        if (instance.get('State') or {}).get('Name') != 'running':
            return
        imageId = instance.get('ImageId')
        status = getattr(self, 'ec2ImageStatus', 'found' if self.ec2ImageInfo else 'missing')

        if status.startswith('error:'):
            self.results[key] = [0, f"Unable to evaluate ({status[6:]})"]
            return
        if status == 'missing' or not self.ec2ImageInfo:
            self.results[key] = [-1, f"{imageId}: AMI no longer available (deregistered or no longer shared with this account)"]
            return

        image = self.ec2ImageInfo
        issues = []
        state = image.get('State')
        if state in ('deregistered', 'disabled'):
            issues.append(f"AMI {state}")

        depTime = self._parseTime(image.get('DeprecationTime')) if image.get('DeprecationTime') else None
        if depTime and depTime <= datetime.datetime.now(datetime.timezone.utc):
            issues.append(f"AMI deprecated since {depTime.strftime('%Y-%m-%d')}")

        selfAccount = (Config.get('stsInfo', {}) or {}).get('Account')
        owner = image.get('OwnerId')
        if image.get('Public') is True and owner and owner != selfAccount and not image.get('ImageOwnerAlias'):
            issues.append(f"public AMI from unverified third-party owner {owner}")

        if issues:
            self.results[key] = [-1, f"{imageId}: " + '; '.join(issues)]
        else:
            self.results[key] = [1, f"{imageId}: available"]

    def _checkEc2UserDataSecrets(self):
        """Instance user data (readable by anyone with ec2:DescribeInstanceAttribute
        and from inside the instance via IMDS) must not embed credentials.
        Only the pattern names are reported, never the values."""
        key = 'ec2UserDataSecrets'
        instance = self.ec2InstanceData
        if (instance.get('State') or {}).get('Name') in ('terminated', 'shutting-down'):
            return
        try:
            resp = self.ec2Client.describe_instance_attribute(InstanceId=instance['InstanceId'], Attribute='userData')
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response.get('Error', {}).get('Code', 'ClientError')})"]
            return

        value = (resp.get('UserData') or {}).get('Value')
        if not value:
            self.results[key] = [1, 'No user data']
            return
        found = findSecrets(decodeUserData(value))
        if found:
            self.results[key] = [-1, 'User data contains: ' + ', '.join(found) + ' (values masked)']
        else:
            self.results[key] = [1, 'No credential patterns in user data']

    def _checkEc2InstanceInPublicSubnet(self):
        """Instance network interfaces in a subnet whose effective route table sends
        0.0.0.0/0 or ::/0 to an internet gateway. Whether the instance should be
        internet-facing is design intent, so this is advisory."""
        key = 'ec2InstanceInPublicSubnet'
        instance = self.ec2InstanceData
        if (instance.get('State') or {}).get('Name') in ('terminated', 'shutting-down'):
            return
        enis = instance.get('NetworkInterfaces', []) or []
        subnetIds = {eni.get('SubnetId') for eni in enis} | {instance.get('SubnetId')}
        subnetIds.discard(None)
        if not subnetIds:
            return

        status, msg = evaluatePlacement(subnetIds, getSubnetRouting(self.ec2Client))
        if status == -1:
            publicIps = [instance.get('PublicIpAddress')] + [(eni.get('Association') or {}).get('PublicIp') for eni in enis]
            publicIps = sorted({ip for ip in publicIps if ip})
            hasIpv6 = any(eni.get('Ipv6Addresses') for eni in enis)
            exposure = ', '.join(publicIps) if publicIps else 'none'
            msg += f"; public IPv4: {exposure}{'; IPv6 assigned' if hasIpv6 else ''}"
        self.results[key] = [status, msg]

    def _checkEc2AutoRecoveryDisabled(self):
        """Simplified automatic recovery restores the instance after a system status
        check failure. It is on by default ('default'); flag only an explicit opt-out."""
        key = 'ec2AutoRecoveryDisabled'
        inst = self.ec2InstanceData
        if (inst.get('State') or {}).get('Name') not in ('running', 'stopped'):
            return
        mode = (inst.get('MaintenanceOptions') or {}).get('AutoRecovery')
        if mode == 'disabled':
            self.results[key] = [-1, 'AutoRecovery=disabled']
        elif mode == 'default':
            self.results[key] = [1, 'AutoRecovery=default']
        else:
            self.results[key] = [0, 'Unable to evaluate (MaintenanceOptions.AutoRecovery not returned)']

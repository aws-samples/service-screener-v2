import boto3
import botocore
import datetime
import time
from utils.Config import Config

from datetime import timedelta
from utils.Tools import aws_parseInstanceFamily, _warn
from services.Evaluator import Evaluator

class Ec2Instance(Evaluator):
    def __init__(self, ec2InstanceData,ec2Client, cwClient):
        super().__init__()
        self.ec2Client = ec2Client
        self.cwClient = cwClient
        self.ec2InstanceData = ec2InstanceData
        self.setTimeDeltaInDays()
        self.init()
        
        self.getImageInfo()
    
        self.addII('platform', ec2InstanceData['Platform'] if 'Platform' in ec2InstanceData else 'linux')
        self.addII('instanceType', ec2InstanceData['InstanceType'])
    
    # supporting functions
    
    def getEC2UtilizationMetrics(self, metricName, verifyDay):
        cwClient = self.cwClient
        instance = self.ec2InstanceData
        
        dimensions = [
            {
                'Name': 'InstanceId',
                'Value': instance['InstanceId']
            },
        ]
        
        results = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/EC2',
            MetricName=metricName,
            StartTime=datetime.datetime.utcnow() - timedelta(days=verifyDay),
            EndTime=datetime.datetime.utcnow(),
            Period=24 * 60 * 60,
            Statistics=['Average'],
        )
        
        return results
    
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
    
    def setTimeDeltaInDays(self):
        launchTimeData = self.ec2InstanceData['LaunchTime']
        
        timeDelta = datetime.datetime.now().timestamp() - launchTimeData.timestamp()
        launchDay = int(timeDelta / (60*60*24))
        
        self.launchTimeDeltaInDays = launchDay
        
    def getImageInfo(self):
        self.ecImageInfo = None
        imageId = self.ec2InstanceData['ImageId']
        resp = self.ec2Client.describe_images(ImageIds=[imageId])
        images = resp.get('Images')
        for image in images:
            self.ec2ImageInfo = image
    
    # checks
    def _checkSQLServerEdition(self):
        EolVersion = Config.get('SQLEolVersion', 2012)

        image = self.ec2ImageInfo
        if image == None:
            return
        
        if 'PlatformDetails' in image and image['PlatformDetails'].find('SQL Server') > 0:
            pos = image['Name'].find('SQL')
            if pos > 0:
                sqlVers = image['Name'][pos+4:pos+8]
                if EolVersion >= sqlVers:
                    self.results['SQLServerEOL'] = [-1, image['Name']]
    
    def _checkWindowsServerEdition(self):
        image = self.ec2ImageInfo
        if image == None:
            return
        
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
       
        try:
            results = self.ec2Client.describe_instance_types(
                InstanceTypes=[newFamily + '.' + size],
                MaxResults=1
            )
        except Exception as e:
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
        
    def _checkEC2Active(self):
        verifyDay = 7
    
        cwClient = self.cwClient
        instance = self.ec2InstanceData
        launchDay = self.launchTimeDeltaInDays
        
        if launchDay < verifyDay:
            return
    
        dimensions = [
            {
                'Name': 'InstanceId',
                'Value': instance['InstanceId']
            }
        ]
    
        results = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            StartTime=datetime.datetime.utcnow() - datetime.timedelta(days=verifyDay),
            EndTime=datetime.datetime.utcnow(),
            Period=verifyDay * 24 * 60 * 60,
            Statistics=['Average']
        )
    
        if not results['Datapoints']:
            results['Datapoints'] = [{'Average': 0.0}]
        if results['Datapoints'][0]['Average'] < 5.0:
            self.results['EC2Active'] = [-1, 'Inactive']
        
        return
        
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
        
        results = self.ec2Client.describe_subnets(
            SubnetIds = [instance.get('SubnetId')]
        )
        
        for subnet in results.get('Subnets'):
            if subnet.get('MapPublicIpOnLaunch'):
                self.results['EC2SubnetAutoPublicIP'] = [-1, subnet.get('SubnetId')]
        
        return
    
    def _checkEC2HasTag(self):
        if self.ec2InstanceData.get('Tags') is None:
            self.results['EC2HasTag'] = [-1, '']
        return

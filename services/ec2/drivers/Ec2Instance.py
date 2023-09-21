import boto3
import botocore
import datetime

from datetime import timedelta
from utils.Tools import aws_parseInstanceFamily
from services.Evaluator import Evaluator

class Ec2Instance(Evaluator):
    def __init__(self, ec2InstanceData,ec2Client):
        super().__init__()
        self.ec2Client = ec2Client
        self.ec2InstanceData = ec2InstanceData
        self.setTimeDeltaInDays()
        self.init()
    
    # supporting functions
    
    def getEC2UtilizationMetrics(self, metricName, verifyDay):
        cwClient = boto3.client('cloudwatch')
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
    
    # checks
    
    def _checkInstanceTypeGeneration(self):
        
        instanceArr = aws_parseInstanceFamily(self.ec2InstanceData['InstanceType'])
        instancePrefixArr = instanceArr['prefixDetail']
        
        instancePrefixArr['version'] = int(instancePrefixArr['version'])+1
        size = instanceArr['suffix']
        newFamily = instancePrefixArr['family'] + str(instancePrefixArr['version']) + instancePrefixArr['attributes']
       
        try:
            results = self.ec2Client.describe_instance_types(
                InstanceTypes=[newFamily + '.' + size]
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
        cw_client = boto3.client('cloudwatch')
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
        cwClient = boto3.client('cloudwatch')
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
    
        cwClient = boto3.client('cloudwatch')
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
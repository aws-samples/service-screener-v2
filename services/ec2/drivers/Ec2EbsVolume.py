import boto3
import botocore
import datetime

from utils.Config import Config
from services.Service import Service

from services.Evaluator import Evaluator

class Ec2EbsVolume(Evaluator):
    OLDGENBLOCK = ('gp2', 'io1')
    
    def __init__(self, ebsVolumeData,ec2Client,cwClient):
        super().__init__()
        self.ec2Client = ec2Client
        self.ebsVolumeData = ebsVolumeData
        self.cwClient = cwClient
        self.setCreateTimeDeltaInDays()
        self.init()
        
    # helper functions
    def setCreateTimeDeltaInDays(self):
        launchTimeData = self.ebsVolumeData['CreateTime']
        
        timeDelta = datetime.datetime.now().timestamp() - launchTimeData.timestamp()
        launchDay = int(timeDelta / (60*60*24))
        
        self.launchTimeDeltaInDays = launchDay
    
    #check functions
    def _checkEBSIops(self):
        volume_id = self.ebsVolumeData['VolumeId']
        volume_type = self.ebsVolumeData['VolumeType']
        if volume_type not in ('io1', 'io2', 'gp3'): # gp2 is under new gen check hence ignore
            return
        provisioned_iops = self.ebsVolumeData['Iops']
        # print(f"Checking IOPS for volume: {volume_id} (Type: {volume_type}) with provisioned IOPS ({iops})")

        metrics = ['VolumeReadOps', 'VolumeWriteOps']
        total_iops = 0
        max_iops = 0

        check_days = 7 # number of days checked
        period = 60 * 60 # 1hr interval
        end_time = datetime.datetime.now(datetime.UTC)
        start_time = end_time - datetime.timedelta(days=check_days)

        for metric in metrics:
            response = self.cwClient.get_metric_statistics(
                Namespace='AWS/EBS',
                MetricName=metric,
                Dimensions=[
                    {'Name': 'VolumeId', 'Value': volume_id}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
                Statistics=['Sum']
            )

            # Sum up the IOPS from read and write operations
            for datapoint in response['Datapoints']:
                total_iops += datapoint['Sum']
                max_iops = max(max_iops, datapoint['Sum']/period)
        
        average_iops = total_iops / (check_days * 24 * 60 * 60)
        # print(f"Average IOPS for volume {volume_id}: {average_iops:.2f}")
        if average_iops > provisioned_iops * 0.9: # 90% threshold
            self.results['EBSHighUtilization'] = [-1, '']
            return
        
        if volume_type == 'gp3':
            if provisioned_iops > 3000: # baseline, can't further right size
                if max_iops < provisioned_iops * 0.5:
                    self.results['EBSRightSizing'] = [-1, '']
            return
        
        return



    def _checkEBSAttachedStoppedEC2(self):
        if not self.ebsVolumeData['Attachments']:
            return
        
        for attachment in self.ebsVolumeData['Attachments']:
            instance_id = attachment['InstanceId']
            
            instance_response = self.ec2Client.describe_instances(InstanceIds=[instance_id])
            instance_state = instance_response['Reservations'][0]['Instances'][0]['State']['Name']

            # all ec2 attached have to be in stopped/stopping state
            if instance_state not in ('stopped', 'stopping'):
                return

        self.results['EBSStoppedInstance'] = [-1, '']
        return

    def _checkEncryptedBlock(self):
        if self.ebsVolumeData['Encrypted']:
            self.results['EBSEncrypted'] = [1,self.ebsVolumeData['Encrypted']]
        else:
            self.results['EBSEncrypted'] = [-1,self.ebsVolumeData['Encrypted']]
        
        return
    
    
    def _checkNewGenBlock(self):
        if self.ebsVolumeData['VolumeType'] in self.OLDGENBLOCK:
            self.results['EBSNewGen'] = [-1,self.ebsVolumeData['VolumeType']]
        else:
            self.results['EBSNewGen'] = [1,self.ebsVolumeData['VolumeType']]
            
        return
    
    def _checkBlockInUse(self):
        if self.ebsVolumeData['State'] == 'in-use':
            self.results['EBSInUse'] = [1,self.ebsVolumeData['State']]
        else:
            self.results['EBSInUse'] = [-1,self.ebsVolumeData['State']]
            
        return
    
    def _checkSnapshot(self):
        filterData = [{
                'Name': 'volume-id',
                'Values': [self.ebsVolumeData['VolumeId']]
            }]
        
        snapshotData = self.ec2Client.describe_snapshots(
            Filters = filterData
        )
        
        if len(snapshotData['Snapshots']) > 0:
            # take latest snapshot to calculate how recently it was created
            snapshotStartTime = snapshotData['Snapshots'][0]['StartTime']
            timeDelta = datetime.datetime.now().timestamp() - snapshotStartTime.timestamp()
            launchDay = int(timeDelta / (60*60*24))
            
            if launchDay > 7:
                self.results['EBSUpToDateSnapshot'] = [-1,'']
            else:
                return
        else:
            self.results['EBSSnapshot'] = [-1,self.ebsVolumeData['SnapshotId']] 
        
        return
    
    def _checkFastSnapshot(self):
        result = self.ec2Client.describe_fast_snapshot_restores()
        
        if len(result) > 0:
            self.results['EBSSnapshot'] = [-1,''] 
        
        return
    
    def _checkLowEBSLowUtilization(self):
        cwClient = self.cwClient
        verifyDay = 7
        
        #if created within the last 7 days, ignore this check
        if self.launchTimeDeltaInDays < verifyDay:
            return
        
        
        dimensions = [
            {
                'Name': 'VolumeId',
                'Value': self.ebsVolumeData['VolumeId']
            }
        ]
        
        #check volume read ops
        readOpsResult = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/EBS',
            MetricName='VolumeReadOps',
            StartTime=datetime.datetime.utcnow() - datetime.timedelta(days=verifyDay),
            EndTime=datetime.datetime.utcnow(),
            Period=verifyDay * 24 * 60 * 60,
            Statistics=['Average']
        )
        
        cnt = 0
        readDatapoints = readOpsResult['Datapoints']
        if len(readDatapoints) < verifyDay:
            cnt = verifyDay - len(readDatapoints)
        
        for data in readDatapoints:
            if data['Average'] < 1:
                cnt += 1
        
        if cnt < verifyDay:
            return
        
        #check volume write ops
        writeOpsResult = cwClient.get_metric_statistics(
            Dimensions=dimensions,
            Namespace='AWS/EBS',
            MetricName='VolumeWriteOps',
            StartTime=datetime.datetime.utcnow() - datetime.timedelta(days=verifyDay),
            EndTime=datetime.datetime.utcnow(),
            Period=verifyDay * 24 * 60 * 60,
            Statistics=['Average']
        )
        
        writeDatapoints = writeOpsResult['Datapoints']
        if len(writeDatapoints) < verifyDay:
            cnt = verifyDay - len(writeDatapoints)
        
        for data in writeDatapoints:
            if data['Average'] < 1:
                cnt += 1
        
        if cnt < verifyDay:
            return
        
        #if read nor write exit due to decent utilization, then flag this
        self.results['EBSLowUtilization'] = [-1, '']
        return
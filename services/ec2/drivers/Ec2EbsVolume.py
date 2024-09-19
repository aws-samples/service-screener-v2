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
            self.hasFastSnapshot(snapshotData['Snapshots'])

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
    
    def hasFastSnapshot(self, snapshots):
        items = [snapshot['SnapshotId'] for snapshot in snapshots]

        filterData = [{
            'Name': 'snapshot-id',
            'Values': items
        }]
        
        result = self.ec2Client.describe_fast_snapshot_restores(
            Filters=filterData
        )

        fastSnapshots = result.get('FastSnapshotRestores')
        
        items = []
        if len(fastSnapshots) > 0:
            items = list(set(snapshot['SnapshotId'] for snapshot in fastSnapshots))
            self.results['EBSFastSnapshot'] = [-1, ('|').join(items)] 
        
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
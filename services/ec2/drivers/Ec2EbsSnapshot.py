import boto3
import botocore
import datetime

from utils.Config import Config
from services.Service import Service

from services.Evaluator import Evaluator

class Ec2EbsSnapshot(Evaluator):
    def __init__(self, ebsVolumeIds, ec2Client):
        super().__init__()
        self.ebsVolumeIds = ebsVolumeIds
        self.ec2Client = ec2Client
        self.init()

    def _checkSnapshotPublic(self):
        snapshotData = self.ec2Client.describe_snapshots(
            OwnerIds = ["self"],
            RestorableByUserIds = ["all"]
        )
        
        publicSnapshotList = []
        for snapshot in snapshotData['Snapshots']:
            publicSnapshotList.append(snapshot.get('SnapshotId'))
        
        if len(publicSnapshotList) > 0:
            self.results['EBSSnapshotIsPublic'] = [-1, ', '.join(publicSnapshotList)]
            
        return

    def _checkDeletedVolumeSnapshotList(self):
        snapshotData = self.ec2Client.describe_snapshots(
            OwnerIds = ["self"],
        )

        deletedVolumeSnapshotList = []
        for snapshot in snapshotData['Snapshots']:
            if snapshot['VolumeId'] not in self.ebsVolumeIds:
                deletedVolumeSnapshotList.append(snapshot['SnapshotId'])
        
        if len(deletedVolumeSnapshotList) > 0:
            self.results['EBSSnapshotDeletedVolume'] = [-1, ', '.join(deletedVolumeSnapshotList)]
            
        return
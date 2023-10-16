import boto3
import botocore
import datetime

from utils.Config import Config
from services.Service import Service

from services.Evaluator import Evaluator

class Ec2EbsSnapshot(Evaluator):
    def __init__(self, ec2Client):
        super().__init__()
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
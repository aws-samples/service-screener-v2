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

        self._resourceName = 'AllEC2Snapshots'

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

    def _checkEBSSnapshotFirstArchived(self):
        """Check if first snapshots in chains are archived"""
        try:
            # Get all snapshots owned by this account
            snapshotData = self.ec2Client.describe_snapshots(
                OwnerIds=["self"]
            )
            
            snapshots = snapshotData.get('Snapshots', [])
            if not snapshots:
                return
            
            # Build snapshot lineage - identify first snapshots (no parent)
            # First snapshots are those that are the base of incremental chains
            snapshotIds = [s['SnapshotId'] for s in snapshots]
            
            # Get tier status for all snapshots
            tierResp = self.ec2Client.describe_snapshot_tier_status(
                Filters=[
                    {
                        'Name': 'snapshot-id',
                        'Values': snapshotIds
                    }
                ]
            )
            
            # Create a map of snapshot tier status
            tierMap = {}
            for tier in tierResp.get('SnapshotTierStatuses', []):
                tierMap[tier['SnapshotId']] = tier.get('StorageTier', 'standard')
            
            # Group snapshots by volume to identify first snapshots
            volumeSnapshots = {}
            for snapshot in snapshots:
                volumeId = snapshot['VolumeId']
                if volumeId not in volumeSnapshots:
                    volumeSnapshots[volumeId] = []
                volumeSnapshots[volumeId].append(snapshot)
            
            archivedFirstSnapshots = []
            
            # For each volume, find the oldest snapshot (first in chain)
            for volumeId, volSnapshots in volumeSnapshots.items():
                if not volSnapshots:
                    continue
                
                # Sort by start time to find first snapshot
                sortedSnapshots = sorted(volSnapshots, key=lambda x: x['StartTime'])
                firstSnapshot = sortedSnapshots[0]
                snapshotId = firstSnapshot['SnapshotId']
                
                # Check if first snapshot is archived
                tier = tierMap.get(snapshotId, 'standard')
                if tier == 'archive':
                    archivedFirstSnapshots.append(snapshotId)
            
            if archivedFirstSnapshots:
                self.results['EBSSnapshotFirstArchived'] = [-1, ', '.join(archivedFirstSnapshots)]
        
        except Exception as e:
            # If API not available or error, skip check
            return
    
    def _checkEBSSnapshotLatestArchived(self):
        """Check if latest snapshots are archived"""
        try:
            # Get all snapshots owned by this account
            snapshotData = self.ec2Client.describe_snapshots(
                OwnerIds=["self"]
            )
            
            snapshots = snapshotData.get('Snapshots', [])
            if not snapshots:
                return
            
            snapshotIds = [s['SnapshotId'] for s in snapshots]
            
            # Get tier status for all snapshots
            tierResp = self.ec2Client.describe_snapshot_tier_status(
                Filters=[
                    {
                        'Name': 'snapshot-id',
                        'Values': snapshotIds
                    }
                ]
            )
            
            # Create a map of snapshot tier status
            tierMap = {}
            for tier in tierResp.get('SnapshotTierStatuses', []):
                tierMap[tier['SnapshotId']] = tier.get('StorageTier', 'standard')
            
            # Group snapshots by volume
            volumeSnapshots = {}
            for snapshot in snapshots:
                volumeId = snapshot['VolumeId']
                if volumeId not in volumeSnapshots:
                    volumeSnapshots[volumeId] = []
                volumeSnapshots[volumeId].append(snapshot)
            
            archivedLatestSnapshots = []
            
            # For each volume, find the most recent snapshot
            for volumeId, volSnapshots in volumeSnapshots.items():
                if not volSnapshots:
                    continue
                
                # Sort by start time to find latest snapshot
                sortedSnapshots = sorted(volSnapshots, key=lambda x: x['StartTime'], reverse=True)
                latestSnapshot = sortedSnapshots[0]
                snapshotId = latestSnapshot['SnapshotId']
                
                # Check if latest snapshot is archived
                tier = tierMap.get(snapshotId, 'standard')
                if tier == 'archive':
                    archivedLatestSnapshots.append(snapshotId)
            
            if archivedLatestSnapshots:
                self.results['EBSSnapshotLatestArchived'] = [-1, ', '.join(archivedLatestSnapshots)]
        
        except Exception as e:
            # If API not available or error, skip check
            return
    
    def _checkEBSSnapshotComplianceArchive(self):
        """Check if old compliance snapshots should be archived"""
        try:
            # Get all snapshots owned by this account
            snapshotData = self.ec2Client.describe_snapshots(
                OwnerIds=["self"]
            )
            
            snapshots = snapshotData.get('Snapshots', [])
            if not snapshots:
                return
            
            snapshotIds = [s['SnapshotId'] for s in snapshots]
            
            # Get tier status for all snapshots
            tierResp = self.ec2Client.describe_snapshot_tier_status(
                Filters=[
                    {
                        'Name': 'snapshot-id',
                        'Values': snapshotIds
                    }
                ]
            )
            
            # Create a map of snapshot tier status
            tierMap = {}
            for tier in tierResp.get('SnapshotTierStatuses', []):
                tierMap[tier['SnapshotId']] = tier.get('StorageTier', 'standard')
            
            # Identify compliance snapshots that are old and not archived
            complianceTagKeys = ['compliance', 'retention', 'regulatory', 'audit']
            oldThresholdDays = 90  # Snapshots older than 90 days
            
            unArchivedOldCompliance = []
            
            for snapshot in snapshots:
                snapshotId = snapshot['SnapshotId']
                tags = snapshot.get('Tags', [])
                
                # Check if snapshot has compliance-related tags
                isCompliance = False
                for tag in tags:
                    tagKey = tag.get('Key', '').lower()
                    tagValue = tag.get('Value', '').lower()
                    if any(keyword in tagKey or keyword in tagValue for keyword in complianceTagKeys):
                        isCompliance = True
                        break
                
                if not isCompliance:
                    continue
                
                # Check snapshot age
                startTime = snapshot['StartTime']
                age = datetime.datetime.now(datetime.timezone.utc) - startTime
                ageDays = age.days
                
                if ageDays < oldThresholdDays:
                    continue
                
                # Check if archived
                tier = tierMap.get(snapshotId, 'standard')
                if tier != 'archive':
                    unArchivedOldCompliance.append(snapshotId)
            
            if unArchivedOldCompliance:
                self.results['EBSSnapshotComplianceArchive'] = [-1, ', '.join(unArchivedOldCompliance)]
        
        except Exception as e:
            # If API not available or error, skip check
            return

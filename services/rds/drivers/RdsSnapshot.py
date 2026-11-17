import botocore

from services.Evaluator import Evaluator


class RdsSnapshot(Evaluator):
    """Checks one manual (or AWS Backup-managed) RDS DB snapshot or DB cluster snapshot.

    snapshot    : item from describe_db_snapshots / describe_db_cluster_snapshots
    isCluster   : True for a DB cluster snapshot
    accountId   : the scanned account (sharing to itself is not external)
    orgAccounts : set of account IDs in the AWS Organization, or None when the
                  list cannot be read (member account / no permission)
    publicCoveredInstances / publicCoveredClusters :
                  identifiers of the DB instances / Aurora clusters on which
                  RdsCommon._checkPublicSnapshot (SnapshotRDSIsPublic) ran in
                  this scan. A public (restore=all) snapshot of one of those
                  sources is already reported under SnapshotRDSIsPublic and is
                  not reported again here; public snapshots whose source no
                  longer exists (or is not evaluated, e.g. Multi-AZ DB
                  clusters, unsupported engines) are reported here.
    """
    def __init__(self, snapshot, isCluster, rdsClient, accountId, orgAccounts=None,
                 publicCoveredInstances=None, publicCoveredClusters=None):
        super().__init__()
        self.snapshot = snapshot
        self.isCluster = isCluster
        self.rdsClient = rdsClient
        self.accountId = accountId
        self.orgAccounts = orgAccounts
        self.publicCoveredInstances = publicCoveredInstances or set()
        self.publicCoveredClusters = publicCoveredClusters or set()

        if isCluster:
            self._resourceName = snapshot['DBClusterSnapshotIdentifier']
        else:
            self._resourceName = snapshot['DBSnapshotIdentifier']

        self.init()

    def _checkRdsSnapshotUnencrypted(self):
        if self.isCluster:
            encrypted = self.snapshot.get('StorageEncrypted')
        else:
            encrypted = self.snapshot.get('Encrypted')

        if encrypted is None:
            self.results['rdsSnapshotUnencrypted'] = [0, 'Unable to evaluate (encryption status not returned)']
        elif encrypted == False:
            self.results['rdsSnapshotUnencrypted'] = [-1, 'Snapshot is not encrypted']
        else:
            self.results['rdsSnapshotUnencrypted'] = [1, 'Encrypted']

    def _publicReportedBySnapshotRDSIsPublic(self):
        # Mirrors RdsCommon._checkPublicSnapshot: Aurora sources are looked up
        # by DBClusterIdentifier (cluster snapshots), other engines by
        # DBInstanceIdentifier (DB snapshots). Multi-AZ DB cluster snapshots
        # (non-Aurora cluster snapshots) are never seen by that check.
        if self.isCluster:
            engine = (self.snapshot.get('Engine') or '').lower()
            return engine.startswith('aurora') and \
                self.snapshot.get('DBClusterIdentifier') in self.publicCoveredClusters
        return self.snapshot.get('DBInstanceIdentifier') in self.publicCoveredInstances

    def _checkRdsSnapshotSharedExternally(self):
        if self.snapshot.get('SnapshotType') == 'awsbackup':
            # AWS Backup-managed snapshots cannot be shared directly (they
            # must first be copied to a manual snapshot); not applicable.
            return
        try:
            if self.isCluster:
                resp = self.rdsClient.describe_db_cluster_snapshot_attributes(
                    DBClusterSnapshotIdentifier=self.snapshot['DBClusterSnapshotIdentifier'])
                attrs = resp.get('DBClusterSnapshotAttributesResult', {}).get('DBClusterSnapshotAttributes', [])
            else:
                resp = self.rdsClient.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=self.snapshot['DBSnapshotIdentifier'])
                attrs = resp.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', [])
        except botocore.exceptions.ClientError as e:
            self.results['rdsSnapshotSharedExternally'] = [0, 'Unable to evaluate ({})'.format(e.response['Error']['Code'])]
            return

        shared = []
        public = False
        for attr in attrs:
            if attr.get('AttributeName') != 'restore':
                continue
            for v in attr.get('AttributeValues', []) or []:
                if v == 'all':
                    # Public: restorable by every AWS account.
                    public = True
                    continue
                if v == self.accountId:
                    continue
                shared.append(v)

        if self.orgAccounts is not None:
            external = [a for a in shared if a not in self.orgAccounts]
            note = 'outside your AWS Organization'
        else:
            external = shared
            note = 'organization membership not verifiable from this account'

        # Public snapshots of a source that SnapshotRDSIsPublic evaluated are
        # reported there only (one finding per issue); here they still fail
        # when the source is gone or not covered by that check.
        publicHere = public and not self._publicReportedBySnapshotRDSIsPublic()

        if external:
            msg = 'Restorable by account(s): {} ({})'.format(', '.join(sorted(external)), note)
            if publicHere:
                msg = 'Public: restorable by any AWS account (restore=all); also ' + msg[0].lower() + msg[1:]
            elif public:
                msg += '; public access (restore=all) is reported under SnapshotRDSIsPublic'
            self.results['rdsSnapshotSharedExternally'] = [-1, msg]
        elif publicHere:
            self.results['rdsSnapshotSharedExternally'] = [-1, 'Public: restorable by any AWS account (restore=all); source DB/cluster not evaluated by SnapshotRDSIsPublic']
        elif public:
            self.results['rdsSnapshotSharedExternally'] = [0, 'Public (restore=all) - reported under SnapshotRDSIsPublic for the source DB/cluster; not shared with specific external accounts']
        else:
            self.results['rdsSnapshotSharedExternally'] = [1, 'Not shared with external accounts']

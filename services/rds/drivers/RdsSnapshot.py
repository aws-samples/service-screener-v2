import botocore

from services.Evaluator import Evaluator


class RdsSnapshot(Evaluator):
    """Checks one manual RDS DB snapshot or DB cluster snapshot.

    snapshot    : item from describe_db_snapshots / describe_db_cluster_snapshots
    isCluster   : True for a DB cluster snapshot
    accountId   : the scanned account (sharing to itself is not external)
    orgAccounts : set of account IDs in the AWS Organization, or None when the
                  list cannot be read (member account / no permission)
    """
    def __init__(self, snapshot, isCluster, rdsClient, accountId, orgAccounts=None):
        super().__init__()
        self.snapshot = snapshot
        self.isCluster = isCluster
        self.rdsClient = rdsClient
        self.accountId = accountId
        self.orgAccounts = orgAccounts

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

    def _checkRdsSnapshotSharedExternally(self):
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
                    # Public: restorable by every AWS account. SnapshotRDSIsPublic
                    # only looks at snapshots of DBs/clusters that still exist,
                    # so a public snapshot whose source was deleted would
                    # otherwise never be reported.
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

        if public:
            msg = 'Public: restorable by any AWS account (restore=all)'
            if external:
                msg += '; also shared with: {} ({})'.format(', '.join(sorted(external)), note)
            self.results['rdsSnapshotSharedExternally'] = [-1, msg]
        elif external:
            self.results['rdsSnapshotSharedExternally'] = [-1, 'Restorable by account(s): {} ({})'.format(', '.join(sorted(external)), note)]
        else:
            self.results['rdsSnapshotSharedExternally'] = [1, 'Not shared with external accounts']

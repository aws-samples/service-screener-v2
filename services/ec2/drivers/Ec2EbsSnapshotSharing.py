from services.Evaluator import Evaluator


class Ec2EbsSnapshotSharing(Evaluator):
    """Per-snapshot checks for self-owned EBS snapshots (incl. AMI backing snapshots):
    - ebsSnapshotUnencrypted: snapshot is not encrypted
    - ebsSnapshotSharedExternally: shared (createVolumePermission) with AWS accounts
      outside the organization

    Inputs are prepared by Ec2.getSnapshotSharing() so the (potentially thousands of)
    describe_snapshot_attribute calls can be fetched concurrently:
      permissions - {'perms': [CreateVolumePermission, ...]} or {'error': '<code>'};
                    None when not fetched (the sharing check then records nothing)
      selfAccount - this account ID
      orgContext  - {'inOrg': True|False|None, 'accounts': set()|None, 'error': '<code>'|None}
                    inOrg None means organization membership could not be determined;
                    accounts None means the org account list is not readable (member account).

    Public sharing (Group 'all') is reported by EBSSnapshotIsPublic and is not
    reported again here.
    """

    def __init__(self, snapshot, permissions, selfAccount, orgContext, backingImages=None):
        super().__init__()
        self.snapshot = snapshot
        self.permissions = permissions
        self.backingImages = backingImages or []
        self.selfAccount = selfAccount
        self.orgContext = orgContext or {}

        self._resourceName = snapshot['SnapshotId']

        self.init()

    def _checkEbsSnapshotSharedExternally(self):
        key = 'ebsSnapshotSharedExternally'
        if self.permissions is None:
            return
        if 'error' in self.permissions:
            self.results[key] = [0, f"Unable to evaluate ({self.permissions['error']})"]
            return

        perms = self.permissions.get('perms', []) or []
        isPublic = any(p.get('Group') == 'all' for p in perms)
        accounts = sorted({p['UserId'] for p in perms if p.get('UserId') and p.get('UserId') != self.selfAccount})

        if not accounts:
            if isPublic:
                self.results[key] = [0, 'Public - reported by EBSSnapshotIsPublic; not shared with specific accounts']
            else:
                self.results[key] = [1, 'Not shared with other accounts']
            return

        inOrg = self.orgContext.get('inOrg')
        orgAccounts = self.orgContext.get('accounts')

        if inOrg is False:
            self.results[key] = [-1, 'Shared with account(s) outside the organization (account is not in an AWS Organization): ' + ', '.join(accounts)]
            return

        if inOrg is True and orgAccounts is not None:
            outside = [a for a in accounts if a not in orgAccounts]
            if outside:
                self.results[key] = [-1, 'Shared with account(s) outside the organization: ' + ', '.join(outside)]
            else:
                self.results[key] = [1, f"Shared only with {len(accounts)} account(s) inside the organization"]
            return

        if inOrg is True:
            self.results[key] = [0, f"Shared with {len(accounts)} account(s) ({', '.join(accounts)}); organization membership not evaluable from member account"]
            return

        err = self.orgContext.get('error') or 'organization membership unknown'
        self.results[key] = [0, f"Unable to evaluate ({err}); shared with {len(accounts)} account(s): {', '.join(accounts)}"]

    def _checkEbsSnapshotUnencrypted(self):
        """Unencrypted snapshots (and the volumes / AMIs created from them) are
        readable by anyone they are copied to or shared with, and fall outside
        KMS key policy control. EBSEncrypted only covers volumes."""
        key = 'ebsSnapshotUnencrypted'
        encrypted = self.snapshot.get('Encrypted')
        ami = f" (backs AMI {', '.join(self.backingImages)})" if self.backingImages else ''
        if encrypted is False:
            self.results[key] = [-1, f"Not encrypted{ami}"]
        elif encrypted is True:
            self.results[key] = [1, f"Encrypted{ami}"]
        else:
            self.results[key] = [0, 'Unable to evaluate (Encrypted attribute not returned)']

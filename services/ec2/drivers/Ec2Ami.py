import re

from services.Evaluator import Evaluator

_ORG_ID = re.compile(r'\b(o-[a-z0-9]{10,32})\b')


class Ec2Ami(Evaluator):
    """Per-AMI checks for images owned by this account (describe_images(Owners=['self'])).

    permissions / selfAccount / orgContext are only needed by
    _checkEc2AmiSharedExternally and are prepared by Ec2.getImageLaunchPermissions()
    (describe_image_attribute is one call per AMI, fetched concurrently):
      permissions - {'perms': [LaunchPermission, ...]} or {'error': '<code>'}; None = not fetched
      orgContext  - see Ec2.getOrgContext()
    """

    def __init__(self, image, permissions=None, selfAccount=None, orgContext=None):
        super().__init__()
        self.image = image
        self.permissions = permissions
        self.selfAccount = selfAccount
        self.orgContext = orgContext or {}

        self._resourceName = image['ImageId']

        self.init()

    def _checkEc2AmiPublic(self):
        image = self.image
        isPublic = image.get('Public')
        name = image.get('Name') or ''
        if isPublic is True:
            self.results['ec2AmiPublic'] = [-1, f"Public (launch permission group 'all'){' - ' + name if name else ''}"]
        elif isPublic is False:
            self.results['ec2AmiPublic'] = [1, 'Private']
        else:
            self.results['ec2AmiPublic'] = [0, 'Unable to evaluate (Public attribute not returned)']

    def _checkEc2AmiSharedExternally(self):
        """Launch permissions granted to AWS accounts (or organizations / OUs) outside
        this account's organization. Sharing with this organization or its OUs is fine.
        Public sharing (Group 'all') is reported by ec2AmiPublic and not repeated here."""
        key = 'ec2AmiSharedExternally'
        if self.permissions is None:
            return
        if 'error' in self.permissions:
            self.results[key] = [0, f"Unable to evaluate ({self.permissions['error']})"]
            return

        perms = self.permissions.get('perms', []) or []
        isPublic = any(p.get('Group') == 'all' for p in perms)
        accounts = sorted({p['UserId'] for p in perms if p.get('UserId') and p.get('UserId') != self.selfAccount})
        orgArns = sorted({p.get('OrganizationArn') or p.get('OrganizationalUnitArn')
                          for p in perms if p.get('OrganizationArn') or p.get('OrganizationalUnitArn')})

        if not accounts and not orgArns:
            if isPublic:
                self.results[key] = [0, 'Public - reported by ec2AmiPublic; not shared with specific accounts']
            else:
                self.results[key] = [1, 'Not shared with other accounts']
            return

        inOrg = self.orgContext.get('inOrg')
        ownOrgId = self.orgContext.get('orgId')
        orgAccounts = self.orgContext.get('accounts')

        outside, undetermined = [], []
        # Organization / OU shares are external only when they name a different organization
        for arn in orgArns:
            m = _ORG_ID.search(arn)
            target = m.group(1) if m else None
            if inOrg is False:
                outside.append(arn)
            elif inOrg is True and ownOrgId and target:
                if target != ownOrgId:
                    outside.append(arn)
            else:
                undetermined.append(arn)

        if accounts:
            if inOrg is False:
                outside += accounts
            elif inOrg is True and orgAccounts is not None:
                outside += [a for a in accounts if a not in orgAccounts]
            else:
                undetermined += accounts

        if outside:
            msg = 'Shared outside the organization: ' + ', '.join(outside)
            if inOrg is False:
                msg += ' (account is not in an AWS Organization)'
            self.results[key] = [-1, msg]
            return

        if undetermined:
            if inOrg is True:
                reason = 'Not evaluable from member account'
            else:
                reason = f"Unable to evaluate ({self.orgContext.get('error') or 'organization membership unknown'})"
            self.results[key] = [0, f"{reason}; shared with: {', '.join(undetermined)}"]
            return

        self.results[key] = [1, f"Shared only inside the organization ({len(accounts) + len(orgArns)} grant(s))"]

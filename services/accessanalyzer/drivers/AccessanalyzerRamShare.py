import re

import botocore

from services.Evaluator import Evaluator


class AccessanalyzerRamShare(Evaluator):
    """
    Per-resource checks for an AWS RAM resource share owned by this account.

    Input:
      share        -- one item of ram.get_resource_shares(resourceOwner='SELF')
      ramClient    -- boto3 RAM client (read-only calls only)
      accountId    -- caller account ID (from sts get_caller_identity)
      orgAccountsFn -- callable returning the set of organization account IDs,
                       or None when it cannot be read. Only used when RAM does
                       not report the 'external' flag on an association.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    ## Associations in these states grant (or are about to grant) access.
    LIVE_ASSOCIATION_STATES = ('ASSOCIATED', 'ASSOCIATING')

    def __init__(self, share, ramClient, accountId=None, orgAccountsFn=None):
        super().__init__()
        self.share = share
        self.ramClient = ramClient
        self.accountId = accountId
        self.orgAccountsFn = orgAccountsFn
        self._resourceName = share.get('resourceShareArn') or share.get('name', 'unknown')

        self.addII('name', share.get('name', 'N/A'))
        self.addII('status', share.get('status', 'N/A'))
        self.addII('featureSet', share.get('featureSet', 'N/A'))
        self.addII('allowExternalPrincipals', str(share.get('allowExternalPrincipals')))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _principalAssociations(self):
        assocs = []
        paginator = self.ramClient.get_paginator('get_resource_share_associations')
        for page in paginator.paginate(associationType='PRINCIPAL',
                                       resourceShareArns=[self.share['resourceShareArn']]):
            assocs += page.get('resourceShareAssociations', []) or []
        return assocs

    @staticmethod
    def _principalAccount(entity):
        """Account ID for a 12-digit account or an IAM role/user ARN; None for
        organization/OU ARNs and service principals (which RAM restricts to
        the owner's own organization or to the service)."""
        entity = entity or ''
        if re.fullmatch(r'\d{12}', entity):
            return entity
        m = re.match(r'arn:[^:]+:iam::(\d{12}):', entity)
        return m.group(1) if m else None

    def _isExternal(self, assoc):
        ## RAM reports 'external' = principal is outside the owner's
        ## organization. It is authoritative when present.
        if 'external' in assoc and assoc.get('external') is not None:
            return bool(assoc.get('external'))
        acct = self._principalAccount(assoc.get('associatedEntity'))
        if acct is None or acct == self.accountId:
            return False
        orgAccounts = self.orgAccountsFn() if self.orgAccountsFn else None
        if orgAccounts:
            return acct not in orgAccounts
        return True

    # ------------------------------------------------------------------ #
    # Checks
    # ------------------------------------------------------------------ #
    def _checkRamShareExternalPrincipals(self):
        key = 'ramShareExternalPrincipals'
        if not self.share.get('allowExternalPrincipals'):
            self.results[key] = [
                1, "Resource share only allows principals inside the organization"
            ]
            return
        try:
            assocs = self._principalAssociations()
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.results[key] = [0, f"Unable to evaluate ({code})"]
            return

        external = [
            a.get('associatedEntity', 'unknown') for a in assocs
            if a.get('status') in self.LIVE_ASSOCIATION_STATES and self._isExternal(a)
        ]
        if external:
            self.results[key] = [
                -1,
                "Resource share allows external principals and is shared with "
                "{} principal(s) outside the organization ({})".format(
                    len(external), ', '.join(external[:5]))
            ]
        else:
            self.results[key] = [
                1,
                "allowExternalPrincipals is enabled but no principal outside the "
                "organization is currently associated"
            ]

    def _checkRamSharesNotPromoted(self):
        key = 'ramSharesNotPromoted'
        fs = self.share.get('featureSet')
        if fs == 'CREATED_FROM_POLICY':
            self.results[key] = [
                -1,
                "Resource share was created from a resource-based policy "
                "(featureSet CREATED_FROM_POLICY) and has not been promoted to a "
                "standard, centrally managed resource share"
            ]
        elif fs == 'PROMOTING_TO_STANDARD':
            self.results[key] = [0, "Resource share is being promoted to STANDARD"]
        elif fs == 'STANDARD':
            self.results[key] = [1, "Resource share is a standard resource share"]
        else:
            self.results[key] = [0, "Unable to evaluate (featureSet not reported)"]

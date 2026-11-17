import botocore

from services.Evaluator import Evaluator


class AccessanalyzerRamAccount(Evaluator):
    """
    Account/region-scoped AWS RAM checks.

    Runs in every region, independently of whether IAM Access Analyzer is
    reachable there, so RAM results are never silently dropped.

    Input:
      detail -- {'_region': str, '_ramSharesError': error code or None}
                '_ramSharesError' is set when ram.get_resource_shares could
                not be read; the per-share checks then report
                'Unable to evaluate' here instead of producing no result.
      orgClient -- boto3 Organizations client (read-only calls only)

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    def __init__(self, detail, orgClient=None):
        super().__init__()
        self.detail = detail
        self.orgClient = orgClient
        self.ramSharesError = detail.get('_ramSharesError')
        self._resourceName = 'RAMAccount'

        self.addII('region', detail.get('_region', 'N/A'))

    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def _isPrimaryRegion(self):
        """Org-wide settings are global: report them once, in the first
        selected region, rather than once per region."""
        from utils.Config import Config
        regions = [r for r in (Config.get('REGIONS_SELECTED', []) or [])
                   if r and r != 'GLOBAL']
        return not regions or self.detail.get('_region') == regions[0]

    # Share list unreadable: the per-share checks cannot run, say so.
    def _checkRamShareExternalPrincipals(self):
        if self.ramSharesError:
            self.results['ramShareExternalPrincipals'] = [
                0, f"Unable to evaluate ({self.ramSharesError})"
            ]

    def _checkRamSharesNotPromoted(self):
        if self.ramSharesError:
            self.results['ramSharesNotPromoted'] = [
                0, f"Unable to evaluate ({self.ramSharesError})"
            ]

    # RAM sharing with AWS Organizations not enabled
    def _checkRamOrgSharingDisabled(self):
        key = 'ramOrgSharingDisabled'
        if self.orgClient is None or not self._isPrimaryRegion():
            return
        from utils.Config import Config
        accountId = (Config.get('stsInfo', {}) or {}).get('Account')

        try:
            org = self.orgClient.describe_organization().get('Organization', {}) or {}
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if code == 'AWSOrganizationsNotInUseException':
                self.results[key] = [0, "Account is not a member of an AWS Organization"]
            else:
                self.results[key] = [0, f"Unable to evaluate ({code})"]
            return
        except botocore.exceptions.EndpointConnectionError:
            self.results[key] = [0, "Unable to evaluate (EndpointConnectionError)"]
            return
        isMgmt = bool(accountId) and org.get('MasterAccountId') == accountId

        principals = set()
        try:
            paginator = self.orgClient.get_paginator(
                'list_aws_service_access_for_organization')
            for page in paginator.paginate():
                principals |= {p.get('ServicePrincipal') for p in
                               page.get('EnabledServicePrincipals', []) or []}
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if not isMgmt and code in ('AccessDeniedException', 'AccessDenied'):
                self.results[key] = [0, "Not evaluable from member account"]
            else:
                self.results[key] = [0, f"Unable to evaluate ({code})"]
            return
        except botocore.exceptions.EndpointConnectionError:
            self.results[key] = [0, "Unable to evaluate (EndpointConnectionError)"]
            return

        if 'ram.amazonaws.com' in principals:
            self.results[key] = [
                1, "AWS RAM trusted access with AWS Organizations is enabled"
            ]
        else:
            self.results[key] = [
                -1,
                "AWS RAM trusted access with AWS Organizations is not enabled — "
                "resources can only be shared with individual accounts by "
                "invitation, not with the organization or its OUs"
            ]

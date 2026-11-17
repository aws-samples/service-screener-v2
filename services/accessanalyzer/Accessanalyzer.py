import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.accessanalyzer.drivers.AccessanalyzerCommon import AccessanalyzerCommon
from services.accessanalyzer.drivers.AccessanalyzerRamShare import AccessanalyzerRamShare


class Accessanalyzer(Service):
    """
    AWS IAM Access Analyzer service scanner.

    Access Analyzer is account/region-scoped: the checks concern whether the
    account HAS the right analyzers enabled, not per-resource state. So discovery
    produces a single 'AccessAnalyzer::Account' descriptor per region, following
    the Config::Account / SSM::Account precedent from SPEC_02.

    Hydration calls (all read-only):
      - list_analyzers            (types, status)
      - list_findings             (per external-access analyzer, CAPPED — see
                                   FINDINGS_PAGE_CAP)
      - list_archive_rules        (per analyzer)
      - list_findings_v2          (unused-access analyzers, in the driver)
      - ram.get_resource_shares   (resourceOwner=SELF; one driver per share)
      - ram.get_resource_share_associations (per share, in the driver)
      - organizations.describe_organization / list_accounts /
        list_aws_service_access_for_organization (lazy, read-only)

    RAM shares live here because they are the other regional mechanism that
    grants access outside the account (no separate RAM service folder).
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## list_findings paginates without bound. Cap the number of pages read and
    ## report "at least N" rather than enumerating a large finding set — the
    ## discipline SPEC_02 established with INVENTORY_SAMPLE_LIMIT. 50 findings
    ## per page x this cap is plenty to decide the boolean "has unresolved
    ## external access".
    FINDINGS_PAGE_CAP = 4

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.aaClient = ssBoto.client('accessanalyzer', config=self.bConfig)
        self.ramClient = ssBoto.client('ram', config=self.bConfig)
        self.orgClient = ssBoto.client('organizations', config=self.bConfig)
        self._orgAccounts = False   # False = not fetched yet; None = unavailable

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        try:
            analyzers = self._listAnalyzers()
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Access Analyzer not available in region {self.region}: {e}")
            return None

        detail = {
            '_region': self.region,
            '_analyzers': analyzers,
            '_activeExternalFindings': None,
            '_findingsCapped': False,
            '_archiveRuleCount': 0,
        }

        ## Only external-access analyzers produce the cross-account findings the
        ## finding-based checks care about. Query findings from the first ACTIVE
        ## one; internal-access and unused-access analyzers have a different
        ## finding model.
        external = [
            a for a in analyzers
            if a.get('status') == 'ACTIVE'
            and a.get('type') in ('ACCOUNT', 'ORGANIZATION')
        ]
        if external:
            arn = external[0].get('arn')
            detail['_activeExternalFindings'], detail['_findingsCapped'] = \
                self._countActiveFindings(arn)
            detail['_archiveRuleCount'] = self._countArchiveRules(arn)

        _pi('Accessanalyzer', f"Access Analyzer posture in {self.region}")
        return detail

    def _listAnalyzers(self):
        analyzers = []
        try:
            paginator = self.aaClient.get_paginator('list_analyzers')
            for page in paginator.paginate():
                analyzers += page.get('analyzers', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_analyzers', e)
        except botocore.exceptions.OperationNotPageableError:
            try:
                analyzers = self.aaClient.list_analyzers().get(
                    'analyzers', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_analyzers', e)
        return analyzers

    def _countActiveFindings(self, analyzerArn):
        """
        Return (count, capped). `capped` is True when the page cap was hit, so
        the count is a floor ("at least N"), not a total. Filters to ACTIVE
        status server-side.
        """
        count, pages, capped = 0, 0, False
        nextToken = None
        try:
            while pages < self.FINDINGS_PAGE_CAP:
                kwargs = {
                    'analyzerArn': analyzerArn,
                    'filter': {'status': {'eq': ['ACTIVE']}},
                    'maxResults': 50,
                }
                if nextToken:
                    kwargs['nextToken'] = nextToken
                resp = self.aaClient.list_findings(**kwargs)
                count += len(resp.get('findings', []) or [])
                pages += 1
                nextToken = resp.get('nextToken')
                if not nextToken:
                    break
            if nextToken:
                capped = True
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_findings', e)
            return None, False
        return count, capped

    def _countArchiveRules(self, analyzerName):
        ## list_archive_rules keys on the analyzer NAME, not its ARN.
        name = analyzerName.split('/')[-1] if analyzerName else None
        if not name:
            return 0
        try:
            resp = self.aaClient.list_archive_rules(analyzerName=name)
            return len(resp.get('archiveRules', []) or [])
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_archive_rules', e)
            return 0

    def _listResourceShares(self):
        """RAM resource shares owned by this account (excluding deleted ones).
        Returns (shares, errorCode)."""
        shares = []
        try:
            paginator = self.ramClient.get_paginator('get_resource_shares')
            for page in paginator.paginate(resourceOwner='SELF'):
                shares += page.get('resourceShares', []) or []
        except botocore.exceptions.EndpointConnectionError:
            return [], None
        except botocore.exceptions.ClientError as e:
            self._logClientError('ram.get_resource_shares', e)
            return [], e.response.get('Error', {}).get('Code', 'Unknown')
        return [s for s in shares
                if s.get('status') not in ('DELETED', 'DELETING')], None

    def orgAccountIds(self):
        """Set of account IDs in the organization, or None when it cannot be
        read (member account, not in an org, access denied). Cached."""
        if self._orgAccounts is not False:
            return self._orgAccounts
        ids = set()
        try:
            for page in self.orgClient.get_paginator('list_accounts').paginate():
                ids |= {a.get('Id') for a in page.get('Accounts', []) or []
                        if a.get('Id')}
            self._orgAccounts = ids or None
        except (botocore.exceptions.ClientError,
                botocore.exceptions.EndpointConnectionError):
            self._orgAccounts = None
        return self._orgAccounts

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        detail = self.getResources()
        if detail is None:
            return objs
        try:
            obj = AccessanalyzerCommon(detail, self.aaClient, self.orgClient)
            obj.run(self.__class__)
            objs['AccessAnalyzer::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing Access Analyzer posture in "
                  f"{self.region}: {e}")

        shares, _err = self._listResourceShares()
        accountId = (Config.get('stsInfo', {}) or {}).get('Account')
        for share in shares:
            try:
                obj = AccessanalyzerRamShare(share, self.ramClient, accountId,
                                             self.orgAccountIds)
                obj.run(self.__class__)
                shareId = (share.get('resourceShareArn') or '').split('/')[-1]
                objs[f"RAM::ResourceShare::{share.get('name', 'unknown')}"
                     f" ({shareId})"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing RAM resource share "
                      f"{share.get('name')} in {self.region}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Accessanalyzer {where}: {code} - {msg}")

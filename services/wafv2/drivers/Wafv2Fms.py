import botocore

from services.Evaluator import Evaluator


NOT_ADMIN_CODES = ('AccessDenied', 'AccessDeniedException', 'ResourceNotFoundException',
                   'InvalidOperationException')
INACTIVE_ROLE_STATUS = ('PENDING_DELETION', 'DELETING', 'DELETED')


def _errCode(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return e.response.get('Error', {}).get('Code', 'Unknown')
    return type(e).__name__


class Wafv2Fms(Evaluator):
    """
    AWS Firewall Manager posture for the scanned region (read-only:
    fms.get_admin_account, fms.get_admin_scope, fms.list_policies).

    FMS policies are regional and only visible to a Firewall Manager
    administrator account. Tier-3 heuristic: FMS is optional (StackSets / LZA
    are valid alternatives), so a FAIL is raised only when get_admin_account
    confirms that THIS account is the (READY) FMS administrator and it has zero
    policies in the region. Every other situation is INFO:
      - no FMS administrator (ResourceNotFoundException) or another account is
        the administrator (e.g. scanning the Organizations management account)
        -> 'Not evaluable from member account'
      - administrator identity unreadable / scanned account id unknown ->
        never FAIL on an empty policy list
      - region outside the administrator's region scope (get_admin_scope)
        -> advisory only
    """

    def __init__(self, fmsClient, region, accountId):
        super().__init__()
        self.fms = fmsClient
        self.region = region
        self.accountId = accountId or ''
        self._resourceName = 'FirewallManager'
        self.addII('region', region)

    def _regionOutOfAdminScope(self):
        """True only when get_admin_scope positively shows this region is not
        administered by this account; any error/missing data -> False."""
        try:
            scope = (self.fms.get_admin_scope(AdminAccount=self.accountId).get('AdminScope') or {})
        except Exception:
            return False
        rs = scope.get('RegionScope')
        if not isinstance(rs, dict) or rs.get('AllRegionsEnabled', True):
            return False
        regions = rs.get('Regions') or []
        return bool(regions) and self.region not in regions

    def _checkFmsNoNetworkPolicies(self):
        rk = 'fmsNoNetworkPolicies'
        adminAccount, roleStatus, adminErr = None, None, None
        try:
            resp = self.fms.get_admin_account()
            adminAccount = resp.get('AdminAccount')
            roleStatus = resp.get('RoleStatus')
        except botocore.exceptions.ClientError as e:
            code = _errCode(e)
            if code == 'ResourceNotFoundException':
                # No Firewall Manager administrator exists for the organization.
                self.addII('fmsAdminAccount', 'none')
                self.results[rk] = [0, 'Not evaluable from member account']
                return
            if code not in NOT_ADMIN_CODES:
                self.results[rk] = [0, f'Unable to evaluate ({code})']
                return
            adminErr = code
        except Exception as e:
            self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
            return

        self.addII('fmsAdminAccount', adminAccount or 'unknown')
        if adminAccount and self.accountId and adminAccount != self.accountId:
            # Another account is the FMS administrator: policies (or their
            # absence) are not visible/meaningful from here.
            self.results[rk] = [0, 'Not evaluable from member account']
            return
        if adminAccount and roleStatus in INACTIVE_ROLE_STATUS:
            self.results[rk] = [0, f'Firewall Manager administrator role is {roleStatus}']
            return

        policies = []
        try:
            for page in self.fms.get_paginator('list_policies').paginate():
                policies.extend(page.get('PolicyList', []) or [])
        except botocore.exceptions.ClientError as e:
            code = _errCode(e)
            if code in NOT_ADMIN_CODES:
                self.results[rk] = [0, 'Not evaluable from member account']
            else:
                self.results[rk] = [0, f'Unable to evaluate ({code})']
            return
        except Exception as e:
            self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
            return

        self.addII('fmsPolicyCount', len(policies))
        if policies:
            types = sorted({(p.get('SecurityServiceType') or '?') for p in policies})
            self.results[rk] = [
                1, f"{len(policies)} Firewall Manager policy(ies) in {self.region}: {', '.join(types)}"
            ]
            return

        confirmedAdmin = bool(adminAccount) and adminAccount == self.accountId
        if not confirmedAdmin:
            why = adminErr or ('scanned account id unknown' if not self.accountId else 'administrator unknown')
            self.results[rk] = [
                0, f'Unable to evaluate ({why}): cannot confirm this account is the Firewall Manager administrator'
            ]
            return
        if self._regionOutOfAdminScope():
            self.results[rk] = [
                0, f'{self.region} is outside this Firewall Manager administrator\'s region scope (advisory only)'
            ]
            return
        self.results[rk] = [
            -1, f'This account is the Firewall Manager administrator but has no Firewall Manager '
                f'policies in {self.region} - WAF/Shield/security-group/network-firewall baselines '
                'are not centrally enforced across the organization'
        ]

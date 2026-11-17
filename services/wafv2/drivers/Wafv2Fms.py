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
    fms.get_admin_account, fms.list_policies).

    FMS policies are regional and only visible to a Firewall Manager
    administrator account. From any other account list_policies is denied, so
    the check reports 'Not evaluable from member account' instead of a FAIL.
    Tier-3 heuristic: FMS is optional (StackSets / LZA are valid alternatives),
    so a finding is raised only when this account IS an FMS administrator and
    has zero policies in the region.
    """

    def __init__(self, fmsClient, region, accountId):
        super().__init__()
        self.fms = fmsClient
        self.region = region
        self.accountId = accountId or ''
        self._resourceName = 'FirewallManager'
        self.addII('region', region)

    def _checkFmsNoNetworkPolicies(self):
        rk = 'fmsNoNetworkPolicies'
        adminAccount, roleStatus = None, None
        try:
            resp = self.fms.get_admin_account()
            adminAccount = resp.get('AdminAccount')
            roleStatus = resp.get('RoleStatus')
        except botocore.exceptions.ClientError as e:
            if _errCode(e) not in NOT_ADMIN_CODES:
                self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
                return
        except botocore.exceptions.EndpointConnectionError as e:
            self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
            return

        self.addII('fmsAdminAccount', adminAccount or 'none')
        if adminAccount and adminAccount == self.accountId and roleStatus in INACTIVE_ROLE_STATUS:
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
        except botocore.exceptions.EndpointConnectionError as e:
            self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
            return

        self.addII('fmsPolicyCount', len(policies))
        if not policies:
            self.results[rk] = [
                -1, f'This account is a Firewall Manager administrator but has no Firewall Manager '
                    f'policies in {self.region} - WAF/Shield/security-group/network-firewall baselines '
                    'are not centrally enforced across the organization'
            ]
        else:
            types = sorted({(p.get('SecurityServiceType') or '?') for p in policies})
            self.results[rk] = [
                1, f"{len(policies)} Firewall Manager policy(ies) in {self.region}: {', '.join(types)}"
            ]

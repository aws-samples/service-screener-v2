from datetime import datetime, timezone, timedelta

from services.Evaluator import Evaluator


class Route53Domain(Evaluator):
    """
    Route 53-registered domain checks (checks 3-6).

    Input:
      domain -- get_domain_detail response with '_name' added. Relevant keys:
        - AutoRenew (bool)
        - ExpirationDate (datetime or ISO str)
        - StatusList (list of EPP status codes, e.g. 'clientTransferProhibited')
        - AdminPrivacy, RegistrantPrivacy, TechPrivacy, BillingPrivacy (bool)
      domainsClient -- boto3 route53domains client.
    """

    EXPIRY_HIGH_DAYS = 30
    EXPIRY_MEDIUM_DAYS = 90

    TRANSFER_LOCK_STATUS = 'clientTransferProhibited'

    def __init__(self, domain, domainsClient):
        super().__init__()
        self.domain = domain
        self.domainsClient = domainsClient

        self._resourceName = domain.get('_name') or domain.get('DomainName') or 'unknown'

        self.addII('name', self._resourceName)
        self.addII('autoRenew', str(bool(domain.get('AutoRenew', False))))
        self.addII('adminPrivacy', str(bool(domain.get('AdminPrivacy', False))))
        self.addII('registrantPrivacy',
                   str(bool(domain.get('RegistrantPrivacy', False))))
        self.addII('techPrivacy', str(bool(domain.get('TechPrivacy', False))))
        status_list = domain.get('StatusList') or []
        self.addII('transferLocked',
                   'true' if self.TRANSFER_LOCK_STATUS in status_list else 'false')
        exp = self._parseExpiration(domain.get('ExpirationDate'))
        self.addII('expiration',
                   exp.isoformat() if exp else str(domain.get('ExpirationDate', 'N/A')))

    # ------------------------------------------------------------------ #
    # 3. AutoRenew disabled
    # ------------------------------------------------------------------ #
    def _checkRoute53DomainAutoRenewDisabled(self):
        auto = self.domain.get('AutoRenew')
        if auto:
            self.results['route53DomainAutoRenewDisabled'] = [
                1, "AutoRenew=true"
            ]
        else:
            self.results['route53DomainAutoRenewDisabled'] = [
                -1, "AutoRenew=false — domain will expire and can be re-registered"
            ]

    # ------------------------------------------------------------------ #
    # 4. Transfer lock (clientTransferProhibited) not set
    # ------------------------------------------------------------------ #
    def _checkRoute53DomainTransferLockDisabled(self):
        status_list = self.domain.get('StatusList') or []
        if self.TRANSFER_LOCK_STATUS in status_list:
            self.results['route53DomainTransferLockDisabled'] = [
                1, f"{self.TRANSFER_LOCK_STATUS} present"
            ]
        else:
            self.results['route53DomainTransferLockDisabled'] = [
                -1,
                f"StatusList lacks {self.TRANSFER_LOCK_STATUS} — domain can be "
                f"transferred out (StatusList={','.join(status_list) or 'empty'})"
            ]

    # ------------------------------------------------------------------ #
    # 5. Privacy protection disabled on any contact type
    # ------------------------------------------------------------------ #
    def _checkRoute53DomainPrivacyDisabled(self):
        missing = []
        for key, label in (('AdminPrivacy', 'admin'),
                           ('RegistrantPrivacy', 'registrant'),
                           ('TechPrivacy', 'tech')):
            if key in self.domain and not self.domain.get(key):
                missing.append(label)
        # BillingPrivacy is optional in some TLDs — only flag when explicitly False.
        if 'BillingPrivacy' in self.domain and self.domain.get('BillingPrivacy') is False:
            missing.append('billing')

        if missing:
            self.results['route53DomainPrivacyDisabled'] = [
                -1,
                f"Contacts without privacy: {', '.join(missing)}"
            ]
        else:
            self.results['route53DomainPrivacyDisabled'] = [
                1, "All contact types have privacy protection"
            ]

    # ------------------------------------------------------------------ #
    # 6. Domain expiring within 90 days
    # ------------------------------------------------------------------ #
    def _checkRoute53DomainExpiringSoon(self):
        exp = self._parseExpiration(self.domain.get('ExpirationDate'))
        if exp is None:
            self.results['route53DomainExpiringSoon'] = [
                0, "No ExpirationDate reported"
            ]
            return
        now = datetime.now(tz=timezone.utc)
        days = (exp - now).days
        auto = bool(self.domain.get('AutoRenew', False))

        if days <= self.EXPIRY_HIGH_DAYS:
            # Within 30 days — always high severity regardless of AutoRenew.
            self.results['route53DomainExpiringSoon'] = [
                -1,
                f"ExpirationDate in {days} day(s) (AutoRenew={'on' if auto else 'OFF'})"
            ]
        elif days <= self.EXPIRY_MEDIUM_DAYS and not auto:
            self.results['route53DomainExpiringSoon'] = [
                -1,
                f"ExpirationDate in {days} day(s) with AutoRenew=false — renew now"
            ]
        else:
            self.results['route53DomainExpiringSoon'] = [
                1,
                f"ExpirationDate in {days} day(s) (AutoRenew={'on' if auto else 'off'})"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parseExpiration(val):
        if val is None:
            return None
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val.replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, TypeError):
                return None
        return None

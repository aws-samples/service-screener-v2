import threading

import botocore

from utils.Config import Config
from services.Evaluator import Evaluator

_accountBpaLock = threading.Lock()


def accountBpaAllOn(s3Control, accountId):
    """True if all four account-level S3 Block Public Access settings are on,
    False if any is off / not configured, None if it could not be read.
    Cached per scan (account-level setting)."""
    cfgKey = f's3::accountBpaAllOn::{accountId}'
    with _accountBpaLock:
        cached = Config.get(cfgKey, '__unset__')
        if cached != '__unset__':
            return cached
        try:
            conf = s3Control.get_public_access_block(AccountId=accountId).get('PublicAccessBlockConfiguration', {}) or {}
            val = all(conf.get(k) is True for k in
                      ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'))
        except botocore.exceptions.ClientError as e:
            val = False if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration' else None
        except botocore.exceptions.BotoCoreError:
            val = None
        Config.set(cfgKey, val)
        return val


class S3AccessPoint(Evaluator):
    """One S3 access point (general purpose buckets) in the current Region.

    When listing access points failed, the driver is created with
    listError=<code> and records an INFO result instead of silently passing."""

    BPA_KEYS = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')

    def __init__(self, name, s3Control, accountId, listError=None):
        super().__init__()
        self.name = name
        self.s3Control = s3Control
        self.accountId = accountId
        self.listError = listError

        self._resourceName = name

        self.init()

    def _checkAccessPointPublic(self):
        key = 's3AccessPointPublic'
        if self.listError:
            self.results[key] = [0, f'Unable to evaluate ({self.listError})']
            return

        issues = []
        unknown = []

        try:
            ps = self.s3Control.get_access_point_policy_status(AccountId=self.accountId, Name=self.name)
            if (ps.get('PolicyStatus', {}) or {}).get('IsPublic') is True:
                issues.append('access point policy is public')
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code not in ('NoSuchAccessPointPolicy', 'NoSuchAccessPoint'):
                unknown.append(f'policy status: {code}')

        networkOrigin = None
        try:
            ap = self.s3Control.get_access_point(AccountId=self.accountId, Name=self.name)
            networkOrigin = ap.get('NetworkOrigin')
            bpa = ap.get('PublicAccessBlockConfiguration', {}) or {}
            off = [k for k in S3AccessPoint.BPA_KEYS if bpa.get(k) is not True]
            if off:
                issues.append('access point Block Public Access off: ' + ', '.join(off))
        except botocore.exceptions.ClientError as e:
            unknown.append(f"access point: {e.response['Error']['Code']}")

        origin = f' [NetworkOrigin={networkOrigin}]' if networkOrigin else ''
        if issues:
            # Account-level Block Public Access applies to access points too and
            # overrides both a public access point policy and access point BPA.
            if accountBpaAllOn(self.s3Control, self.accountId) is True:
                self.results[key] = [1, 'Mitigated by account-level Block Public Access (' + '; '.join(issues) + ')' + origin]
            else:
                self.results[key] = [-1, '; '.join(issues) + origin]
        elif unknown:
            self.results[key] = [0, 'Unable to evaluate (' + '; '.join(unknown) + ')']
        else:
            self.results[key] = [1, 'Not public; Block Public Access fully enabled' + origin]

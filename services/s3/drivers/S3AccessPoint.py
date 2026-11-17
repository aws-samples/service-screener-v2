import threading

import botocore

from utils.Config import Config
from services.Evaluator import Evaluator

_accountBpaLock = threading.Lock()
_bucketBpaLock = threading.Lock()

BPA_KEYS = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')


def _readBpa(call):
    """{key: bool} from a get_public_access_block call; all False when no
    configuration exists; None when it could not be read."""
    try:
        conf = call().get('PublicAccessBlockConfiguration', {}) or {}
        return {k: conf.get(k) is True for k in BPA_KEYS}
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return {k: False for k in BPA_KEYS}
        return None
    except botocore.exceptions.BotoCoreError:
        return None


def accountBpa(s3Control, accountId):
    """Account-level S3 Block Public Access settings ({key: bool}) or None if
    unreadable. Cached per scan (account-level setting)."""
    cfgKey = f's3::accountBpa::{accountId}'
    with _accountBpaLock:
        cached = Config.get(cfgKey, '__unset__')
        if cached != '__unset__':
            return cached
        val = _readBpa(lambda: s3Control.get_public_access_block(AccountId=accountId))
        Config.set(cfgKey, val)
        return val


def bucketBpa(s3Client, bucket):
    """Bucket-level S3 Block Public Access settings ({key: bool}) or None if
    unreadable (e.g. cross-account bucket, AccessDenied). Cached per bucket."""
    cfgKey = f's3::bucketBpa::{bucket}'
    with _bucketBpaLock:
        cached = Config.get(cfgKey, '__unset__')
        if cached != '__unset__':
            return cached
        val = _readBpa(lambda: s3Client.get_public_access_block(Bucket=bucket))
        Config.set(cfgKey, val)
        return val


class S3AccessPoint(Evaluator):
    """One S3 access point (general purpose buckets) in the current Region.

    When listing access points failed, the driver is created with
    listError=<code> and records an INFO result instead of silently passing.

    S3 evaluates Block Public Access at the access point, the underlying
    bucket and the account, and blocks a request if ANY of them blocks it
    (access-points-bpa-settings.html). So a setting that is off on the access
    point is only a finding when it is also off on both the bucket and the
    account."""

    BPA_KEYS = BPA_KEYS

    def __init__(self, name, s3Control, accountId, listError=None, s3Client=None):
        super().__init__()
        self.name = name
        self.s3Control = s3Control
        self.s3Client = s3Client
        self.accountId = accountId
        self.listError = listError

        self._resourceName = name

        self.init()

    @staticmethod
    def _effective(keys, layers):
        """For each key: True if any layer enables it, False if every layer is
        known and has it off, None if not enabled anywhere known but at least
        one layer is unreadable."""
        out = {}
        for k in keys:
            if any(l is not None and l.get(k) is True for l in layers):
                out[k] = True
            elif any(l is None for l in layers):
                out[k] = None
            else:
                out[k] = False
        return out

    def _checkAccessPointPublic(self):
        key = 's3AccessPointPublic'
        if self.listError:
            self.results[key] = [0, f'Unable to evaluate ({self.listError})']
            return

        policyPublic = False
        unknown = []

        try:
            ps = self.s3Control.get_access_point_policy_status(AccountId=self.accountId, Name=self.name)
            if (ps.get('PolicyStatus', {}) or {}).get('IsPublic') is True:
                policyPublic = True
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code not in ('NoSuchAccessPointPolicy', 'NoSuchAccessPoint'):
                unknown.append(f'policy status: {code}')

        networkOrigin = None
        bucket = None
        bucketAccountId = None
        apBpa = None
        try:
            ap = self.s3Control.get_access_point(AccountId=self.accountId, Name=self.name)
            networkOrigin = ap.get('NetworkOrigin')
            bucket = ap.get('Bucket')
            bucketAccountId = ap.get('BucketAccountId')
            apBpa = {k: (ap.get('PublicAccessBlockConfiguration', {}) or {}).get(k) is True for k in BPA_KEYS}
        except botocore.exceptions.ClientError as e:
            unknown.append(f"access point: {e.response['Error']['Code']}")

        apOff = [k for k in BPA_KEYS if apBpa is not None and apBpa[k] is not True]
        origin = f' [NetworkOrigin={networkOrigin}]' if networkOrigin else ''

        if not policyPublic and not apOff:
            if unknown:
                self.results[key] = [0, 'Unable to evaluate (' + '; '.join(unknown) + ')']
            else:
                self.results[key] = [1, 'Not public; Block Public Access fully enabled' + origin]
            return

        # Something is off on the access point itself: check whether the
        # underlying bucket or the account blocks it instead.
        acct = accountBpa(self.s3Control, self.accountId)
        bkt = None
        bucketNote = ''
        if bucket and self.s3Client is not None and (not bucketAccountId or bucketAccountId == self.accountId):
            bkt = bucketBpa(self.s3Client, bucket)
            if bkt is None:
                bucketNote = 'bucket Block Public Access unreadable'
        elif bucket and bucketAccountId and bucketAccountId != self.accountId:
            bucketNote = f'bucket owned by account {bucketAccountId}'
        else:
            bucketNote = 'bucket Block Public Access not read'
        eff = self._effective(BPA_KEYS, [apBpa or {}, bkt, acct])

        findings, mitigated, unresolved = [], [], []
        if policyPublic:
            # RestrictPublicBuckets is what blocks access granted by an existing public policy.
            state = eff['RestrictPublicBuckets']
            msg = 'access point policy is public'
            (mitigated if state is True else findings if state is False else unresolved).append(msg)
        if apOff:
            stillOff = [k for k in apOff if eff[k] is False]
            unk = [k for k in apOff if eff[k] is None]
            msg = 'access point Block Public Access off: ' + ', '.join(apOff)
            if stillOff:
                if networkOrigin == 'VPC' and not policyPublic:
                    # VPC-origin access points are not reachable from the internet;
                    # with no public policy this is not an exposure.
                    self.results[key] = [0, msg + ' (not blocked by bucket/account) but access point is VPC-only' + origin]
                    return
                findings.append(msg + ' (also off on bucket and account: ' + ', '.join(stillOff) + ')')
            elif unk:
                unresolved.append(msg)
            else:
                mitigated.append(msg)

        if findings:
            self.results[key] = [-1, '; '.join(findings) + origin]
        elif unresolved:
            reasons = [r for r in [bucketNote, 'account Block Public Access unreadable' if acct is None else ''] if r]
            self.results[key] = [0, 'Unable to evaluate (' + '; '.join(unresolved) + '; ' + '; '.join(reasons) + ')' + origin]
        else:
            self.results[key] = [1, 'Mitigated by Block Public Access on the access point, bucket or account (' + '; '.join(mitigated) + ')' + origin]

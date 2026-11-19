"""Account-scoped keys for the EC2 caches kept in utils.Config.

Config's cache is process-global and is not cleared between accounts: with
--sequential --crossAccounts every account is scanned in the same process. A
cache entry that holds account data (route tables, subnets, security groups,
organization membership, private AMIs, trust stores, run-once flags) must
therefore be keyed by the account being scanned, or account B would be
evaluated against account A's data.
"""
from utils.Config import Config


def currentAccount():
    return str((Config.get('stsInfo', {}) or {}).get('Account') or 'default')


def acctKey(key):
    """`key` prefixed with the account ID currently being scanned."""
    return 'acct::' + currentAccount() + '::' + key

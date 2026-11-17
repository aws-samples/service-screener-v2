"""
Read-only, cached access to IAM Identity Center (sso-admin) data for the IAM
account checks. Checks on IamAccount run concurrently, so fetches are guarded
by a lock and every API is called at most once per scan.

sso-admin is regional: the organization instance lives in its home Region
(plus any additional Regions of a multi-Region instance), so list_instances
is called in every scanned Region and instances are de-duplicated by ARN.
"""
import re
import threading

import botocore
from botocore.config import Config as bConfig

# list_permission_sets on an *account* instance of Identity Center fails
# with this code; permission sets only exist on the organization instance.
ACCOUNT_INSTANCE_CODE = 'ValidationException'

_ISO_DURATION = re.compile(r'^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$', re.IGNORECASE)


def parseIsoDuration(value):
    """'PT8H' -> 28800 seconds; None if unparseable."""
    m = _ISO_DURATION.match(str(value or '').strip())
    if not m or not any(m.groups()):
        return None
    d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + s


def _code(e):
    return e.response.get('Error', {}).get('Code', 'Unknown')


class SsoData:
    def __init__(self, ssBoto, regions):
        self.ssBoto = ssBoto
        self.regions = [r for r in (regions or []) if r and r != 'GLOBAL']
        self._lock = threading.RLock()
        self._cache = {}
        self._clients = {}

    def _client(self, region):
        if region not in self._clients:
            self._clients[region] = self.ssBoto.client('sso-admin', config=bConfig(region_name=region))
        return self._clients[region]

    @staticmethod
    def _paginate(client, op, resultKey, **kw):
        out = []
        for page in client.get_paginator(op).paginate(**kw):
            out.extend(page.get(resultKey, []))
        return out

    def _cached(self, key, fn):
        with self._lock:
            if key not in self._cache:
                try:
                    self._cache[key] = (fn(), None)
                except botocore.exceptions.ClientError as e:
                    self._cache[key] = (None, _code(e))
            return self._cache[key]

    # ------------------------------------------------------------------ #
    def instances(self):
        """([{'Region','Client','Instance','Kind'('ORG'|'ACCOUNT'),'PermissionSets'}], errors)

        Kind is decided by whether list_permission_sets is supported.
        PermissionSets is a list of permission set ARNs for ORG instances."""
        with self._lock:
            if 'instances' in self._cache:
                return self._cache['instances']
            found, errors, seen = [], [], set()
            for region in self.regions:
                client = self._client(region)
                try:
                    insts = self._paginate(client, 'list_instances', 'Instances')
                except botocore.exceptions.ClientError as e:
                    errors.append('{}: {}'.format(region, _code(e)))
                    continue
                for inst in insts:
                    arn = inst.get('InstanceArn')
                    if not arn or arn in seen or inst.get('Status') not in (None, 'ACTIVE'):
                        continue
                    seen.add(arn)
                    item = {'Region': region, 'Client': client, 'Instance': inst, 'Kind': 'ORG', 'PermissionSets': []}
                    try:
                        item['PermissionSets'] = self._paginate(client, 'list_permission_sets', 'PermissionSets',
                                                                InstanceArn=arn)
                    except botocore.exceptions.ClientError as e:
                        if _code(e) == ACCOUNT_INSTANCE_CODE:
                            item['Kind'] = 'ACCOUNT'
                        else:
                            errors.append('{} {}: {}'.format(region, arn, _code(e)))
                            continue
                    found.append(item)
            self._cache['instances'] = (found, errors)
            return self._cache['instances']

    def permissionSet(self, inst, psArn):
        client, iArn = inst['Client'], inst['Instance']['InstanceArn']
        return self._cached('ps::' + psArn, lambda: client.describe_permission_set(
            InstanceArn=iArn, PermissionSetArn=psArn).get('PermissionSet', {}))

    def managedPolicies(self, inst, psArn):
        client, iArn = inst['Client'], inst['Instance']['InstanceArn']
        return self._cached('mp::' + psArn, lambda: self._paginate(
            client, 'list_managed_policies_in_permission_set', 'AttachedManagedPolicies',
            InstanceArn=iArn, PermissionSetArn=psArn))

    def inlinePolicy(self, inst, psArn):
        client, iArn = inst['Client'], inst['Instance']['InstanceArn']
        return self._cached('inline::' + psArn, lambda: client.get_inline_policy_for_permission_set(
            InstanceArn=iArn, PermissionSetArn=psArn).get('InlinePolicy') or '')

    def provisionedAccounts(self, inst, psArn):
        client, iArn = inst['Client'], inst['Instance']['InstanceArn']
        return self._cached('accts::' + psArn, lambda: self._paginate(
            client, 'list_accounts_for_provisioned_permission_set', 'AccountIds',
            InstanceArn=iArn, PermissionSetArn=psArn))

    def assignments(self, inst, psArn, accountId):
        client, iArn = inst['Client'], inst['Instance']['InstanceArn']
        return self._cached('assign::{}::{}'.format(psArn, accountId), lambda: self._paginate(
            client, 'list_account_assignments', 'AccountAssignments',
            InstanceArn=iArn, AccountId=accountId, PermissionSetArn=psArn))

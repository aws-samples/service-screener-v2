"""Read-only helpers shared by the CloudTrail drivers.

Only describe/get/list calls are made here.
"""
import threading

import botocore

from utils.Config import Config

KMS_SOURCE = 'kms.amazonaws.com'

_lock = threading.Lock()


def errCode(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return e.response.get('Error', {}).get('Code', 'ClientError')
    return type(e).__name__


def accountIdFromArn(arn):
    parts = (arn or '').split(':')
    return parts[4] if len(parts) > 4 else None


def ownedBucketNames(s3Client):
    """Return (set of bucket names owned by this account, None) or (None, errorCode).
    Cached per account for the whole scan (bucket ownership is account-wide; the
    account id is part of the key so --sequential multi-account scans do not leak)."""
    accountId = (Config.get('stsInfo', {}) or {}).get('Account') or 'unknown'
    cacheKey = 'CloudTrail_ownedBuckets::' + accountId
    with _lock:
        cached = Config.get(cacheKey, None)
        if cached is not None:
            return cached
        try:
            names = set()
            for page in s3Client.get_paginator('list_buckets').paginate():
                for b in page.get('Buckets', []) or []:
                    if b.get('Name'):
                        names.add(b['Name'])
            cached = (names, None)
        except Exception as e:
            cached = (None, errCode(e))
        Config.set(cacheKey, cached)
        return cached


_POSITIVE_OPS = ('Equals', 'StartsWith', 'EndsWith')


def _matchesValue(fieldSel, value):
    """Does `value` satisfy every operator of one advanced field selector?
    Operators inside one field selector are ANDed (as CloudTrail evaluates them)."""
    if 'Equals' in fieldSel and value not in (fieldSel.get('Equals') or []):
        return False
    if 'NotEquals' in fieldSel and value in (fieldSel.get('NotEquals') or []):
        return False
    if 'StartsWith' in fieldSel and not any(value.startswith(p) for p in fieldSel.get('StartsWith') or []):
        return False
    if 'NotStartsWith' in fieldSel and any(value.startswith(p) for p in fieldSel.get('NotStartsWith') or []):
        return False
    if 'EndsWith' in fieldSel and not any(value.endswith(p) for p in fieldSel.get('EndsWith') or []):
        return False
    if 'NotEndsWith' in fieldSel and any(value.endswith(p) for p in fieldSel.get('NotEndsWith') or []):
        return False
    return True


def _isManagementAdvanced(sel):
    for fs in sel.get('FieldSelectors', []) or []:
        if fs.get('Field') == 'eventCategory':
            return _matchesValue(fs, 'Management')
    return False


def _isDataAdvanced(sel):
    for fs in sel.get('FieldSelectors', []) or []:
        if fs.get('Field') == 'eventCategory':
            return _matchesValue(fs, 'Data')
    return False


def selectorCoverage(selectors):
    """Summarise get_event_selectors output.

    Returns dict(management=bool, kms=bool, data=bool):
      management - trail captures management events
      kms        - trail captures management events from kms.amazonaws.com
      data       - trail captures data events
      kmsAmbiguous - an advanced management selector combines several positive
                     operators (Equals/StartsWith/EndsWith) on eventSource; CloudTrail
                     does not document how those combine, so a "KMS excluded" verdict
                     from such a selector is not trusted (callers report INFO).
    """
    out = {'management': False, 'kms': False, 'data': False, 'kmsAmbiguous': False}
    selectors = selectors or {}
    for es in selectors.get('EventSelectors') or []:
        if es.get('IncludeManagementEvents') is True:
            out['management'] = True
            if KMS_SOURCE not in (es.get('ExcludeManagementEventSources') or []):
                out['kms'] = True
        if es.get('DataResources'):
            out['data'] = True

    for sel in selectors.get('AdvancedEventSelectors') or []:
        if _isManagementAdvanced(sel):
            out['management'] = True
            kmsOk = True
            for fs in sel.get('FieldSelectors', []) or []:
                if fs.get('Field') == 'eventSource' and not _matchesValue(fs, KMS_SOURCE):
                    kmsOk = False
                    if sum(1 for op in _POSITIVE_OPS if op in fs) > 1:
                        out['kmsAmbiguous'] = True
            if kmsOk:
                out['kms'] = True
        if _isDataAdvanced(sel):
            out['data'] = True
    return out

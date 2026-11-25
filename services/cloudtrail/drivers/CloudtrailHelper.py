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


def trailStatus(ev, ctClient, arn):
    """ctClient.get_trail_status(Name=arn), read once per scan: the per-trail
    CloudtrailCommon driver and CloudtrailAccount both need it."""
    return ev._sharedMemo(('cloudtrail.get_trail_status', ctClient.meta.region_name, arn),
                          lambda: ctClient.get_trail_status(Name=arn))


def trailEventSelectors(ev, ctClient, arn):
    """ctClient.get_event_selectors(TrailName=arn), read once per scan: the
    per-trail CloudtrailCommon driver and CloudtrailAccount both need it."""
    return ev._sharedMemo(('cloudtrail.get_event_selectors', ctClient.meta.region_name, arn),
                          lambda: ctClient.get_event_selectors(TrailName=arn))


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


def _readWriteOfBasic(es):
    """(reads, writes) recorded by a basic event selector (ReadWriteType, default All)."""
    rw = es.get('ReadWriteType') or 'All'
    return rw in ('All', 'ReadOnly'), rw in ('All', 'WriteOnly')


def _readWriteOfAdvanced(sel):
    """(reads, writes) recorded by an advanced selector: a readOnly field selector
    limits it to read-only ('true') or write-only ('false') events."""
    reads = writes = True
    for fs in sel.get('FieldSelectors', []) or []:
        if fs.get('Field') == 'readOnly':
            reads = reads and _matchesValue(fs, 'true')
            writes = writes and _matchesValue(fs, 'false')
    return reads, writes


def selectorCoverage(selectors):
    """Summarise get_event_selectors output.

    Returns dict(management=bool, kms=bool, kmsRead=bool, kmsWrite=bool, data=bool,
    kmsAmbiguous=bool):
      management - trail captures management events
      kmsRead    - trail captures read-only KMS management events (Decrypt, Encrypt,
                   GenerateDataKey, ...)
      kmsWrite   - trail captures write KMS management events (DisableKey,
                   ScheduleKeyDeletion, PutKeyPolicy, ...)
      kms        - kmsRead and kmsWrite (all KMS management events are recorded)
      data       - trail captures data events
      kmsAmbiguous - an advanced management selector combines several positive
                     operators (Equals/StartsWith/EndsWith) on eventSource; CloudTrail
                     does not document how those combine, so a "KMS excluded" verdict
                     from such a selector is not trusted (callers report INFO).
    """
    out = {'management': False, 'kms': False, 'kmsRead': False, 'kmsWrite': False,
           'data': False, 'kmsAmbiguous': False}
    selectors = selectors or {}
    for es in selectors.get('EventSelectors') or []:
        if es.get('IncludeManagementEvents') is True:
            out['management'] = True
            if KMS_SOURCE not in (es.get('ExcludeManagementEventSources') or []):
                reads, writes = _readWriteOfBasic(es)
                out['kmsRead'] = out['kmsRead'] or reads
                out['kmsWrite'] = out['kmsWrite'] or writes
        if es.get('DataResources'):
            out['data'] = True

    for sel in selectors.get('AdvancedEventSelectors') or []:
        if _isManagementAdvanced(sel):
            reads, writes = _readWriteOfAdvanced(sel)
            if not (reads or writes):
                continue  # contradictory readOnly filter: the selector matches nothing
            out['management'] = True
            kmsOk = True
            for fs in sel.get('FieldSelectors', []) or []:
                if fs.get('Field') == 'eventSource' and not _matchesValue(fs, KMS_SOURCE):
                    kmsOk = False
                    if sum(1 for op in _POSITIVE_OPS if op in fs) > 1:
                        out['kmsAmbiguous'] = True
            if kmsOk:
                out['kmsRead'] = out['kmsRead'] or reads
                out['kmsWrite'] = out['kmsWrite'] or writes
        if _isDataAdvanced(sel):
            out['data'] = True
    out['kms'] = out['kmsRead'] and out['kmsWrite']
    return out

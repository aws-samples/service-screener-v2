"""
Cross-account trust classification for IAM role trust policies (pure
functions plus a small context builder).

A trusted AWS account is classified as:
  'self'     - the scanned account
  'org'      - a member of this AWS Organization (org account list readable,
               or it is the management account)
  'external' - definitely outside the organization (org account list
               readable, or the scanned account is not in an organization)
  'unknown'  - org account list not readable (typical for member accounts),
               so it cannot be told apart from an intra-org account

Checks must not FAIL on 'unknown' (intra-org trusts would be false
positives); they record [0, ...] instead.
"""
import fnmatch
import json
import re
import urllib.parse

ACCOUNT_RE = re.compile(r'^\d{12}$')
ARN_ACCOUNT_RE = re.compile(r'^arn:aws[a-z0-9-]*:(?:iam|sts)::(\d{12}):')
ORG_CONDITION_KEYS = {'aws:principalorgid', 'aws:principalorgpaths'}
ASSUME_ACTION = 'sts:assumerole'
MIN_EXTERNAL_ID_LENGTH = 8


def buildTrustContext(orgData, selfAccount):
    """{'self', 'orgAccounts' (set|None), 'inOrg' (bool|None), 'mgmt', 'orgId', 'reason'}"""
    ctx = {'self': str(selfAccount) if selfAccount else None, 'orgAccounts': None, 'inOrg': None,
           'mgmt': None, 'orgId': None, 'reason': None}
    org, err = orgData.organization()
    if err == 'AWSOrganizationsNotInUseException':
        ctx['inOrg'] = False
        return ctx
    if err or not org:
        ctx['reason'] = 'organization not readable ({})'.format(err or 'empty')
        return ctx
    ctx['inOrg'] = True
    ctx['mgmt'] = org.get('MasterAccountId')
    ctx['orgId'] = org.get('Id')
    accounts, err = orgData.accounts()
    if err:
        ctx['reason'] = 'organization account list not readable ({})'.format(err)
    else:
        ctx['orgAccounts'] = {str(a.get('Id')) for a in accounts if a.get('Id')}
    return ctx


def _asList(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parseDocument(doc):
    """Policy documents may arrive URL-encoded / as JSON strings."""
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except ValueError:
            return None
    return doc


def _stmts(doc):
    doc = parseDocument(doc)
    if not isinstance(doc, dict):
        return []
    st = doc.get('Statement', [])
    st = [st] if isinstance(st, dict) else st
    return [s for s in st if isinstance(s, dict)] if isinstance(st, list) else []


def principalAccount(p):
    p = str(p)
    if ACCOUNT_RE.match(p):
        return p
    m = ARN_ACCOUNT_RE.match(p)
    return m.group(1) if m else None


def classifyAccount(account, ctx):
    if not ctx.get('self'):
        return 'unknown'
    if account == ctx.get('self'):
        return 'self'
    if ctx.get('inOrg') is False:
        return 'external'
    if ctx.get('orgAccounts') is not None:
        return 'org' if account in ctx['orgAccounts'] else 'external'
    if ctx.get('mgmt') and account == ctx['mgmt']:
        return 'org'
    return 'unknown'


def _conditions(stmt):
    out = []
    cond = stmt.get('Condition', {})
    if not isinstance(cond, dict):
        return out
    for op, kv in cond.items():
        if not isinstance(kv, dict):
            continue
        for k, v in kv.items():
            out.append((str(op).lower(), str(k).lower(), [str(x) for x in _asList(v)]))
    return out


def externalIdWeakness(stmt, knownAccounts):
    """None if the statement enforces a strong sts:ExternalId, else a reason."""
    ext = [(op, vals) for op, k, vals in _conditions(stmt) if k == 'sts:externalid']
    if not ext:
        return 'no sts:ExternalId condition'
    for op, vals in ext:
        if op.endswith('ifexists'):
            return 'sts:ExternalId uses {} (not enforced when absent)'.format(op)
        if op not in ('stringequals', 'stringlike'):
            return 'sts:ExternalId uses unsupported operator {}'.format(op)
        for v in vals:
            if op == 'stringlike' and ('*' in v or '?' in v):
                return 'sts:ExternalId contains wildcards'
            if len(v) < MIN_EXTERNAL_ID_LENGTH:
                return 'sts:ExternalId shorter than {} characters'.format(MIN_EXTERNAL_ID_LENGTH)
            if v.isdigit():
                return 'sts:ExternalId is numeric-only'
            if v in knownAccounts:
                return 'sts:ExternalId equals an account ID'
    return None


def _orgValueIsOwn(key, base, value, orgId):
    """True when one condition value only admits principals of org `orgId`."""
    oid = orgId.lower() if base.endswith('ignorecase') else orgId
    v = value.lower() if base.endswith('ignorecase') else value
    if key == 'aws:principalorgid':
        # No wildcards: "o-abc*" or "*" would admit other organizations.
        return v == oid
    # aws:PrincipalOrgPaths values look like "o-abc/r-ab12/ou-ab12-1111/".
    # The org part must be the literal own org ID (wildcards allowed after it
    # only with StringLike, where they stay inside our org).
    return v.startswith(oid + '/') and (base.startswith('stringlike') or not any(c in v for c in '*?'))


def orgConditionScope(stmt, orgId):
    """How an aws:PrincipalOrgID / aws:PrincipalOrgPaths condition restricts the
    statement:
      'own'     - every value names our organization (orgId) with an enforced
                  operator (StringEquals/StringLike, no IfExists, which would
                  also admit principals that are in no organization)
      'unknown' - an enforced org condition exists but our org ID is unknown
      None      - no enforced org condition, or it admits other organizations
                  (a vendor's org ID, a wildcard)
    Conditions are ANDed, so one 'own' block restricts the whole statement."""
    result = None
    for op, k, vals in _conditions(stmt):
        if k not in ORG_CONDITION_KEYS or not vals:
            continue
        prefix, _, base = op.rpartition(':')
        if base.endswith('ifexists') or prefix == 'forallvalues':
            continue
        if prefix == 'foranyvalue' and k != 'aws:principalorgpaths':
            continue
        if base not in ('stringequals', 'stringlike', 'stringequalsignorecase'):
            continue
        if not orgId:
            result = 'unknown'
            continue
        if all(_orgValueIsOwn(k, base, v, orgId) for v in vals):
            return 'own'
    return result


def hasOrgCondition(stmt, orgId):
    return orgConditionScope(stmt, orgId) == 'own'


def crossAccountTrusts(trustDoc, ctx):
    """[{'account', 'class', 'orgConditioned', 'externalIdWeakness'}] for every
    Allow statement that lets an AWS account principal call sts:AssumeRole."""
    out = []
    for s in _stmts(trustDoc):
        if s.get('Effect') != 'Allow':
            continue
        actions = [str(a).lower() for a in _asList(s.get('Action'))]
        if not any(fnmatch.fnmatchcase(ASSUME_ACTION, a) for a in actions):
            continue
        principal = s.get('Principal')
        if not isinstance(principal, dict):
            continue
        accounts = {principalAccount(p) for p in _asList(principal.get('AWS'))}
        accounts.discard(None)
        # Our own org ID is only meaningful when the account is in an org; a
        # standalone account has no org, so any org condition names another.
        orgId = ctx.get('orgId') if ctx.get('inOrg') else None
        scope = orgConditionScope(s, orgId)
        if scope == 'unknown' and ctx.get('inOrg') is False:
            scope = None
        for acc in sorted(accounts):
            cls = classifyAccount(acc, ctx)
            if cls in ('self', 'org'):
                continue
            if scope == 'unknown':
                # Org-conditioned, but the condition cannot be compared with
                # our org ID: neither PASS nor FAIL.
                cls = 'unknown'
            known = set(accounts) | ({ctx['self']} if ctx.get('self') else set())
            out.append({'account': acc, 'class': cls, 'orgConditioned': scope == 'own',
                        'externalIdWeakness': externalIdWeakness(s, known)})
    return out


def isAdminLevelDocument(doc):
    """Allow of '*' / '*:*' / 'iam:*' (or a NotAction Allow that leaves IAM
    writes allowed) on Resource '*'."""
    for s in _stmts(doc):
        if s.get('Effect') != 'Allow':
            continue
        res = [str(r) for r in _asList(s.get('Resource'))]
        if '*' not in res:
            continue
        if 'Action' in s:
            acts = [str(a).lower() for a in _asList(s.get('Action'))]
            if any(a in ('*', '*:*', 'iam:*') for a in acts):
                return True
        elif 'NotAction' in s:
            nacts = [str(a).lower() for a in _asList(s.get('NotAction'))]
            if not any(fnmatch.fnmatchcase('iam:putrolepolicy', a) for a in nacts):
                return True
    return False

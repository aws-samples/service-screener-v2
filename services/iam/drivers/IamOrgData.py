"""
Read-only, cached access to AWS Organizations data for the IAM account checks.

Checks on IamAccount run concurrently on one object, so every fetch is guarded
by a lock and cached: each Organizations API is called at most once per scan.

Every getter returns (value, errorCode). errorCode is None on success, else the
botocore error code (e.g. AccessDeniedException) so the calling check can
record [0, ...] instead of silently passing.
"""
import copy
import fnmatch
import json
import threading

import botocore

# Codes that mean "this account cannot read org-level data" (member account
# without delegated administration, or not in an org at all).
MEMBER_ERROR_CODES = {
    'AccessDeniedException', 'AccessDenied',
    'AWSOrganizationsNotInUseException',
    'AccountNotManagementOrDelegatedAdministratorException',
}
NOT_IN_ORG = 'AWSOrganizationsNotInUseException'
FULL_AWS_ACCESS_ID = 'p-FullAWSAccess'

SCP = 'SERVICE_CONTROL_POLICY'
RCP = 'RESOURCE_CONTROL_POLICY'
TAG = 'TAG_POLICY'
BACKUP = 'BACKUP_POLICY'
DECLARATIVE_EC2 = 'DECLARATIVE_POLICY_EC2'


def _code(e):
    return e.response.get('Error', {}).get('Code', 'Unknown')


class OrgData:
    def __init__(self, orgClient, callerAccountId, describeOrgResp=None, describeOrgErr=None):
        self.orgClient = orgClient
        self.callerAccountId = str(callerAccountId) if callerAccountId else None
        self._lock = threading.RLock()
        self._cache = {}
        if describeOrgResp is not None or describeOrgErr is not None:
            self._cache['org'] = ((describeOrgResp or {}).get('Organization'), describeOrgErr)

    # ------------------------------------------------------------------ #
    def _cached(self, key, fn):
        with self._lock:
            if key not in self._cache:
                try:
                    self._cache[key] = (fn(), None)
                except botocore.exceptions.ClientError as e:
                    self._cache[key] = (None, _code(e))
            return self._cache[key]

    def _paginate(self, op, resultKey, **kw):
        out = []
        for page in self.orgClient.get_paginator(op).paginate(**kw):
            out.extend(page.get(resultKey, []))
        return out

    def listChildren(self, op, resultKey, **kw):
        """_paginate() fetched at most once per (op, args): tree(), ous() and
        IamAccount._checkOrgOuStructureFlat list the children of the same
        parents. A raised exception is cached and re-raised to every caller,
        as if each had made the call itself. Each caller gets its own copy."""
        key = ('list', op, resultKey, tuple(sorted(kw.items())))
        with self._lock:
            if key not in self._cache:
                try:
                    self._cache[key] = (True, self._paginate(op, resultKey, **kw))
                except Exception as e:
                    self._cache[key] = (False, e)
            ok, value = self._cache[key]
        if not ok:
            raise value
        return copy.deepcopy(value)

    # ------------------------------------------------------------------ #
    def organization(self):
        return self._cached('org', lambda: self.orgClient.describe_organization().get('Organization'))

    def inOrganization(self):
        org, err = self.organization()
        return org is not None

    def isManagementAccount(self):
        org, err = self.organization()
        return bool(org) and self.callerAccountId is not None and org.get('MasterAccountId') == self.callerAccountId

    def notEvaluable(self, err):
        """Result for an org-level read that failed with `err`."""
        if err == NOT_IN_ORG:
            return [0, 'Not applicable: account is not part of an AWS Organization']
        if err in MEMBER_ERROR_CODES and not self.isManagementAccount():
            return [0, 'Not evaluable from member account']
        return [0, 'Unable to evaluate ({})'.format(err)]

    def preconditionResult(self):
        """None if org-level checks can proceed, else the [0, msg] to record."""
        org, err = self.organization()
        if err:
            return self.notEvaluable(err)
        if not org:
            return [0, 'Not applicable: account is not part of an AWS Organization']
        return None

    # ------------------------------------------------------------------ #
    def roots(self):
        return self._cached('roots', lambda: self._paginate('list_roots', 'Roots'))

    def policyTypeStatus(self, policyType):
        """'ENABLED' / 'PENDING_*' / None (not enabled) for the first root."""
        roots, err = self.roots()
        if err:
            return None, err
        if not roots:
            return None, 'NoRoot'
        for pt in roots[0].get('PolicyTypes', []) or []:
            if pt.get('Type') == policyType:
                return pt.get('Status'), None
        return None, None

    def policies(self, policyType):
        """All policies of a type with parsed content and targets.
        [{'Id','Name','AwsManaged','Content'(dict|None),'Targets':[{TargetId,Type,Name}]}]"""
        def fetch():
            out = []
            for p in self._paginate('list_policies', 'Policies', Filter=policyType):
                pid = p['Id']
                item = {'Id': pid, 'Name': p.get('Name', pid), 'AwsManaged': bool(p.get('AwsManaged', False)),
                        'Content': None, 'Targets': []}
                item['Targets'] = self._paginate('list_targets_for_policy', 'Targets', PolicyId=pid)
                if not item['AwsManaged']:
                    raw = self.orgClient.describe_policy(PolicyId=pid).get('Policy', {}).get('Content')
                    try:
                        item['Content'] = json.loads(raw) if isinstance(raw, str) else raw
                    except (ValueError, TypeError):
                        item['Content'] = None
                out.append(item)
            return out
        return self._cached('policies::' + policyType, fetch)

    def tree(self):
        """Organization structure.
        {'rootId', 'nodes': {id: {'Type': ROOT|ORGANIZATIONAL_UNIT|ACCOUNT, 'Name', 'Parent'}}}"""
        roots, err = self.roots()
        if err:
            return None, err

        def fetch():
            if not roots:
                return {'rootId': None, 'nodes': {}}
            rootId = roots[0]['Id']
            nodes = {rootId: {'Type': 'ROOT', 'Name': roots[0].get('Name', 'Root'), 'Parent': None}}
            stack = [rootId]
            while stack:
                parent = stack.pop()
                for ou in self.listChildren('list_organizational_units_for_parent', 'OrganizationalUnits', ParentId=parent):
                    nodes[ou['Id']] = {'Type': 'ORGANIZATIONAL_UNIT', 'Name': ou.get('Name', ou['Id']), 'Parent': parent}
                    stack.append(ou['Id'])
                for acc in self.listChildren('list_accounts_for_parent', 'Accounts', ParentId=parent):
                    nodes[acc['Id']] = {'Type': 'ACCOUNT', 'Name': acc.get('Name', acc['Id']), 'Parent': parent,
                                        'State': acc.get('State') or acc.get('Status')}
            return {'rootId': rootId, 'nodes': nodes}
        return self._cached('tree', fetch)

    def accounts(self):
        return self._cached('accounts', lambda: self._paginate('list_accounts', 'Accounts'))

    def ous(self):
        """Every OU in the organization, walked with the OU APIs only (no
        account listing). {ouId: {'Name', 'Parent', 'Path'}} where Path is
        'Root/Parent/Child'."""
        roots, err = self.roots()
        if err:
            return None, err

        def fetch():
            out = {}
            if not roots:
                return out
            stack = [(roots[0]['Id'], roots[0].get('Name', 'Root'))]
            while stack:
                parent, path = stack.pop()
                for ou in self.listChildren('list_organizational_units_for_parent', 'OrganizationalUnits', ParentId=parent):
                    ouPath = '{}/{}'.format(path, ou.get('Name', ou['Id']))
                    out[ou['Id']] = {'Name': ou.get('Name', ou['Id']), 'Parent': parent, 'Path': ouPath}
                    stack.append((ou['Id'], ouPath))
            return out
        return self._cached('ous', fetch)

    def accountTags(self, accountId):
        return self._cached('tags::' + str(accountId), lambda: self._paginate(
            'list_tags_for_resource', 'Tags', ResourceId=accountId))


# ---------------------------------------------------------------------- #
# Policy document helpers (pure functions, unit-testable)
# ---------------------------------------------------------------------- #
def statements(doc):
    if not isinstance(doc, dict):
        return []
    st = doc.get('Statement', [])
    if isinstance(st, dict):
        st = [st]
    return [s for s in st if isinstance(s, dict)] if isinstance(st, list) else []


def _asList(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _actionMatches(pattern, action):
    return fnmatch.fnmatchcase(action.lower(), str(pattern).lower())


def denyCoversAction(stmt, action):
    """True if a Deny statement's Action/NotAction covers `action`."""
    if stmt.get('Effect') != 'Deny':
        return False
    if 'Action' in stmt:
        return any(_actionMatches(p, action) for p in _asList(stmt.get('Action')))
    if 'NotAction' in stmt:
        return not any(_actionMatches(p, action) for p in _asList(stmt.get('NotAction')))
    return False


def conditionKeys(stmt):
    """{(operatorLower, keyLower): [values]} for a statement."""
    out = {}
    cond = stmt.get('Condition', {})
    if not isinstance(cond, dict):
        return out
    for op, kv in cond.items():
        if not isinstance(kv, dict):
            continue
        for k, v in kv.items():
            out[(str(op).lower(), str(k).lower())] = [str(x) for x in _asList(v)]
    return out


PRIV_ESC_ACTIONS = [
    'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion', 'iam:AttachUserPolicy',
    'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy', 'iam:CreateAccessKey',
    'iam:CreateLoginProfile', 'iam:UpdateLoginProfile', 'iam:PassRole',
]
SCP_GUARDRAILS = {
    'denyRoot': 'root user denial',
    'restrictRegions': 'region restriction',
    'preventPrivEscalation': 'privilege escalation prevention',
}


def scpGuardrails(doc):
    """Which best-practice guardrails a single SCP document provides."""
    found = set()
    for s in statements(doc):
        if s.get('Effect') != 'Deny':
            continue
        # A Deny "*" without a narrowing condition (quarantine / suspended
        # SCP) blocks every action - including root user, out-of-region and
        # privilege-escalation actions - so it provides every guardrail.
        if any(str(p) == '*' for p in _asList(s.get('Action'))) and denyIsUnconditionalGuardrail(s):
            found.update(SCP_GUARDRAILS)
            continue
        conds = conditionKeys(s)
        for (op, key), vals in conds.items():
            baseOp = op[:-len('ifexists')] if op.endswith('ifexists') else op
            if key == 'aws:principalarn' and baseOp in ('stringlike', 'stringequals', 'arnlike', 'arnequals') \
                    and any(v.endswith(':root') for v in vals):
                found.add('denyRoot')
            if key == 'aws:requestedregion' and op.startswith('stringnot'):
                found.add('restrictRegions')
        # Only IAM-specific action patterns count: a broad Deny "*" scoped by a
        # condition (e.g. region deny) is not a privilege-escalation guardrail.
        iamPatterns = [p for p in _asList(s.get('Action')) if str(p).lower().startswith('iam:')]
        if any(_actionMatches(p, a) for p in iamPatterns for a in PRIV_ESC_ACTIONS):
            found.add('preventPrivEscalation')
    return found


# ---------------------------------------------------------------------- #
# SCP guardrail coverage (shared by the scpNo* action-guard checks)
# ---------------------------------------------------------------------- #
# A Deny only works as an org-wide guardrail when its Condition (if any) is
# an *exception* (e.g. "everyone except the BreakGlass role"). A Deny scoped
# by a positive condition - e.g. only for the root user, only outside the
# approved regions - leaves the action allowed for everyone else and must not
# count as coverage (that would be a false PASS).
_EXCEPTION_BOOL_KEYS = {'aws:principalisawsservice', 'aws:viaawsservice'}


def _baseOperator(op):
    op = str(op).lower()
    for prefix in ('forallvalues:', 'foranyvalue:'):
        if op.startswith(prefix):
            op = op[len(prefix):]
    if op.endswith('ifexists'):
        op = op[:-len('ifexists')]
    return op


def denyIsUnconditionalGuardrail(stmt):
    """True when the Deny applies to everyone except explicit exceptions."""
    cond = stmt.get('Condition')
    if not cond:
        return True
    if not isinstance(cond, dict):
        return False
    for (op, key), vals in conditionKeys(stmt).items():
        base = _baseOperator(op)
        if key == 'aws:requestedregion':
            return False
        if base.startswith('stringnot') or base.startswith('arnnot'):
            continue
        if base == 'bool' and key in _EXCEPTION_BOOL_KEYS and all(v.lower() == 'false' for v in vals):
            continue
        return False
    return True


def guardrailCoverage(policies, requirements):
    """Evaluate attached customer SCPs against guardrail requirements.

    policies:     [{'Name', 'Content'}] (customer SCPs that are attached)
    requirements: [(label, [[alt, alt...], [alt...]])] - a guardrail is met
                  when every inner list has at least one action denied.
    Returns {'met': {label: set(policyNames)}, 'missing': [label],
             'conditional': {label: set(policyNames)}, 'unparsed': [names]}
    """
    deniedBy, condBy, unparsed = {}, {}, []
    allActions = {a for _, reqs in requirements for alts in reqs for a in alts}
    for p in policies:
        if p.get('Content') is None:
            unparsed.append(p.get('Name'))
            continue
        for s in statements(p['Content']):
            for a in allActions:
                if denyCoversAction(s, a):
                    target = deniedBy if denyIsUnconditionalGuardrail(s) else condBy
                    target.setdefault(a, set()).add(p.get('Name'))
    met, missing, conditional = {}, [], {}
    for label, reqs in requirements:
        if all(any(a in deniedBy for a in alts) for alts in reqs):
            met[label] = set().union(*[deniedBy[a] for alts in reqs for a in alts if a in deniedBy])
        else:
            missing.append(label)
            names = set().union(*([condBy[a] for alts in reqs for a in alts if a in condBy] or [set()]))
            if names:
                conditional[label] = names
    return {'met': met, 'missing': missing, 'conditional': conditional, 'unparsed': unparsed}

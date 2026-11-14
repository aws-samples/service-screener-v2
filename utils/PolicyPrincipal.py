"""
Shared helpers for evaluating wildcard / public principals in AWS resource
policies (S3 bucket policies, SQS queue policies, Glue Data Catalog resource
policies, Lambda function policies, ...).

IAM accepts a principal value either as a single string or as a list of
strings, so {"AWS": "*"} and {"AWS": ["*"]} grant identical access. Checks
must therefore never compare a principal value against "*" with ``==`` alone.

A statement is treated as public when it is an Allow statement whose
principal is a wildcard (or which uses NotPrincipal), and which is not
restricted by a recognised scoping Condition such as aws:PrincipalOrgID or
aws:SourceArn. Condition evaluation is deliberately conservative: anything
that cannot be shown to restrict the caller (IfExists / negated / ForAllValues
operators, wildcard-only values, unrelated keys) is treated as NOT scoping, so
the check errs toward reporting public access rather than hiding it.

Known limitation: Deny statements are not used to subtract from Allow
statements. A policy that pairs a public Allow with a broad Deny may still be
reported as public.
"""
import fnmatch
import json

# Condition keys that bind the caller to a known account, organisation,
# source resource or network path. Compared case-insensitively.
SCOPING_CONDITION_KEYS = frozenset(k.lower() for k in (
    'aws:PrincipalOrgID',
    'aws:PrincipalOrgPaths',
    'aws:PrincipalAccount',
    'aws:PrincipalArn',
    'aws:SourceAccount',
    'aws:SourceArn',
    'aws:SourceOwner',
    'aws:SourceOrgID',
    'aws:SourceOrgPaths',
    'aws:SourceVpc',
    'aws:SourceVpce',
))

# Positive-match operators that restrict the key to a known set of values.
# Negated operators, IfExists variants and ForAllValues are excluded because
# they can evaluate to true for callers that do not carry the key at all.
SCOPING_OPERATORS = frozenset(o.lower() for o in (
    'StringEquals',
    'StringEqualsIgnoreCase',
    'StringLike',
    'ArnEquals',
    'ArnLike',
))


def parsePolicy(doc):
    """Return the policy as a dict, or None if it cannot be parsed."""
    if isinstance(doc, (str, bytes)):
        if not doc:
            return None
        try:
            doc = json.loads(doc)
        except (ValueError, TypeError):
            return None
    return doc if isinstance(doc, dict) else None


def iterStatements(doc):
    """Return the list of statement dicts in a policy (str or dict)."""
    policy = parsePolicy(doc)
    if policy is None:
        return []
    stmts = policy.get('Statement', [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return []
    return [s for s in stmts if isinstance(s, dict)]


def _asList(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def principalIsWildcard(principal):
    """
    True if the Principal grants access to any identity:
    "*", {"AWS": "*"}, {"AWS": ["*"]}, {"AWS": ["arn:...", "*"]}, and the same
    for any other principal type key.
    """
    if principal == '*':
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if '*' in _asList(value):
                return True
    return False


def _valueIsWildcardOnly(value):
    return isinstance(value, str) and value != '' and set(value) <= {'*', '?'}


def conditionScopes(condition):
    """
    True if the Condition block contains at least one positive-match operator
    on a scoping key with a concrete (non-wildcard) value.
    """
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(block, dict) or not isinstance(operator, str):
            continue
        op = operator.lower()
        if op.startswith('forallvalues:'):
            continue
        if op.startswith('foranyvalue:'):
            op = op[len('foranyvalue:'):]
        if op not in SCOPING_OPERATORS:
            continue
        for key, value in block.items():
            if str(key).lower() not in SCOPING_CONDITION_KEYS:
                continue
            values = _asList(value)
            if values and not any(_valueIsWildcardOnly(v) for v in values):
                return True
    return False


def statementIsPublic(statement):
    """
    True if the statement is an Allow that applies to any principal and is not
    restricted by a scoping Condition.
    """
    if not isinstance(statement, dict):
        return False
    if str(statement.get('Effect', '')).lower() != 'allow':
        return False
    # Allow + NotPrincipal grants access to everyone except the listed principals.
    wildcard = principalIsWildcard(statement.get('Principal')) or 'NotPrincipal' in statement
    if not wildcard:
        return False
    return not conditionScopes(statement.get('Condition'))


def statementAllowsAction(statement, targetActions):
    """
    True if the statement's Action (or NotAction) covers any of targetActions,
    honouring IAM wildcards (e.g. "s3:*", "*", "s3:Get*"). Case-insensitive.
    """
    targets = [t.lower() for t in targetActions]

    if 'NotAction' in statement:
        excluded = [str(a).lower() for a in _asList(statement.get('NotAction'))]
        return any(not any(fnmatch.fnmatchcase(t, p) for p in excluded) for t in targets)

    patterns = [str(a).lower() for a in _asList(statement.get('Action'))]
    return any(fnmatch.fnmatchcase(t, p) for t in targets for p in patterns)


def policyIsPublic(doc, targetActions=None):
    """
    True if any statement in the policy is public. If targetActions is given,
    the public statement must also allow at least one of those actions.
    """
    for stmt in iterStatements(doc):
        if not statementIsPublic(stmt):
            continue
        if targetActions is None or statementAllowsAction(stmt, targetActions):
            return True
    return False

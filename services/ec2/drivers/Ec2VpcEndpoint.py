from services.Evaluator import Evaluator
from utils.PolicyPrincipal import iterStatements, parsePolicy, principalIsWildcard

# Data-perimeter condition keys that bind the caller or the target resource to
# this organization / known accounts. Compared case-insensitively.
PERIMETER_KEYS = frozenset(k.lower() for k in (
    'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths', 'aws:PrincipalAccount',
    'aws:ResourceOrgID', 'aws:ResourceOrgPaths', 'aws:ResourceAccount',
))

ALLOW_OPERATORS = frozenset(o.lower() for o in ('StringEquals', 'StringEqualsIgnoreCase', 'StringLike'))
DENY_OPERATORS = frozenset(o.lower() for o in (
    'StringNotEquals', 'StringNotEqualsIgnoreCase', 'StringNotLike',
    'StringNotEqualsIfExists', 'StringNotEqualsIgnoreCaseIfExists', 'StringNotLikeIfExists',
))

INACTIVE_STATES = ('deleting', 'deleted', 'rejected', 'failed', 'expired')


def _asList(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _concrete(values):
    vals = _asList(values)
    return bool(vals) and not any(isinstance(v, str) and set(v) <= {'*', '?'} for v in vals)


def _perimeterCondition(condition, operators):
    if not isinstance(condition, dict):
        return False
    for op, block in condition.items():
        if not isinstance(op, str) or not isinstance(block, dict):
            continue
        o = op.lower()
        if o.startswith('foranyvalue:'):
            o = o[len('foranyvalue:'):]
        if o not in operators:
            continue
        for k, v in block.items():
            if str(k).lower() in PERIMETER_KEYS and _concrete(v):
                return True
    return False


def _coversEverything(stmt):
    """Principal '*', Action '*' and Resource '*' (or no Resource)."""
    if not principalIsWildcard(stmt.get('Principal')):
        return False
    actions = [str(a) for a in _asList(stmt.get('Action'))]
    if not any(a in ('*', '*:*') for a in actions):
        return False
    resources = _asList(stmt.get('Resource'))
    if 'Resource' in stmt and '*' not in resources:
        return False
    return 'NotResource' not in stmt


def _isFullAccess(stmt):
    return str(stmt.get('Effect', '')).lower() == 'allow' and _coversEverything(stmt)


def _isPerimeterDeny(stmt):
    """Deny on every action/resource for callers or resources outside the perimeter."""
    return (str(stmt.get('Effect', '')).lower() == 'deny' and _coversEverything(stmt)
            and _perimeterCondition(stmt.get('Condition'), DENY_OPERATORS))


def evaluateEndpointPolicy(doc):
    """[status, message] for a VPC endpoint policy document."""
    if parsePolicy(doc) is None:
        return [0, 'Unable to evaluate (policy document not returned or not parseable)']
    stmts = iterStatements(doc)
    # A Deny on callers / resources outside the perimeter restricts every Allow.
    if any(_isPerimeterDeny(s) for s in stmts):
        return [1, 'Restricted by a data-perimeter Deny statement']
    open_ = [s for s in stmts if _isFullAccess(s) and not _perimeterCondition(s.get('Condition'), ALLOW_OPERATORS)]
    if open_:
        return [-1, 'Full-access policy (Principal "*", Action "*", Resource "*") without an organization/account condition']
    return [1, 'Policy is scoped']


class Ec2VpcEndpoint(Evaluator):
    """VPC endpoints for services that support endpoint policies should not keep
    the default full-access policy (data perimeter).
      policySupported - VpcEndpointPolicySupported from DescribeVpcEndpointServices,
                        or None when the service details could not be read."""

    def __init__(self, endpoint, policySupported, lookupError=None):
        super().__init__()
        self.endpoint = endpoint
        self.policySupported = policySupported
        self.lookupError = lookupError

        self._resourceName = endpoint['VpcEndpointId']

        self.init()

    def _checkVpcEndpointPolicyFullAccess(self):
        key = 'vpcEndpointPolicyFullAccess'
        ep = self.endpoint
        if str(ep.get('State', '')).lower() in INACTIVE_STATES:
            return
        epType = ep.get('VpcEndpointType', '')
        svc = ep.get('ServiceName') or ''
        label = f"{epType} endpoint {svc}".strip()

        if epType not in ('Gateway', 'Interface') or not svc:
            self.results[key] = [0, f"{label}: endpoint type does not use an endpoint policy"]
            return
        if self.policySupported is False:
            self.results[key] = [0, f"{label}: service does not support endpoint policies"]
            return

        status, msg = evaluateEndpointPolicy(ep.get('PolicyDocument'))
        if status == -1 and self.policySupported is None:
            self.results[key] = [0, f"Unable to evaluate ({self.lookupError or 'endpoint service details not readable'}); {label}: {msg}"]
            return
        self.results[key] = [status, f"{label}: {msg}"]

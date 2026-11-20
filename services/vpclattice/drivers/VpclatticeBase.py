import fnmatch

import botocore

from services.Evaluator import Evaluator
from utils import PolicyPrincipal as pp


class VpclatticeBase(Evaluator):
    """
    Shared logic for VPC Lattice service networks and services.

    Both resource types carry an authType (NONE | AWS_IAM), an optional auth
    policy (get_auth_policy) and optional access log subscriptions
    (list_access_log_subscriptions). Subclasses set:
      self.resource      -- get_service_network / get_service output
      self.kindLabel     -- 'service network' / 'service'
    All calls here are read-only.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    INVOKE_ACTIONS = ['vpc-lattice-svcs:Invoke']

    def __init__(self, resource, client, accountId=None):
        super().__init__()
        self.resource = resource or {}
        self.client = client
        self.accountId = accountId
        self.identifier = self.resource.get('arn') or self.resource.get('id')
        name = self.resource.get('name') or self.resource.get('id') or 'unknown'
        ## list_services / list_service_networks also return RAM-shared resources,
        ## whose names can collide with local ones. Qualify shared resources with
        ## the owner account so results and checkpoints never overwrite each other.
        self._resourceName = f"{name}@{self._ownerAccount()}" if self._sharedFromOtherAccount() else name
        self.addII('id', self.resource.get('id'))
        self.addII('authType', self.resource.get('authType'))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def _ownerAccount(self):
        arn = self.resource.get('arn') or ''
        parts = arn.split(':')
        return parts[4] if len(parts) > 5 else None

    def _sharedFromOtherAccount(self):
        owner = self._ownerAccount()
        return bool(owner and self.accountId and owner != self.accountId)

    def _listAccessLogSubscriptions(self, identifier):
        """Return the list of subscriptions, or raise ClientError."""
        items = []
        paginator = self.client.get_paginator('list_access_log_subscriptions')
        for page in paginator.paginate(resourceIdentifier=identifier):
            items += page.get('items', []) or []
        return items

    @staticmethod
    def _coversServiceTraffic(subscriptions):
        """serviceNetworkLogType RESOURCE captures resource-configuration
        traffic only. Subscriptions without the field (services, and service
        networks created before resource logging existed) log service traffic."""
        return [s for s in subscriptions
                if (s.get('serviceNetworkLogType') or 'SERVICE') == 'SERVICE']

    # Condition keys that are only present in the request context of an
    # authenticated (SigV4-signed) caller. An anonymous caller has none of them.
    IDENTITY_KEYS = (
        'aws:principalorgid', 'aws:principalaccount', 'aws:principalarn',
        'aws:principalorgpaths', 'aws:userid', 'aws:username',
    )
    IDENTITY_KEY_PREFIXES = ('aws:principaltag/',)
    # Positive operators: evaluate false when the key is missing.
    POSITIVE_OPS = (
        'stringequals', 'stringequalsignorecase', 'stringlike',
        'arnequals', 'arnlike',
    )
    NEGATED_STRING_OPS = ('stringnotequals', 'stringnotequalsignorecase', 'stringnotlike')

    @classmethod
    def _isIdentityKey(cls, key):
        k = str(key).lower()
        return k in cls.IDENTITY_KEYS or k.startswith(cls.IDENTITY_KEY_PREFIXES)

    @staticmethod
    def _normaliseOp(operator):
        """Return (baseOperator, missingKeyIsTrue) for a condition operator.
        ForAllValues: and ...IfExists evaluate true when the key is missing, so
        they never exclude an anonymous caller."""
        op = str(operator).lower()
        missingTrue = False
        if op.startswith('forallvalues:'):
            op, missingTrue = op[len('forallvalues:'):], True
        elif op.startswith('foranyvalue:'):
            op = op[len('foranyvalue:'):]
        if op.endswith('ifexists'):
            op, missingTrue = op[:-len('ifexists')], True
        return op, missingTrue

    @staticmethod
    def _anonymousTypeMatches(op, values):
        """Would aws:PrincipalType == 'Anonymous' satisfy the positive string
        operator op with these values?"""
        for v in values:
            v = str(v)
            if op == 'stringequals' and v == 'Anonymous':
                return True
            if op == 'stringequalsignorecase' and v.lower() == 'anonymous':
                return True
            if op == 'stringlike' and fnmatch.fnmatchcase('Anonymous', v):
                return True
        return False

    @classmethod
    def _clauseExcludesAnonymous(cls, operator, key, value):
        """True if this single (operator, key, value) clause can never be
        satisfied by an anonymous (unsigned) request."""
        op, missingTrue = cls._normaliseOp(operator)
        values = value if isinstance(value, list) else [value]
        k = str(key).lower()

        if k == 'aws:principaltype':
            # Present for anonymous callers with value 'Anonymous'.
            if str(operator).lower().startswith('forallvalues:'):
                return False
            if op in ('stringequals', 'stringequalsignorecase', 'stringlike'):
                return bool(values) and not cls._anonymousTypeMatches(op, values)
            if op in cls.NEGATED_STRING_OPS:
                posOp = {'stringnotequals': 'stringequals',
                         'stringnotequalsignorecase': 'stringequalsignorecase',
                         'stringnotlike': 'stringlike'}[op]
                return cls._anonymousTypeMatches(posOp, values)
            return False

        if not cls._isIdentityKey(k) or missingTrue:
            return False
        if op in cls.POSITIVE_OPS:
            return bool(values)
        if op == 'null':
            # {"Null": {"aws:PrincipalArn": "false"}} requires the key to exist.
            return any(str(v).lower() == 'false' for v in values)
        # Negated operators (StringNotEquals, ArnNotLike, ...) evaluate true
        # when the key is missing, so anonymous callers satisfy them.
        return False

    @classmethod
    def _clauseMatchesAnonymous(cls, operator, key, value):
        """True if this clause is definitely satisfied by every anonymous
        request (used to recognise Deny statements that block anonymous)."""
        op, missingTrue = cls._normaliseOp(operator)
        values = value if isinstance(value, list) else [value]
        k = str(key).lower()
        if k == 'aws:principaltype':
            if str(operator).lower().startswith('forallvalues:'):
                return False
            if op in ('stringequals', 'stringequalsignorecase', 'stringlike'):
                return cls._anonymousTypeMatches(op, values)
            if op in cls.NEGATED_STRING_OPS:
                posOp = {'stringnotequals': 'stringequals',
                         'stringnotequalsignorecase': 'stringequalsignorecase',
                         'stringnotlike': 'stringlike'}[op]
                return bool(values) and not cls._anonymousTypeMatches(posOp, values)
            return False
        if not cls._isIdentityKey(k):
            return False
        if op in ('stringnotequals', 'stringnotequalsignorecase', 'stringnotlike',
                  'arnnotequals', 'arnnotlike'):
            return True  # key missing -> negated operator is true
        if missingTrue and op in cls.POSITIVE_OPS:
            return True  # ...IfExists with key missing -> true
        if op == 'null':
            return bool(values) and all(str(v).lower() == 'true' for v in values)
        return False

    @classmethod
    def conditionExcludesAnonymous(cls, condition):
        """Condition blocks are ANDed: one clause that anonymous callers can
        never satisfy is enough to exclude them. Keys anonymous callers can
        satisfy (vpc-lattice-svcs:SourceVpc, SourceVpcOwnerAccount,
        ServiceNetworkArn, ServiceArn, aws:SourceIp, ...) do not exclude them."""
        if not isinstance(condition, dict):
            return False
        for operator, block in condition.items():
            if not isinstance(block, dict):
                continue
            for key, value in block.items():
                if cls._clauseExcludesAnonymous(operator, key, value):
                    return True
        return False

    @classmethod
    def conditionMatchesAnonymous(cls, condition):
        """True if every clause is satisfied by any anonymous request
        (an absent/empty Condition matches everyone)."""
        if not condition:
            return True
        if not isinstance(condition, dict):
            return False
        if not all(isinstance(b, dict) for b in condition.values()):
            return False
        clauses = [(op, k, v) for op, block in condition.items() for k, v in block.items()]
        return all(cls._clauseMatchesAnonymous(op, k, v) for op, k, v in clauses)

    @staticmethod
    def _resourceIsWildcard(stmt):
        if 'NotResource' in stmt:
            return False
        res = stmt.get('Resource', '*')
        res = res if isinstance(res, list) else [res]
        return '*' in res

    @classmethod
    def anonymousDenyStatements(cls, policyDoc):
        """Deny statements that deny vpc-lattice-svcs:Invoke on every resource
        to every anonymous caller (e.g. Deny when aws:PrincipalType is
        Anonymous, or Deny when StringNotEquals aws:PrincipalOrgID)."""
        out = []
        for stmt in pp.iterStatements(policyDoc):
            if str(stmt.get('Effect', '')).lower() != 'deny':
                continue
            if 'NotPrincipal' in stmt or not pp.principalIsWildcard(stmt.get('Principal')):
                continue
            if 'NotAction' in stmt:
                continue
            if not pp.statementAllowsAction(stmt, cls.INVOKE_ACTIONS):
                continue
            if not cls._resourceIsWildcard(stmt):
                continue
            if cls.conditionMatchesAnonymous(stmt.get('Condition')):
                out.append(stmt)
        return out

    @classmethod
    def anonymousAllowStatements(cls, policyDoc):
        """Allow statements that let anonymous (unsigned) callers invoke:
        wildcard principal (or NotPrincipal), an action covering
        vpc-lattice-svcs:Invoke, and no Condition clause that anonymous
        callers are unable to satisfy. Network-scoped conditions such as
        vpc-lattice-svcs:SourceVpc still admit anonymous callers from that VPC.
        Returns [] when a Deny statement blocks all anonymous callers."""
        out = []
        for stmt in pp.iterStatements(policyDoc):
            if str(stmt.get('Effect', '')).lower() != 'allow':
                continue
            if not (pp.principalIsWildcard(stmt.get('Principal')) or 'NotPrincipal' in stmt):
                continue
            if cls.conditionExcludesAnonymous(stmt.get('Condition')):
                continue
            if pp.statementAllowsAction(stmt, cls.INVOKE_ACTIONS):
                out.append(stmt)
        if out and cls.anonymousDenyStatements(policyDoc):
            return []
        return out

    # ------------------------------------------------------------------ #
    # Auth type
    # ------------------------------------------------------------------ #
    def _evaluateAuthType(self):
        key = 'latticeAuthTypeNone'
        label = self.kindLabel
        authType = self.resource.get('authType')

        if self._sharedFromOtherAccount():
            self.results[key] = [0, f"Shared from account {self._ownerAccount()}; evaluate in the owner account"]
            return
        if not authType:
            self.results[key] = [0, 'Unable to evaluate (authType not returned)']
            return
        if authType == 'NONE':
            self.results[key] = [
                -1,
                f"The {label} has authType NONE: any caller in a VPC connected to the "
                "service network can send unauthenticated, unauthorised requests at this layer"
            ]
            return
        if authType != 'AWS_IAM':
            self.results[key] = [0, f'Unable to evaluate (unknown authType {authType})']
            return

        try:
            resp = self.client.get_auth_policy(resourceIdentifier=self.identifier)
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if code == 'ResourceNotFoundException':
                self.results[key] = [
                    1,
                    f"AWS_IAM is enforced and no auth policy is attached, so every request to "
                    f"the {label} is denied by default"
                ]
            else:
                self.results[key] = [0, f'Unable to evaluate ({code})']
            return

        policy = resp.get('policy')
        if not policy:
            self.results[key] = [
                1,
                f"AWS_IAM is enforced and the auth policy is empty, so every request to the "
                f"{label} is denied by default"
            ]
            return
        if pp.parsePolicy(policy) is None:
            self.results[key] = [0, 'Unable to evaluate (auth policy could not be parsed)']
            return

        anon = self.anonymousAllowStatements(policy)
        if anon:
            sids = ', '.join(str(s.get('Sid', '(no Sid)')) for s in anon[:3])
            self.results[key] = [
                -1,
                f"authType is AWS_IAM but the auth policy allows Principal \"*\" to invoke without a "
                f"condition that requires an authenticated principal (statement {sids}), so anonymous "
                "(unsigned) callers are admitted - equivalent to NONE for those requests"
            ]
            return
        self.results[key] = [1, 'AWS_IAM is enforced with an auth policy that does not allow anonymous callers']

    # ------------------------------------------------------------------ #
    # Access logs
    # ------------------------------------------------------------------ #
    def _ownAccessLogs(self):
        """Return (subscriptions, None) or (None, errorCode)."""
        try:
            return self._listAccessLogSubscriptions(self.identifier), None
        except botocore.exceptions.ClientError as e:
            return None, self._errCode(e)

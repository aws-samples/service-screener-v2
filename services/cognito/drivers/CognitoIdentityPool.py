from services.Evaluator import Evaluator


class CognitoIdentityPool(Evaluator):
    """
    Checks for Amazon Cognito identity pools (Cognito Federated Identities).

    Input:
      pool -- output of cognito-identity DescribeIdentityPool with injected fields:
              pool['_roles']             -- GetIdentityPoolRoles response
                                            ({'Roles': {...}, 'RoleMappings': {...}}),
                                            or None when it could not be read
              pool['_rolesError']        -- error code when GetIdentityPoolRoles failed
              pool['_principalTagMaps']  -- {providerName: {'UseDefaults', 'PrincipalTags'}
                                            | None (not configured)
                                            | {'_error': code}}
              pool['_unauthRole']        -- role evaluation data for the
                                            unauthenticated role (see
                                            Cognito._fetchRoleEvaluation), or None
                                            when no unauthenticated role is set.
              pool['_resourceName']      -- unique display id (name + id)
              pool['_describeError']     -- error code when DescribeIdentityPool failed
    """

    # AWS managed policies that grant broad access by name (admin, and the
    # account-wide read / view job-function policies: anonymous read of every
    # service's data or configuration).
    BROAD_MANAGED_POLICY_NAMES = ('AdministratorAccess', 'PowerUserAccess', 'ReadOnlyAccess',
                                  'ViewOnlyAccess', 'SecurityAudit')

    def __init__(self, pool):
        super().__init__()
        self.pool = pool
        self._resourceName = pool.get('_resourceName') or pool.get('IdentityPoolId') or 'unknown'

        self.addII('name', pool.get('IdentityPoolName', 'N/A'))
        self.addII('identityPoolId', pool.get('IdentityPoolId', 'N/A'))
        self.addII('allowUnauthenticatedIdentities', bool(pool.get('AllowUnauthenticatedIdentities')))
        self.addII('allowClassicFlow', bool(pool.get('AllowClassicFlow')))
        self.addII('loginProviderCount', len(self.loginProviders(pool)))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def loginProviders(pool):
        """Return the distinct identity-provider names configured on the pool
        (the names used by principal tag maps).

        Several app clients of one Cognito user pool share one ProviderName
        and are one sign-in source (one user directory), so they are counted
        once."""
        out = []
        for p in pool.get('CognitoIdentityProviders') or []:
            name = p.get('ProviderName')
            if name:
                out.append(name)
        out.extend((pool.get('SupportedLoginProviders') or {}).keys())
        out.extend(pool.get('OpenIdConnectProviderARNs') or [])
        out.extend(pool.get('SamlProviderARNs') or [])
        if pool.get('DeveloperProviderName'):
            out.append(pool['DeveloperProviderName'])
        seen, uniq = set(), []
        for n in out:
            if n not in seen:
                seen.add(n)
                uniq.append(n)
        return uniq

    @staticmethod
    def userPoolClientProviders(pool):
        """{providerName: ['<providerName>:<clientId>', ...]} for Cognito user
        pool providers - the client-qualified form used as role-mapping keys,
        tried as an alternative name for principal tag maps."""
        out = {}
        for p in pool.get('CognitoIdentityProviders') or []:
            name, cid = p.get('ProviderName'), p.get('ClientId')
            if name and cid:
                out.setdefault(name, [])
                q = f"{name}:{cid}"
                if q not in out[name]:
                    out[name].append(q)
        return out

    @staticmethod
    def _asList(v):
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    # Policy variables that make a resource / condition specific to the caller's
    # own Cognito identity (the documented per-identity least-privilege pattern).
    IDENTITY_VARS = ('${cognito-identity.amazonaws.com:sub}',)

    @classmethod
    def _mentionsIdentityVar(cls, value):
        if isinstance(value, str):
            return any(v in value for v in cls.IDENTITY_VARS)
        if isinstance(value, dict):
            return any(cls._mentionsIdentityVar(v) for v in value.values())
        if isinstance(value, list):
            return any(cls._mentionsIdentityVar(v) for v in value)
        return False

    # Condition keys that confine a request to the caller's own data when their
    # value is the caller's identity id (documented per-identity patterns).
    PER_IDENTITY_KEYS = ('dynamodb:leadingkeys', 's3:prefix')

    @classmethod
    def _conditionKeyedOnIdentity(cls, cond):
        """True when the Condition confines the caller to its own identity: a
        positive string match (StringEquals / StringLike / StringEqualsIgnoreCase,
        plain or ForAnyValue:) on a known per-identity key (dynamodb:LeadingKeys,
        s3:prefix) whose every value is ${cognito-identity.amazonaws.com:sub}-based.

        - Negated (StringNot*) and ...IfExists operators do not confine the caller.
        - ForAllValues: evaluates to true when the key is absent from the request
          (e.g. dynamodb:DeleteTable / Scan carry no LeadingKeys), so it only
          counts when the same Condition also has Null {key: 'false'}.
        - Other keys (e.g. cognito-identity.amazonaws.com:sub itself, or keys the
          caller controls) are not accepted."""
        if not isinstance(cond, dict):
            return False
        nullFalse = set()
        for op, kv in cond.items():
            if str(op).lower() == 'null' and isinstance(kv, dict):
                for k, v in kv.items():
                    vals = cls._asList(v)
                    if vals and all(str(x).lower() == 'false' for x in vals):
                        nullFalse.add(str(k).lower())
        for op, kv in cond.items():
            if not isinstance(kv, dict):
                continue
            parts = str(op).split(':')
            if len(parts) > 2:
                continue
            qualifier = parts[0].lower() if len(parts) == 2 else ''
            base = parts[-1]
            if base not in ('StringEquals', 'StringLike', 'StringEqualsIgnoreCase'):
                continue
            if qualifier not in ('', 'foranyvalue', 'forallvalues'):
                continue
            for k, v in kv.items():
                key = str(k).lower()
                if key not in cls.PER_IDENTITY_KEYS:
                    continue
                if qualifier == 'forallvalues' and key not in nullFalse:
                    continue
                vals = cls._asList(v)
                if vals and all(isinstance(x, str) and cls._mentionsIdentityVar(x) for x in vals):
                    return True
        return False

    @staticmethod
    def _isUnscopedResource(r):
        """'*' or an ARN whose resource part is only '*' (e.g. arn:aws:s3:::*)."""
        if not isinstance(r, str):
            return True
        r = r.strip()
        if r == '*':
            return True
        parts = r.split(':', 5)
        return len(parts) == 6 and parts[5] in ('*', '*/*')

    @classmethod
    def resourceScope(cls, stmt):
        """'unscoped'    -- Resource '*' (or equivalent), NotResource, or no Resource
           'perIdentity' -- every Resource (or a Condition) is keyed on the caller's
                            ${cognito-identity.amazonaws.com:sub}
           'shared'      -- specific resources shared by every identity"""
        if 'NotResource' in stmt:
            return 'unscoped'
        res = cls._asList(stmt.get('Resource'))
        if not res or any(cls._isUnscopedResource(r) for r in res):
            ## A condition keyed on the identity still confines the caller to its own data
            ## (e.g. dynamodb:LeadingKeys = ${cognito-identity.amazonaws.com:sub}).
            if cls._conditionKeyedOnIdentity(stmt.get('Condition')):
                return 'perIdentity'
            return 'unscoped'
        if all(cls._mentionsIdentityVar(r) for r in res) or cls._conditionKeyedOnIdentity(stmt.get('Condition')):
            return 'perIdentity'
        return 'shared'

    @staticmethod
    def _isServiceWildcard(a):
        """'*', '<svc>:*' (or ':**'), or a colon-less glob such as 's3*' (IAM
        globbing matches every action of the service)."""
        if not isinstance(a, str):
            return False
        s = a.strip()
        if not s:
            return False
        if ':' not in s:
            return s.endswith('*')
        if s.count(':') != 1:
            return False
        name = s.split(':', 1)[1]
        return bool(name) and set(name) == {'*'}

    @staticmethod
    def _actionService(a):
        """Lower-cased service prefix of a wildcard action, or None for an
        all-services pattern ('*', '*:*')."""
        s = a.strip().lower()
        svc = (s.split(':', 1)[0] if ':' in s else s).rstrip('*')
        return svc or None

    @classmethod
    def denyLimits(cls, docs):
        """Collect unconditional Deny statements on Resource '*' across a role's policies.

        Returns {'all': bool, 'services': {svc}, 'notActionCaps': [[action, ...], ...]}:
          all            -- Deny Action '*' (nothing is allowed)
          services       -- Deny '<svc>:*' (that service is not allowed)
          notActionCaps  -- Deny NotAction [...]: only those actions remain allowed
        Conditional or resource-scoped Deny statements are ignored (conservative)."""
        out = {'all': False, 'services': set(), 'notActionCaps': []}
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            for stmt in cls._asList(doc.get('Statement')):
                if not isinstance(stmt, dict) or stmt.get('Effect') != 'Deny':
                    continue
                if stmt.get('Condition') or 'NotResource' in stmt:
                    continue
                if not any(r == '*' for r in cls._asList(stmt.get('Resource'))):
                    continue
                if 'NotAction' in stmt:
                    out['notActionCaps'].append([a for a in cls._asList(stmt['NotAction']) if isinstance(a, str)])
                    continue
                for a in cls._asList(stmt.get('Action')):
                    if not isinstance(a, str):
                        continue
                    a = a.strip().lower()
                    if a == '*':
                        out['all'] = True
                    elif a.endswith(':*') and a.count(':') == 1:
                        out['services'].add(a[:-2])
        return out

    @classmethod
    def _stillBroad(cls, action, limits):
        """Is an allowed wildcard ('*', '<svc>:*' or a NotAction allow, given as '*')
        still a wildcard after the role's unconditional Deny statements?"""
        if limits['all']:
            return False
        svc = cls._actionService(action)
        if svc and svc in limits['services']:
            return False
        for cap in limits['notActionCaps']:
            ## Only actions listed in the Deny NotAction stay allowed.
            keep = []
            for c in cap:
                if not cls._isServiceWildcard(c):
                    continue
                cs = cls._actionService(c)
                if cs is None or ((svc is None or cs == svc) and cs not in limits['services']):
                    keep.append(c)
            if not keep:
                return False
        return True

    @classmethod
    def policyBroadReasons(cls, doc, limits=None):
        """Return a list of reasons a policy document grants broad access to
        every guest: an Allow statement with Action '*' or '<service>:*', or an
        Allow statement using NotAction, on resources that are not confined to
        the caller's own identity.

        - Partial wildcards (e.g. 's3:Get*') are not treated as broad.
        - Wildcards on resources (or conditions) keyed on
          ${cognito-identity.amazonaws.com:sub} are the documented per-identity
          pattern (e.g. cognito-sync:* on .../identity/${...:sub}/*) and are skipped.
        - Wildcards on specific resources shared by all guests are reported with
          the resource, because any anonymous caller gets every action on them.
        - Unconditional Deny statements on Resource '*' (limits) narrow the allows."""
        reasons = []
        if not isinstance(doc, dict):
            return reasons
        limits = limits or {'all': False, 'services': set(), 'notActionCaps': []}
        for stmt in cls._asList(doc.get('Statement')):
            if not isinstance(stmt, dict) or stmt.get('Effect') != 'Allow':
                continue
            scope = cls.resourceScope(stmt)
            if scope == 'perIdentity':
                continue
            suffix = ''
            if scope == 'shared':
                res = [r for r in cls._asList(stmt.get('Resource')) if isinstance(r, str)]
                suffix = f" on {res[0]}" + (f" (+{len(res) - 1})" if len(res) > 1 else '') + \
                         " (shared by all guests)"
            if 'NotAction' in stmt:
                if cls._stillBroad('*', limits):
                    reasons.append('Allow with NotAction' + suffix)
                continue
            for a in cls._asList(stmt.get('Action')):
                if not cls._isServiceWildcard(a):
                    continue
                a = a.strip()
                if cls._stillBroad(a, limits):
                    reasons.append(f"Action '{a}'" + suffix)
        return reasons

    @classmethod
    def roleBroadReasons(cls, role):
        """Return the list of reasons a role evaluation dict grants broad access."""
        reasons = []
        pols = role.get('policies') or []
        limits = cls.denyLimits([p.get('document') for p in pols])
        for pol in pols:
            name = pol.get('name') or '?'
            if pol.get('managedByAws') and (
                    name in cls.BROAD_MANAGED_POLICY_NAMES or name.endswith('FullAccess')):
                if not limits['all']:
                    reasons.append(f"AWS managed policy {name}")
                continue
            for r in cls.policyBroadReasons(pol.get('document'), limits):
                reasons.append(f"{name}: {r}")
        return reasons

    @classmethod
    def isLegacyDefaultGuestRole(cls, role):
        """The role the Cognito console used to create for guests
        (Cognito_<pool>Unauth_Role: mobileanalytics:PutEvents + cognito-sync:* on '*')."""
        name = role.get('roleName') or ''
        if not (name.startswith('Cognito_') and name.endswith('Unauth_Role')):
            return False
        actions = set()
        for pol in role.get('policies') or []:
            doc = pol.get('document')
            if pol.get('managedByAws') or not isinstance(doc, dict):
                return False
            for stmt in cls._asList(doc.get('Statement')):
                if isinstance(stmt, dict) and stmt.get('Effect') == 'Allow':
                    if 'NotAction' in stmt:
                        return False
                    actions |= {a.strip().lower() for a in cls._asList(stmt.get('Action')) if isinstance(a, str)}
        return bool(actions) and actions <= {'mobileanalytics:putevents', 'cognito-sync:*'}

    # ------------------------------------------------------------------ #
    # Guest (unauthenticated) role is broad
    # ------------------------------------------------------------------ #
    def _checkCognitoIdentityPoolGuestRoleBroad(self):
        key = 'cognitoIdentityPoolGuestRoleBroad'
        if self.pool.get('_describeError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_describeError']})"]
            return
        if not self.pool.get('AllowUnauthenticatedIdentities'):
            self.results[key] = [1, "Unauthenticated (guest) identities are disabled"]
            return
        if self.pool.get('_rolesError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_rolesError']})"]
            return
        role = self.pool.get('_unauthRole')
        if not role:
            self.results[key] = [
                1, "Guest access enabled but no unauthenticated role is set (no credentials issued)"
            ]
            return
        roleName = role.get('roleName') or role.get('roleArn') or '?'
        if role.get('crossAccount'):
            self.results[key] = [
                0, f"Guest role {roleName} belongs to another account and was not evaluated"
            ]
            return
        if role.get('error'):
            self.results[key] = [0, f"Unable to evaluate ({role['error']})"]
            return

        reasons = self.roleBroadReasons(role)
        if not reasons and role.get('policyErrors'):
            self.results[key] = [0, f"Unable to evaluate ({role['policyErrors'][0]})"]
            return
        if not reasons:
            self.results[key] = [
                1, f"Guest role {roleName} has no wildcard / full-access permissions"
            ]
            return

        boundary = role.get('boundary')
        if boundary:
            if boundary.get('error'):
                self.results[key] = [
                    0, f"Guest role {roleName} has broad policies but its permissions boundary "
                       f"could not be read: Unable to evaluate ({boundary['error']})"
                ]
                return
            bReasons = self.roleBroadReasons({'policies': [boundary]})
            if not bReasons:
                self.results[key] = [
                    0, f"Guest role {roleName} has broad policies ({'; '.join(reasons[:3])}) "
                       f"but is capped by permissions boundary {boundary.get('name')}; review"
                ]
                return

        detail = f"{'; '.join(reasons[:3])}" + (f" (+{len(reasons) - 3} more)" if len(reasons) > 3 else "")
        if self.isLegacyDefaultGuestRole(role):
            self.results[key] = [
                -1, f"Anonymous identities receive the legacy console-default guest role {roleName} "
                    f"({detail}): the grant is not limited to the caller's own identity. "
                    "Scope cognito-sync resources to ${cognito-identity.amazonaws.com:sub} or "
                    "remove it"
            ]
            return
        self.results[key] = [
            -1, f"Anonymous identities receive role {roleName} with broad access: {detail}"
        ]

    # ------------------------------------------------------------------ #
    # Several sign-in sources share one authenticated role (no role mapping)
    # ------------------------------------------------------------------ #
    def _checkCognitoIdentityPoolNoRoleMapping(self):
        key = 'cognitoIdentityPoolNoRoleMapping'
        if self.pool.get('_describeError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_describeError']})"]
            return
        if self.pool.get('_rolesError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_rolesError']})"]
            return
        rolesResp = self.pool.get('_roles') or {}
        roles = rolesResp.get('Roles') or {}
        mappings = rolesResp.get('RoleMappings') or {}
        providers = self.loginProviders(self.pool)

        if mappings:
            self.results[key] = [1, f"{len(mappings)} role mapping(s) configured"]
            return

        tagMaps = self.pool.get('_principalTagMaps') or {}
        abac, errors = [], []
        for name, m in tagMaps.items():
            if m is None:
                continue
            if m.get('_error'):
                errors.append(m['_error'])
            elif m.get('UseDefaults') or m.get('PrincipalTags'):
                abac.append(name)
        if abac:
            self.results[key] = [
                1, f"Attribute-based access control (principal tags) configured for "
                   f"{len(abac)} provider(s)"
            ]
            return

        if not roles.get('authenticated'):
            self.results[key] = [0, "No authenticated role or role mapping configured"]
            return
        if len(providers) < 2:
            self.results[key] = [
                0, f"Single sign-in source ({len(providers)}) uses the default authenticated role; "
                   "acceptable when one role fits every user"
            ]
            return
        if errors:
            self.results[key] = [0, f"Unable to evaluate ({errors[0]})"]
            return
        self.results[key] = [
            -1, f"{len(providers)} sign-in sources share the default authenticated role with no "
                "role mapping or principal-tag (ABAC) mapping"
        ]

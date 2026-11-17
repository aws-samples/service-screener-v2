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

    # AWS managed policies that grant broad access by name.
    BROAD_MANAGED_POLICY_NAMES = ('AdministratorAccess', 'PowerUserAccess')

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
        """Return the list of identity-provider names configured on the pool,
        in the form used by role mappings / principal tag maps.

        Cognito user pool providers are listed once per app client (role
        mapping keys are '<provider>:<clientId>'), because each app client is a
        distinct sign-in source."""
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
        return out

    @staticmethod
    def _asList(v):
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    @classmethod
    def policyBroadReasons(cls, doc):
        """Return a list of reasons a policy document grants broad access:
        an Allow statement with Action '*' or '<service>:*', or an Allow
        statement using NotAction. Partial wildcards (e.g. 's3:Get*') are not
        treated as broad."""
        reasons = []
        if not isinstance(doc, dict):
            return reasons
        for stmt in cls._asList(doc.get('Statement')):
            if not isinstance(stmt, dict) or stmt.get('Effect') != 'Allow':
                continue
            if 'NotAction' in stmt:
                reasons.append('Allow with NotAction')
                continue
            for a in cls._asList(stmt.get('Action')):
                if not isinstance(a, str):
                    continue
                a = a.strip()
                if a == '*':
                    reasons.append("Action '*'")
                elif a.endswith(':*') and ':' in a and a.count(':') == 1:
                    reasons.append(f"Action '{a}'")
        return reasons

    @classmethod
    def roleBroadReasons(cls, role):
        """Return the list of reasons a role evaluation dict grants broad access."""
        reasons = []
        for pol in role.get('policies') or []:
            name = pol.get('name') or '?'
            if pol.get('managedByAws') and (
                    name in cls.BROAD_MANAGED_POLICY_NAMES or name.endswith('FullAccess')):
                reasons.append(f"AWS managed policy {name}")
                continue
            for r in cls.policyBroadReasons(pol.get('document')):
                reasons.append(f"{name}: {r}")
        return reasons

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

        self.results[key] = [
            -1, f"Anonymous identities receive role {roleName} with broad access: "
                f"{'; '.join(reasons[:3])}" + (f" (+{len(reasons) - 3} more)" if len(reasons) > 3 else "")
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

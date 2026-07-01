from services.Evaluator import Evaluator


class CognitoCommon(Evaluator):
    """
    All 12 Cognito user-pool checks.

    Input:
      pool -- output of DescribeUserPool with injected fields:
              pool['_tagList']    -- list of {'Key','Value'} (normalised from UserPoolTags dict)
              pool['_appClients'] -- list of UserPoolClient descriptors (each may
                                     contain AccessTokenValidity / IdTokenValidity /
                                     RefreshTokenValidity + TokenValidityUnits).
      cognitoClient -- boto3 cognito-idp client (kept for future extension).
    """

    # Password policy thresholds
    PASSWORD_MIN_LENGTH = 12

    # Token validity thresholds (converted to a common unit for comparison)
    # AWS defaults: access=60 min, id=60 min, refresh=30 days.
    ACCESS_TOKEN_MAX_MINUTES = 60
    ID_TOKEN_MAX_MINUTES = 60
    REFRESH_TOKEN_MAX_MINUTES = 30 * 24 * 60  # 30 days

    # Lambda triggers we consider relevant for auth observability / customisation.
    RELEVANT_LAMBDA_TRIGGERS = (
        'PreSignUp', 'CustomMessage', 'PostConfirmation',
        'PreAuthentication', 'PostAuthentication', 'DefineAuthChallenge',
        'CreateAuthChallenge', 'VerifyAuthChallengeResponse',
        'PreTokenGeneration', 'PreTokenGenerationConfig',
        'UserMigration', 'CustomSMSSender', 'CustomEmailSender',
    )

    def __init__(self, pool, cognitoClient):
        super().__init__()
        self.pool = pool
        self.cognitoClient = cognitoClient

        self._resourceName = pool.get('Name') or pool.get('Id') or 'unknown'

        self.addII('name', pool.get('Name', 'N/A'))
        self.addII('poolId', pool.get('Id', 'N/A'))
        self.addII('arn', pool.get('Arn', 'N/A'))
        self.addII('mfaConfiguration', pool.get('MfaConfiguration', 'OFF'))
        self.addII('deletionProtection', pool.get('DeletionProtection', 'INACTIVE'))
        self.addII('estimatedNumberOfUsers', pool.get('EstimatedNumberOfUsers', 0))
        self.addII('userPoolTier', pool.get('UserPoolTier', 'N/A'))
        self.addII('appClientCount', len(pool.get('_appClients') or []))

    # ------------------------------------------------------------------ #
    # 1. MFA not enforced
    # ------------------------------------------------------------------ #
    def _checkCognitoMfaNotEnforced(self):
        mfa = self.pool.get('MfaConfiguration', 'OFF')
        if mfa == 'ON':
            self.results['cognitoMfaNotEnforced'] = [1, "MfaConfiguration=ON"]
        else:
            self.results['cognitoMfaNotEnforced'] = [
                -1, f"MfaConfiguration={mfa} (should be ON)"
            ]

    # ------------------------------------------------------------------ #
    # 2. Weak password policy
    # ------------------------------------------------------------------ #
    def _checkCognitoWeakPasswordPolicy(self):
        policies = self.pool.get('Policies') or {}
        pw = policies.get('PasswordPolicy') or {}

        if not pw:
            self.results['cognitoWeakPasswordPolicy'] = [
                -1, "No PasswordPolicy present"
            ]
            return

        issues = []
        try:
            minLen = int(pw.get('MinimumLength', 0))
        except (TypeError, ValueError):
            minLen = 0
        if minLen < self.PASSWORD_MIN_LENGTH:
            issues.append(f"MinimumLength={minLen} (< {self.PASSWORD_MIN_LENGTH})")

        for key in ('RequireUppercase', 'RequireLowercase',
                    'RequireNumbers', 'RequireSymbols'):
            if not pw.get(key, False):
                issues.append(f"{key}=false")

        if issues:
            self.results['cognitoWeakPasswordPolicy'] = [
                -1, "Weak password policy: " + ", ".join(issues)
            ]
        else:
            self.results['cognitoWeakPasswordPolicy'] = [
                1, f"MinimumLength={minLen} and all four character classes required"
            ]

    # ------------------------------------------------------------------ #
    # 3. Advanced security not enforced
    # ------------------------------------------------------------------ #
    def _checkCognitoAdvancedSecurityNotEnforced(self):
        addOns = self.pool.get('UserPoolAddOns') or {}
        mode = addOns.get('AdvancedSecurityMode', 'OFF')
        if mode == 'ENFORCED':
            self.results['cognitoAdvancedSecurityNotEnforced'] = [
                1, "AdvancedSecurityMode=ENFORCED"
            ]
        else:
            self.results['cognitoAdvancedSecurityNotEnforced'] = [
                -1, f"AdvancedSecurityMode={mode} (should be ENFORCED)"
            ]

    # ------------------------------------------------------------------ #
    # 4. Deletion protection disabled
    # ------------------------------------------------------------------ #
    def _checkCognitoDeletionProtectionDisabled(self):
        dp = self.pool.get('DeletionProtection', 'INACTIVE')
        if dp == 'ACTIVE':
            self.results['cognitoDeletionProtectionDisabled'] = [
                1, "DeletionProtection=ACTIVE"
            ]
        else:
            self.results['cognitoDeletionProtectionDisabled'] = [
                -1, f"DeletionProtection={dp}"
            ]

    # ------------------------------------------------------------------ #
    # 5. No email / phone verification (AutoVerifiedAttributes empty)
    # ------------------------------------------------------------------ #
    def _checkCognitoNoEmailPhoneVerification(self):
        auto = self.pool.get('AutoVerifiedAttributes') or []
        if auto:
            self.results['cognitoNoEmailPhoneVerification'] = [
                1, f"AutoVerifiedAttributes: {', '.join(auto)}"
            ]
        else:
            self.results['cognitoNoEmailPhoneVerification'] = [
                -1, "AutoVerifiedAttributes is empty (no email/phone verification)"
            ]

    # ------------------------------------------------------------------ #
    # 6. No Lambda triggers for monitoring / customisation
    # ------------------------------------------------------------------ #
    def _checkCognitoNoLambdaTriggers(self):
        lambdaCfg = self.pool.get('LambdaConfig') or {}
        configured = [k for k in self.RELEVANT_LAMBDA_TRIGGERS if lambdaCfg.get(k)]
        if configured:
            self.results['cognitoNoLambdaTriggers'] = [
                1, f"Lambda trigger(s) configured: {', '.join(configured[:5])}"
                + (f" (+{len(configured)-5} more)" if len(configured) > 5 else "")
            ]
        else:
            self.results['cognitoNoLambdaTriggers'] = [
                -1, "LambdaConfig has no auth-time triggers"
            ]

    # ------------------------------------------------------------------ #
    # 7. Account recovery not configured
    # ------------------------------------------------------------------ #
    def _checkCognitoAccountRecoveryNotConfigured(self):
        recovery = self.pool.get('AccountRecoverySetting') or {}
        mechanisms = recovery.get('RecoveryMechanisms') or []
        if mechanisms:
            names = [m.get('Name') for m in mechanisms if m.get('Name')]
            self.results['cognitoAccountRecoveryNotConfigured'] = [
                1, f"{len(mechanisms)} recovery mechanism(s): {', '.join(names)}"
            ]
        else:
            self.results['cognitoAccountRecoveryNotConfigured'] = [
                -1, "AccountRecoverySetting is missing or has no RecoveryMechanisms"
            ]

    # ------------------------------------------------------------------ #
    # 8. Single recovery option (only one mechanism configured)
    # ------------------------------------------------------------------ #
    def _checkCognitoSingleRecoveryOption(self):
        recovery = self.pool.get('AccountRecoverySetting') or {}
        mechanisms = recovery.get('RecoveryMechanisms') or []
        if not mechanisms:
            # Fully unconfigured — covered by #7, avoid double-counting.
            self.results['cognitoSingleRecoveryOption'] = [
                0, "No recovery mechanisms — see cognitoAccountRecoveryNotConfigured"
            ]
            return
        if len(mechanisms) < 2:
            names = [m.get('Name') for m in mechanisms if m.get('Name')]
            self.results['cognitoSingleRecoveryOption'] = [
                -1, f"Only 1 recovery mechanism: {', '.join(names)}"
            ]
        else:
            self.results['cognitoSingleRecoveryOption'] = [
                1, f"{len(mechanisms)} recovery mechanisms configured"
            ]

    # ------------------------------------------------------------------ #
    # 9. Unused user pool (0 estimated users)
    # ------------------------------------------------------------------ #
    def _checkCognitoUnusedUserPool(self):
        try:
            count = int(self.pool.get('EstimatedNumberOfUsers', 0))
        except (TypeError, ValueError):
            count = 0
        if count == 0:
            self.results['cognitoUnusedUserPool'] = [
                -1, "EstimatedNumberOfUsers=0"
            ]
        else:
            self.results['cognitoUnusedUserPool'] = [
                1, f"EstimatedNumberOfUsers={count}"
            ]

    # ------------------------------------------------------------------ #
    # 10. Token validity too long (per-app-client)
    # ------------------------------------------------------------------ #
    def _checkCognitoTokenValidityTooLong(self):
        clients = self.pool.get('_appClients') or []
        if not clients:
            self.results['cognitoTokenValidityTooLong'] = [
                0, "No app clients configured — token validity not applicable"
            ]
            return

        offending = []
        for c in clients:
            issues = self._appClientTokenIssues(c)
            if issues:
                clientName = c.get('ClientName') or c.get('ClientId', 'unknown')
                offending.append(f"{clientName}: {'; '.join(issues)}")

        if offending:
            self.results['cognitoTokenValidityTooLong'] = [
                -1, f"App client(s) with long-lived tokens — "
                + " | ".join(offending[:3])
                + (f" (+{len(offending)-3} more)" if len(offending) > 3 else "")
            ]
        else:
            self.results['cognitoTokenValidityTooLong'] = [
                1, f"All {len(clients)} app client(s) within token-validity thresholds"
            ]

    # ------------------------------------------------------------------ #
    # 11. Device tracking disabled
    # ------------------------------------------------------------------ #
    def _checkCognitoDeviceTrackingDisabled(self):
        dev = self.pool.get('DeviceConfiguration')
        if not dev:
            self.results['cognitoDeviceTrackingDisabled'] = [
                -1, "DeviceConfiguration is not set"
            ]
            return

        # Cognito exposes two flags: ChallengeRequiredOnNewDevice + DeviceOnlyRememberedOnUserPrompt.
        # Device tracking is meaningfully enabled only when ChallengeRequiredOnNewDevice=True.
        if dev.get('ChallengeRequiredOnNewDevice'):
            self.results['cognitoDeviceTrackingDisabled'] = [
                1, "Device tracking enabled (ChallengeRequiredOnNewDevice=True)"
            ]
        else:
            self.results['cognitoDeviceTrackingDisabled'] = [
                -1, "DeviceConfiguration set but ChallengeRequiredOnNewDevice=False"
            ]

    # ------------------------------------------------------------------ #
    # 12. No tags
    # ------------------------------------------------------------------ #
    def _checkCognitoResourcesWithoutTags(self):
        tags = self.pool.get('_tagList') or []
        if not tags:
            self.results['cognitoResourcesWithoutTags'] = [-1, "No tags applied"]
        else:
            keys = [t.get('Key') for t in tags if t.get('Key')]
            self.results['cognitoResourcesWithoutTags'] = [
                1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _appClientTokenIssues(self, client):
        """Return a list of human-readable issues for one app client, or []."""
        issues = []
        units = client.get('TokenValidityUnits') or {}

        access = self._toMinutes(
            client.get('AccessTokenValidity'), units.get('AccessToken', 'hours')
        )
        ident = self._toMinutes(
            client.get('IdTokenValidity'), units.get('IdToken', 'hours')
        )
        refresh = self._toMinutes(
            client.get('RefreshTokenValidity'), units.get('RefreshToken', 'days')
        )

        if access is not None and access > self.ACCESS_TOKEN_MAX_MINUTES:
            issues.append(f"Access={self._humanise(access)}")
        if ident is not None and ident > self.ID_TOKEN_MAX_MINUTES:
            issues.append(f"Id={self._humanise(ident)}")
        if refresh is not None and refresh > self.REFRESH_TOKEN_MAX_MINUTES:
            issues.append(f"Refresh={self._humanise(refresh)}")
        return issues

    @staticmethod
    def _toMinutes(value, unit):
        """Convert a Cognito token-validity value to minutes. Returns None if unset."""
        if value is None:
            return None
        try:
            n = int(value)
        except (TypeError, ValueError):
            return None
        u = (unit or 'hours').lower()
        if u == 'seconds':
            return n // 60
        if u == 'minutes':
            return n
        if u == 'hours':
            return n * 60
        if u == 'days':
            return n * 24 * 60
        # Unknown unit — treat as hours (Cognito API default for access/id).
        return n * 60

    @staticmethod
    def _humanise(minutes):
        if minutes >= 24 * 60:
            days = minutes // (24 * 60)
            return f"{days}d"
        if minutes >= 60:
            hours = minutes // 60
            return f"{hours}h"
        return f"{minutes}m"

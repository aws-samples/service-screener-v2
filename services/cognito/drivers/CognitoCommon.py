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

    # ------------------------------------------------------------------ #
    # 13. Compromised-credentials protection not set to BLOCK
    # ------------------------------------------------------------------ #
    def _checkCognitoCompromisedCredentialProtection(self):
        # If Advanced Security is off entirely, this is not the check to flag —
        # cognitoAdvancedSecurityNotEnforced handles that. Skip here.
        add_ons = self.pool.get('UserPoolAddOns') or {}
        adv_mode = add_ons.get('AdvancedSecurityMode', 'OFF')
        if adv_mode != 'ENFORCED':
            self.results['cognitoCompromisedCredentialProtection'] = [
                0,
                f"Advanced Security is {adv_mode} — see cognitoAdvancedSecurityNotEnforced"
            ]
            return

        risk = self.pool.get('_riskConfiguration')
        if not risk:
            # DescribeRiskConfiguration returned nothing usable — treat as
            # not configured (which is a FAIL, since Advanced Security IS on).
            self.results['cognitoCompromisedCredentialProtection'] = [
                -1,
                "Advanced Security is ENFORCED but no RiskConfiguration is set"
            ]
            return

        cc = risk.get('CompromisedCredentialsRiskConfiguration') or {}
        actions = cc.get('Actions') or {}
        event_action = actions.get('EventAction', 'NO_ACTION')
        if event_action == 'BLOCK':
            self.results['cognitoCompromisedCredentialProtection'] = [
                1, "CompromisedCredentials EventAction=BLOCK"
            ]
        else:
            self.results['cognitoCompromisedCredentialProtection'] = [
                -1,
                f"CompromisedCredentials EventAction={event_action} (should be BLOCK)"
            ]

    # ------------------------------------------------------------------ #
    # 14. Self-service sign-up with no verification
    # ------------------------------------------------------------------ #
    def _checkCognitoSelfServiceSignUpNoVerification(self):
        admin_only = (self.pool.get('AdminCreateUserConfig') or {}).get(
            'AllowAdminCreateUserOnly', False
        )
        # Self-service is enabled when AllowAdminCreateUserOnly is False.
        if admin_only:
            self.results['cognitoSelfServiceSignUpNoVerification'] = [
                1, "Self-service sign-up disabled (admin-only)"
            ]
            return

        verified = self.pool.get('AutoVerifiedAttributes') or []
        if not verified:
            self.results['cognitoSelfServiceSignUpNoVerification'] = [
                -1,
                "Self-service sign-up enabled but AutoVerifiedAttributes is empty "
                "(no email/phone verification)"
            ]
        else:
            self.results['cognitoSelfServiceSignUpNoVerification'] = [
                1,
                f"Self-service sign-up enabled with verification of: "
                f"{', '.join(verified)}"
            ]

    # ------------------------------------------------------------------ #
    # 15. No custom domain (informational)
    # ------------------------------------------------------------------ #
    def _checkCognitoNoCustomDomain(self):
        # describe_user_pool returns:
        #   Domain       -- Cognito prefix on amazoncognito.com (may be blank)
        #   CustomDomain -- fully-qualified custom domain (blank when unset)
        custom = self.pool.get('CustomDomain')
        default = self.pool.get('Domain')

        if custom:
            self.results['cognitoNoCustomDomain'] = [
                1, f"Custom domain: {custom}"
            ]
        elif default:
            self.results['cognitoNoCustomDomain'] = [
                0,
                f"Only default domain configured ({default}.auth.<region>.amazoncognito.com)"
            ]
        else:
            self.results['cognitoNoCustomDomain'] = [
                0, "No hosted-UI domain configured on this user pool"
            ]

    # ------------------------------------------------------------------ #
    # 16. No WAFv2 WebACL associated
    # ------------------------------------------------------------------ #
    def _checkCognitoNoWafAssociation(self):
        arn = self.pool.get('_wafWebAclArn')
        if arn:
            # Show just the WebACL name for readability
            name = arn.split('/')[-2] if '/webacl/' in arn else arn.split('/')[-1]
            self.results['cognitoNoWafAssociation'] = [
                1, f"Associated WebACL: {name}"
            ]
        else:
            self.results['cognitoNoWafAssociation'] = [
                -1, "No WAFv2 WebACL associated with this user pool"
            ]

    # ------------------------------------------------------------------ #
    # Helper: iterate app clients with names for compact reporting
    # ------------------------------------------------------------------ #
    def _appClients(self):
        return self.pool.get('_appClients') or []

    def _clientLabel(self, c):
        return c.get('ClientName') or c.get('ClientId') or '?'

    # ------------------------------------------------------------------ #
    # 17. App client with Implicit grant enabled
    # ------------------------------------------------------------------ #
    def _checkCognitoClientImplicitGrantEnabled(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientImplicitGrantEnabled'] = [
                0, "No app clients"
            ]
            return
        offenders = [
            self._clientLabel(c) for c in clients
            if 'implicit' in [f.lower() for f in (c.get('AllowedOAuthFlows') or [])]
        ]
        if offenders:
            self.results['cognitoClientImplicitGrantEnabled'] = [
                -1, f"App client(s) using Implicit flow: {', '.join(offenders[:5])}"
            ]
        else:
            self.results['cognitoClientImplicitGrantEnabled'] = [
                1, f"{len(clients)} app client(s), none use Implicit flow"
            ]

    # ------------------------------------------------------------------ #
    # 18. App client token revocation disabled
    # ------------------------------------------------------------------ #
    def _checkCognitoClientTokenRevocationDisabled(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientTokenRevocationDisabled'] = [
                0, "No app clients"
            ]
            return
        offenders = [
            self._clientLabel(c) for c in clients
            if c.get('EnableTokenRevocation') is False
        ]
        if offenders:
            self.results['cognitoClientTokenRevocationDisabled'] = [
                -1,
                f"App client(s) with EnableTokenRevocation=false: "
                f"{', '.join(offenders[:5])}"
            ]
        else:
            self.results['cognitoClientTokenRevocationDisabled'] = [
                1, f"All {len(clients)} app client(s) enable token revocation"
            ]

    # ------------------------------------------------------------------ #
    # 19. App client with http:// CallbackURL
    # ------------------------------------------------------------------ #
    @staticmethod
    def _isInsecureHttpUrl(url):
        """True if url is http:// AND the host is not localhost/127.x."""
        if not isinstance(url, str):
            return False
        u = url.lower().strip()
        if not u.startswith('http://'):
            return False
        # Strip scheme + optional port
        host = u[len('http://'):].split('/', 1)[0].split(':', 1)[0]
        if host in ('localhost', '127.0.0.1') or host.startswith('127.'):
            return False
        return True

    def _checkCognitoClientHttpCallbackUrl(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientHttpCallbackUrl'] = [0, "No app clients"]
            return
        offenders = []
        for c in clients:
            for url in (c.get('CallbackURLs') or []):
                if self._isInsecureHttpUrl(url):
                    offenders.append(f"{self._clientLabel(c)}:{url}")
                    break
        if offenders:
            self.results['cognitoClientHttpCallbackUrl'] = [
                -1, f"App client(s) with http:// CallbackURL: {', '.join(offenders[:3])}"
            ]
        else:
            self.results['cognitoClientHttpCallbackUrl'] = [
                1, "No app clients use http:// CallbackURLs"
            ]

    # ------------------------------------------------------------------ #
    # 20. App client with PreventUserExistenceErrors = LEGACY (or missing)
    # ------------------------------------------------------------------ #
    def _checkCognitoClientUserExistenceErrors(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientUserExistenceErrors'] = [0, "No app clients"]
            return
        offenders = [
            self._clientLabel(c) for c in clients
            if (c.get('PreventUserExistenceErrors') or 'LEGACY') != 'ENABLED'
        ]
        if offenders:
            self.results['cognitoClientUserExistenceErrors'] = [
                -1,
                f"App client(s) with PreventUserExistenceErrors!=ENABLED: "
                f"{', '.join(offenders[:5])}"
            ]
        else:
            self.results['cognitoClientUserExistenceErrors'] = [
                1, f"All {len(clients)} app client(s) prevent user-existence errors"
            ]

    # ------------------------------------------------------------------ #
    # 21. App client with insecure auth flow (ALLOW_USER_PASSWORD_AUTH)
    # ------------------------------------------------------------------ #
    def _checkCognitoClientInsecureAuthFlow(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientInsecureAuthFlow'] = [0, "No app clients"]
            return
        offenders = [
            self._clientLabel(c) for c in clients
            if 'ALLOW_USER_PASSWORD_AUTH' in (c.get('ExplicitAuthFlows') or [])
        ]
        if offenders:
            self.results['cognitoClientInsecureAuthFlow'] = [
                -1,
                f"App client(s) allow ALLOW_USER_PASSWORD_AUTH (no SRP): "
                f"{', '.join(offenders[:5])}"
            ]
        else:
            self.results['cognitoClientInsecureAuthFlow'] = [
                1, "No app clients use plain USER_PASSWORD_AUTH"
            ]

    # ------------------------------------------------------------------ #
    # 22. App client with http:// LogoutURL
    # ------------------------------------------------------------------ #
    def _checkCognitoClientHttpLogoutUrl(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientHttpLogoutUrl'] = [0, "No app clients"]
            return
        offenders = []
        for c in clients:
            for url in (c.get('LogoutURLs') or []):
                if self._isInsecureHttpUrl(url):
                    offenders.append(f"{self._clientLabel(c)}:{url}")
                    break
        if offenders:
            self.results['cognitoClientHttpLogoutUrl'] = [
                -1, f"App client(s) with http:// LogoutURL: {', '.join(offenders[:3])}"
            ]
        else:
            self.results['cognitoClientHttpLogoutUrl'] = [
                1, "No app clients use http:// LogoutURLs"
            ]

    # ------------------------------------------------------------------ #
    # 23. Account-takeover protection weak (HighAction != BLOCK)
    # ------------------------------------------------------------------ #
    def _checkCognitoAccountTakeoverProtectionWeak(self):
        add_ons = self.pool.get('UserPoolAddOns') or {}
        adv_mode = add_ons.get('AdvancedSecurityMode', 'OFF')
        if adv_mode != 'ENFORCED':
            self.results['cognitoAccountTakeoverProtectionWeak'] = [
                0,
                f"Advanced Security is {adv_mode} — see cognitoAdvancedSecurityNotEnforced"
            ]
            return
        risk = self.pool.get('_riskConfiguration')
        if not risk:
            self.results['cognitoAccountTakeoverProtectionWeak'] = [
                -1, "Advanced Security ENFORCED but no RiskConfiguration set"
            ]
            return
        ato = risk.get('AccountTakeoverRiskConfiguration') or {}
        actions = ato.get('Actions') or {}
        high = (actions.get('HighAction') or {}).get('EventAction')
        if high == 'BLOCK':
            self.results['cognitoAccountTakeoverProtectionWeak'] = [
                1, "AccountTakeover HighAction=BLOCK"
            ]
        else:
            self.results['cognitoAccountTakeoverProtectionWeak'] = [
                -1,
                f"AccountTakeover HighAction={high or 'not set'} (should be BLOCK)"
            ]

    # ------------------------------------------------------------------ #
    # 24. No log delivery configuration
    # ------------------------------------------------------------------ #
    def _checkCognitoNoLoggingConfiguration(self):
        cfg = self.pool.get('_logConfig') or {}
        # AWS returns the field as 'LogConfigurations' — list of per-event-type entries.
        entries = cfg.get('LogConfigurations') or []
        if entries:
            targets = []
            for e in entries:
                for k in ('CloudWatchLogsConfiguration', 'S3Configuration',
                          'FirehoseConfiguration'):
                    if e.get(k):
                        targets.append(k.replace('Configuration', ''))
                        break
            self.results['cognitoNoLoggingConfiguration'] = [
                1, f"{len(entries)} log delivery configuration(s) "
                   f"({', '.join(sorted(set(targets)))[:60]})"
            ]
        else:
            self.results['cognitoNoLoggingConfiguration'] = [
                -1, "No LogDeliveryConfiguration on this user pool"
            ]

    # ------------------------------------------------------------------ #
    # 25. Threat protection in AUDIT mode (detection without enforcement)
    # ------------------------------------------------------------------ #
    def _checkCognitoThreatProtectionAuditOnly(self):
        add_ons = self.pool.get('UserPoolAddOns') or {}
        mode = add_ons.get('AdvancedSecurityMode', 'OFF')
        if mode == 'AUDIT':
            self.results['cognitoThreatProtectionAuditOnly'] = [
                -1,
                "AdvancedSecurityMode=AUDIT (detection only — no protective action)"
            ]
        elif mode == 'ENFORCED':
            self.results['cognitoThreatProtectionAuditOnly'] = [
                1, "AdvancedSecurityMode=ENFORCED"
            ]
        else:
            # OFF → covered by cognitoAdvancedSecurityNotEnforced; skip here
            self.results['cognitoThreatProtectionAuditOnly'] = [
                0, "AdvancedSecurityMode=OFF — see cognitoAdvancedSecurityNotEnforced"
            ]

    # ------------------------------------------------------------------ #
    # 26. Default email sender (COGNITO_DEFAULT instead of DEVELOPER/SES)
    # ------------------------------------------------------------------ #
    def _checkCognitoDefaultEmailSender(self):
        email_cfg = self.pool.get('EmailConfiguration') or {}
        acct = email_cfg.get('EmailSendingAccount', 'COGNITO_DEFAULT')
        if acct == 'DEVELOPER':
            self.results['cognitoDefaultEmailSender'] = [
                1, f"EmailSendingAccount=DEVELOPER (SES: {email_cfg.get('SourceArn','?')})"
            ]
        else:
            self.results['cognitoDefaultEmailSender'] = [
                -1,
                f"EmailSendingAccount={acct} — limited to 50 emails/day and no-reply@verificationemail.com"
            ]

    # ------------------------------------------------------------------ #
    # 27. Identity provider MetadataURL over http://
    # ------------------------------------------------------------------ #
    def _checkCognitoIdpHttpMetadataUrl(self):
        providers = self.pool.get('_identityProviders') or []
        if not providers:
            self.results['cognitoIdpHttpMetadataUrl'] = [
                0, "No identity providers configured"
            ]
            return
        offenders = []
        for p in providers:
            details = p.get('ProviderDetails') or {}
            url = details.get('MetadataURL') or details.get('oidc_issuer')
            if url and isinstance(url, str) and url.lower().startswith('http://'):
                offenders.append(f"{p.get('ProviderName','?')}:{url}")
        if offenders:
            self.results['cognitoIdpHttpMetadataUrl'] = [
                -1,
                f"IdP metadata over http://: {', '.join(offenders[:3])}"
            ]
        else:
            self.results['cognitoIdpHttpMetadataUrl'] = [
                1, f"All {len(providers)} identity provider(s) use https metadata"
            ]

    # ==================================================================== #
    # Phase 2 additions (checks 28-37)
    # ==================================================================== #

    # ------------------------------------------------------------------ #
    # 28. Compromised-credentials event filter incomplete
    # ------------------------------------------------------------------ #
    REQUIRED_CC_EVENT_TYPES = {'SIGN_IN', 'SIGN_UP', 'PASSWORD_CHANGE'}

    def _checkCognitoCompromisedCredentialIncompleteFilter(self):
        add_ons = self.pool.get('UserPoolAddOns') or {}
        adv_mode = add_ons.get('AdvancedSecurityMode', 'OFF')
        if adv_mode == 'OFF':
            self.results['cognitoCompromisedCredentialIncompleteFilter'] = [
                0, "Advanced Security is OFF — see cognitoAdvancedSecurityNotEnforced"
            ]
            return

        risk = self.pool.get('_riskConfiguration')
        if not risk:
            self.results['cognitoCompromisedCredentialIncompleteFilter'] = [
                0, "No RiskConfiguration set"
            ]
            return

        cc = risk.get('CompromisedCredentialsRiskConfiguration') or {}
        actions = cc.get('Actions') or {}
        event_action = actions.get('EventAction')
        if not event_action:
            self.results['cognitoCompromisedCredentialIncompleteFilter'] = [
                0, "CompromisedCredentials risk config not enabled"
            ]
            return

        event_filter = set(cc.get('EventFilter') or [])
        missing = self.REQUIRED_CC_EVENT_TYPES - event_filter
        if not event_filter:
            # Empty EventFilter is treated by Cognito as "all event types"
            self.results['cognitoCompromisedCredentialIncompleteFilter'] = [
                1, "EventFilter empty (all event types covered)"
            ]
        elif missing:
            self.results['cognitoCompromisedCredentialIncompleteFilter'] = [
                -1,
                f"CompromisedCredentials EventFilter missing: {', '.join(sorted(missing))}"
            ]
        else:
            self.results['cognitoCompromisedCredentialIncompleteFilter'] = [
                1, "EventFilter covers SIGN_IN, SIGN_UP, and PASSWORD_CHANGE"
            ]

    # ------------------------------------------------------------------ #
    # 29. No LogDelivery for userAuthEvents
    # ------------------------------------------------------------------ #
    def _checkCognitoNoThreatProtectionLogging(self):
        add_ons = self.pool.get('UserPoolAddOns') or {}
        mode = add_ons.get('AdvancedSecurityMode', 'OFF')
        if mode == 'OFF':
            self.results['cognitoNoThreatProtectionLogging'] = [
                0, "Advanced Security OFF — no threat events to log"
            ]
            return

        cfg = self.pool.get('_logConfig') or {}
        entries = cfg.get('LogConfigurations') or []
        has_auth = any(e.get('EventSource') == 'userAuthEvents' for e in entries)
        if has_auth:
            self.results['cognitoNoThreatProtectionLogging'] = [
                1, "LogDelivery configured for userAuthEvents"
            ]
        else:
            self.results['cognitoNoThreatProtectionLogging'] = [
                -1,
                f"AdvancedSecurityMode={mode} but no LogDelivery entry for userAuthEvents"
            ]

    # ------------------------------------------------------------------ #
    # 30. Temporary password validity too long
    # ------------------------------------------------------------------ #
    TEMP_PASSWORD_MAX_DAYS = 7

    def _checkCognitoLongTemporaryPassword(self):
        policies = self.pool.get('Policies') or {}
        pw = policies.get('PasswordPolicy') or {}
        val = pw.get('TemporaryPasswordValidityDays')
        try:
            days = int(val) if val is not None else 7
        except (TypeError, ValueError):
            self.results['cognitoLongTemporaryPassword'] = [
                0, f"TemporaryPasswordValidityDays unparseable: {val}"
            ]
            return
        if days > self.TEMP_PASSWORD_MAX_DAYS:
            self.results['cognitoLongTemporaryPassword'] = [
                -1,
                f"TemporaryPasswordValidityDays={days} (> {self.TEMP_PASSWORD_MAX_DAYS})"
            ]
        else:
            self.results['cognitoLongTemporaryPassword'] = [
                1, f"TemporaryPasswordValidityDays={days}"
            ]

    # ------------------------------------------------------------------ #
    # 31. Confidential app client without ClientSecret
    # ------------------------------------------------------------------ #
    def _checkCognitoClientNoSecret(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientNoSecret'] = [0, "No app clients"]
            return
        offenders = []
        confidential = 0
        for c in clients:
            flows = [f.lower() for f in (c.get('AllowedOAuthFlows') or [])]
            # "client_credentials" flow is machine-to-machine and REQUIRES a secret.
            if 'client_credentials' not in flows:
                continue
            confidential += 1
            if not c.get('ClientSecret'):
                offenders.append(self._clientLabel(c))
        if confidential == 0:
            self.results['cognitoClientNoSecret'] = [
                0, "No confidential (client_credentials) app clients"
            ]
        elif offenders:
            self.results['cognitoClientNoSecret'] = [
                -1,
                f"Confidential app client(s) without ClientSecret: "
                f"{', '.join(offenders[:5])}"
            ]
        else:
            self.results['cognitoClientNoSecret'] = [
                1, f"All {confidential} confidential app client(s) have a ClientSecret"
            ]

    # ------------------------------------------------------------------ #
    # 32. App client with excessive OAuth scopes
    # ------------------------------------------------------------------ #
    EXCESSIVE_SCOPE = 'aws.cognito.signin.user.admin'

    def _checkCognitoClientExcessiveScopes(self):
        clients = self._appClients()
        if not clients:
            self.results['cognitoClientExcessiveScopes'] = [0, "No app clients"]
            return
        offenders = []
        for c in clients:
            if not c.get('AllowedOAuthFlowsUserPoolClient'):
                continue
            if self.EXCESSIVE_SCOPE in (c.get('AllowedOAuthScopes') or []):
                offenders.append(self._clientLabel(c))
        if offenders:
            self.results['cognitoClientExcessiveScopes'] = [
                0,
                f"App client(s) granting {self.EXCESSIVE_SCOPE}: "
                f"{', '.join(offenders[:5])} (advisory)"
            ]
        else:
            self.results['cognitoClientExcessiveScopes'] = [
                1, f"No OAuth app clients grant {self.EXCESSIVE_SCOPE}"
            ]

    # ------------------------------------------------------------------ #
    # 33. MFA required but no methods configured
    # ------------------------------------------------------------------ #
    def _checkCognitoNoMfaMethods(self):
        mfa = self.pool.get('MfaConfiguration', 'OFF')
        if mfa != 'ON':
            self.results['cognitoNoMfaMethods'] = [
                0, f"MfaConfiguration={mfa} — see cognitoMfaNotEnforced"
            ]
            return

        sms_cfg = self.pool.get('SmsConfiguration') or {}
        sms_ok = bool(sms_cfg.get('SnsCallerArn'))
        totp_cfg = self.pool.get('SoftwareTokenMfaConfiguration') or {}
        totp_ok = bool(totp_cfg.get('Enabled'))

        if sms_ok or totp_ok:
            methods = []
            if sms_ok:  methods.append('SMS')
            if totp_ok: methods.append('TOTP')
            self.results['cognitoNoMfaMethods'] = [
                1, f"MFA method(s) configured: {', '.join(methods)}"
            ]
        else:
            self.results['cognitoNoMfaMethods'] = [
                -1,
                "MfaConfiguration=ON but neither SMS nor TOTP MFA is configured"
            ]

    # ------------------------------------------------------------------ #
    # 34. SMS-only MFA (no TOTP)
    # ------------------------------------------------------------------ #
    def _checkCognitoSmsOnlyMfa(self):
        mfa = self.pool.get('MfaConfiguration', 'OFF')
        if mfa == 'OFF':
            self.results['cognitoSmsOnlyMfa'] = [0, "MFA is OFF"]
            return
        sms_cfg = self.pool.get('SmsConfiguration') or {}
        sms_ok = bool(sms_cfg.get('SnsCallerArn'))
        totp_cfg = self.pool.get('SoftwareTokenMfaConfiguration') or {}
        totp_ok = bool(totp_cfg.get('Enabled'))
        if sms_ok and not totp_ok:
            self.results['cognitoSmsOnlyMfa'] = [
                0, "SMS MFA only (TOTP not enabled — advisory)"
            ]
        else:
            self.results['cognitoSmsOnlyMfa'] = [
                1, "TOTP MFA available (or MFA not configured)"
            ]

    # ------------------------------------------------------------------ #
    # 35. AccountTakeover risk actions do not notify users
    # ------------------------------------------------------------------ #
    def _checkCognitoAccountTakeoverNoNotification(self):
        add_ons = self.pool.get('UserPoolAddOns') or {}
        mode = add_ons.get('AdvancedSecurityMode', 'OFF')
        if mode == 'OFF':
            self.results['cognitoAccountTakeoverNoNotification'] = [
                0, "Advanced Security OFF"
            ]
            return
        risk = self.pool.get('_riskConfiguration')
        if not risk:
            self.results['cognitoAccountTakeoverNoNotification'] = [
                0, "No RiskConfiguration"
            ]
            return
        ato = risk.get('AccountTakeoverRiskConfiguration') or {}
        actions = ato.get('Actions') or {}
        high = actions.get('HighAction') or {}
        medium = actions.get('MediumAction') or {}
        # If neither High nor Medium is configured, skip.
        if not (high or medium):
            self.results['cognitoAccountTakeoverNoNotification'] = [
                0, "No High/Medium risk actions configured"
            ]
            return
        no_notify = []
        if high and not high.get('Notify', False):
            no_notify.append('HighAction')
        if medium and not medium.get('Notify', False):
            no_notify.append('MediumAction')
        if no_notify:
            self.results['cognitoAccountTakeoverNoNotification'] = [
                0,
                f"Risk actions without user notification: {', '.join(no_notify)} (advisory)"
            ]
        else:
            self.results['cognitoAccountTakeoverNoNotification'] = [
                1, "Configured risk actions notify users"
            ]

    # ------------------------------------------------------------------ #
    # 36. User pool group's IAM role is overly permissive
    # ------------------------------------------------------------------ #
    BROAD_GROUP_ACTIONS = {'*', 'iam:*', 's3:*', 'kms:*', 'dynamodb:*'}

    def _checkCognitoGroupOverlyPermissiveRole(self):
        groups = self.pool.get('_groups') or []
        if not groups:
            self.results['cognitoGroupOverlyPermissiveRole'] = [
                0, "No user-pool groups"
            ]
            return

        offenders = []
        cross_account = []
        for g in groups:
            role_arn = g.get('RoleArn')
            if not role_arn:
                continue
            name = g.get('GroupName', '?')
            if g.get('_crossAccount'):
                cross_account.append(name)
                continue
            for doc in g.get('_rolePolicies') or []:
                if self._statementIsBroad(doc):
                    offenders.append(name)
                    break

        if offenders:
            msg = f"Overly permissive group role(s): {', '.join(sorted(set(offenders))[:5])}"
            if cross_account:
                msg += f" (skipped {len(cross_account)} cross-account role(s))"
            self.results['cognitoGroupOverlyPermissiveRole'] = [-1, msg]
        elif cross_account:
            self.results['cognitoGroupOverlyPermissiveRole'] = [
                0,
                f"{len(cross_account)} group role(s) belong to another account and were not evaluated"
            ]
        else:
            self.results['cognitoGroupOverlyPermissiveRole'] = [
                1, "All group roles evaluated appear scoped"
            ]

    @classmethod
    def _statementIsBroad(cls, policy_doc):
        """True if the policy has a wildcard-action statement or a broad-action + wildcard-resource pair."""
        if not isinstance(policy_doc, dict):
            return False
        stmts = policy_doc.get('Statement', [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if not isinstance(stmt, dict) or stmt.get('Effect') != 'Allow':
                continue
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            actset = {a.lower() for a in actions if isinstance(a, str)}
            if '*' in actset:
                return True
            if '*' in resources and (actset & cls.BROAD_GROUP_ACTIONS):
                return True
        return False

    # ------------------------------------------------------------------ #
    # 37. Custom auth Lambda triggers configured without Advanced Security
    # ------------------------------------------------------------------ #
    CUSTOM_AUTH_TRIGGERS = (
        'DefineAuthChallenge', 'CreateAuthChallenge', 'VerifyAuthChallengeResponse'
    )

    def _checkCognitoCustomAuthThreatProtectionDisabled(self):
        lambda_cfg = self.pool.get('LambdaConfig') or {}
        has_custom = any(lambda_cfg.get(t) for t in self.CUSTOM_AUTH_TRIGGERS)
        if not has_custom:
            self.results['cognitoCustomAuthThreatProtectionDisabled'] = [
                0, "No custom-auth Lambda triggers configured"
            ]
            return
        add_ons = self.pool.get('UserPoolAddOns') or {}
        mode = add_ons.get('AdvancedSecurityMode', 'OFF')
        if mode == 'ENFORCED':
            self.results['cognitoCustomAuthThreatProtectionDisabled'] = [
                1, "Custom-auth triggers configured with AdvancedSecurityMode=ENFORCED"
            ]
        else:
            configured = [t for t in self.CUSTOM_AUTH_TRIGGERS if lambda_cfg.get(t)]
            self.results['cognitoCustomAuthThreatProtectionDisabled'] = [
                -1,
                f"Custom-auth triggers ({', '.join(configured)}) with "
                f"AdvancedSecurityMode={mode}"
            ]

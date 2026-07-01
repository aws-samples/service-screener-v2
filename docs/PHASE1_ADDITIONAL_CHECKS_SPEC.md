# Phase 1: Additional Checks Spec — +31 Checks

Project: /Users/kuettai/Documents/project/ss-genai/service-screener-v2

**IMPORTANT**: The 15 checks from `ADDITIONAL_CHECKS_SPEC.md` are ALREADY in the working tree (unstaged). This spec adds MORE checks ON TOP of those. Do NOT remove or modify the existing 16/15/16/16 checks.

Current state: SFN=16, SNS=15, WAFv2=16, Cognito=16 (total 670 unstaged)
Target: SFN=24, SNS=19, WAFv2=24, Cognito=27 (total 701)

---

## Step Functions — Add 8 checks (17→24)

### Service class changes needed:
- Add call to `validate_state_machine_definition` API (client method: `validate_state_machine_definition(definition=..., type=...)`) — store result in `self.results[sm_name]['_validationResult']`
- Add IAM `get_role` check for the state machine's roleArn — store `_roleExists` boolean
- Add `describe_log_group` check on the configured log destination (if logging enabled) — store `_logGroupExists` boolean

### New checks:

17. `sfnDefinitionValidationErrors` (O/H) — Use `validate_state_machine_definition` API. If result contains diagnostics with severity=ERROR, FAIL. Report the error messages. This catches structural issues AWS itself flags.

18. `sfnChoiceNoDefault` (R/H) — Parse definition JSON. Find all states with `Type: Choice`. If any Choice state lacks a `Default` field, FAIL. Without Default, unmatched input causes runtime failure. Report which state names lack Default.

19. `sfnRoleDoesNotExist` (O/H) — Call IAM `get_role(RoleName=...)` for the role in the SM's `roleArn`. If role doesn't exist (NoSuchEntity), FAIL. A broken role = completely non-functional state machine. Handle cross-account roles gracefully (skip/INFO if role ARN is different account).

20. `sfnUnreachableStates` (O/M) — Parse definition JSON. Build directed graph from StartAt + all Next/Default/Catch transitions. Find states that are never reachable from StartAt (dead code). FAIL if any unreachable states found. Report state names. Exclude states only reachable via Choice branches (they ARE reachable).

21. `sfnParallelNoCatch` (R/M) — Parse definition. Find `Type: Parallel` states. If any Parallel state has no `Catch` field, FAIL. One failing branch crashes the entire execution. Report which Parallel states lack Catch.

22. `sfnMapNoCatch` (R/M) — Same as above but for `Type: Map` states. A single item failure crashes the whole Map without Catch.

23. `sfnRetryNoBackoff` (R/M) — Parse definition. Find all Retry configurations. If any has `BackoffRate` explicitly set to 1.0 (or missing — default is 2.0 which is fine), check if `IntervalSeconds * MaxAttempts` indicates hammering (IntervalSeconds=1 + MaxAttempts>5 without backoff). Only FAIL if BackoffRate=1.0 AND MaxAttempts>3. Low threshold for noise.

24. `sfnLogGroupDoesNotExist` (O/M) — If logging is configured (logDestinations not empty), extract the log group ARN and call CloudWatch Logs `describe_log_groups(logGroupNamePrefix=...)`. If the log group doesn't exist, FAIL. Config drift = silent logging failure.

---

## SNS — Add 4 checks (16→19)

### Service class changes needed:
- For each topic, parse the Policy JSON (already fetched in attributes as 'Policy')
- For subscriptions, fetch `get_subscription_attributes` for `ConfirmationWasAuthenticated`
- Add `get_platform_application_attributes` if `list_platform_applications` returns any

### New checks:

16. `snsPolicyOverlyBroadActions` (S/H) — Parse topic Policy. Find Allow statements where Action contains `SNS:*` or sensitive actions (`sns:AddPermission`, `sns:RemovePermission`, `sns:SetTopicAttributes`, `sns:DeleteTopic`) granted to non-owner principals (not the topic owner account). FAIL if found. Different from check #3 (which is Principal:*) — this catches specific accounts given admin powers.

17. `snsSubscriptionUnauthenticatedConfirmation` (S/M) — For each confirmed subscription, check `get_subscription_attributes` → `ConfirmationWasAuthenticated`. If "false", the subscription was confirmed without authentication (potential unauthorized endpoint). FAIL per subscription. Skip pending subs.

18. `snsSubscriptionEndpointIsIPAddress` (S/M) — For HTTP/HTTPS subscriptions, check if the Endpoint URL contains a raw IP address instead of a domain name (regex: `https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`). Exclude localhost/127.x. FAIL if raw IP found. AWS docs explicitly flag this.

19. `snsPlatformAppCertExpiringSoon` (R/H) — Call `list_platform_applications`, then `get_platform_application_attributes` for each. Check `AppleCertificateExpiryDate` — if within 30 days of expiry, FAIL. If no platform applications exist, skip this check entirely (return None/skip, don't report PASS).

---

## WAFv2 — Add 8 checks (17→24)

### Service class changes needed:
- For each WebACL, already have full `get_web_acl` response. Need to also call:
  - `describe_managed_rule_group(VendorName, Name, Scope)` for version info on managed groups
  - `list_available_managed_rule_group_versions(VendorName, Name, Scope)` for version checks
  - `get_ip_set(Id, Name, Scope)` for IP set analysis (when referenced)

### New checks:

17. `wafv2ManagedRuleGroupAllCountOverride` (S/H) — For each managed rule group in the WebACL, check `ExcludedRules` list. If ALL rules in the group are excluded (count = total rules in group via `describe_managed_rule_group`), FAIL. This completely neuters the group. Also check `RuleActionOverrides` where all are set to Count.

18. `wafv2NoCoreRuleSet` (S/H) — WebACL has managed rule groups but does NOT include `AWSManagedRulesCommonRuleSet` (the Core Rule Set / CRS). This is the foundational free rule group every WAF should have. Only flag if the ACL has at least 1 other managed group (if no managed groups at all, check #2 already covers it).

19. `wafv2AllowRuleBeforeManagedRules` (S/H) — A rule with Action=Allow has a LOWER priority number (runs first) than managed rule groups. This means matching traffic bypasses all security inspection. Check rule priorities: if any Allow-action rule has priority < lowest managed-group priority, FAIL. Report the rule name.

20. `wafv2ManagedRuleGroupVersionPinned` (O/M) — Managed rule group has `VersionName` explicitly set (pinned) instead of using the default (auto-updating). INFO-level unless the pinned version is near expiration (check `list_available_managed_rule_group_versions` → `ExpiryTimestamp`). If expiring within 30 days, FAIL as H.

21. `wafv2NoBotControl` (S/M) — WebACL protects internet-facing resources but has no `AWSManagedRulesBotControlRuleSet`. Only flag if the ACL IS associated with resources (check #11 handles unassociated). INFO level — it's a paid add-on, so advisory only.

22. `wafv2RateBasedRuleThresholdTooHigh` (S/M) — Rate-based rule exists but threshold is >10000 requests per 5 minutes. At that rate, most DDoS/abuse scenarios won't trigger the rule. FAIL if any rate rule has Limit > 10000. Report the rule name and its limit.

23. `wafv2LoggingFilterDropsBlocked` (S/M) — Logging is configured with filters, and the filter drops (excludes) BLOCK actions. This means attack evidence is discarded. Parse LoggingFilter → if any filter with Behavior=DROP matches on ActionCondition=BLOCK, FAIL.

24. `wafv2IpSetOverlyPermissive` (S/H) — WebACL references an IP set (via `IPSetReferenceStatement`). Fetch the IP set with `get_ip_set`. If any address in `Addresses` has a prefix shorter than /8 (e.g., 0.0.0.0/1, 10.0.0.0/4), FAIL. Overly broad CIDR in an allow-list defeats WAF purpose. Only check IP sets used in Allow rules.

---

## Cognito — Add 11 checks (17→27)

### Service class changes needed:
- Add `list_user_pool_clients` + `describe_user_pool_client` for each client — store in `self.results[pool]['_clients']` as list
- Add `get_log_delivery_configuration(UserPoolId)` — store in `_logConfig`
- Risk configuration already added in prior batch (`_riskConfiguration`)
- Add `list_identity_providers` — store in `_identityProviders`

### New checks (App Client checks — the biggest gap):

17. `cognitoClientImplicitGrantEnabled` (S/H) — For each app client, check `AllowedOAuthFlows`. If contains "implicit", FAIL. Deprecated per OAuth 2.1 — tokens exposed in URL fragments. Report which client(s).

18. `cognitoClientTokenRevocationDisabled` (S/M) — For each app client, check `EnableTokenRevocation`. If False, FAIL. Stolen refresh tokens remain valid even after user signs out.

19. `cognitoClientHttpCallbackUrl` (S/H) — For each app client, check `CallbackURLs`. If any URL starts with `http://` (excluding `http://localhost` and `http://127.0.0.1`), FAIL. Auth codes/tokens exposed to MitM.

20. `cognitoClientUserExistenceErrors` (S/M) — For each app client, check `PreventUserExistenceErrors`. If "LEGACY" or not set, FAIL. Enables username enumeration attacks.

21. `cognitoClientInsecureAuthFlow` (S/M) — For each app client, check `ExplicitAuthFlows`. If contains `ALLOW_USER_PASSWORD_AUTH` (sends password in cleartext to Cognito, no SRP), FAIL. `ALLOW_USER_SRP_AUTH` is the secure alternative.

22. `cognitoClientHttpLogoutUrl` (S/M) — For each app client, check `LogoutURLs`. Same pattern as #19 — if any uses http:// (non-localhost), FAIL.

### Pool-level checks:

23. `cognitoAccountTakeoverProtectionWeak` (S/H) — Risk configuration exists and AdvancedSecurity is ENFORCED, but `AccountTakeoverRiskConfiguration.Actions.HighAction.EventAction` is not BLOCK (or is NO_ACTION). Detecting threats but not blocking them. FAIL if high-risk action != BLOCK.

24. `cognitoNoLoggingConfiguration` (O/M) — `get_log_delivery_configuration` returns empty LogDeliveryConfigurations list. No audit trail for auth events. FAIL.

25. `cognitoThreatProtectionAuditOnly` (S/M) — `AdvancedSecurityMode` is "AUDIT" (not OFF, not ENFORCED). Detection without enforcement — threats are logged but not blocked. INFO level (distinct from check #3 which flags OFF).

26. `cognitoDefaultEmailSender` (O/M) — `EmailConfiguration.EmailSendingAccount` is "COGNITO_DEFAULT" instead of "DEVELOPER" (SES). Limited to 50 emails/day, uses no-reply@verificationemail.com (phishing-like). FAIL if sending production emails.

27. `cognitoIdpHttpMetadataUrl` (S/M) — For each identity provider (list_identity_providers + describe_identity_provider), check `ProviderDetails.MetadataURL`. If it starts with `http://` (not https), FAIL. SAML/OIDC metadata fetched insecurely.

---

## Framework Mapping (for all 31 new checks):

### AAIL:
- sfnChoiceNoDefault, sfnUnreachableStates, sfnParallelNoCatch, sfnMapNoCatch → AGENTREL02.BP01 (Workflow failure handling)
- sfnDefinitionValidationErrors, sfnRoleDoesNotExist, sfnLogGroupDoesNotExist → AGENTOPS03.BP01 (Operational validation)
- wafv2ManagedRuleGroupAllCountOverride, wafv2NoCoreRuleSet, wafv2AllowRuleBeforeManagedRules → AGENTSEC08.BP01 (Network protection)
- cognitoClientImplicitGrantEnabled, cognitoClientHttpCallbackUrl, cognitoAccountTakeoverProtectionWeak → AGENTSEC03.BP01 (Identity & access)
- snsPolicyOverlyBroadActions → AGENTSEC01.BP02 (Least privilege)

### WAFS:
- wafv2ManagedRuleGroupAllCountOverride, wafv2NoCoreRuleSet, wafv2AllowRuleBeforeManagedRules, wafv2IpSetOverlyPermissive → SEC09.BP02 (Network protection)
- cognitoClientImplicitGrantEnabled, cognitoClientTokenRevocationDisabled, cognitoAccountTakeoverProtectionWeak → SEC02.BP01 (Short-lived credentials)
- cognitoClientHttpCallbackUrl, cognitoClientHttpLogoutUrl, cognitoIdpHttpMetadataUrl → SEC09.BP01 (Encryption in transit)
- snsPolicyOverlyBroadActions → SEC03.BP01 (Least privilege)

### Other frameworks: Map to the same BPs where existing checks of similar nature already exist (e.g., Cognito auth checks → same RMiT/RBI/FTR/MSR/SSB/SPIP identity controls).

---

## Implementation Order:
1. Service class extensions (add API calls, store results)
2. Driver methods (all new _check methods)
3. Reporter JSON entries
4. Framework map.json updates
5. Validate (reporter↔method match, framework ref resolve)
6. Run full scan: `python3 main.py --regions us-east-1 --services stepfunctions,sns,wafv2,cognito --beta 1 --sequential 1`
7. Report: final counts, any errors, sample findings from new checks

## Commit message (when ready):
```
feat: Phase 1 expansion — +31 checks across Step Functions/SNS/WAFv2/Cognito

Step Functions (16→24): +8 definition analysis & operational validation
  sfnDefinitionValidationErrors, sfnChoiceNoDefault, sfnRoleDoesNotExist,
  sfnUnreachableStates, sfnParallelNoCatch, sfnMapNoCatch,
  sfnRetryNoBackoff, sfnLogGroupDoesNotExist

SNS (15→19): +4 policy analysis & platform operations
  snsPolicyOverlyBroadActions, snsSubscriptionUnauthenticatedConfirmation,
  snsSubscriptionEndpointIsIPAddress, snsPlatformAppCertExpiringSoon

WAFv2 (16→24): +8 rule effectiveness & configuration depth
  wafv2ManagedRuleGroupAllCountOverride, wafv2NoCoreRuleSet,
  wafv2AllowRuleBeforeManagedRules, wafv2ManagedRuleGroupVersionPinned,
  wafv2NoBotControl, wafv2RateBasedRuleThresholdTooHigh,
  wafv2LoggingFilterDropsBlocked, wafv2IpSetOverlyPermissive

Cognito (16→27): +11 app client security & threat protection
  cognitoClientImplicitGrantEnabled, cognitoClientTokenRevocationDisabled,
  cognitoClientHttpCallbackUrl, cognitoClientUserExistenceErrors,
  cognitoClientInsecureAuthFlow, cognitoClientHttpLogoutUrl,
  cognitoAccountTakeoverProtectionWeak, cognitoNoLoggingConfiguration,
  cognitoThreatProtectionAuditOnly, cognitoDefaultEmailSender,
  cognitoIdpHttpMetadataUrl

Total rule count: 670 → 701 (+31)
```

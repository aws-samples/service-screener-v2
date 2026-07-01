# Phase 2: Remaining Checks — Hit Realistic Max

Project: /Users/kuettai/Documents/project/ss-genai/service-screener-v2

Current state: SFN=24, SNS=19, WAFv2=24, Cognito=27 (total 701, commit 0ec26d4)
Target: SFN=28, SNS=23, WAFv2=41, Cognito=37 (total ~129 across 4 services)

**IMPORTANT**: Do NOT remove or modify existing checks. ONLY append new ones.

---

## Step Functions — Add 4 checks (25→28)

### Service class changes:
- Add `list_state_machine_versions` call per SM — store `_versions` list
- Add IAM inline+attached policy fetching for the SM's roleArn (if not already done) — need to parse policy documents for PassRole and service breadth
- Add `cloudwatch.describe_alarms` filtered by SM name dimension — store `_alarms`

### New checks:

25. `sfnIAMRoleAllowsPassRole` (S/H) — Parse execution role's IAM policies (inline + attached). If any policy has Action containing `iam:PassRole` with Resource `"*"`, FAIL. PassRole on * enables privilege escalation. Use `iam.list_attached_role_policies` + `iam.get_policy` + `iam.get_policy_version` to get attached policy docs; `iam.list_role_policies` + `iam.get_role_policy` for inline. Skip if role doesn't exist (check #19 covers that).

26. `sfnNoCloudWatchAlarm` (O/M) — Call `cloudwatch.describe_alarms(AlarmNamePrefix=..., Dimensions=[{Name:'StateMachineArn', Value=sm_arn}])`. Actually better: use `cloudwatch.describe_alarms_for_metric(MetricName='ExecutionsFailed', Namespace='AWS/States', Dimensions=[...])`. If no alarms exist for this SM (checking ExecutionsFailed OR ExecutionsTimedOut OR ExecutionsAborted), FAIL. Without alarms, failures go unnoticed.

27. `sfnLoggingWithoutEncryption` (S/M) — If `loggingConfiguration.includeExecutionData` is True AND `encryptionConfiguration.type` is `AWS_OWNED_KEY` (not CMK), FAIL. Sensitive execution payloads are logged but not protected by customer-managed encryption.

28. `sfnHttpTaskNoTLS` (S/H) — Parse definition JSON. Find Task states with Resource `arn:aws:states:::http:invoke`. Check Parameters → `ApiEndpoint` (or `ApiEndpoint.$`). If any static ApiEndpoint starts with `http://` (not https), FAIL. Dynamic endpoints (`ApiEndpoint.$`) should be flagged as INFO.

---

## SNS — Add 4 checks (20→23)

### Service class changes:
- Add `get_sms_attributes()` call (account-level) — store in class variable `_smsAttributes`
- Add FIFO topic detection (check TopicArn ending in `.fifo` or FifoTopic attribute)

### New checks:

20. `snsFifoContentDeduplicationDisabled` (R/L) — For FIFO topics (TopicArn ends with `.fifo`), check attribute `ContentBasedDeduplication`. If "false", publishers must always supply MessageDeduplicationId — higher operational burden and risk of duplicate processing if forgotten. INFO level only.

21. `snsSmsNoSpendLimit` (C/M) — Check `get_sms_attributes()` → `MonthlySpendLimit`. If not set or set to the AWS default maximum ($1.00 for sandbox, region-dependent for production), FAIL. Unbounded SMS spend is a cost risk (SMS pumping attacks). Only flag if account has any SMS subscriptions.

22. `snsPolicyVersionOutdated` (S/M) — Parse topic Policy JSON. If `"Version"` is `"2008-10-17"` instead of `"2012-10-17"`, FAIL. Outdated policy version lacks policy variables and has different evaluation semantics (no deny-by-default for some conditions).

23. `snsFifoNoArchivePolicy` (R/L) — For FIFO topics, check if `ArchivePolicy` attribute exists and is configured. Without archive policy, message replay is not available for disaster recovery. INFO level only.

---

## WAFv2 — Add 17 checks (25→41)

### Service class changes:
- Need `list_ip_sets(Scope)` + `get_ip_set()` for orphan and empty checks
- Need `list_regex_pattern_sets(Scope)` + `get_regex_pattern_set()`
- Need `list_rule_groups(Scope)` + `get_rule_group()` for empty/orphan checks
- Need cross-service clients: `elbv2`, `apigateway`, `cloudfront`, `appsync` for coverage gap checks
- For each managed rule group, need `describe_managed_rule_group` to get total rule count (for all-count-override validation)

### Remaining Tier 1 checks:

25. `wafv2NoAccountTakeoverPrevention` (S/M) — WebACL has login-related resources associated but no `AWSManagedRulesATPRuleSet`. INFO level since it's paid — note in description. Only flag if WebACL is associated with at least one resource.

26. `wafv2NoAccountCreationFraudPrevention` (S/L) — No `AWSManagedRulesACFPRuleSet`. INFO only — very context-dependent (only relevant for apps with registration flows). Skip if no association.

27. `wafv2PaidRuleGroupWithoutScopeDown` (C/M) — Paid managed rule groups (`AWSManagedRulesBotControlRuleSet`, `AWSManagedRulesATPRuleSet`, `AWSManagedRulesACFPRuleSet`) without `ScopeDownStatement`. These charge per-request — without scope-down, ALL requests are evaluated. FAIL if paid group lacks scope-down.

28. `wafv2ManagedRuleGroupExcludedRulesExcessive` (S/M) — For each managed rule group, count rules in `ExcludedRules` + `RuleActionOverrides` (set to Count). If >50% of total rules in the group are overridden, FAIL. Use `describe_managed_rule_group` to get total rule count. Different from check #17 (which requires ALL overridden).

29. `wafv2NoKnownBadInputsRuleSet` (S/M) — No rule references `AWSManagedRulesKnownBadInputsRuleSet`. This covers Log4j/Log4Shell, Java deserialization exploits. Free, low WCU. Only flag if ACL has at least one other managed group.

30. `wafv2NoAnonymousIpList` (S/M) — No `AWSManagedRulesAnonymousIpList`. Detects VPN/Tor/hosting providers. Free managed group. Only flag if ACL has at least one other managed group.

31. `wafv2RulePriorityOrdering` (C/M) — Check rule evaluation order. AWS best practice: IP block → rate limit → free AMR → paid AMR. FAIL if: rate-based rules have HIGHER priority number than paid managed groups (evaluated after, meaning you pay for requests that should have been rate-limited). Only check relative ordering.

32. `wafv2IpSetEmpty` (O/L) — List all IP sets for both scopes. If any IP set has empty `Addresses` list AND is referenced by a WebACL rule, INFO. Empty IP set = dead rule consuming WCU.

33. `wafv2RegexPatternSetEmpty` (O/L) — Same pattern: regex pattern set with empty `RegularExpressionList` and referenced by a rule. INFO.

34. `wafv2RuleGroupEmpty` (S/M) — Custom rule group (from `list_rule_groups`) that has zero rules but is referenced in a WebACL. Wastes WCU allocation with zero protection. FAIL.

35. `wafv2LoggingMissingRedactedFields` (S/M) — Logging is configured but `RedactedFields` is empty. Sensitive data (Authorization header, cookies, query strings with tokens) may be logged in plaintext. FAIL for compliance environments. Note: describe what should be redacted in recommendation.

36. `wafv2ManagedRuleGroupVersionExpiring` (S/H) — Pinned managed rule group version has `ExpiryTimestamp` within 30 days (from `list_available_managed_rule_group_versions`). Expired versions get force-upgraded. FAIL if expiring soon.

### Cross-service coverage gap checks (Tier 2):

37. `wafv2AlbWithoutWebAcl` (S/H) — Call `elbv2.describe_load_balancers()`. For each internet-facing ALB (Scheme='internet-facing', Type='application'), call `wafv2.get_web_acl_for_resource(ResourceArn=alb_arn)`. If WAFNonexistentItemException or empty, FAIL. Every internet-facing ALB should have WAF.

38. `wafv2ApiGatewayWithoutWebAcl` (S/H) — Call `apigateway.get_rest_apis()`. For each REST API, get stages (`get_stages`). For each stage, construct stage ARN and call `wafv2.get_web_acl_for_resource()`. FAIL if no WebACL. Only check REST APIs (HTTP APIs use a different mechanism).

39. `wafv2CloudFrontWithoutWebAcl` (S/H) — Call `cloudfront.list_distributions()`. Check each distribution's `WebACLId` field. If empty string, FAIL. Note: must run from us-east-1 for CLOUDFRONT scope.

40. `wafv2AppSyncWithoutWebAcl` (S/M) — Call `appsync.list_graphql_apis()`. Check `WafWebAclArn` field. If empty/null AND API is not PRIVATE (check `AuthenticationType`), FAIL.

41. `wafv2CognitoUserPoolWithoutWebAcl` (S/M) — Call `cognito-idp.list_user_pools()`. For each pool ARN, call `wafv2.get_web_acl_for_resource()`. FAIL if no WebACL. Note: overlaps with Cognito check #cognitoNoWafAssociation — this is the WAFv2-side view.

---

## Cognito — Add 10 checks (28→37)

### Service class changes:
- Add `describe_risk_configuration` → `CompromisedCredentialsRiskConfiguration.EventFilter` field access
- Add `get_log_delivery_configuration` → check for `userAuthEvents` event source
- Add `list_groups` per pool + IAM policy evaluation for group roles
- Check `TemporaryPasswordValidityDays` from existing pool describe

### New checks:

28. `cognitoCompromisedCredentialIncompleteFilter` (S/M) — Risk config has CompromisedCredentials enabled, but `EventFilter` does not contain all of ["SIGN_IN", "SIGN_UP", "PASSWORD_CHANGE"]. Incomplete coverage means breached passwords can slip through during uncovered event types. Only check if compromised credentials feature is enabled.

29. `cognitoNoThreatProtectionLogging` (S/M) — `get_log_delivery_configuration` has log configs but none with `EventSource = "userAuthEvents"`. Threat protection events (risk scores, adaptive auth decisions) not being exported. Only flag if AdvancedSecurity is ENFORCED or AUDIT.

30. `cognitoLongTemporaryPassword` (S/M) — `Policies.PasswordPolicy.TemporaryPasswordValidityDays` > 7. Long-lived temp passwords increase interception window. Aligns with Security Hub Cognito.3. Default is 7 which is the threshold.

31. `cognitoClientInsecureAuthFlow` (S/M) — Already added in Phase 1 check #21. SKIP — already exists.

Actually let me recount. Phase 1 added checks 17-27. So next is 28. Let me list only what's NOT already implemented:

28. `cognitoCompromisedCredentialIncompleteFilter` (S/M) — As above.

29. `cognitoNoThreatProtectionLogging` (S/M) — As above.

30. `cognitoLongTemporaryPassword` (S/M) — As above.

31. `cognitoClientNoRefreshTokenRotation` (S/L) — For each app client, check `AuthSessionValidity` and whether `EnableTokenRevocation` is True but no explicit refresh token rotation config exists. Actually check for the `TokenValidityUnits` + rotation. Simpler: check if refresh token validity exceeds 30 days (already covered by check #7). ALTERNATIVE: Check if `ExplicitAuthFlows` allows `ALLOW_REFRESH_TOKEN_AUTH` but `EnableTokenRevocation` is False (overlap with #18). 

Let me pick truly NEW checks not overlapping existing:

28. `cognitoCompromisedCredentialIncompleteFilter` (S/M) — CompromisedCredentials EventFilter not covering all event types.

29. `cognitoNoThreatProtectionLogging` (S/M) — No userAuthEvents log config.

30. `cognitoLongTemporaryPassword` (S/M) — TemporaryPasswordValidityDays > 7.

31. `cognitoClientNoSecret` (S/M) — App client uses OAuth flows (code or client_credentials) with `AllowedOAuthFlowsUserPoolClient=True` but has no ClientSecret generated. This means any party with the client ID can initiate auth. Only flag server-side clients (not SPAs/mobile). Heuristic: if `AllowedOAuthFlows` contains "client_credentials", a secret is REQUIRED.

32. `cognitoClientExcessiveScopes` (S/L) — App client's `AllowedOAuthScopes` includes `aws.cognito.signin.user.admin` AND client is OAuth-enabled. This scope grants full self-service user attribute access. INFO level.

33. `cognitoNoMfaMethods` (S/M) — Pool has `MfaConfiguration = "ON"` but neither SMS config (`SmsConfiguration`) nor software token (`SoftwareTokenMfaConfiguration.Enabled=True`) is properly configured. MFA is required but can't actually be delivered = broken auth.

34. `cognitoSmsOnlyMfa` (S/L) — Pool only supports SMS MFA (no TOTP option). SMS is vulnerable to SIM swapping. INFO level with recommendation to add TOTP.

35. `cognitoAccountTakeoverNoNotification` (S/L) — Risk config AccountTakeover Actions have `Notify = False` for High and Medium risk events. Threats detected but users not informed. INFO level.

36. `cognitoGroupOverlyPermissiveRole` (S/H) — For each group with a RoleArn, evaluate the attached IAM policies. If any policy grants `"*"` resource on sensitive actions (or Action: `"*"`), FAIL. Requires IAM client for policy evaluation.

37. `cognitoIdpNoSignatureVerification` (S/H) — For SAML IdPs, check `ProviderDetails`. If only `MetadataURL` is provided without explicit `IDPSignout` or signing certificate validation markers, INFO (can't definitively determine from API alone whether signing is enforced — metadata contains cert, but we can flag if metadata fetched over HTTP which is #cognitoIdpHttpMetadataUrl already). Actually this is hard to verify purely via API. ALTERNATIVE: `cognitoCustomAuthThreatProtectionDisabled` (S/M) — Pool has custom auth Lambda triggers configured (`CustomAuthConfig` in `LambdaConfig`) but threat protection for custom auth is not enforced. Check via risk config.

Revised final list for Cognito:

28. `cognitoCompromisedCredentialIncompleteFilter` (S/M)
29. `cognitoNoThreatProtectionLogging` (S/M)  
30. `cognitoLongTemporaryPassword` (S/M)
31. `cognitoClientNoSecret` (S/M)
32. `cognitoClientExcessiveScopes` (S/L)
33. `cognitoNoMfaMethods` (S/M)
34. `cognitoSmsOnlyMfa` (S/L)
35. `cognitoAccountTakeoverNoNotification` (S/L)
36. `cognitoGroupOverlyPermissiveRole` (S/H)
37. `cognitoCustomAuthThreatProtectionDisabled` (S/M)

---

## Summary of additions:

| Service | Current | Adding | New Total |
|---|---|---|---|
| Step Functions | 24 | +4 | 28 |
| SNS | 19 | +4 | 23 |
| WAFv2 | 24 | +17 | 41 |
| Cognito | 27 | +10 | 37 |
| **Total** | 94 | **+35** | **129** |

## Framework Mapping (new checks):

### AAIL:
- sfnIAMRoleAllowsPassRole → AGENTSEC01.BP02 (least privilege)
- sfnHttpTaskNoTLS → AGENTSEC06.BP01 (encryption in transit)
- wafv2AlbWithoutWebAcl, wafv2ApiGatewayWithoutWebAcl, wafv2CloudFrontWithoutWebAcl → AGENTSEC08.BP01 (network protection)
- cognitoCompromisedCredentialIncompleteFilter, cognitoGroupOverlyPermissiveRole → AGENTSEC03.BP01 (identity)
- cognitoCustomAuthThreatProtectionDisabled → AGENTSEC03.BP02

### WAFS:
- sfnIAMRoleAllowsPassRole → SEC03.BP01 (least privilege)
- sfnHttpTaskNoTLS, sfnLoggingWithoutEncryption → SEC09.BP01 (encryption in transit / at rest)
- wafv2 cross-service checks → SEC09.BP02 (network protection)
- wafv2LoggingMissingRedactedFields → SEC08.BP01 (protect data at rest)
- cognitoGroupOverlyPermissiveRole → SEC03.BP01
- cognitoCompromisedCredentialIncompleteFilter → SEC02.BP01

### Other frameworks: map to same BPs where similar existing checks already have refs.

## Implementation Order:
1. WAFv2 (biggest batch — 17 checks, needs cross-service clients)
2. Cognito (10 checks — needs IAM policy evaluation for groups)
3. Step Functions (4 checks — needs IAM + CloudWatch)
4. SNS (4 checks — needs SMS attributes + FIFO detection)
5. Framework mappings
6. Validate + RuleCount
7. Full scan test
8. Commit

## Commit message:
```
feat: Phase 2 — hit realistic max with +35 checks (SFN/SNS/WAFv2/Cognito)

Step Functions (24→28): +4 IAM/operational checks
  sfnIAMRoleAllowsPassRole, sfnNoCloudWatchAlarm,
  sfnLoggingWithoutEncryption, sfnHttpTaskNoTLS

SNS (19→23): +4 FIFO/SMS/policy checks
  snsFifoContentDeduplicationDisabled, snsSmsNoSpendLimit,
  snsPolicyVersionOutdated, snsFifoNoArchivePolicy

WAFv2 (24→41): +17 rule effectiveness + cross-service coverage
  wafv2NoAccountTakeoverPrevention, wafv2NoAccountCreationFraudPrevention,
  wafv2PaidRuleGroupWithoutScopeDown, wafv2ManagedRuleGroupExcludedRulesExcessive,
  wafv2NoKnownBadInputsRuleSet, wafv2NoAnonymousIpList,
  wafv2RulePriorityOrdering, wafv2IpSetEmpty, wafv2RegexPatternSetEmpty,
  wafv2RuleGroupEmpty, wafv2LoggingMissingRedactedFields,
  wafv2ManagedRuleGroupVersionExpiring,
  wafv2AlbWithoutWebAcl, wafv2ApiGatewayWithoutWebAcl,
  wafv2CloudFrontWithoutWebAcl, wafv2AppSyncWithoutWebAcl,
  wafv2CognitoUserPoolWithoutWebAcl

Cognito (27→37): +10 threat protection depth + IAM analysis
  cognitoCompromisedCredentialIncompleteFilter, cognitoNoThreatProtectionLogging,
  cognitoLongTemporaryPassword, cognitoClientNoSecret,
  cognitoClientExcessiveScopes, cognitoNoMfaMethods,
  cognitoSmsOnlyMfa, cognitoAccountTakeoverNoNotification,
  cognitoGroupOverlyPermissiveRole, cognitoCustomAuthThreatProtectionDisabled

Cross-service clients added: elbv2, apigateway, cloudfront, appsync
IAM policy evaluation for SFN roles and Cognito group roles

Total rule count: 701 → 736 (+35)
```

# Additional Checks Spec — Extend Existing Services

Project: /Users/kuettai/Documents/project/ss-genai/service-screener-v2

Use the `prompt-template-extend-service.md` pattern: ONLY ADD new checks, do NOT remove or modify existing ones.

## Step Functions — Add 4 checks (services/stepfunctions/)

### New checks to add to stepfunctions.reporter.json + StepfunctionsCommon.py:

13. `sfnNoHeartbeat` (R/M) — Task states using `.waitForTaskToken` pattern without `HeartbeatSeconds` field. Parse definition JSON, find Task states where Resource contains `.waitForTaskToken`, check if `HeartbeatSeconds` is set. FAIL if any waitForTaskToken task lacks heartbeat. Ref: https://docs.aws.amazon.com/step-functions/latest/dg/sfn-best-practices.html ("Using timeouts" section explicitly recommends HeartbeatSeconds for callback tasks)

14. `sfnLargePayloadRisk` (P/L) — State machine definition has no S3 integration pattern but has Pass/Result states with large inline payloads (>10KB in ResultPath or Parameters). Informational — flag as INFO (0) not FAIL. Hard to detect perfectly, so use heuristic: if definition JSON > 50KB AND no `arn:aws:s3` reference in definition, flag.

15. `sfnMapNoConcurrencyLimit` (P/M) — Map state exists in definition without `MaxConcurrency` set (unbounded parallel execution can exhaust downstream resources). Parse definition, find states with `Type: Map`, check for `MaxConcurrency` field. FAIL if any Map state lacks it.

16. `sfnTaskNoTimeout` (R/M) — Individual Task states without `TimeoutSeconds` (separate from top-level timeout check #8). Parse definition, find `Type: Task` states, flag those without `TimeoutSeconds` or `HeartbeatSeconds`. Report which task names lack timeout.

## SNS — Add 3 checks (services/sns/)

### New checks to add to sns.reporter.json + SnsCommon.py:

13. `snsNoDataProtectionPolicy` (S/M) — Topic has no DataProtectionPolicy configured (PII can flow through messages undetected/unmasked). Check: `GetDataProtectionPolicy` API or check `DataProtectionPolicy` field in topic attributes. If empty/null, FAIL. Ref: https://docs.aws.amazon.com/sns/latest/dg/sns-message-data-protection.html

14. `snsCrossAccountAccessNoCondition` (S/M) — Policy allows cross-account principals (specific account IDs, not * but not same account) WITHOUT requiring aws:PrincipalOrgID condition. Parse policy, find Allow statements where Principal contains account IDs different from topic owner, check for OrgID condition. Separate from check #3 (which is wildcard *).

15. `snsNoDeliveryRetryPolicy` (R/L) — Topic uses default delivery retry policy (aggressive backoff that may overwhelm subscribers). Check: If `EffectiveDeliveryPolicy` matches the AWS default or is absent, flag as INFO. Low criticality — informational only.

## WAFv2 — Add 4 checks (services/wafv2/)

### New checks to add to wafv2.reporter.json + Wafv2Common.py:

13. `wafv2NoIpReputationList` (S/M) — WebACL has managed rule groups but does NOT include `AWSManagedRulesAmazonIpReputationList`. This blocks known malicious IPs. Only flag if the ACL has at least one managed group (don't flag empty ACLs — that's check #1). Ref: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html

14. `wafv2NoSqlInjectionProtection` (S/M) — No SQL injection protection: neither `AWSManagedRulesSQLiRuleSet` managed group NOR any custom rule with `SqliMatchStatement`. Recursive statement walk. Ref: OWASP Top 10 + AWS managed rules docs.

15. `wafv2NoXssProtection` (S/M) — No XSS protection: neither managed XSS group NOR any custom rule with `XssMatchStatement`. Same recursive walk pattern.

16. `wafv2HighCapacityUsage` (P/M) — WebACL capacity (WCU) is > 80% of the 5000 WCU limit (REGIONAL) or 1500 WCU limit (CLOUDFRONT). Field: `Capacity` from GetWebACL response. Threshold: capacity/limit > 0.8.

## Cognito — Add 4 checks (services/cognito/)

### New checks to add to cognito.reporter.json + CognitoCommon.py:

13. `cognitoCompromisedCredentialProtection` (S/H) — Advanced security is enabled (AdvancedSecurityMode=ENFORCED) BUT CompromisedCredentialsRiskConfiguration EventAction is not BLOCK. Check: call `describe_risk_configuration` for the pool, check `CompromisedCredentialsRiskConfiguration.Actions.EventAction`. If not BLOCK, FAIL. If advanced security is OFF, skip (check #3 already covers that).

14. `cognitoSelfServiceSignUpNoVerification` (S/M) — Self-service sign-up is enabled (`AdminCreateUserConfig.AllowAdminCreateUserOnly = false`) AND no email/phone verification required (`AutoVerifiedAttributes` empty). Spam/abuse risk. Only FAIL if BOTH conditions true.

15. `cognitoNoCustomDomain` (O/L) — User pool uses only the default Cognito domain (`amazoncognito.com`) without a custom domain configured. Check: `describe_user_pool` → `Domain` field or `CustomDomain` field. INFO-level only.

16. `cognitoNoWafAssociation` (S/M) — User pool has no WAF WebACL associated (no bot/abuse protection on hosted UI auth endpoints). Check: `get_web_acl_for_resource` on the pool ARN, or check via `wafv2:GetWebACLForResource`. If no ACL, FAIL.

## After adding all 15 new checks:

1. Validate: all reporter keys match _check methods for each service
2. Run RuleCount.py from project root
3. Update framework mappings for new checks:
   - AAIL: sfnNoHeartbeat/sfnTaskNoTimeout → AGENTREL02.BP01; snsNoDataProtectionPolicy → AGENTSEC01.BP02; wafv2NoIpReputationList/wafv2NoSqlInjectionProtection → AGENTSEC08.BP01; cognitoCompromisedCredentialProtection → AGENTSEC03.BP01
   - WAFS: wafv2NoIpReputationList/NoSqlI/NoXss → SEC09.BP02; cognitoCompromisedCredentialProtection → SEC02.BP01; snsNoDataProtectionPolicy → SEC07.BP01
4. Test all 4 services: python3 main.py --regions us-east-1 --services stepfunctions,sns,wafv2,cognito --beta 1 --sequential 1
5. Report: new total check counts per service, any errors

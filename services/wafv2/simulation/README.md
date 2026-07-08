# WAFv2 Simulation Testing

Scripts to create intentionally-misconfigured WAFv2 resources to validate
all 41 `wafv2*` service-screener checks.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| WAFv2 WebACL `ss-test-wafv2-acl-*` (REGIONAL) | `DefaultAction=Allow`, `Rules=[]`, VisibilityConfig everything off, no logging, no tags, no association | #1, #5, #6, #8, #9, #11, #12 |
| CloudWatch Log Group `aws-waf-logs-ss-test-*` | Destination for WAF logging config on the partial WebACL | supports #35 |
| IPSet `ss-test-ipset-empty-*` | `Addresses=[]`, referenced by partial ACL | #32 |
| Regex Pattern Set `ss-test-regex-empty-*` | Empty regex list, referenced by partial ACL | #33 |
| Custom Rule Group `ss-test-rulegroup-empty-*` | `Rules=[]`, referenced by partial ACL | #34 |
| WAFv2 WebACL `ss-test-wafv2-acl-partial-*` | CommonRuleSet with 9 rules overridden to Count; references the three empty entities above; logging configured with **no RedactedFields** | #17-related, #29, #30, #32, #33, #34, #35 |
| AppSync GraphQL API `ss-test-appsync-nowaf-*` | `wafWebAclArn` unset | #40 |

## Coverage — All 41 Checks

| # | Check | Simulated? | Notes |
|---:|---|:---:|---|
| 1 | wafv2NoRules | ✓ | insecure ACL |
| 2 | wafv2NoManagedRuleGroups | (N/A) | deferred to #1 |
| 3 | wafv2NoRateBasedRules | (N/A) | deferred to #1 |
| 4 | wafv2RulesInCountMode | (N/A) | deferred to #1 |
| 5 | wafv2DefaultActionAllow | ✓ | insecure ACL |
| 6 | wafv2LoggingNotConfigured | ✓ | insecure ACL |
| 7 | wafv2LoggingFilterAllDrop | (N/A) | deferred to #6 |
| 8 | wafv2CloudWatchMetricsDisabled | ✓ | insecure ACL |
| 9 | wafv2SampledRequestsDisabled | ✓ | insecure ACL |
| 10 | wafv2RuleVisibilityDisabled | (N/A) | deferred to #1 |
| 11 | wafv2NotAssociated | ✓ | insecure ACL |
| 12 | wafv2ResourcesWithoutTags | ✓ | both ACLs |
| 13-16 | (Phase 1a) | ✓ | fire on partial ACL (`wafv2NoIpReputationList` etc.) |
| 17 | wafv2ManagedRuleGroupAllCountOverride | ~partial | Overrides 9/N rules; whether this trips depends on N. Partial coverage — #28 is the "excessive" variant which is the main target. |
| 18 | wafv2NoCoreRuleSet | ✓ | insecure ACL has no managed groups at all |
| 19 | wafv2AllowRuleBeforeManagedRules | (N/A) | not fabricated (would require specific priority setup) |
| 20 | wafv2ManagedRuleGroupVersionPinned | (N/A) | partial ACL uses default (unpinned) version |
| 21 | wafv2NoBotControl | (N/A) | insecure ACL unassociated |
| 22 | wafv2RateBasedRuleThresholdTooHigh | (N/A) | no rate rules created |
| 23 | wafv2LoggingFilterDropsBlocked | (N/A) | test logging has no filter |
| 24 | wafv2IpSetOverlyPermissive | (N/A) | IP set is empty, not overly broad |
| **25** | wafv2NoAccountTakeoverPrevention | INFO | Reports INFO on unassociated test ACLs (check defers). To force FAIL, attach one of the test ACLs to a real resource. |
| **26** | wafv2NoAccountCreationFraudPrevention | INFO | Same INFO-when-unassociated caveat |
| **27** | wafv2PaidRuleGroupWithoutScopeDown | (N/A) | Paid groups (BotControl/ATP/ACFP) not attached — cost concern |
| **28** | wafv2ManagedRuleGroupExcludedRulesExcessive | ~partial | 9 CRS overrides. Modern CommonRuleSet has >18 rules, so 9/N sits at <50% and check PASSes. Increase overrides in the script to force FAIL — see "Known limitation" below. |
| **29** | wafv2NoKnownBadInputsRuleSet | ✓ **FAIL** | partial ACL has CRS only |
| **30** | wafv2NoAnonymousIpList | ✓ **FAIL** | partial ACL has CRS only |
| **31** | wafv2RulePriorityOrdering | (N/A) | no rate-rule / paid-group pair to order |
| **32** | wafv2IpSetEmpty | ✓ **FAIL** | empty IPSet referenced |
| **33** | wafv2RegexPatternSetEmpty | ✓ **FAIL** | empty regex referenced |
| **34** | wafv2RuleGroupEmpty | ✓ **FAIL** | empty custom rule group referenced |
| **35** | wafv2LoggingMissingRedactedFields | ✓ **FAIL** | logging config attached without `RedactedFields` |
| **36** | wafv2ManagedRuleGroupVersionExpiring | (N/A) | AWS-controlled — no pinned versions in this test |
| **37** | wafv2AlbWithoutWebAcl | (N/A) | No ALBs in region. **Manual** — create an ALB to trigger |
| **38** | wafv2ApiGatewayWithoutWebAcl | ✓ **FAIL** | fires against natural account state (existing unprotected REST APIs) |
| **39** | wafv2CloudFrontWithoutWebAcl | ✓ **FAIL** | fires against natural account state |
| **40** | wafv2AppSyncWithoutWebAcl | ✓ **FAIL** | AppSync API created without wafWebAclArn |
| **41** | wafv2CognitoUserPoolWithoutWebAcl | ✓ **FAIL** | fires against natural account state |

**End-to-end validation (this session):** 16 of 17 new-in-Phase-2 checks
fired the expected result. `wafv2ManagedRuleGroupExcludedRulesExcessive`
(check #28) was the miss — see "Known limitation" below.

## Known Limitation

### Check #28 (`wafv2ManagedRuleGroupExcludedRulesExcessive`)
The script overrides 9 rules in `AWSManagedRulesCommonRuleSet`. To trip the
>50% threshold in check #28, the number of overrides needs to exceed half the
group's live rule count. AWS has expanded CRS to well over 18 rules, so 9
overrides now sits below 50% and the check reports PASS.

**Workaround:** edit `create_test_resources.sh` Step 6 and expand the
`RuleActionOverrides` list to include ~15 rules (add
`GenericLFI_QUERYARGUMENTS`, `GenericLFI_URIPATH`, `GenericLFI_BODY`,
`RestrictedExtensions_URIPATH`, `GenericRFI_URIPATH`,
`CrossSiteScripting_QUERYARGUMENTS`). Alternatively, use `aws wafv2
describe-managed-rule-group` at build time to enumerate the live rules and
override half+1 dynamically.

## Not Simulated (Documented as Manual)

- **Check #37 (ALB without WAF)** — an internet-facing ALB idles at ~$16/month
  and requires two subnets in different AZs. Excluded to keep sim cost near
  zero. To validate manually: create a t3.micro-fronting ALB in a default
  VPC without associating a WebACL, then re-run the scan.
- **Check #27 (paid group without ScopeDown)** — paid managed groups (ATP,
  ACFP, BotControl) accrue per-request charges. Attach one manually to a
  test ACL to validate.
- **Check #31 (priority ordering)** — depends on #27 (paid group presence).
- **Check #36 (managed rule group version expiring)** — depends on AWS's
  version release schedule; not deterministically reproducible.

## Cost Impact

- 2 REGIONAL WebACLs: ~$5/month each = **~$10/month prorated** while alive
- IPSet / Regex / RuleGroup / LogGroup / AppSync API: no standing charge
- **Total per test cycle (30 min):** < **$0.30**

## Usage

```bash
cd services/wafv2/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

# Create
./create_test_resources.sh          # or --skip-appsync to skip check #40

# Scan
cd ../../..
python3 main.py --regions us-east-1 --services wafv2 --beta 1 --sequential 1

# Cleanup
cd services/wafv2/simulation
./cleanup_test_resources.sh --force
```

## IAM Permissions Required

Base (Phase 1):
- `wafv2:CreateWebACL`, `wafv2:GetWebACL`, `wafv2:DeleteWebACL`,
  `wafv2:ListWebACLs`, `wafv2:GetLoggingConfiguration`,
  `wafv2:ListResourcesForWebACL`, `wafv2:ListTagsForResource`
- `sts:GetCallerIdentity`
- (Scanner only) `cloudfront:ListDistributionsByWebACLId`

Phase 2 additions:
- `wafv2:CreateIPSet`, `wafv2:GetIPSet`, `wafv2:DeleteIPSet`, `wafv2:ListIPSets`
- `wafv2:CreateRegexPatternSet`, `wafv2:GetRegexPatternSet`,
  `wafv2:DeleteRegexPatternSet`, `wafv2:ListRegexPatternSets`
- `wafv2:CreateRuleGroup`, `wafv2:GetRuleGroup`, `wafv2:DeleteRuleGroup`,
  `wafv2:ListRuleGroups`, `wafv2:DescribeManagedRuleGroup`,
  `wafv2:ListAvailableManagedRuleGroupVersions`
- `wafv2:PutLoggingConfiguration`, `wafv2:DeleteLoggingConfiguration`
- `wafv2:GetWebACLForResource` (for cross-service coverage checks)
- `logs:CreateLogGroup`, `logs:DeleteLogGroup`, `logs:DescribeLogGroups`
- `appsync:CreateGraphqlApi`, `appsync:DeleteGraphqlApi`, `appsync:ListGraphqlApis`
- (Scanner only, cross-service) `elasticloadbalancing:DescribeLoadBalancers`,
  `apigateway:GET` on `/restapis`, `cognito-idp:ListUserPools`

## Notes

- Deletion order in cleanup is precise: logging config → WebACLs →
  RuleGroup → RegexPatternSet → IPSet → LogGroup. WAFv2 blocks deletion
  of any entity while it's still referenced.
- Every WAFv2 delete uses a fresh `LockToken` fetched via the matching
  `get_*` API. Stale tokens from create-time responses will cause deletes
  to fail with `WAFOptimisticLockException`.
- The AppSync API is deleted first because it has no dependencies on the
  rest of the WAFv2 resources.
- CloudWatch log groups can be deleted while the WAF logging config
  points at them — the config's `DeleteLoggingConfiguration` call runs
  before the log group delete so the reference is gone by then.

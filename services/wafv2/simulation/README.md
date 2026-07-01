# WAFv2 Simulation Testing

Scripts to create an intentionally-insecure REGIONAL WebACL to validate the
12 `wafv2*` service-screener checks.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| WAFv2 WebACL `ss-test-wafv2-acl-*` (REGIONAL) | `DefaultAction=Allow`, `Rules=[]`, `VisibilityConfig.CloudWatchMetricsEnabled=false`, `VisibilityConfig.SampledRequestsEnabled=false`, no logging configuration, no tags, not associated with any resource | #1, #2, #3, #5, #6, #8, #9, #11, #12 |

## Coverage

| # | Check | Result on simulated WebACL |
|---:|---|---|
| 1 | wafv2NoRules | ✓ **FAIL** |
| 2 | wafv2NoManagedRuleGroups | N/A — deferred to #1 (empty WebACL) |
| 3 | wafv2NoRateBasedRules | N/A — deferred to #1 |
| 4 | wafv2RulesInCountMode | N/A — deferred to #1 |
| 5 | wafv2DefaultActionAllow | ✓ **FAIL** |
| 6 | wafv2LoggingNotConfigured | ✓ **FAIL** |
| 7 | wafv2LoggingFilterAllDrop | N/A — deferred to #6 |
| 8 | wafv2CloudWatchMetricsDisabled | ✓ **FAIL** |
| 9 | wafv2SampledRequestsDisabled | ✓ **FAIL** |
| 10 | wafv2RuleVisibilityDisabled | N/A — deferred to #1 |
| 11 | wafv2NotAssociated | ✓ **FAIL** |
| 12 | wafv2ResourcesWithoutTags | ✓ **FAIL** |

**Directly triggered: 7 FAILs. 5 checks correctly return N/A** because their
concern is already covered by a sibling check that FAILs (avoiding
double-flagging the same root cause).

The five N/A checks are validated on real-world WebACLs elsewhere:
- #2, #3, #4, #10 fire when the WebACL has rules but with the specific
  problem (no managed groups, no rate-based rule, action=Count, per-rule
  visibility off). They passed correctly against the account's existing
  CloudFront-scoped WebACLs during development.
- #7 fires when logging IS configured with a DROP-everything filter. It
  cannot coexist with #6 on the same test resource.

The design deliberately avoids double-flagging: check #2 does not FAIL a
second time on a WebACL that already FAILs #1 for having zero rules —
fixing #1 makes #2 meaningful.

## Cost

While the WebACL exists you pay the base ~$5/month prorated (WAFv2 minimum
charge per WebACL). The test WebACL has no rules → no per-rule charge.
Delete promptly after testing.

## Usage

```bash
cd services/wafv2/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh
# no wait needed — WAFv2 GetWebACL is immediately consistent
cd ../../..
python3 main.py --regions us-east-1 --services wafv2 --beta 1 --sequential 1
cd services/wafv2/simulation
./cleanup_test_resources.sh --force
```

## IAM Permissions Required

- `wafv2:CreateWebACL`, `wafv2:GetWebACL`, `wafv2:DeleteWebACL`,
  `wafv2:ListWebACLs`, `wafv2:GetLoggingConfiguration`,
  `wafv2:ListResourcesForWebACL`, `wafv2:ListTagsForResource`
- `sts:GetCallerIdentity`
- (Scanner only) `cloudfront:ListDistributionsByWebACLId` — for
  CLOUDFRONT-scoped WebACL association lookups.

## Notes

- The scanner queries both REGIONAL (in every scanned region) and
  CLOUDFRONT scope (only when scanning `us-east-1`, since CLOUDFRONT
  WebACLs live only there).
- REGIONAL WebACL association is resolved via
  `wafv2:ListResourcesForWebACL` across the six regional resource types
  (ALB, API Gateway, AppSync, Cognito User Pool, App Runner, Verified Access).
- CLOUDFRONT WebACL association is resolved via
  `cloudfront:ListDistributionsByWebACLId`.
- If your account has zero WebACLs and you scan without running the
  simulation, the scanner prints no findings — that is correct behaviour.

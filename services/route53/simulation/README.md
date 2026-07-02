# Route 53 Simulation Testing

Scripts to create intentionally-misconfigured Route 53 resources to validate
the `route53*` service-screener checks.

## Coverage Matrix — All 24 Checks

| # | Check | Simulated? | How |
|---:|---|:---:|---|
| 1 | `route53DnssecNotEnabled` | ✓ | Every public zone created without DNSSEC signing (default) fires this — the test zone included. |
| 2 | `route53QueryLoggingNotEnabled` | ✓ | Test zones created without query logging config. |
| 3 | `route53DomainAutoRenewDisabled` | **manual** | Requires a real registered domain in `route53domains`; cannot be fabricated for testing without paying for a registration. |
| 4 | `route53DomainTransferLockDisabled` | **manual** | Same reason as #3. |
| 5 | `route53DomainPrivacyDisabled` | **manual** | Same reason as #3. |
| 6 | `route53DomainExpiringSoon` | **manual** | Same reason as #3. |
| 7 | `route53HealthCheckUsingHttp` | ✓ | HTTP health check created (`Type=HTTP`). |
| 8 | `route53HealthCheckNoAlarm` | ✓ | Every test health check is created without a CloudWatch alarm. |
| 9 | `route53ResolverDnsFirewallNotConfigured` | **natural** | Most accounts have no DNS Firewall by default — fires without any setup. |
| 10 | `route53ResolverQueryLoggingNotEnabled` | **natural** | Same as #9. |
| 11 | `route53ResolverDnssecValidationDisabled` | **natural** | Same as #9. |
| 12 | `route53HostedZoneUnused` | ✓ (delayed) | Empty test zone is created — check exempts zones < 24h old, so re-run scan tomorrow to observe FAIL. |
| 13 | `route53HealthCheckSlowInterval` | ✓ | Every test health check uses `RequestInterval=30`. |
| 14 | `route53HealthCheckLowFailureThreshold` | ✓ | HTTP test health check uses `FailureThreshold=1`. |
| 15 | `route53CnameAtZoneApex` | **manual** | Route 53 API rejects apex CNAME creation. To exercise this check, import a zone file that has CNAME co-existing with NS/SOA (or migrate an existing misconfigured zone). |
| 16 | `route53MxWithoutSpfDmarc` | ✓ | Test zone has MX record but no SPF/DMARC TXT. |
| 17 | `route53HealthCheckDisabled` | ✓ | Test health check created with `Disabled=true`. |
| 18 | `route53RecordNoHealthCheck` | ✓ | Test zone has `weighted.<zone>` A record with `Weight=100` but no `HealthCheckId`. |
| 19 | `route53DanglingDnsRecords` | ✓ | Test zone has `www.<zone>` CNAME pointing to a non-existent `d3b0gu5nonex1st.cloudfront.net` target. |
| 20 | `route53LowTtlOnStableRecords` | ✓ | Test zone has `flappy.<zone>` A record with `TTL=15`. |
| 21 | `route53PublicZoneSensitiveNames` | ✓ | Test zone has `admin.<zone>` A record. |
| 22 | `route53HealthCheckSniDisabled` | ✓ | HTTPS health check created with `EnableSNI=false`. |
| 23 | `route53EmptyHostedZone` | ✓ (delayed) | Same as #12 — 24h delay. |
| 24 | `route53NoRecordRoutingPolicy` | ✓ | Test zone has `flappy.<zone>` A record (no routing policy, no alias). |

**Coverage:** 15 checks fully fabricated + 3 delayed (24h) + 3 natural-state + 3 manual (need real domain).

## Resources Created

- **1 populated hosted zone** (`ss-test-route53-fail-<timestamp>.example.internal.`)
  containing: dangling CNAME, MX-without-SPF, sensitive `admin.*` record,
  low-TTL record, weighted record without HealthCheckId.
- **1 empty hosted zone** (`ss-test-route53-empty-<timestamp>.example.internal.`)
  used to demonstrate the unused / empty zone checks (24h delay).
- **3 health checks**:
  - HTTP, RequestInterval=30, FailureThreshold=1 (fires #7 + #8 + #13 + #14).
  - HTTPS with EnableSNI=false, RequestInterval=30 (fires #8 + #13 + #22).
  - Disabled HTTP (fires #7 + #8 + #13 + #17).

## Cost Impact

- 2 hosted zones × $0.50/month = ~$1/month prorated while alive
- 3 health checks × $0.50/month = $1.50/month prorated while alive
- **Total for a 30-minute test cycle: < $0.10**

## Usage

```bash
cd services/route53/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh

# Create test resources
./create_test_resources.sh                     # ap-southeast-1 by default
./create_test_resources.sh --region us-east-1  # or explicit region

# Scan
cd ../../..
python3 main.py --regions ap-southeast-1 --services route53 --beta 1 --sequential 1

# Cleanup (uses most-recent manifest by default)
cd services/route53/simulation
./cleanup_test_resources.sh --force
```

## Notes on Regionality

- Hosted zones and health checks are **global** resources (accessible from any
  region). The scanner claims a single "primary" region per scan for global
  discovery to avoid duplicating findings across regions; the simulation script
  works with any region.
- `route53domains` runs ONLY in `us-east-1`. Domain checks (#3-#6) require
  boto3 with the domains client region-pinned to `us-east-1` — the scanner
  does this automatically.
- Resolver (DNS Firewall, query logging, DNSSEC validation) is **regional**.
  Resolver checks fire per-region — if you scan multiple regions each region
  reports independently.

## IAM Permissions Required for the Simulation

- `route53:CreateHostedZone`, `route53:DeleteHostedZone`,
  `route53:ChangeResourceRecordSets`, `route53:ListResourceRecordSets`
- `route53:CreateHealthCheck`, `route53:DeleteHealthCheck`,
  `route53:GetHealthCheck`
- `sts:GetCallerIdentity`

Scanner also needs:
- `route53:GetDNSSEC`, `route53:GetHostedZone`,
  `route53:ListHostedZones`, `route53:ListHealthChecks`,
  `route53:ListQueryLoggingConfigs`
- `route53domains:ListDomains`, `route53domains:GetDomainDetail` (us-east-1)
- `route53resolver:ListFirewallRuleGroupAssociations`,
  `route53resolver:ListResolverQueryLogConfigs`,
  `route53resolver:ListResolverQueryLogConfigAssociations`,
  `route53resolver:ListResolverDnssecConfigs`
- Cross-service (for #19 dangling records):
  `cloudfront:ListDistributions`, `elasticloadbalancing:DescribeLoadBalancers`,
  `elasticloadbalancing:DescribeLoadBalancers` (classic ELB),
  `s3:ListAllMyBuckets`, `elasticbeanstalk:DescribeEnvironments`.

Missing IAM permissions do not crash the scanner — affected checks
downgrade to INFO with a message indicating the lookup failed.

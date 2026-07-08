# Route 53 — Service Screener v2: Complete Check Enumeration

## Overview

**Boto3 Clients Required:**
- `route53` — Hosted Zones, Records, Health Checks, DNSSEC
- `route53resolver` — DNS Firewall, Resolver Query Logging, DNSSEC Validation
- `route53domains` — Domain Registration (⚠️ us-east-1 only)

**Security Hub Controls Covered:**
- `Route53.1` → Health checks tagged (tagging check — low value)
- `Route53.2` → Public hosted zones should log DNS queries

---

## TIER 1 — HIGH VALUE (Implement First)

These are deterministic, low-API-cost checks aligned with Security Hub, Well-Architected, and common compliance frameworks.

---

### 1. `route53DnssecNotEnabled`

| Field | Value |
|-------|-------|
| **Category** | Hosted Zones |
| **Pillar** | Security |
| **Severity** | Medium |
| **Security Hub** | — (not a current SH control, but aligns with DNSSEC best practice) |
| **API Calls** | `route53.list_hosted_zones()` → `route53.get_dnssec(HostedZoneId=id)` |
| **FAIL Condition** | `Status.ServeSignature != 'SIGNING'` (or no KeySigningKeys present) |
| **Logic** | For each public hosted zone (`Config.PrivateZone == False`), call `get_dnssec`. If `ServeSignature` is `NOT_SIGNING` or empty, FAIL. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — DNSSEC prevents DNS spoofing/cache poisoning. Required by many compliance frameworks. |
| **Notes** | Only applies to public zones. Private zones cannot have DNSSEC. |

---

### 2. `route53QueryLoggingNotEnabled`

| Field | Value |
|-------|-------|
| **Category** | Hosted Zones |
| **Pillar** | Security (Logging/Monitoring) |
| **Severity** | Medium |
| **Security Hub** | **Route53.2** — "Route 53 public hosted zones should log DNS queries" |
| **API Calls** | `route53.list_hosted_zones()` → `route53.list_query_logging_configs(HostedZoneId=id)` |
| **FAIL Condition** | `QueryLoggingConfigs` list is empty for a public hosted zone |
| **Logic** | For each public zone, check if at least one query logging config exists. Empty list = FAIL. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Direct Security Hub control. DNS query logs critical for incident response & threat detection. |
| **Notes** | Query logging sends to CloudWatch Logs. Private zones use Resolver query logging (separate check). |

---

### 3. `route53DomainAutoRenewDisabled`

| Field | Value |
|-------|-------|
| **Category** | Domains |
| **Pillar** | Reliability |
| **Severity** | High |
| **API Calls** | `route53domains.list_domains()` → `route53domains.get_domain_detail(DomainName=name)` |
| **FAIL Condition** | `AutoRenew == False` |
| **Logic** | For each domain, if `AutoRenew` is `False`, FAIL. Domain could expire and be registered by attacker. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Domain expiry is a critical availability AND security risk (domain hijacking). |
| **Notes** | `route53domains` client must be created in `us-east-1`. |

---

### 4. `route53DomainTransferLockDisabled`

| Field | Value |
|-------|-------|
| **Category** | Domains |
| **Pillar** | Security |
| **Severity** | High |
| **API Calls** | `route53domains.get_domain_detail(DomainName=name)` |
| **FAIL Condition** | `StatusList` does NOT contain `'clientTransferProhibited'` |
| **Logic** | Check `StatusList` for the EPP status code `clientTransferProhibited`. If absent, transfer lock is disabled. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Without transfer lock, domain can be stolen via unauthorized registrar transfer. |
| **Notes** | Some TLDs don't support transfer lock. Handle gracefully. |

---

### 5. `route53DomainPrivacyDisabled`

| Field | Value |
|-------|-------|
| **Category** | Domains |
| **Pillar** | Security |
| **Severity** | Medium |
| **API Calls** | `route53domains.get_domain_detail(DomainName=name)` |
| **FAIL Condition** | `AdminPrivacy == False` OR `RegistrantPrivacy == False` OR `TechPrivacy == False` |
| **Logic** | Any contact type without privacy protection enabled is a FAIL. Exposes PII via WHOIS. |
| **Usefulness** | ⭐⭐⭐⭐ — Prevents social engineering via exposed WHOIS data. |
| **Notes** | Some TLDs don't support privacy. Check `BillingPrivacy` too if present. |

---

### 6. `route53DomainExpiringSoon`

| Field | Value |
|-------|-------|
| **Category** | Domains |
| **Pillar** | Reliability |
| **Severity** | High (≤30 days), Medium (≤90 days) |
| **API Calls** | `route53domains.get_domain_detail(DomainName=name)` |
| **FAIL Condition** | `ExpirationDate` is within 90 days of current date (AND `AutoRenew == False`) |
| **Logic** | Calculate days until `ExpirationDate`. If ≤90 days and AutoRenew is off, FAIL. If ≤30 days regardless, HIGH severity FAIL. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Proactive warning before domain loss. |
| **Notes** | Even with AutoRenew, if payment fails the domain will expire. Consider warning at ≤30 days regardless. |

---

### 7. `route53HealthCheckUsingHttp`

| Field | Value |
|-------|-------|
| **Category** | Health Checks |
| **Pillar** | Security |
| **Severity** | Medium |
| **API Calls** | `route53.list_health_checks()` |
| **FAIL Condition** | `HealthCheckConfig.Type` is `'HTTP'` or `'HTTP_STR_MATCH'` |
| **Logic** | Health checks using HTTP transmit data in cleartext. Check if `Type` starts with `HTTP` (not `HTTPS`). Also check `EnableSNI == False` on HTTPS checks (minor additional flag). |
| **Usefulness** | ⭐⭐⭐⭐ — HTTP health checks may leak internal paths and allow MITM manipulation of health status. |
| **Notes** | TCP and CLOUDWATCH_METRIC types are exempt. Some endpoints genuinely only support HTTP. |

---

### 8. `route53HealthCheckNoAlarm`

| Field | Value |
|-------|-------|
| **Category** | Health Checks |
| **Pillar** | Operational Excellence |
| **Severity** | Medium |
| **API Calls** | `route53.list_health_checks()` |
| **FAIL Condition** | `CloudWatchAlarmConfiguration` is `None`/absent AND `HealthCheckConfig.Type` is NOT `'CLOUDWATCH_METRIC'` |
| **Logic** | For endpoint health checks (HTTP/HTTPS/TCP), verify that a CloudWatch alarm is associated. The `CloudWatchAlarmConfiguration` field in the response indicates this. If absent, there's no alerting on health check failures. |
| **Usefulness** | ⭐⭐⭐⭐ — Without alarms, health check failures go unnoticed until user impact. |
| **Notes** | CLOUDWATCH_METRIC type health checks are inherently alarm-based, so exempt them. CALCULATED types may also be exempt. |

---

### 9. `route53ResolverDnsFirewallNotConfigured`

| Field | Value |
|-------|-------|
| **Category** | Resolver |
| **Pillar** | Security |
| **Severity** | Medium |
| **API Calls** | `route53resolver.list_firewall_rule_group_associations()` |
| **FAIL Condition** | No firewall rule group associations exist (empty list) |
| **Logic** | If `FirewallRuleGroupAssociations` is empty across the account/region, DNS Firewall is not protecting any VPC. FAIL. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — DNS Firewall blocks DNS-based data exfiltration and C2 communication. Critical for zero-trust. |
| **Notes** | Check per-VPC or account-wide. Consider also checking for AWS-managed domain lists (e.g., malware domains). |

---

### 10. `route53ResolverQueryLoggingNotEnabled`

| Field | Value |
|-------|-------|
| **Category** | Resolver |
| **Pillar** | Security (Logging) |
| **Severity** | Medium |
| **API Calls** | `route53resolver.list_resolver_query_log_configs()` → `route53resolver.list_resolver_query_log_config_associations()` |
| **FAIL Condition** | No query log configs exist, OR configs exist but no VPCs are associated |
| **Logic** | First check if any `ResolverQueryLogConfigs` exist. Then verify VPCs are associated via `list_resolver_query_log_config_associations`. If no associations, FAIL. |
| **Usefulness** | ⭐⭐⭐⭐⭐ — Resolver query logging captures all DNS queries from VPCs (including private zones). Critical for threat hunting. |
| **Notes** | This is different from Route53.2 (which covers public hosted zone query logging). This covers VPC-level resolver logging. |

---

### 11. `route53ResolverDnssecValidationDisabled`

| Field | Value |
|-------|-------|
| **Category** | Resolver |
| **Pillar** | Security |
| **Severity** | Medium |
| **API Calls** | `route53resolver.list_resolver_dnssec_configs()` |
| **FAIL Condition** | No configs with `ValidationStatus == 'ENABLED'` exist, OR VPCs have `ValidationStatus == 'DISABLED'` |
| **Logic** | List DNSSEC validation configs. The API only returns enabled configs. If the list is empty or specific VPCs are not present, DNSSEC validation is not enforced. |
| **Usefulness** | ⭐⭐⭐⭐ — Ensures resolvers validate DNSSEC signatures, preventing cache poisoning for signed domains. |
| **Notes** | Complements `route53DnssecNotEnabled` (signing side). This is the validation/verification side. |

---

## TIER 2 — MEDIUM VALUE (Implement Second)

These are useful but require slightly more complex logic or have more edge cases.

---

### 12. `route53HostedZoneUnused`

| Field | Value |
|-------|-------|
| **Category** | Hosted Zones |
| **Pillar** | Cost Optimization / Security |
| **Severity** | Low |
| **API Calls** | `route53.list_hosted_zones()` → `route53.list_resource_record_sets(HostedZoneId=id)` |
| **FAIL Condition** | Zone contains ONLY NS and SOA records (record count = 2 for the zone apex NS + SOA) |
| **Logic** | List all RRsets. If only 2 records exist and they are both the apex NS and SOA, zone is unused. Cost: $0.50/month/zone wasted. |
| **Usefulness** | ⭐⭐⭐ — Cost hygiene. Unused zones are attack surface with no value. |
| **Notes** | New zones always have NS+SOA. Filter out zones created in last 24h. |

---

### 13. `route53HealthCheckSlowInterval`

| Field | Value |
|-------|-------|
| **Category** | Health Checks |
| **Pillar** | Reliability |
| **Severity** | Low |
| **API Calls** | `route53.list_health_checks()` |
| **FAIL Condition** | `HealthCheckConfig.RequestInterval == 30` (standard, not fast) |
| **Logic** | Route53 supports 10s (fast) or 30s (standard) intervals. If `RequestInterval == 30`, detection is slower. FAIL for informational/low severity. |
| **Usefulness** | ⭐⭐⭐ — Fast interval costs more ($1/month vs $0.50) but detects failures 3x faster. Context-dependent. |
| **Notes** | This is opinionated. 30s is default and acceptable for many workloads. Consider making this informational only. |

---

### 14. `route53HealthCheckLowFailureThreshold`

| Field | Value |
|-------|-------|
| **Category** | Health Checks |
| **Pillar** | Reliability |
| **Severity** | Low |
| **API Calls** | `route53.list_health_checks()` |
| **FAIL Condition** | `HealthCheckConfig.FailureThreshold == 1` |
| **Logic** | FailureThreshold of 1 means a single failed check triggers failover — may cause flapping. Recommend ≥ 3. |
| **Usefulness** | ⭐⭐⭐ — Very low threshold causes unnecessary failovers from transient issues. |
| **Notes** | Conversely, very HIGH threshold (e.g., 10) means slow detection. Consider warning on both extremes. Default is 3. |

---

### 15. `route53CnameAtZoneApex`

| Field | Value |
|-------|-------|
| **Category** | Records |
| **Pillar** | Reliability / Performance |
| **Severity** | Medium |
| **API Calls** | `route53.list_resource_record_sets(HostedZoneId=id)` |
| **FAIL Condition** | A CNAME record exists where `Name` equals the zone apex (hosted zone name) |
| **Logic** | Iterate RRsets. If `Type == 'CNAME'` and `Name` matches the zone name (e.g., `example.com.`), FAIL. CNAME at apex violates RFC 1034 and breaks MX/NS records. |
| **Usefulness** | ⭐⭐⭐⭐ — This is a real DNS misconfiguration that breaks email and other services. Should use ALIAS instead. |
| **Notes** | Route53 alias records solve this. The check catches manual misconfigurations. |

---

### 16. `route53MxWithoutSpfDmarc`

| Field | Value |
|-------|-------|
| **Category** | Records |
| **Pillar** | Security |
| **Severity** | Medium |
| **API Calls** | `route53.list_resource_record_sets(HostedZoneId=id)` |
| **FAIL Condition** | MX records exist but no TXT record contains `v=spf1` or `v=DMARC1` for the domain |
| **Logic** | 1. Find all MX records. 2. For each domain with MX, check TXT records for SPF (`v=spf1`). 3. Check `_dmarc.{domain}` TXT record for DMARC. FAIL if MX exists without SPF or DMARC. |
| **Usefulness** | ⭐⭐⭐⭐ — Missing email authentication enables phishing/spoofing of the domain. |
| **Notes** | DKIM is harder to verify (varies by ESP). SPF and DMARC are deterministic from DNS. |

---

### 17. `route53HealthCheckDisabled`

| Field | Value |
|-------|-------|
| **Category** | Health Checks |
| **Pillar** | Reliability |
| **Severity** | Medium |
| **API Calls** | `route53.list_health_checks()` |
| **FAIL Condition** | `HealthCheckConfig.Disabled == True` |
| **Logic** | A disabled health check provides no value but still exists. Either re-enable or delete. |
| **Usefulness** | ⭐⭐⭐⭐ — Disabled health checks mean failover won't work. Silent failure waiting to happen. |
| **Notes** | May be intentionally disabled during maintenance. Check if associated with active record sets. |

---

### 18. `route53RecordNoHealthCheck`

| Field | Value |
|-------|-------|
| **Category** | Records |
| **Pillar** | Reliability |
| **Severity** | Low |
| **API Calls** | `route53.list_resource_record_sets(HostedZoneId=id)` |
| **FAIL Condition** | Record with failover/weighted/latency routing but `HealthCheckId` is absent |
| **Logic** | For records with routing policies (`Failover`, `Weight`, `Region`, `MultiValueAnswer`), check if `HealthCheckId` is set. If routing policy exists without health check, failover won't work correctly. |
| **Usefulness** | ⭐⭐⭐⭐ — Routing policies without health checks are useless for automatic failover. |
| **Notes** | Simple routing records don't need health checks. Only flag records with explicit routing policies. |

---

## TIER 3 — LOWER VALUE / HARDER TO IMPLEMENT

These are useful but have high false-positive rates, require cross-service correlation, or are highly opinionated.

---

### 19. `route53DanglingDnsRecords`

| Field | Value |
|-------|-------|
| **Category** | Records |
| **Pillar** | Security |
| **Severity** | High (if confirmed) |
| **API Calls** | `route53.list_resource_record_sets()` + cross-service validation (ELB, CloudFront, S3, Elastic Beanstalk, etc.) |
| **FAIL Condition** | Record points to a resource that no longer exists (subdomain takeover risk) |
| **Logic** | For CNAME/ALIAS records pointing to `*.elb.amazonaws.com`, `*.cloudfront.net`, `*.s3-website-*.amazonaws.com`, `*.elasticbeanstalk.com` — verify the target resource exists. If not, dangling = subdomain takeover. |
| **Usefulness** | ⭐⭐⭐⭐⭐ (value) but ⭐⭐ (feasibility) — Extremely impactful but requires cross-service API calls and complex logic. |
| **Notes** | This is a known attack vector (subdomain takeover). Implementation requires ELB, CF, S3, EB describe calls. Consider partial implementation for known patterns. |

---

### 20. `route53LowTtlOnStableRecords`

| Field | Value |
|-------|-------|
| **Category** | Records |
| **Pillar** | Performance / Cost Optimization |
| **Severity** | Low |
| **API Calls** | `route53.list_resource_record_sets(HostedZoneId=id)` |
| **FAIL Condition** | `TTL < 60` for non-failover records |
| **Logic** | Records with very low TTL (< 60s) that don't use routing policies generate more DNS queries (cost) and don't benefit from caching. |
| **Usefulness** | ⭐⭐ — Very opinionated. Some architectures legitimately need low TTLs. High false-positive rate. |
| **Notes** | Alias records don't have TTL (inherit from target). Only check non-alias records. |

---

### 21. `route53PublicZoneSensitiveNames`

| Field | Value |
|-------|-------|
| **Category** | Hosted Zones |
| **Pillar** | Security |
| **Severity** | Low |
| **API Calls** | `route53.list_resource_record_sets(HostedZoneId=id)` |
| **FAIL Condition** | Public zone contains records with names like `internal.*`, `private.*`, `staging.*`, `dev.*`, `vpn.*`, `admin.*`, `db.*`, `database.*` |
| **Logic** | Pattern-match record names against a list of sensitive prefixes. Flag as informational. |
| **Usefulness** | ⭐⭐ — Information disclosure risk but very heuristic. High false-positive rate. |
| **Notes** | This is advisory only. Many legitimate use cases for these names. |

---

### 22. `route53HealthCheckSniDisabled`

| Field | Value |
|-------|-------|
| **Category** | Health Checks |
| **Pillar** | Security |
| **Severity** | Low |
| **API Calls** | `route53.list_health_checks()` |
| **FAIL Condition** | `HealthCheckConfig.Type` is `'HTTPS'` or `'HTTPS_STR_MATCH'` AND `HealthCheckConfig.EnableSNI == False` |
| **Logic** | HTTPS health checks without SNI may not validate the correct certificate if the endpoint hosts multiple domains. |
| **Usefulness** | ⭐⭐⭐ — Edge case but relevant for shared hosting/CDN endpoints. |
| **Notes** | Default for HTTPS is `EnableSNI=True`. Only fails if explicitly disabled. |

---

### 23. `route53EmptyHostedZone`

| Field | Value |
|-------|-------|
| **Category** | Hosted Zones |
| **Pillar** | Cost Optimization |
| **Severity** | Low |
| **API Calls** | `route53.get_hosted_zone(Id=id)` |
| **FAIL Condition** | `HostedZone.ResourceRecordSetCount == 2` (only NS + SOA exist) |
| **Logic** | The `ResourceRecordSetCount` field from `get_hosted_zone` gives the total count without listing all records. If count = 2, only default NS and SOA exist. |
| **Usefulness** | ⭐⭐⭐ — Same as #12 but using the faster count-based approach. |
| **Notes** | Combine with #12. Use count as fast-path, full listing only if needed for other checks. |

---

### 24. `route53NoRecordRoutingPolicy`

| Field | Value |
|-------|-------|
| **Category** | Records |
| **Pillar** | Reliability |
| **Severity** | Low |
| **API Calls** | `route53.list_resource_record_sets(HostedZoneId=id)` |
| **FAIL Condition** | A/AAAA records for a domain without any routing policy (single point of failure) |
| **Logic** | Flag A/AAAA records that have no `Failover`, `Weight`, `Region`, `MultiValueAnswer`, or `GeoLocation` routing. These are single-endpoint with no redundancy. |
| **Usefulness** | ⭐⭐ — Extremely noisy. Most records legitimately point to one endpoint (behind a load balancer). |
| **Notes** | Too many false positives. Consider limiting to records pointing directly at EC2 IPs. Not recommended for default implementation. |

---

## IMPLEMENTATION SUMMARY

### API Call Inventory

| Client | API Call | Used By Checks |
|--------|----------|----------------|
| `route53` | `list_hosted_zones()` | #1, #2, #12, #15, #16, #18, #19, #20, #21, #23 |
| `route53` | `get_hosted_zone(Id)` | #23 |
| `route53` | `get_dnssec(HostedZoneId)` | #1 |
| `route53` | `list_query_logging_configs(HostedZoneId)` | #2 |
| `route53` | `list_resource_record_sets(HostedZoneId)` | #12, #15, #16, #18, #19, #20, #21 |
| `route53` | `list_health_checks()` | #7, #8, #13, #14, #17, #22 |
| `route53domains` | `list_domains()` | #3, #4, #5, #6 |
| `route53domains` | `get_domain_detail(DomainName)` | #3, #4, #5, #6 |
| `route53resolver` | `list_firewall_rule_group_associations()` | #9 |
| `route53resolver` | `list_resolver_query_log_configs()` | #10 |
| `route53resolver` | `list_resolver_query_log_config_associations()` | #10 |
| `route53resolver` | `list_resolver_dnssec_configs()` | #11 |

---

### Recommended Implementation Order

**Phase 1 (MVP — 6 checks):**
1. `route53QueryLoggingNotEnabled` — Security Hub control
2. `route53DnssecNotEnabled` — Top security ask
3. `route53DomainAutoRenewDisabled` — Critical reliability
4. `route53DomainTransferLockDisabled` — Critical security
5. `route53ResolverDnsFirewallNotConfigured` — Zero-trust essential
6. `route53ResolverQueryLoggingNotEnabled` — Visibility essential

**Phase 2 (Full coverage — 7 more checks):**
7. `route53DomainPrivacyDisabled`
8. `route53DomainExpiringSoon`
9. `route53HealthCheckUsingHttp`
10. `route53HealthCheckNoAlarm`
11. `route53HealthCheckDisabled`
12. `route53ResolverDnssecValidationDisabled`
13. `route53CnameAtZoneApex`

**Phase 3 (Nice-to-have — 5 checks):**
14. `route53MxWithoutSpfDmarc`
15. `route53RecordNoHealthCheck`
16. `route53HostedZoneUnused`
17. `route53HealthCheckSlowInterval`
18. `route53HealthCheckLowFailureThreshold`

**Deferred (complex/noisy):**
19. `route53DanglingDnsRecords` (cross-service)
20. `route53LowTtlOnStableRecords` (opinionated)
21. `route53PublicZoneSensitiveNames` (heuristic)
22. `route53HealthCheckSniDisabled` (edge case)
23-24. Duplicates/variants of above

---

### Pillar Distribution

| Pillar | Checks |
|--------|--------|
| **Security** | #1, #2, #4, #5, #7, #9, #10, #11, #16, #19, #21, #22 |
| **Reliability** | #3, #6, #13, #14, #17, #18, #24 |
| **Operational Excellence** | #8 |
| **Cost Optimization** | #12, #20, #23 |
| **Performance** | #15 (partial), #20 (partial) |

---

### Region Considerations

| Resource | Region Behavior |
|----------|----------------|
| Hosted Zones | **Global** — accessible from any region (typically us-east-1) |
| Health Checks | **Global** — same as hosted zones |
| Route53 Domains | **us-east-1 ONLY** — must create client in us-east-1 |
| Route53 Resolver | **Regional** — must scan per-region where VPCs exist |

---

### Code Pattern (Skeleton)

```python
# Client setup
import boto3
from datetime import datetime, timedelta

route53_client = boto3.client('route53')  # Global
domains_client = boto3.client('route53domains', region_name='us-east-1')  # Must be us-east-1
resolver_client = boto3.client('route53resolver', region_name='us-east-1')  # Per-region

# Check: DNSSEC not enabled
def check_dnssec_not_enabled(zone_id, is_private):
    if is_private:
        return None  # Skip private zones
    response = route53_client.get_dnssec(HostedZoneId=zone_id)
    status = response.get('Status', {})
    if status.get('ServeSignature') != 'SIGNING':
        return 'FAIL'
    return 'PASS'

# Check: Domain transfer lock
def check_transfer_lock(domain_name):
    response = domains_client.get_domain_detail(DomainName=domain_name)
    status_list = response.get('StatusList', [])
    if 'clientTransferProhibited' not in status_list:
        return 'FAIL'
    return 'PASS'

# Check: DNS Firewall
def check_dns_firewall():
    response = resolver_client.list_firewall_rule_group_associations()
    if not response.get('FirewallRuleGroupAssociations', []):
        return 'FAIL'
    return 'PASS'
```

---

### Cost/Throttling Considerations

| API | Rate Limit | Cost |
|-----|-----------|------|
| `list_hosted_zones` | 10 req/s | Free |
| `get_dnssec` | 10 req/s | Free |
| `list_query_logging_configs` | 10 req/s | Free |
| `list_resource_record_sets` | 5 req/s | Free |
| `list_health_checks` | 10 req/s | Free |
| `list_domains` | 10 req/s | Free |
| `get_domain_detail` | 10 req/s | Free |
| `list_firewall_rule_group_associations` | 20 req/s | Free |
| `list_resolver_query_log_configs` | 20 req/s | Free |
| `list_resolver_dnssec_configs` | 20 req/s | Free |

**Optimization:** Batch hosted zone processing. Call `list_hosted_zones` once, then loop through zones. For health checks, `list_health_checks` returns full config inline (no need for `get_health_check` per item).

---

### Mapping to Well-Architected Framework

| WA Pillar | Principle | Checks |
|-----------|-----------|--------|
| Security | SEC01 - Establish clear security ownership | #2, #10 (logging) |
| Security | SEC03 - Reduce blast radius | #9, #11 (DNS protection) |
| Security | SEC08 - Protect data in transit | #7, #22 (HTTPS) |
| Security | SEC09 - Protect data at rest | #5 (privacy) |
| Security | SEC10 - Incident management | #2, #8, #10 (logging/alerting) |
| Reliability | REL01 - Service quotas | #12, #23 (unused resources) |
| Reliability | REL06 - Monitor resources | #8, #17 (health checks) |
| Reliability | REL11 - Adapt to demand | #13, #14 (detection speed) |
| Cost Opt | COST02 - Cost-aware architecture | #12, #20, #23 |
| Ops Excel | OPS08 - Understand operational health | #2, #8, #10 |

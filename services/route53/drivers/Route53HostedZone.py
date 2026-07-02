from datetime import datetime, timezone, timedelta

from services.Evaluator import Evaluator


class Route53HostedZone(Evaluator):
    """
    Route 53 hosted-zone-level and record-level checks.

    Input:
      zone -- dict produced by Route53._describeHostedZone. Keys:
        '_zoneId', '_name', '_isPrivate', '_resourceRecordSetCount',
        '_config', '_dnssecStatus', '_queryLoggingConfigs', '_records',
        '_getHostedZoneMeta'.
      route53Client -- boto3 route53 client (kept for future extension).
      danglingIdx -- pre-built index of existing cross-service targets
                     (cloudfront_domains, alb_domains, elb_classic_domains,
                     s3_buckets, eb_domains) + a lookupFailed flag.
      sensitivePrefixes -- tuple of prefix strings for check #21.
      danglingSuffixes -- tuple of suffix substrings for check #19.
    """

    # Records that legitimately exist at the zone apex (not flagged as apex CNAME).
    APEX_ALLOWED_TYPES = {'NS', 'SOA', 'A', 'AAAA', 'MX', 'TXT', 'DNSKEY'}

    # Routing-policy attributes that make a record a "routing" record.
    ROUTING_POLICY_KEYS = (
        'Failover', 'Weight', 'Region', 'MultiValueAnswer', 'GeoLocation',
        'GeoProximityLocation',
    )

    # Minimum TTL below which we flag non-routing, non-alias records (check #20).
    LOW_TTL_THRESHOLD = 60

    # Zones created within this many hours are exempt from the "unused" check.
    NEW_ZONE_GRACE_HOURS = 24

    def __init__(self, zone, route53Client, danglingIdx,
                 sensitivePrefixes, danglingSuffixes):
        super().__init__()
        self.zone = zone
        self.route53Client = route53Client
        self.danglingIdx = danglingIdx or {}
        self.sensitivePrefixes = sensitivePrefixes
        self.danglingSuffixes = danglingSuffixes

        self._zoneId = zone.get('_zoneId', '')
        self._zoneName = (zone.get('_name') or '').rstrip('.')
        self._resourceName = self._zoneName or self._zoneId
        self._isPrivate = bool(zone.get('_isPrivate'))
        self._records = zone.get('_records') or []
        self._rrCount = int(zone.get('_resourceRecordSetCount') or 0)

        self.addII('zoneId', self._zoneId)
        self.addII('name', self._zoneName)
        self.addII('type', 'Private' if self._isPrivate else 'Public')
        self.addII('recordCount', self._rrCount)

    # ------------------------------------------------------------------ #
    # 1. DNSSEC signing not enabled (public zones only)
    # ------------------------------------------------------------------ #
    def _checkRoute53DnssecNotEnabled(self):
        if self._isPrivate:
            self.results['route53DnssecNotEnabled'] = [
                0, "Private zone — DNSSEC signing not applicable"
            ]
            return

        dnssec = self.zone.get('_dnssecStatus')
        if dnssec is None:
            self.results['route53DnssecNotEnabled'] = [
                0, "DNSSEC status unavailable (permission or API error)"
            ]
            return

        status = (dnssec.get('Status') or {}) if isinstance(dnssec, dict) else {}
        serveSig = status.get('ServeSignature') or ''
        ksks = dnssec.get('KeySigningKeys') or []
        if serveSig == 'SIGNING' and ksks:
            self.results['route53DnssecNotEnabled'] = [
                1, f"DNSSEC ServeSignature=SIGNING ({len(ksks)} KSK)"
            ]
        else:
            reason = serveSig if serveSig else "NOT_SIGNING"
            self.results['route53DnssecNotEnabled'] = [
                -1, f"DNSSEC ServeSignature={reason}, {len(ksks)} KSK(s)"
            ]

    # ------------------------------------------------------------------ #
    # 2. Query logging not enabled (public zones only) — SecHub Route53.2
    # ------------------------------------------------------------------ #
    def _checkRoute53QueryLoggingNotEnabled(self):
        if self._isPrivate:
            self.results['route53QueryLoggingNotEnabled'] = [
                0, "Private zone — public query logging not applicable"
            ]
            return
        configs = self.zone.get('_queryLoggingConfigs') or []
        if configs:
            self.results['route53QueryLoggingNotEnabled'] = [
                1, f"{len(configs)} query-logging config(s) attached"
            ]
        else:
            self.results['route53QueryLoggingNotEnabled'] = [
                -1, "No DNS query logging configuration (Security Hub Route53.2)"
            ]

    # ------------------------------------------------------------------ #
    # 12. Hosted zone unused (only NS + SOA)
    # ------------------------------------------------------------------ #
    def _checkRoute53HostedZoneUnused(self):
        # Skip newly created zones (< 24h old) — they've had no time to be populated.
        if self._isRecentlyCreated():
            self.results['route53HostedZoneUnused'] = [
                0, "Zone < 24h old — exempt from unused check"
            ]
            return

        non_default = self._nonDefaultRecords()
        if not non_default:
            self.results['route53HostedZoneUnused'] = [
                -1, "Only default NS + SOA records — zone is unused"
            ]
        else:
            self.results['route53HostedZoneUnused'] = [
                1, f"{len(non_default)} user-defined record(s)"
            ]

    # ------------------------------------------------------------------ #
    # 15. CNAME at zone apex
    # ------------------------------------------------------------------ #
    def _checkRoute53CnameAtZoneApex(self):
        apex_cnames = []
        for r in self._records:
            if r.get('Type') != 'CNAME':
                continue
            if self._isApex(r.get('Name', '')):
                apex_cnames.append(r.get('Name', ''))
        if apex_cnames:
            self.results['route53CnameAtZoneApex'] = [
                -1,
                f"CNAME at zone apex: {', '.join(apex_cnames)} "
                "(use an ALIAS record instead)"
            ]
        else:
            self.results['route53CnameAtZoneApex'] = [
                1, "No CNAME records at the zone apex"
            ]

    # ------------------------------------------------------------------ #
    # 16. MX record without SPF or DMARC TXT
    # ------------------------------------------------------------------ #
    def _checkRoute53MxWithoutSpfDmarc(self):
        # Map: normalised name -> True (has MX)
        mx_names = set()
        # Map: normalised name -> list of concatenated TXT values (lower)
        txt_values = {}
        # Map: normalised name -> True (has DMARC-style TXT — record name starts _dmarc.)
        dmarc_names = set()

        for r in self._records:
            rtype = r.get('Type', '')
            name = (r.get('Name') or '').lower().rstrip('.')
            if not name:
                continue
            if rtype == 'MX':
                mx_names.add(name)
            elif rtype == 'TXT':
                values = self._collectTxtValues(r)
                if name.startswith('_dmarc.'):
                    if any('v=dmarc1' in v.lower() for v in values):
                        # strip _dmarc. prefix
                        dmarc_names.add(name[len('_dmarc.'):])
                else:
                    lst = txt_values.setdefault(name, [])
                    lst.extend(v.lower() for v in values)

        if not mx_names:
            self.results['route53MxWithoutSpfDmarc'] = [
                0, "No MX records in this zone"
            ]
            return

        missing = []
        for domain in sorted(mx_names):
            spf_ok = any('v=spf1' in v for v in txt_values.get(domain, []))
            dmarc_ok = domain in dmarc_names
            issues = []
            if not spf_ok:
                issues.append('SPF')
            if not dmarc_ok:
                issues.append('DMARC')
            if issues:
                missing.append(f"{domain} (missing {'+'.join(issues)})")

        if missing:
            self.results['route53MxWithoutSpfDmarc'] = [
                -1,
                f"MX domain(s) without email auth: {', '.join(missing[:5])}"
                + (f" (+{len(missing)-5} more)" if len(missing) > 5 else "")
            ]
        else:
            self.results['route53MxWithoutSpfDmarc'] = [
                1, f"All {len(mx_names)} MX domain(s) have SPF and DMARC"
            ]

    # ------------------------------------------------------------------ #
    # 18. Record with routing policy but no HealthCheckId
    # ------------------------------------------------------------------ #
    def _checkRoute53RecordNoHealthCheck(self):
        offenders = []
        for r in self._records:
            if not self._hasRoutingPolicy(r):
                continue
            if r.get('HealthCheckId'):
                continue
            name = (r.get('Name') or '').rstrip('.')
            offenders.append(f"{name}[{r.get('Type', '?')}]")
        if not any(self._hasRoutingPolicy(r) for r in self._records):
            self.results['route53RecordNoHealthCheck'] = [
                0, "No records with explicit routing policy"
            ]
            return
        if offenders:
            self.results['route53RecordNoHealthCheck'] = [
                -1,
                f"Routing records without HealthCheckId: {', '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['route53RecordNoHealthCheck'] = [
                1, "All routing-policy records have a HealthCheckId"
            ]

    # ------------------------------------------------------------------ #
    # 19. Dangling DNS records
    # ------------------------------------------------------------------ #
    def _checkRoute53DanglingDnsRecords(self):
        if self._isPrivate:
            self.results['route53DanglingDnsRecords'] = [
                0, "Private zone — subdomain takeover risk not applicable"
            ]
            return
        # If our cross-service index is empty and lookupFailed, we can't decide.
        lookup_failed = bool(self.danglingIdx.get('lookupFailed'))
        cf_domains = self.danglingIdx.get('cloudfront_domains', set())
        alb_domains = self.danglingIdx.get('alb_domains', set())
        elb_domains = self.danglingIdx.get('elb_classic_domains', set())
        s3_buckets = self.danglingIdx.get('s3_buckets', set())
        eb_domains = self.danglingIdx.get('eb_domains', set())

        offenders = []
        checked = 0
        for r in self._records:
            targets = self._targetHostsForRecord(r)
            if not targets:
                continue
            for tgt in targets:
                if not self._isCrossServiceTarget(tgt):
                    continue
                checked += 1
                if self._targetExists(tgt, cf_domains, alb_domains,
                                      elb_domains, s3_buckets, eb_domains):
                    continue
                name = (r.get('Name') or '').rstrip('.')
                offenders.append(f"{name} -> {tgt}")

        if checked == 0:
            self.results['route53DanglingDnsRecords'] = [
                0, "No records point at CloudFront/ELB/S3/EB targets"
            ]
            return
        if offenders and not lookup_failed:
            self.results['route53DanglingDnsRecords'] = [
                -1,
                f"Dangling target(s) detected: {'; '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        elif offenders and lookup_failed:
            # We saw missing targets but at least one cross-service lookup
            # failed — downgrade to INFO so we don't false-positive.
            self.results['route53DanglingDnsRecords'] = [
                0,
                "Possible dangling target(s) but cross-service lookup was "
                "partial: " + '; '.join(offenders[:3])
            ]
        else:
            self.results['route53DanglingDnsRecords'] = [
                1, f"All {checked} cross-service target(s) exist"
            ]

    # ------------------------------------------------------------------ #
    # 20. Low TTL on stable (non-routing, non-alias) records
    # ------------------------------------------------------------------ #
    def _checkRoute53LowTtlOnStableRecords(self):
        offenders = []
        for r in self._records:
            if r.get('AliasTarget'):
                continue  # Alias records have no TTL (inherit from target).
            if self._hasRoutingPolicy(r):
                continue
            rtype = r.get('Type')
            if rtype in ('NS', 'SOA'):
                continue
            ttl = r.get('TTL')
            if ttl is None:
                continue
            try:
                ttl_int = int(ttl)
            except (TypeError, ValueError):
                continue
            if ttl_int < self.LOW_TTL_THRESHOLD:
                name = (r.get('Name') or '').rstrip('.')
                offenders.append(f"{name}[{rtype}]={ttl_int}s")
        if offenders:
            self.results['route53LowTtlOnStableRecords'] = [
                -1,
                f"Records with TTL < {self.LOW_TTL_THRESHOLD}s: "
                f"{', '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['route53LowTtlOnStableRecords'] = [
                1, f"No stable records below TTL {self.LOW_TTL_THRESHOLD}s"
            ]

    # ------------------------------------------------------------------ #
    # 21. Public zone with sensitive record names
    # ------------------------------------------------------------------ #
    def _checkRoute53PublicZoneSensitiveNames(self):
        if self._isPrivate:
            self.results['route53PublicZoneSensitiveNames'] = [
                0, "Private zone — sensitive-name disclosure risk not applicable"
            ]
            return
        matches = []
        for r in self._records:
            name = (r.get('Name') or '').lower().rstrip('.')
            if not name or name == self._zoneName.lower():
                continue
            # Strip zone suffix to inspect just the subdomain portion.
            zone_suffix = self._zoneName.lower()
            if zone_suffix and name.endswith('.' + zone_suffix):
                sub = name[:-(len(zone_suffix) + 1)]
            else:
                sub = name
            # sub may still have leading dots or empty.
            if not sub:
                continue
            leftmost = sub.split('.')[0] + '.'
            for prefix in self.sensitivePrefixes:
                if leftmost.startswith(prefix) or (sub + '.').startswith(prefix):
                    matches.append(name)
                    break

        if matches:
            self.results['route53PublicZoneSensitiveNames'] = [
                -1,
                f"Sensitive names in public zone: {', '.join(matches[:5])}"
                + (f" (+{len(matches)-5} more)" if len(matches) > 5 else "")
            ]
        else:
            self.results['route53PublicZoneSensitiveNames'] = [
                1, "No records with sensitive-name patterns"
            ]

    # ------------------------------------------------------------------ #
    # 23. Empty hosted zone (ResourceRecordSetCount == 2)
    # ------------------------------------------------------------------ #
    def _checkRoute53EmptyHostedZone(self):
        if self._isRecentlyCreated():
            self.results['route53EmptyHostedZone'] = [
                0, "Zone < 24h old — exempt from empty check"
            ]
            return
        if self._rrCount <= 2:
            self.results['route53EmptyHostedZone'] = [
                -1,
                f"ResourceRecordSetCount={self._rrCount} — zone has only NS + SOA"
            ]
        else:
            self.results['route53EmptyHostedZone'] = [
                1, f"ResourceRecordSetCount={self._rrCount}"
            ]

    # ------------------------------------------------------------------ #
    # 24. A/AAAA record without any routing policy
    # ------------------------------------------------------------------ #
    def _checkRoute53NoRecordRoutingPolicy(self):
        # Advisory only — high false-positive rate. Only look at records that
        # point directly at IP addresses (not alias records).
        offenders = []
        for r in self._records:
            if r.get('Type') not in ('A', 'AAAA'):
                continue
            if r.get('AliasTarget'):
                continue  # alias points at an ELB/CloudFront/S3, HA-managed
            if self._hasRoutingPolicy(r):
                continue
            name = (r.get('Name') or '').rstrip('.')
            # Exclude apex records — they often legitimately point to a single
            # dual-stack endpoint. Focus on subdomain A records without
            # routing.
            if self._isApex(r.get('Name', '')):
                continue
            offenders.append(f"{name}[{r.get('Type')}]")
        if offenders:
            self.results['route53NoRecordRoutingPolicy'] = [
                -1,
                f"Direct-IP A/AAAA record(s) without routing policy: "
                f"{', '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['route53NoRecordRoutingPolicy'] = [
                1, "No direct-IP records without routing policy"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _isApex(self, record_name):
        """True if record_name equals the zone apex (with or without trailing dot)."""
        rn = (record_name or '').lower().rstrip('.')
        zn = self._zoneName.lower()
        return rn == zn

    def _hasRoutingPolicy(self, record):
        for k in self.ROUTING_POLICY_KEYS:
            if k in record:
                # Weight may legitimately be 0; MultiValueAnswer may be False.
                # Just presence of the key indicates a routing policy was set
                # (except MultiValueAnswer == False, which is the default).
                v = record.get(k)
                if k == 'MultiValueAnswer' and v is False:
                    continue
                return True
        return False

    def _nonDefaultRecords(self):
        """Return records that are NOT the mandatory apex NS+SOA."""
        keep = []
        for r in self._records:
            name = (r.get('Name') or '').lower().rstrip('.')
            rtype = r.get('Type', '')
            if self._isApex(r.get('Name', '')) and rtype in ('NS', 'SOA'):
                continue
            keep.append(r)
        return keep

    def _isRecentlyCreated(self):
        meta = self.zone.get('_getHostedZoneMeta') or {}
        # get_hosted_zone doesn't return CreatedDate in most SDK versions;
        # fall back to "false" (not-recent) when unknown.
        hz = meta.get('HostedZone') or {}
        # Newer API versions may expose Config only; skip if we can't decide.
        created = hz.get('CreatedDate')
        if not created:
            return False
        try:
            if isinstance(created, str):
                created = datetime.fromisoformat(created.replace('Z', '+00:00'))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            return (now - created) < timedelta(hours=self.NEW_ZONE_GRACE_HOURS)
        except (ValueError, TypeError, AttributeError):
            return False

    @staticmethod
    def _collectTxtValues(record):
        """TXT records return a list of ResourceRecords, each Value is a
        quoted string possibly split into multiple 255-char chunks."""
        out = []
        for rr in record.get('ResourceRecords', []) or []:
            v = rr.get('Value') or ''
            # Strip surrounding double-quotes and unescape any inner quotes.
            # A single TXT record may contain multiple quoted chunks that
            # concatenate to form the full string.
            parts = []
            i = 0
            while i < len(v):
                if v[i] == '"':
                    # scan to matching close quote
                    j = i + 1
                    buf = []
                    while j < len(v):
                        if v[j] == '\\' and j + 1 < len(v):
                            buf.append(v[j + 1])
                            j += 2
                            continue
                        if v[j] == '"':
                            break
                        buf.append(v[j])
                        j += 1
                    parts.append(''.join(buf))
                    i = j + 1
                else:
                    i += 1
            if parts:
                out.append(''.join(parts))
            else:
                out.append(v)
        return out

    def _targetHostsForRecord(self, record):
        """Return every remote hostname referenced by this record, lower-cased,
        without trailing dot. Includes AliasTarget.DNSName and each CNAME value."""
        hosts = []
        alias = record.get('AliasTarget')
        if isinstance(alias, dict):
            dn = alias.get('DNSName')
            if dn:
                hosts.append(dn.lower().rstrip('.'))
        if record.get('Type') == 'CNAME':
            for rr in record.get('ResourceRecords', []) or []:
                v = (rr.get('Value') or '').lower().rstrip('.')
                if v:
                    hosts.append(v)
        return hosts

    def _isCrossServiceTarget(self, host):
        h = host.lower()
        for sfx in self.danglingSuffixes:
            if sfx in h:
                return True
        return False

    @staticmethod
    def _targetExists(host, cf_domains, alb_domains, elb_domains,
                      s3_buckets, eb_domains):
        h = host.lower().rstrip('.')

        # CloudFront distributions
        if h.endswith('.cloudfront.net'):
            return h in cf_domains

        # ALB/NLB DNS names. Route 53 aliases may use a "dualstack." prefix
        # that isn't present in the raw DNSName from describe_load_balancers.
        if 'elb.amazonaws.com' in h:
            if h in alb_domains or h in elb_domains:
                return True
            if h.startswith('dualstack.'):
                bare = h[len('dualstack.'):]
                if bare in alb_domains or bare in elb_domains:
                    return True
            return False

        # Elastic Beanstalk environment CNAMEs
        if h.endswith('.elasticbeanstalk.com'):
            return h in eb_domains

        # S3 website endpoints: bucket-name.s3-website-<region>.amazonaws.com
        # or bucket-name.s3.amazonaws.com or bucket-name.s3.<region>.amazonaws.com
        if '.s3' in h and 'amazonaws.com' in h:
            bucket = h.split('.', 1)[0]
            return bucket in s3_buckets

        # Unknown pattern — treat as exists so we don't false-positive on
        # third-party or unlisted target types.
        return True

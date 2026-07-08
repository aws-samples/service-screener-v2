import botocore
from datetime import datetime, timezone

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

from services.route53.drivers.Route53HostedZone import Route53HostedZone
from services.route53.drivers.Route53HealthCheck import Route53HealthCheck
from services.route53.drivers.Route53Domain import Route53Domain
from services.route53.drivers.Route53Resolver import Route53Resolver


class Route53(Service):
    """
    Amazon Route 53 service scanner.

    Route 53 is a hybrid global/regional service:
      * Hosted zones + health checks + DNSSEC signing config = GLOBAL. Accessible
        from any regional endpoint (we use the region's endpoint for latency).
      * Domain registration (route53domains) = us-east-1 ONLY. We hard-code
        region_name='us-east-1' for the domains client regardless of the
        scan region.
      * Resolver (DNS Firewall, query logging, DNSSEC validation) = REGIONAL.
        Each region is scanned independently for these.

    To avoid duplicating the global findings once per scanned region during
    multi-region scans, we pick a single "primary" region (the first one that
    initialises Route53) and only run the global-resource discovery there.
    """

    # Global (non-resolver) checks are claimed by exactly one region per scan.
    GLOBAL_CLAIM_KEY = 'route53::globalScanRegion'

    # Sensitive-name prefixes flagged for public zones (check #21).
    SENSITIVE_NAME_PREFIXES = (
        'internal.', 'private.', 'staging.', 'stg.', 'dev.', 'test.', 'qa.', 'uat.',
        'vpn.', 'admin.', 'root.', 'db.', 'database.', 'db-', 'mysql.', 'postgres.',
        'jenkins.', 'gitlab.', 'ci.', 'jira.', 'confluence.', 'grafana.', 'kibana.',
    )

    # Dangling-DNS target suffixes we know how to cross-check within the same account.
    DANGLING_SUFFIXES = (
        '.cloudfront.net', '.elb.amazonaws.com', '.elasticbeanstalk.com',
        '.s3.amazonaws.com', '.s3-website',  # s3-website-<region>.amazonaws.com pattern
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto

        # route53 API is technically hosted in us-east-1 but every regional
        # endpoint proxies to the same global control plane.
        self.route53Client = ssBoto.client('route53', config=self.bConfig)
        # route53domains ONLY works in us-east-1 — hard-code it regardless of
        # the scan region.
        self.domainsClient = ssBoto.client('route53domains', region_name='us-east-1')
        # route53resolver is regional.
        self.resolverClient = ssBoto.client('route53resolver', config=self.bConfig)

        # Cross-service clients used for the dangling-DNS check (#19).
        self.elbv2Client = ssBoto.client('elbv2', config=self.bConfig)
        try:
            self.elbClient = ssBoto.client('elb', config=self.bConfig)
        except Exception:  # ELB classic not always available in newer regions
            self.elbClient = None
        # CloudFront + S3 are global — we still use the region client which
        # routes to the global endpoint automatically.
        self.cfClient = ssBoto.client('cloudfront', config=self.bConfig)
        self.s3Client = ssBoto.client('s3', config=self.bConfig)
        try:
            self.ebClient = ssBoto.client('elasticbeanstalk', config=self.bConfig)
        except Exception:
            self.ebClient = None

        self._runGlobalChecks = self._claimGlobalScanRegion()
        self._danglingIndex = None  # lazily built when needed

    # ------------------------------------------------------------------ #
    # Global-scan region gate
    # ------------------------------------------------------------------ #
    def _claimGlobalScanRegion(self):
        """Return True if this region should run hosted-zone/health-check/domain checks.

        Uses a Config cache so the first region to initialise wins the claim.
        Subsequent regions in a multi-region scan skip global discovery to
        avoid duplicate findings.
        """
        existing = Config.get(self.GLOBAL_CLAIM_KEY, None)
        if not existing:
            Config.set(self.GLOBAL_CLAIM_KEY, self.region)
            return True
        return existing == self.region

    # ------------------------------------------------------------------ #
    # Discovery — Hosted Zones + Records
    # ------------------------------------------------------------------ #
    def getHostedZones(self):
        zones = []
        try:
            paginator = self.route53Client.get_paginator('list_hosted_zones')
            for page in paginator.paginate():
                for zone in page.get('HostedZones', []) or []:
                    detail = self._describeHostedZone(zone)
                    if detail is None:
                        continue
                    zones.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_hosted_zones', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Route53 not available in region {self.region}: {e}")
        return zones

    def _describeHostedZone(self, summary):
        zid_full = summary.get('Id', '')
        zid = zid_full.replace('/hostedzone/', '') if zid_full else ''
        name = summary.get('Name', '')
        if not zid or not name:
            return None

        config = summary.get('Config', {}) or {}
        is_private = bool(config.get('PrivateZone', False))

        detail = {
            '_zoneId': zid,
            '_name': name,
            '_isPrivate': is_private,
            '_resourceRecordSetCount': int(summary.get('ResourceRecordSetCount', 0) or 0),
            '_config': config,
            '_dnssecStatus': None,
            '_queryLoggingConfigs': [],
            '_records': [],
            '_getHostedZoneMeta': None,
        }

        # DNSSEC signing state (public zones only)
        if not is_private:
            detail['_dnssecStatus'] = self._getDnssecStatus(zid)
            detail['_queryLoggingConfigs'] = self._listQueryLoggingConfigs(zid)

        # get_hosted_zone returns HostedZone + DelegationSet — use for created/rcount
        try:
            meta = self.route53Client.get_hosted_zone(Id=zid)
            detail['_getHostedZoneMeta'] = meta
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_hosted_zone({zid})', e)

        # List all resource record sets (paginated).
        detail['_records'] = self._listResourceRecordSets(zid)
        return detail

    def _getDnssecStatus(self, zid):
        try:
            resp = self.route53Client.get_dnssec(HostedZoneId=zid)
            return resp
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('DNSSECNotFound', 'NoSuchHostedZone'):
                return {}
            self._logClientError(f'get_dnssec({zid})', e)
            return None

    def _listQueryLoggingConfigs(self, zid):
        configs = []
        try:
            paginator = self.route53Client.get_paginator('list_query_logging_configs')
            for page in paginator.paginate(HostedZoneId=zid):
                for cfg in page.get('QueryLoggingConfigs', []) or []:
                    configs.append(cfg)
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'NoSuchQueryLoggingConfig':
                return []
            self._logClientError(f'list_query_logging_configs({zid})', e)
        return configs

    def _listResourceRecordSets(self, zid):
        records = []
        try:
            paginator = self.route53Client.get_paginator('list_resource_record_sets')
            for page in paginator.paginate(HostedZoneId=zid):
                for rr in page.get('ResourceRecordSets', []) or []:
                    records.append(rr)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_resource_record_sets({zid})', e)
        return records

    # ------------------------------------------------------------------ #
    # Discovery — Health Checks
    # ------------------------------------------------------------------ #
    def getHealthChecks(self):
        checks = []
        try:
            paginator = self.route53Client.get_paginator('list_health_checks')
            for page in paginator.paginate():
                for hc in page.get('HealthChecks', []) or []:
                    checks.append(hc)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_health_checks', e)
        return checks

    # ------------------------------------------------------------------ #
    # Discovery — Domains (route53domains, us-east-1 only)
    # ------------------------------------------------------------------ #
    def getDomains(self):
        domains = []
        try:
            paginator = self.domainsClient.get_paginator('list_domains')
            for page in paginator.paginate():
                for dom in page.get('Domains', []) or []:
                    name = dom.get('DomainName')
                    if not name:
                        continue
                    detail = self._describeDomain(name)
                    if detail is not None:
                        domains.append(detail)
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # route53domains not available in some partitions (e.g. GovCloud, China)
            if code not in ('AccessDenied', 'AccessDeniedException',
                            'UnrecognizedClientException'):
                self._logClientError('list_domains', e)
        except botocore.exceptions.EndpointConnectionError:
            # route53domains endpoint not reachable — nothing to scan.
            pass
        return domains

    def _describeDomain(self, name):
        try:
            resp = self.domainsClient.get_domain_detail(DomainName=name)
            resp['_name'] = name
            return resp
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_domain_detail({name})', e)
            return None

    # ------------------------------------------------------------------ #
    # Discovery — Resolver (DNS Firewall / Query Logging / DNSSEC Validation)
    # ------------------------------------------------------------------ #
    def getResolverConfig(self):
        """Return a single synthetic resource describing the account's Resolver
        posture for THIS region."""
        detail = {
            '_region': self.region,
            '_firewallAssociations': [],
            '_queryLogConfigs': [],
            '_queryLogAssociations': [],
            '_dnssecConfigs': [],
        }

        # DNS Firewall associations
        try:
            paginator = self.resolverClient.get_paginator(
                'list_firewall_rule_group_associations'
            )
            for page in paginator.paginate():
                for a in page.get('FirewallRuleGroupAssociations', []) or []:
                    detail['_firewallAssociations'].append(a)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_firewall_rule_group_associations', e)
        except botocore.exceptions.EndpointConnectionError:
            return None  # resolver not available in this region

        # Query logging configs + associations
        try:
            paginator = self.resolverClient.get_paginator(
                'list_resolver_query_log_configs'
            )
            for page in paginator.paginate():
                for c in page.get('ResolverQueryLogConfigs', []) or []:
                    detail['_queryLogConfigs'].append(c)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_resolver_query_log_configs', e)

        try:
            paginator = self.resolverClient.get_paginator(
                'list_resolver_query_log_config_associations'
            )
            for page in paginator.paginate():
                for a in page.get('ResolverQueryLogConfigAssociations', []) or []:
                    detail['_queryLogAssociations'].append(a)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_resolver_query_log_config_associations', e)

        # DNSSEC validation configs (list only returns configs; ValidationStatus per VPC)
        try:
            paginator = self.resolverClient.get_paginator(
                'list_resolver_dnssec_configs'
            )
            for page in paginator.paginate():
                for c in page.get('ResolverDnssecConfigs', []) or []:
                    detail['_dnssecConfigs'].append(c)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_resolver_dnssec_configs', e)

        return detail

    # ------------------------------------------------------------------ #
    # Cross-service helpers for dangling-DNS check (#19)
    # ------------------------------------------------------------------ #
    def getDanglingIndex(self):
        """Return (and lazily build) a dict of known-existing targets. Structure:
          {
            'cloudfront_domains': set of every existing distribution DomainName,
            'alb_domains':        set of every existing ALB/NLB DNSName,
            'elb_classic_domains':set of every existing classic ELB DNSName,
            's3_buckets':         set of every existing S3 bucket name (owned by us),
            'eb_domains':         set of every existing Elastic Beanstalk env CNAME,
          }

        The check is best-effort: if any lookup fails (missing IAM permission
        or unsupported region), we return partial data and the driver
        downgrades the finding to INFO.
        """
        if self._danglingIndex is not None:
            return self._danglingIndex

        idx = {
            'cloudfront_domains': set(),
            'alb_domains': set(),
            'elb_classic_domains': set(),
            's3_buckets': set(),
            'eb_domains': set(),
            'lookupFailed': False,
        }

        # CloudFront
        try:
            marker = None
            while True:
                kw = {}
                if marker:
                    kw['Marker'] = marker
                resp = self.cfClient.list_distributions(**kw)
                dl = resp.get('DistributionList') or {}
                for item in dl.get('Items', []) or []:
                    dn = item.get('DomainName')
                    if dn:
                        idx['cloudfront_domains'].add(dn.lower().rstrip('.'))
                if dl.get('IsTruncated'):
                    marker = dl.get('NextMarker')
                    if not marker:
                        break
                else:
                    break
        except botocore.exceptions.ClientError as e:
            idx['lookupFailed'] = True
            self._logClientError('cloudfront.list_distributions', e)
        except botocore.exceptions.EndpointConnectionError:
            idx['lookupFailed'] = True

        # ALB / NLB
        try:
            paginator = self.elbv2Client.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []) or []:
                    dn = lb.get('DNSName')
                    if dn:
                        idx['alb_domains'].add(dn.lower().rstrip('.'))
        except botocore.exceptions.ClientError as e:
            idx['lookupFailed'] = True
            self._logClientError('elbv2.describe_load_balancers', e)
        except botocore.exceptions.EndpointConnectionError:
            pass

        # Classic ELB
        if self.elbClient is not None:
            try:
                paginator = self.elbClient.get_paginator('describe_load_balancers')
                for page in paginator.paginate():
                    for lb in page.get('LoadBalancerDescriptions', []) or []:
                        dn = lb.get('DNSName')
                        if dn:
                            idx['elb_classic_domains'].add(dn.lower().rstrip('.'))
            except botocore.exceptions.ClientError as e:
                idx['lookupFailed'] = True
                self._logClientError('elb.describe_load_balancers', e)
            except botocore.exceptions.EndpointConnectionError:
                pass

        # S3 buckets
        try:
            resp = self.s3Client.list_buckets()
            for b in resp.get('Buckets', []) or []:
                name = b.get('Name')
                if name:
                    idx['s3_buckets'].add(name.lower())
        except botocore.exceptions.ClientError as e:
            idx['lookupFailed'] = True
            self._logClientError('s3.list_buckets', e)

        # Elastic Beanstalk environments (per current region only)
        if self.ebClient is not None:
            try:
                marker = None
                while True:
                    kw = {}
                    if marker:
                        kw['NextToken'] = marker
                    resp = self.ebClient.describe_environments(**kw)
                    for env in resp.get('Environments', []) or []:
                        cname = env.get('CNAME')
                        if cname:
                            idx['eb_domains'].add(cname.lower().rstrip('.'))
                    marker = resp.get('NextToken')
                    if not marker:
                        break
            except botocore.exceptions.ClientError as e:
                idx['lookupFailed'] = True
                self._logClientError(
                    'elasticbeanstalk.describe_environments', e
                )
            except botocore.exceptions.EndpointConnectionError:
                pass

        self._danglingIndex = idx
        return idx

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}

        if self._runGlobalChecks:
            # Hosted zones
            zones = self.getHostedZones()
            danglingIdx = None
            if zones:
                # Only fetch dangling index if we have any zones to check.
                danglingIdx = self.getDanglingIndex()
            for zone in zones:
                try:
                    name = zone.get('_name', 'unknown').rstrip('.')
                    _pi('Route53', f"HostedZone: {name}")
                    obj = Route53HostedZone(zone, self.route53Client,
                                            danglingIdx or {},
                                            self.SENSITIVE_NAME_PREFIXES,
                                            self.DANGLING_SUFFIXES)
                    obj.run(self.__class__)
                    objs[f"Route53::HostedZone={name}"] = obj.getInfo()
                    del obj
                except Exception as e:
                    print(f"Error processing hosted zone {zone.get('_zoneId')}: {e}")

            # Health checks
            for hc in self.getHealthChecks():
                try:
                    hcid = hc.get('Id', 'unknown')
                    _pi('Route53', f"HealthCheck: {hcid}")
                    obj = Route53HealthCheck(hc, self.route53Client)
                    obj.run(self.__class__)
                    objs[f"Route53::HealthCheck={hcid}"] = obj.getInfo()
                    del obj
                except Exception as e:
                    print(f"Error processing health check {hc.get('Id')}: {e}")

            # Domains
            for dom in self.getDomains():
                try:
                    name = dom.get('_name', 'unknown')
                    _pi('Route53', f"Domain: {name}")
                    obj = Route53Domain(dom, self.domainsClient)
                    obj.run(self.__class__)
                    objs[f"Route53::Domain={name}"] = obj.getInfo()
                    del obj
                except Exception as e:
                    print(f"Error processing domain {dom.get('_name')}: {e}")

        # Resolver — always per-region
        resolver = self.getResolverConfig()
        if resolver is not None:
            try:
                _pi('Route53', f"Resolver::{self.region}")
                obj = Route53Resolver(resolver, self.resolverClient)
                obj.run(self.__class__)
                objs[f"Route53::Resolver={self.region}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing resolver ({self.region}): {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError',
                    'UnauthorizedOperation'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Route53 {where}: {code} - {msg}")


if __name__ == "__main__":
    Config.init()
    o = Route53('ap-southeast-1')
    out = o.advise()
    print(out)

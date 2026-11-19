import re

import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

from services.arc.drivers.ArcAccount import ArcAccount
from services.arc.drivers.ArcRegionSwitchPlan import ArcRegionSwitchPlan


class Arc(Service):
    """
    Amazon Application Recovery Controller (ARC) scanner.

    ARC Region switch plans and Routing control clusters are account-wide
    (global) resources:
      * arc-region-switch ListPlans is a control-plane operation
        (UseControlPlaneEndpoint) served from the partition's global endpoint
        regardless of the client's Region.
      * route53-recovery-control-config is served from a single global endpoint
        (us-west-2 in the aws partition).
      * arc-region-switch ListPlanExecutions is a REGIONAL data-plane operation,
        so executions are read from every Region listed in the plan and merged.

    To avoid reporting the same account-wide findings once per scanned Region,
    the first Region to initialise this service claims the scan (same approach
    as services/route53). Other Regions return no resources.

    All calls are read-only: list_plans, list_tags_for_resource,
    list_plan_executions, list_clusters.

    regionSwitchPlanMissing is only a gap for an account that runs a
    multi-Region workload. When no plan and no cluster exist, read-only probes
    look for multi-Region evidence (see _multiRegionEvidence): EventBridge
    global endpoints, Aurora global databases, DynamoDB global tables (in the
    scanning Region) and Route 53 latency / failover records that point at
    different Regions.
    """

    GLOBAL_CLAIM_KEY = 'arc::globalScanRegion'

    ## Bounds on the multi-Region evidence probes (each is a read-only list or
    ## describe call). Hitting a bound is reported, never treated as absence.
    DDB_DESCRIBE_CAP = 100
    R53_ZONE_CAP = 50
    R53_PAGES_PER_ZONE = 5

    ## AWS Region code inside a service DNS name, e.g.
    ## dualstack.my-alb-1.eu-west-1.elb.amazonaws.com, s3-website-us-east-1...
    REGION_IN_DNS = re.compile(
        r'((?:us|eu|ap|sa|ca|me|af|il|mx|cn)(?:-gov|-iso[a-z]?)?-'
        r'(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d)')

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.rsClient = ssBoto.client('arc-region-switch', config=self.bConfig)
        self.rcClient = ssBoto.client('route53-recovery-control-config', config=self.bConfig)
        self._regionalRsClients = {region: self.rsClient}
        self._runGlobalChecks = self._claimGlobalScanRegion()

    def _claimGlobalScanRegion(self):
        existing = Config.get(self.GLOBAL_CLAIM_KEY, None)
        if not existing:
            Config.set(self.GLOBAL_CLAIM_KEY, self.region)
            return True
        return existing == self.region

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errCode(e):
        if isinstance(e, botocore.exceptions.ClientError):
            return e.response.get('Error', {}).get('Code', 'Unknown')
        return type(e).__name__

    def _listPlans(self):
        """Return (plans, errorCode). errorCode is None on success."""
        plans = []
        try:
            for page in self.rsClient.get_paginator('list_plans').paginate():
                plans += page.get('plans', []) or []
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            return None, self._errCode(e)
        return plans, None

    def _listClusters(self):
        clusters = []
        try:
            for page in self.rcClient.get_paginator('list_clusters').paginate():
                clusters += page.get('Clusters', []) or []
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            return None, self._errCode(e)
        return clusters, None

    def _planTags(self, arn):
        try:
            tags = self.rsClient.list_tags_for_resource(arn=arn).get('resourceTags', {}) or {}
            return [{'Key': k, 'Value': v} for k, v in tags.items()]
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError):
            return []

    def _regionalClient(self, region):
        if region not in self._regionalRsClients:
            self._regionalRsClients[region] = self.ssBoto.client(
                'arc-region-switch', region_name=region, config=self.bConfig)
        return self._regionalRsClients[region]

    def _listExecutions(self, plan):
        """Merge executions from every Region of the plan.

        Returns (executions, errors) where errors maps region -> error code
        for Regions whose executions could not be read."""
        executions = {}
        errors = {}
        regions = list(plan.get('regions') or []) or [self.region]
        for reg in regions:
            try:
                client = self._regionalClient(reg)
                for page in client.get_paginator('list_plan_executions').paginate(planArn=plan['arn']):
                    for item in page.get('items', []) or []:
                        key = item.get('executionId') or id(item)
                        executions[key] = item
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                errors[reg] = self._errCode(e)
        return list(executions.values()), errors

    # ------------------------------------------------------------------ #
    # Multi-Region workload evidence (regionSwitchPlanMissing)
    # ------------------------------------------------------------------ #
    def _multiRegionEvidence(self):
        """
        Returns {'evidence': [str], 'errors': [str], 'incomplete': [str]}.
        Probes stop at the first piece of evidence. A probe that cannot be read
        is recorded in errors; a probe that hit its bound is recorded in
        incomplete, so absence is never asserted from partial data.
        """
        out = {'evidence': [], 'errors': [], 'incomplete': []}
        probes = [
            ('events:ListEndpoints', self._probeGlobalEndpoints),
            ('rds:DescribeGlobalClusters', self._probeAuroraGlobal),
            ('dynamodb:ListGlobalTables', self._probeDynamoLegacyGlobal),
            ('dynamodb:DescribeTable', lambda: self._probeDynamoReplicas(out)),
            ('route53:ListResourceRecordSets', lambda: self._probeRoute53(out)),
        ]
        for name, fn in probes:
            try:
                found = fn()
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                out['errors'].append(f"{name}: {self._errCode(e)}")
                continue
            if found:
                out['evidence'].append(found)
                break
        return out

    def _probeGlobalEndpoints(self):
        ev = self.ssBoto.client('events', config=self.bConfig)
        kw = {}
        while True:
            resp = ev.list_endpoints(**kw)
            for e in resp.get('Endpoints', []) or []:
                return f"EventBridge global endpoint {e.get('Name', '?')}"
            if not resp.get('NextToken'):
                return None
            kw['NextToken'] = resp['NextToken']

    @staticmethod
    def _arnRegion(arn):
        parts = (arn or '').split(':')
        return parts[3] if len(parts) > 3 else ''

    def _probeAuroraGlobal(self):
        rds = self.ssBoto.client('rds', config=self.bConfig)
        for page in rds.get_paginator('describe_global_clusters').paginate():
            for gc in page.get('GlobalClusters', []) or []:
                regions = {self._arnRegion(m.get('DBClusterArn')) for m in gc.get('GlobalClusterMembers', []) or []}
                regions.discard('')
                if len(regions) >= 2:
                    return (f"Aurora global database {gc.get('GlobalClusterIdentifier', '?')} "
                            f"({', '.join(sorted(regions))})")
        return None

    def _probeDynamoLegacyGlobal(self):
        ddb = self.ssBoto.client('dynamodb', config=self.bConfig)
        kw = {}
        while True:
            resp = ddb.list_global_tables(**kw)
            for gt in resp.get('GlobalTables', []) or []:
                regions = {r.get('RegionName') for r in gt.get('ReplicationGroup', []) or []} - {None}
                if len(regions) >= 2:
                    return (f"DynamoDB global table {gt.get('GlobalTableName', '?')} "
                            f"({', '.join(sorted(regions))})")
            last = resp.get('LastEvaluatedGlobalTableName')
            if not last:
                return None
            kw['ExclusiveStartGlobalTableName'] = last

    def _probeDynamoReplicas(self, out):
        ddb = self.ssBoto.client('dynamodb', config=self.bConfig)
        names = []
        for page in ddb.get_paginator('list_tables').paginate():
            names += page.get('TableNames', []) or []
        if len(names) > self.DDB_DESCRIBE_CAP:
            out['incomplete'].append(
                f"DynamoDB replicas checked on {self.DDB_DESCRIBE_CAP} of {len(names)} tables in {self.region}")
        for name in names[:self.DDB_DESCRIBE_CAP]:
            try:
                table = ddb.describe_table(TableName=name).get('Table') or {}
            except botocore.exceptions.ClientError as e:
                if self._errCode(e) == 'ResourceNotFoundException':
                    continue
                raise
            others = {r.get('RegionName') for r in table.get('Replicas', []) or []} - {None, self.region}
            if others:
                return f"DynamoDB global table {name} (replicas in {', '.join(sorted(others))})"
        return None

    def _dnsRegion(self, record):
        if record.get('Region'):
            return record['Region']
        dns = ((record.get('AliasTarget') or {}).get('DNSName') or '').lower()
        found = self.REGION_IN_DNS.findall(dns)
        if found:
            return found[-1]
        for rr in record.get('ResourceRecords', []) or []:
            found = self.REGION_IN_DNS.findall((rr.get('Value') or '').lower())
            if found:
                return found[-1]
        return None

    def _probeRoute53(self, out):
        """Latency records for one name in >= 2 Regions, or a failover
        PRIMARY/SECONDARY pair whose targets are in different Regions."""
        r53 = self.ssBoto.client('route53', config=self.bConfig)
        zones = []
        for page in r53.get_paginator('list_hosted_zones').paginate():
            zones += page.get('HostedZones', []) or []
        if len(zones) > self.R53_ZONE_CAP:
            out['incomplete'].append(f"Route 53 records checked in {self.R53_ZONE_CAP} of {len(zones)} hosted zones")
        for zone in zones[:self.R53_ZONE_CAP]:
            zid = zone.get('Id')
            if not zid:
                continue
            latency, failover = {}, {}
            pages = 0
            for page in r53.get_paginator('list_resource_record_sets').paginate(HostedZoneId=zid):
                pages += 1
                for rec in page.get('ResourceRecordSets', []) or []:
                    key = (rec.get('Name'), rec.get('Type'))
                    if rec.get('Region'):
                        latency.setdefault(key, set()).add(rec['Region'])
                    elif rec.get('Failover'):
                        region = self._dnsRegion(rec)
                        if region:
                            failover.setdefault(key, {})[rec['Failover']] = region
                if pages >= self.R53_PAGES_PER_ZONE and page.get('IsTruncated'):
                    out['incomplete'].append(f"Route 53 records partially read in hosted zone {zone.get('Name', zid)}")
                    break
            for (name, rtype), regions in latency.items():
                if len(regions) >= 2:
                    return f"Route 53 latency records {name} {rtype} ({', '.join(sorted(regions))})"
            for (name, rtype), roles in failover.items():
                p, sec = roles.get('PRIMARY'), roles.get('SECONDARY')
                if p and sec and p != sec:
                    return f"Route 53 failover records {name} {rtype} (PRIMARY {p}, SECONDARY {sec})"
        return None

    def getResources(self):
        plans, planErr = self._listPlans()
        clusters, clusterErr = self._listClusters()
        detail = {
            '_region': self.region,
            '_plans': plans,
            '_planError': planErr,
            '_clusters': clusters,
            '_clusterError': clusterErr,
            '_multiRegion': None,
        }
        ## Evidence only matters when absence of ARC has been established.
        if plans == [] and clusters == []:
            detail['_multiRegion'] = self._multiRegionEvidence()
        return detail

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        if not self._runGlobalChecks:
            return objs

        detail = self.getResources()

        try:
            obj = ArcAccount(detail)
            obj.run(self.__class__)
            objs['ARC::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing ARC account posture: {e}")

        for plan in detail.get('_plans') or []:
            arn = plan.get('arn')
            if not arn:
                continue
            if self.tags and not self.resourceHasTags(self._planTags(arn)):
                continue
            name = plan.get('name') or arn.split('/')[-1]
            _pi('Arc', f"Region switch plan: {name}")
            executions, errors = self._listExecutions(plan)
            try:
                obj = ArcRegionSwitchPlan(plan, executions, errors)
                obj.run(self.__class__)
                objs[f"RegionSwitchPlan::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Region switch plan {name}: {e}")

        return objs

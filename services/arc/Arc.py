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
    """

    GLOBAL_CLAIM_KEY = 'arc::globalScanRegion'

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

    def getResources(self):
        plans, planErr = self._listPlans()
        clusters, clusterErr = self._listClusters()
        return {
            '_region': self.region,
            '_plans': plans,
            '_planError': planErr,
            '_clusters': clusters,
            '_clusterError': clusterErr,
        }

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

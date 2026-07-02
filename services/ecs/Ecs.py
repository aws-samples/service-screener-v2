import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

from services.ecs.drivers.EcsCluster import EcsCluster
from services.ecs.drivers.EcsService import EcsService
from services.ecs.drivers.EcsTaskDefinition import EcsTaskDefinition


class Ecs(Service):
    """
    Amazon ECS service scanner.

    Resource hierarchy (per region):
        clusters --list_clusters--> [clusterArn]
                 --describe_clusters(include=[SETTINGS,CONFIGURATIONS,STATISTICS,TAGS])
        services --list_services(cluster) per cluster
                 --describe_services(cluster, services[<=10], include=[TAGS])
                 --describe_task_sets(cluster, service) when deploymentController=EXTERNAL
        task definitions --list_task_definition_families(status=ACTIVE)
                         --describe_task_definition(family, include=[TAGS]) => latest ACTIVE revision
        scaling  --application-autoscaling:describe_scalable_targets(ServiceNamespace='ecs')
                 (called ONCE per region and indexed by ResourceId)

    Drivers:
        EcsCluster        -- 8 cluster-level checks (7 T1 + 1 T2)
        EcsService        -- 15 service-level checks (12 T1 + 3 T2, incl. task-set)
        EcsTaskDefinition -- 19 task-definition-level checks (16 T1 + 3 T2)
    """

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        # Primary ECS client
        self.ecsClient = ssBoto.client('ecs', config=self.bConfig)
        # Application Auto Scaling — for service auto-scaling detection (check 12)
        self.aasClient = ssBoto.client('application-autoscaling', config=self.bConfig)
        # CloudWatch Logs — used by task-definition driver to validate log-group existence
        self.logsClient = ssBoto.client('logs', config=self.bConfig)
        # Secrets Manager / SSM — used by check 35 to validate secret references
        self.secretsClient = ssBoto.client('secretsmanager', config=self.bConfig)
        self.ssmClient = ssBoto.client('ssm', config=self.bConfig)

        # Populated in getResources()
        self._clusters = []             # list of describe_clusters dicts
        self._services = []             # list of describe_services dicts (each has _cluster and _taskSets)
        self._taskDefs = []             # list of describe_task_definition['taskDefinition'] dicts
        self._scalableTargets = {}      # ResourceId -> scalable target
        self._latestRevisions = {}      # family -> latest ACTIVE revision number

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        self._collectClusters()
        self._collectServices()
        self._collectTaskDefinitions()
        self._collectScalableTargets()
        return {
            'clusters': self._clusters,
            'services': self._services,
            'taskDefs': self._taskDefs,
        }

    def _collectClusters(self):
        try:
            paginator = self.ecsClient.get_paginator('list_clusters')
            arns = []
            for page in paginator.paginate():
                arns.extend(page.get('clusterArns', []) or [])
            # describe_clusters accepts up to 100 per call
            for i in range(0, len(arns), 100):
                chunk = arns[i:i+100]
                try:
                    resp = self.ecsClient.describe_clusters(
                        clusters=chunk,
                        include=['SETTINGS', 'CONFIGURATIONS', 'STATISTICS', 'TAGS'],
                    )
                    for c in resp.get('clusters', []) or []:
                        if self.tags and not self.resourceHasTags(c.get('tags', []) or []):
                            continue
                        self._clusters.append(c)
                        _pi('Ecs', f"Cluster: {c.get('clusterName', c.get('clusterArn'))}")
                except botocore.exceptions.ClientError as e:
                    self._logClientError('describe_clusters', e)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_clusters', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"ECS not available in region {self.region}: {e}")

    def _collectServices(self):
        for cluster in self._clusters:
            cluster_arn = cluster.get('clusterArn')
            if not cluster_arn:
                continue
            try:
                paginator = self.ecsClient.get_paginator('list_services')
                service_arns = []
                for page in paginator.paginate(cluster=cluster_arn):
                    service_arns.extend(page.get('serviceArns', []) or [])
                # describe_services accepts up to 10 per call
                for i in range(0, len(service_arns), 10):
                    chunk = service_arns[i:i+10]
                    try:
                        resp = self.ecsClient.describe_services(
                            cluster=cluster_arn,
                            services=chunk,
                            include=['TAGS'],
                        )
                        for s in resp.get('services', []) or []:
                            if self.tags and not self.resourceHasTags(s.get('tags', []) or []):
                                continue
                            s['_cluster'] = cluster
                            s['_taskSets'] = self._collectTaskSetsIfExternal(cluster_arn, s)
                            self._services.append(s)
                            _pi('Ecs', f"Service: {s.get('serviceName')} in {cluster.get('clusterName')}")
                    except botocore.exceptions.ClientError as e:
                        self._logClientError('describe_services', e)
            except botocore.exceptions.ClientError as e:
                self._logClientError(f'list_services({cluster_arn})', e)

    def _collectTaskSetsIfExternal(self, cluster_arn, service):
        """Only EXTERNAL deployment controllers expose task sets to the API."""
        dc = (service.get('deploymentController') or {}).get('type')
        if dc != 'EXTERNAL':
            # ECS services with the default (ECS) or CODE_DEPLOY controller
            # also expose task sets internally, but describe_task_sets works
            # generically — still, we only care about EXTERNAL for check 18
            # since the other controllers manage networkConfiguration on the
            # service itself. Skip to save API calls.
            return []
        try:
            resp = self.ecsClient.describe_task_sets(
                cluster=cluster_arn,
                service=service.get('serviceArn') or service.get('serviceName'),
            )
            return resp.get('taskSets', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_task_sets', e)
            return []

    def _collectTaskDefinitions(self):
        """Enumerate ACTIVE task-definition families and fetch the latest revision of each."""
        try:
            paginator = self.ecsClient.get_paginator('list_task_definition_families')
            families = []
            for page in paginator.paginate(status='ACTIVE'):
                families.extend(page.get('families', []) or [])

            for family in families:
                # list_task_definitions returns revisions in ASC order; latest ACTIVE first when DESC
                try:
                    resp = self.ecsClient.list_task_definitions(
                        familyPrefix=family,
                        status='ACTIVE',
                        sort='DESC',
                        maxResults=1,
                    )
                    arns = resp.get('taskDefinitionArns') or []
                    if not arns:
                        continue
                    latest_arn = arns[0]
                    # Track latest revision number for check 39 (stale task def)
                    try:
                        rev_num = int(latest_arn.rsplit(':', 1)[1])
                    except (ValueError, IndexError):
                        rev_num = None
                    if rev_num is not None:
                        self._latestRevisions[family] = rev_num

                    try:
                        td_resp = self.ecsClient.describe_task_definition(
                            taskDefinition=latest_arn,
                            include=['TAGS'],
                        )
                        td = td_resp.get('taskDefinition')
                        if td is None:
                            continue
                        tags = td_resp.get('tags', []) or []
                        if self.tags and not self.resourceHasTags(tags):
                            continue
                        td['_tags'] = tags
                        self._taskDefs.append(td)
                        _pi('Ecs', f"Task Definition: {family} rev={rev_num}")
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(f'describe_task_definition({latest_arn})', e)
                except botocore.exceptions.ClientError as e:
                    self._logClientError(f'list_task_definitions({family})', e)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_task_definition_families', e)

    def _collectScalableTargets(self):
        """
        Fetch every ECS scalable target in the region once.
        Index by ResourceId which is 'service/{cluster_name}/{service_name}'.
        """
        try:
            paginator = self.aasClient.get_paginator('describe_scalable_targets')
            for page in paginator.paginate(ServiceNamespace='ecs'):
                for t in page.get('ScalableTargets', []) or []:
                    rid = t.get('ResourceId')
                    if rid:
                        self._scalableTargets[rid] = t
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_scalable_targets', e)

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        self.getResources()

        # Index task definitions by family for cross-referencing from services
        td_by_family = {}
        for td in self._taskDefs:
            fam = td.get('family')
            if fam:
                td_by_family[fam] = td

        # --------- CLUSTER CHECKS ---------
        # Also need to know if any service in cluster has enableExecuteCommand
        # and multi-service flag for serviceConnectDefaults check
        services_by_cluster = {}
        for s in self._services:
            cid = (s.get('_cluster') or {}).get('clusterArn')
            services_by_cluster.setdefault(cid, []).append(s)

        for cluster in self._clusters:
            try:
                name = cluster.get('clusterName', cluster.get('clusterArn', 'unknown'))
                _pi('Ecs', f"Analyzing cluster: {name}")
                cluster_services = services_by_cluster.get(cluster.get('clusterArn'), [])
                obj = EcsCluster(cluster, cluster_services)
                obj.run(self.__class__)
                objs[f"Ecs::Cluster::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing ECS cluster {cluster.get('clusterArn')}: {e}")

        # --------- SERVICE CHECKS ---------
        for service in self._services:
            try:
                cluster = service.get('_cluster') or {}
                cname = cluster.get('clusterName', 'unknown')
                sname = service.get('serviceName', 'unknown')
                _pi('Ecs', f"Analyzing service: {cname}/{sname}")
                obj = EcsService(
                    service=service,
                    cluster=cluster,
                    task_def_by_family=td_by_family,
                    scalable_targets=self._scalableTargets,
                    latest_revisions=self._latestRevisions,
                    elbv2Client=self._elbv2Client(),
                )
                obj.run(self.__class__)
                objs[f"Ecs::Service::{cname}/{sname}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing ECS service {service.get('serviceArn')}: {e}")

        # --------- TASK DEFINITION CHECKS ---------
        # Cluster-level KMS keys for check 42
        cluster_has_fargate_cmk = any(
            (c.get('configuration') or {})
            .get('managedStorageConfiguration', {})
            .get('fargateEphemeralStorageKmsKeyId')
            for c in self._clusters
        )
        for td in self._taskDefs:
            try:
                fam = td.get('family', 'unknown')
                rev = td.get('revision', '?')
                _pi('Ecs', f"Analyzing task definition: {fam}:{rev}")
                obj = EcsTaskDefinition(
                    task_def=td,
                    secrets_client=self.secretsClient,
                    ssm_client=self.ssmClient,
                    cluster_has_fargate_cmk=cluster_has_fargate_cmk,
                )
                obj.run(self.__class__)
                objs[f"Ecs::TaskDef::{fam}:{rev}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing ECS task definition {td.get('taskDefinitionArn')}: {e}")

        return objs

    def _elbv2Client(self):
        """Lazily initialise elbv2 client — only needed if any service has load balancers."""
        if not hasattr(self, '_elbv2ClientCache'):
            try:
                self._elbv2ClientCache = self.ssBoto.client('elbv2', config=self.bConfig)
            except Exception:
                self._elbv2ClientCache = None
        return self._elbv2ClientCache

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Ecs {where}: {code} - {msg}")

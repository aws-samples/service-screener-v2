import re

import botocore

from services.Evaluator import Evaluator


class EcsCluster(Evaluator):
    """
    Cluster-level ECS checks (8 total: 7 Tier 1 + 1 Tier 2).

    Input:
      cluster           -- output of DescribeClusters with SETTINGS, CONFIGURATIONS,
                           STATISTICS, TAGS included.
      cluster_services  -- list of service dicts in this cluster (already fetched);
                           used to detect if any service enables ExecuteCommand
                           (needed for check #2) and to detect multi-service usage
                           for check #36.
    """

    # Check IDs from spec
    #  1  ecsClusterContainerInsightsEnabled
    #  2  ecsClusterExecuteCommandLogging
    #  3  ecsClusterExecuteCommandEncryption
    #  4  ecsClusterManagedStorageEncryption
    #  5  ecsClusterDefaultCapacityProviderStrategy
    #  6  ecsClusterNoRunningTasks
    #  7  ecsClusterTagging
    # 36  ecsClusterServiceConnectDefaults
    # 43  ecsContainerAgentOutdated (WAFS2027 SEC06-BP01)

    # An instance is "outdated" when its agent is more than this many minor
    # releases behind the version shipped in the latest recommended
    # ECS-optimized AMI. The agent releases every 1-3 weeks; a small lag is a
    # normal patch cadence, so it is tolerated to avoid noisy findings.
    AGENT_MINOR_LAG_TOLERANCE = 2
    EVALUATED_INSTANCE_STATUSES = {'ACTIVE', 'DRAINING'}

    def __init__(self, cluster, cluster_services, ecs_client=None, latest_agent=None):
        super().__init__()
        self.cluster = cluster or {}
        self.services = cluster_services or []
        self.ecsClient = ecs_client
        # (versionString or None, errorCode or None) from the SSM public parameter
        self.latestAgent = latest_agent or (None, 'NotFetched')

        name = self.cluster.get('clusterName') or self.cluster.get('clusterArn', 'unknown')
        self._resourceName = f"Cluster::{name}"

        self.addII('clusterName', name)
        self.addII('clusterArn', self.cluster.get('clusterArn', 'N/A'))
        self.addII('status', self.cluster.get('status', 'N/A'))
        self.addII('activeServicesCount', self.cluster.get('activeServicesCount', 0))
        self.addII('runningTasksCount', self.cluster.get('runningTasksCount', 0))
        self.addII('registeredContainerInstancesCount',
                   self.cluster.get('registeredContainerInstancesCount', 0))

    # ------------------------------------------------------------------ #
    # #1 ecsClusterContainerInsightsEnabled
    # ------------------------------------------------------------------ #
    def _checkEcsClusterContainerInsightsEnabled(self):
        settings = self.cluster.get('settings') or []
        for s in settings:
            if s.get('name') == 'containerInsights' and s.get('value') == 'enabled':
                self.results['ecsClusterContainerInsightsEnabled'] = [
                    1, "Container Insights enabled"
                ]
                return
        current = 'not set'
        for s in settings:
            if s.get('name') == 'containerInsights':
                current = s.get('value', 'unknown')
                break
        self.results['ecsClusterContainerInsightsEnabled'] = [
            -1, f"Container Insights: {current}"
        ]

    # ------------------------------------------------------------------ #
    # #2 ecsClusterExecuteCommandLogging
    # ------------------------------------------------------------------ #
    def _checkEcsClusterExecuteCommandLogging(self):
        # If no service in this cluster enables ECS Exec, this check is N/A.
        any_exec = any(bool(s.get('enableExecuteCommand')) for s in self.services)
        if not any_exec:
            self.results['ecsClusterExecuteCommandLogging'] = [
                0, "No service in cluster uses ECS Exec"
            ]
            return

        cfg = (self.cluster.get('configuration') or {}).get('executeCommandConfiguration') or {}
        logging_mode = cfg.get('logging', 'NONE')
        if logging_mode == 'NONE' or not logging_mode:
            self.results['ecsClusterExecuteCommandLogging'] = [
                -1, f"ECS Exec logging={logging_mode or 'unset'} while service(s) enable ExecuteCommand"
            ]
        else:
            self.results['ecsClusterExecuteCommandLogging'] = [
                1, f"ECS Exec logging={logging_mode}"
            ]

    # ------------------------------------------------------------------ #
    # #3 ecsClusterExecuteCommandEncryption
    # ------------------------------------------------------------------ #
    def _checkEcsClusterExecuteCommandEncryption(self):
        cfg = (self.cluster.get('configuration') or {}).get('executeCommandConfiguration') or {}
        logging_mode = cfg.get('logging', 'NONE')
        if logging_mode == 'NONE' or not logging_mode:
            self.results['ecsClusterExecuteCommandEncryption'] = [
                0, "ECS Exec logging not enabled — encryption check N/A"
            ]
            return
        kms = cfg.get('kmsKeyId')
        if kms:
            self.results['ecsClusterExecuteCommandEncryption'] = [
                1, f"ECS Exec sessions use CMK: {kms}"
            ]
        else:
            self.results['ecsClusterExecuteCommandEncryption'] = [
                -1, "ECS Exec logging enabled without customer-managed KMS key"
            ]

    # ------------------------------------------------------------------ #
    # #4 ecsClusterManagedStorageEncryption
    # ------------------------------------------------------------------ #
    def _checkEcsClusterManagedStorageEncryption(self):
        cfg = (self.cluster.get('configuration') or {}).get('managedStorageConfiguration') or {}
        fargate_kms = cfg.get('fargateEphemeralStorageKmsKeyId')
        ebs_kms = cfg.get('kmsKeyId')
        if fargate_kms or ebs_kms:
            parts = []
            if fargate_kms:
                parts.append(f"fargateEphemeralStorage KMS: {fargate_kms}")
            if ebs_kms:
                parts.append(f"managed EBS KMS: {ebs_kms}")
            self.results['ecsClusterManagedStorageEncryption'] = [1, "; ".join(parts)]
        else:
            self.results['ecsClusterManagedStorageEncryption'] = [
                -1, "No CMK for Fargate ephemeral storage or managed EBS volumes"
            ]

    # ------------------------------------------------------------------ #
    # #5 ecsClusterDefaultCapacityProviderStrategy
    # ------------------------------------------------------------------ #
    def _checkEcsClusterDefaultCapacityProviderStrategy(self):
        default_strategy = self.cluster.get('defaultCapacityProviderStrategy') or []
        capacity_providers = self.cluster.get('capacityProviders') or []
        if not default_strategy and not capacity_providers:
            self.results['ecsClusterDefaultCapacityProviderStrategy'] = [
                -1, "No default capacity-provider strategy and no capacity providers registered"
            ]
        elif not default_strategy:
            # Providers registered but no default strategy — informational.
            self.results['ecsClusterDefaultCapacityProviderStrategy'] = [
                0, f"Capacity providers registered ({', '.join(capacity_providers)}) but no default strategy"
            ]
        else:
            names = [d.get('capacityProvider', '?') for d in default_strategy]
            self.results['ecsClusterDefaultCapacityProviderStrategy'] = [
                1, f"Default strategy: {', '.join(names)}"
            ]

    # ------------------------------------------------------------------ #
    # #6 ecsClusterNoRunningTasks
    # ------------------------------------------------------------------ #
    def _checkEcsClusterNoRunningTasks(self):
        running = self.cluster.get('runningTasksCount', 0)
        active_services = self.cluster.get('activeServicesCount', 0)
        if active_services > 0 and running == 0:
            self.results['ecsClusterNoRunningTasks'] = [
                -1,
                f"{active_services} active service(s) but 0 running tasks"
            ]
        else:
            self.results['ecsClusterNoRunningTasks'] = [
                1,
                f"activeServicesCount={active_services}, runningTasksCount={running}"
            ]

    # ------------------------------------------------------------------ #
    # #7 ecsClusterTagging
    # ------------------------------------------------------------------ #
    def _checkEcsClusterTagging(self):
        tags = self.cluster.get('tags') or []
        if not tags:
            self.results['ecsClusterTagging'] = [-1, "No tags applied"]
        else:
            keys = [t.get('key', '') for t in tags if t.get('key')]
            self.results['ecsClusterTagging'] = [
                1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
            ]

    # ------------------------------------------------------------------ #
    # #36 ecsClusterServiceConnectDefaults (Tier 2)
    # ------------------------------------------------------------------ #
    def _checkEcsClusterServiceConnectDefaults(self):
        # Only meaningful when the cluster hosts multiple services
        if len(self.services) < 2:
            self.results['ecsClusterServiceConnectDefaults'] = [
                0, f"Cluster has {len(self.services)} service(s) — Service Connect defaults not required"
            ]
            return
        sc = self.cluster.get('serviceConnectDefaults') or {}
        ns = sc.get('namespace')
        if ns:
            self.results['ecsClusterServiceConnectDefaults'] = [
                1, f"Service Connect namespace: {ns}"
            ]
        else:
            self.results['ecsClusterServiceConnectDefaults'] = [
                -1,
                f"{len(self.services)} services but no serviceConnectDefaults.namespace"
            ]

    # ------------------------------------------------------------------ #
    # #43 ecsContainerAgentOutdated (WAFS2027 SEC06-BP01)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parseVersion(v):
        m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)', str(v or '').strip())
        return tuple(int(x) for x in m.groups()) if m else None

    def _checkEcsContainerAgentOutdated(self):
        key = 'ecsContainerAgentOutdated'
        arn = self.cluster.get('clusterArn')
        if not arn or self.ecsClient is None:
            self.results[key] = [0, "Unable to evaluate (no cluster ARN / ECS client)"]
            return
        try:
            ciArns = []
            for page in self.ecsClient.get_paginator('list_container_instances').paginate(cluster=arn):
                ciArns.extend(page.get('containerInstanceArns', []) or [])
            instances = []
            for i in range(0, len(ciArns), 100):
                resp = self.ecsClient.describe_container_instances(cluster=arn, containerInstances=ciArns[i:i+100])
                instances.extend(resp.get('containerInstances', []) or [])
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response.get('Error', {}).get('Code', 'Unknown')})"]
            return

        instances = [c for c in instances if c.get('status') in self.EVALUATED_INSTANCE_STATUSES]
        if not instances:
            self.results[key] = [0, "No EC2/external container instances registered (Fargate-only or empty)"]
            return

        latestStr, latestErr = self.latestAgent
        latest = self._parseVersion(latestStr)
        failed, outdated, unknown = [], [], 0
        for c in instances:
            ident = c.get('ec2InstanceId') or c.get('containerInstanceArn', '?').rsplit('/', 1)[-1]
            if c.get('agentUpdateStatus') == 'FAILED':
                failed.append(ident)
            ver = (c.get('versionInfo') or {}).get('agentVersion')
            cur = self._parseVersion(ver)
            if cur is None:
                unknown += 1
                continue
            if latest and (cur[0] < latest[0] or
                           (cur[0] == latest[0] and latest[1] - cur[1] > self.AGENT_MINOR_LAG_TOLERANCE)):
                outdated.append(f"{ident} ({ver})")

        if failed or outdated:
            parts = []
            if outdated:
                parts.append(f"{len(outdated)} instance(s) run agent more than {self.AGENT_MINOR_LAG_TOLERANCE} "
                             f"minor releases behind {latestStr}: " + ", ".join(outdated[:5]))
            if failed:
                parts.append("agentUpdateStatus=FAILED on: " + ", ".join(failed[:5]))
            self.results[key] = [-1, "; ".join(parts)]
        elif latest is None:
            self.results[key] = [0, f"Unable to evaluate ({latestErr or 'latest agent version unavailable'})"]
        elif unknown:
            self.results[key] = [0, f"Unable to evaluate (agentVersion missing on {unknown} instance(s))"]
        else:
            self.results[key] = [1, f"All {len(instances)} container instance(s) within "
                                    f"{self.AGENT_MINOR_LAG_TOLERANCE} minor releases of agent {latestStr}"]

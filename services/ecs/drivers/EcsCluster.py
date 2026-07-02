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

    def __init__(self, cluster, cluster_services):
        super().__init__()
        self.cluster = cluster or {}
        self.services = cluster_services or []

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

import botocore

from services.Evaluator import Evaluator


class EcsService(Evaluator):
    """
    Service-level ECS checks (15 total: 12 Tier 1 + 3 Tier 2, incl. task-set check).

    Input:
      service              -- describe_services entry (with _cluster, _taskSets injected)
      cluster              -- parent cluster dict
      task_def_by_family   -- {family: taskDefinition dict}  (latest ACTIVE revision)
      scalable_targets     -- {resourceId: target dict}  (ecs scalable targets in region)
      latest_revisions     -- {family: latest ACTIVE revision number}
      elbv2Client          -- lazy elbv2 client (may be None if init failed)
    """

    # Check IDs from spec
    #  8  ecsServicePublicIpDisabled
    #  9  ecsServiceDeploymentCircuitBreakerEnabled
    # 10  ecsServiceDeploymentCircuitBreakerRollback
    # 11  ecsServiceFargateLatestPlatformVersion
    # 12  ecsServiceAutoScalingConfigured
    # 13  ecsServiceDesiredCountZero
    # 14  ecsServiceLoadBalancerHealthCheck
    # 15  ecsServiceEBSVolumeEncryption
    # 16  ecsServiceMinimumHealthyPercent
    # 17  ecsServiceNetworkModeAwsvpc
    # 18  ecsTaskSetPublicIpDisabled
    # 19  ecsServicePropagateTags
    # 37  ecsServiceCapacityProviderFargateSpot (T2)
    # 38  ecsServiceServiceDiscoveryConfigured (T2)
    # 39  ecsServiceStaleTaskDefinition (T2)

    # Fargate platform versions considered "current"
    CURRENT_PLATFORM_VERSIONS = {'LATEST', '1.4.0'}

    # Stale revisions threshold
    STALE_REVISION_LAG = 5

    def __init__(self, service, cluster, task_def_by_family,
                 scalable_targets, latest_revisions, elbv2Client):
        super().__init__()
        self.service = service or {}
        self.cluster = cluster or {}
        self.td_by_family = task_def_by_family or {}
        self.scalable_targets = scalable_targets or {}
        self.latest_revisions = latest_revisions or {}
        self.elbv2Client = elbv2Client

        sname = self.service.get('serviceName', 'unknown')
        cname = self.cluster.get('clusterName', 'unknown')
        self._resourceName = f"Service::{cname}/{sname}"

        self.addII('serviceName', sname)
        self.addII('serviceArn', self.service.get('serviceArn', 'N/A'))
        self.addII('clusterName', cname)
        self.addII('launchType', self.service.get('launchType', 'N/A'))
        self.addII('platformVersion', self.service.get('platformVersion', 'N/A'))
        self.addII('desiredCount', self.service.get('desiredCount', 0))
        self.addII('runningCount', self.service.get('runningCount', 0))
        self.addII('status', self.service.get('status', 'N/A'))

        # Task definition cache lookup (family key or arn)
        self._task_def = self._resolveTaskDef()

    # ------------------------------------------------------------------ #
    # Task-definition resolution helper
    # ------------------------------------------------------------------ #
    def _resolveTaskDef(self):
        """Return the task def dict this service points at (from cache), or None."""
        td_ref = self.service.get('taskDefinition') or ''
        # taskDefinition can be ARN or family:revision or family alone
        # Extract family
        fam = None
        if 'task-definition/' in td_ref:
            fam_rev = td_ref.split('task-definition/', 1)[1]
            fam = fam_rev.split(':', 1)[0]
        elif ':' in td_ref:
            fam = td_ref.split(':', 1)[0]
        elif td_ref:
            fam = td_ref
        if not fam:
            return None
        return self.td_by_family.get(fam)

    # ------------------------------------------------------------------ #
    # #8 ecsServicePublicIpDisabled
    # ------------------------------------------------------------------ #
    def _checkEcsServicePublicIpDisabled(self):
        nc = self.service.get('networkConfiguration') or {}
        av = nc.get('awsvpcConfiguration') or {}
        if not av:
            self.results['ecsServicePublicIpDisabled'] = [
                0, "Service does not use awsvpc network configuration"
            ]
            return
        assign = av.get('assignPublicIp', 'DISABLED')
        if assign == 'ENABLED':
            self.results['ecsServicePublicIpDisabled'] = [
                -1, "assignPublicIp=ENABLED — tasks reachable from the internet"
            ]
        else:
            self.results['ecsServicePublicIpDisabled'] = [
                1, f"assignPublicIp={assign}"
            ]

    # ------------------------------------------------------------------ #
    # #9 ecsServiceDeploymentCircuitBreakerEnabled
    # ------------------------------------------------------------------ #
    def _checkEcsServiceDeploymentCircuitBreakerEnabled(self):
        cb = (self.service.get('deploymentConfiguration') or {}).get('deploymentCircuitBreaker') or {}
        if cb.get('enable'):
            self.results['ecsServiceDeploymentCircuitBreakerEnabled'] = [
                1, "Deployment circuit breaker enabled"
            ]
        else:
            self.results['ecsServiceDeploymentCircuitBreakerEnabled'] = [
                -1, "Deployment circuit breaker disabled"
            ]

    # ------------------------------------------------------------------ #
    # #10 ecsServiceDeploymentCircuitBreakerRollback
    # ------------------------------------------------------------------ #
    def _checkEcsServiceDeploymentCircuitBreakerRollback(self):
        cb = (self.service.get('deploymentConfiguration') or {}).get('deploymentCircuitBreaker') or {}
        if not cb.get('enable'):
            self.results['ecsServiceDeploymentCircuitBreakerRollback'] = [
                0, "Circuit breaker disabled — rollback flag is N/A"
            ]
            return
        if cb.get('rollback'):
            self.results['ecsServiceDeploymentCircuitBreakerRollback'] = [
                1, "Automatic rollback enabled"
            ]
        else:
            self.results['ecsServiceDeploymentCircuitBreakerRollback'] = [
                -1, "Circuit breaker enabled but rollback disabled"
            ]

    # ------------------------------------------------------------------ #
    # #11 ecsServiceFargateLatestPlatformVersion
    # ------------------------------------------------------------------ #
    def _checkEcsServiceFargateLatestPlatformVersion(self):
        launch = self.service.get('launchType')
        strategy = self.service.get('capacityProviderStrategy') or []
        is_fargate = launch == 'FARGATE' or any(
            (cp.get('capacityProvider') or '').startswith('FARGATE') for cp in strategy
        )
        if not is_fargate:
            self.results['ecsServiceFargateLatestPlatformVersion'] = [
                0, "Not a Fargate service"
            ]
            return
        pv = self.service.get('platformVersion')
        if pv is None or pv in self.CURRENT_PLATFORM_VERSIONS:
            self.results['ecsServiceFargateLatestPlatformVersion'] = [
                1, f"platformVersion={pv or 'LATEST (unset)'}"
            ]
        else:
            self.results['ecsServiceFargateLatestPlatformVersion'] = [
                -1, f"platformVersion={pv} (below current 1.4.0)"
            ]

    # ------------------------------------------------------------------ #
    # #12 ecsServiceAutoScalingConfigured
    # ------------------------------------------------------------------ #
    def _checkEcsServiceAutoScalingConfigured(self):
        # Skip DAEMON services — one task per container instance, auto-scaling N/A
        strategy = self.service.get('schedulingStrategy', 'REPLICA')
        if strategy == 'DAEMON':
            self.results['ecsServiceAutoScalingConfigured'] = [
                0, "DAEMON scheduling strategy — auto-scaling N/A"
            ]
            return
        cname = self.cluster.get('clusterName', '')
        sname = self.service.get('serviceName', '')
        resource_id = f"service/{cname}/{sname}"
        if resource_id in self.scalable_targets:
            t = self.scalable_targets[resource_id]
            self.results['ecsServiceAutoScalingConfigured'] = [
                1, f"Scalable target min={t.get('MinCapacity')} max={t.get('MaxCapacity')}"
            ]
        else:
            self.results['ecsServiceAutoScalingConfigured'] = [
                -1, "No Application Auto Scaling target registered"
            ]

    # ------------------------------------------------------------------ #
    # #13 ecsServiceDesiredCountZero
    # ------------------------------------------------------------------ #
    def _checkEcsServiceDesiredCountZero(self):
        status = self.service.get('status', '')
        desired = self.service.get('desiredCount', 0)
        if status == 'ACTIVE' and desired == 0:
            self.results['ecsServiceDesiredCountZero'] = [
                -1, "ACTIVE service with desiredCount=0"
            ]
        else:
            self.results['ecsServiceDesiredCountZero'] = [
                1, f"status={status}, desiredCount={desired}"
            ]

    # ------------------------------------------------------------------ #
    # #14 ecsServiceLoadBalancerHealthCheck
    # ------------------------------------------------------------------ #
    def _checkEcsServiceLoadBalancerHealthCheck(self):
        lbs = self.service.get('loadBalancers') or []
        if not lbs:
            self.results['ecsServiceLoadBalancerHealthCheck'] = [
                0, "Service has no load balancer attached"
            ]
            return
        tg_arns = [lb.get('targetGroupArn') for lb in lbs if lb.get('targetGroupArn')]
        if not tg_arns:
            # Classic Load Balancer path — no target-group config to inspect.
            self.results['ecsServiceLoadBalancerHealthCheck'] = [
                0, "Classic Load Balancer — target-group check N/A"
            ]
            return
        if not self.elbv2Client:
            self.results['ecsServiceLoadBalancerHealthCheck'] = [
                0, "elbv2 client unavailable"
            ]
            return
        try:
            resp = self.elbv2Client.describe_target_groups(TargetGroupArns=tg_arns)
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('AccessDenied', 'AccessDeniedException', 'TargetGroupNotFound'):
                self.results['ecsServiceLoadBalancerHealthCheck'] = [
                    0, f"elbv2:describe_target_groups failed: {code}"
                ]
                return
            self.results['ecsServiceLoadBalancerHealthCheck'] = [
                0, f"elbv2 error: {code}"
            ]
            return

        weak = []
        for tg in resp.get('TargetGroups', []) or []:
            hthresh = tg.get('HealthyThresholdCount', 0)
            path = tg.get('HealthCheckPath')
            proto = tg.get('HealthCheckProtocol')
            tg_name = tg.get('TargetGroupName', '?')
            issues = []
            if hthresh and hthresh < 2:
                issues.append(f"HealthyThresholdCount={hthresh}")
            # Absent path on HTTP/HTTPS target groups indicates default '/' which
            # is often not what the app serves — flag as weak only if protocol is
            # HTTP/HTTPS and there is no custom path.
            if proto in ('HTTP', 'HTTPS') and (not path or path == '/'):
                issues.append(f"HealthCheckPath='{path or '/'}'")
            if issues:
                weak.append(f"{tg_name}[{', '.join(issues)}]")

        if weak:
            self.results['ecsServiceLoadBalancerHealthCheck'] = [
                -1, "Weak health-check config on target group(s): " + "; ".join(weak[:5])
            ]
        else:
            self.results['ecsServiceLoadBalancerHealthCheck'] = [
                1, f"Health-check config OK on {len(resp.get('TargetGroups') or [])} target group(s)"
            ]

    # ------------------------------------------------------------------ #
    # #15 ecsServiceEBSVolumeEncryption
    # ------------------------------------------------------------------ #
    def _checkEcsServiceEBSVolumeEncryption(self):
        vc = self.service.get('volumeConfigurations') or []
        if not vc:
            self.results['ecsServiceEBSVolumeEncryption'] = [
                0, "Service does not attach managed EBS volumes"
            ]
            return
        unencrypted = []
        for v in vc:
            mev = v.get('managedEBSVolume') or {}
            if not mev.get('encrypted'):
                unencrypted.append(v.get('name', '?'))
        if unencrypted:
            self.results['ecsServiceEBSVolumeEncryption'] = [
                -1, f"Unencrypted managed EBS volume(s): {', '.join(unencrypted[:5])}"
            ]
        else:
            self.results['ecsServiceEBSVolumeEncryption'] = [
                1, f"All {len(vc)} managed EBS volume(s) encrypted"
            ]

    # ------------------------------------------------------------------ #
    # #16 ecsServiceMinimumHealthyPercent
    # ------------------------------------------------------------------ #
    def _checkEcsServiceMinimumHealthyPercent(self):
        strategy = self.service.get('schedulingStrategy', 'REPLICA')
        if strategy != 'REPLICA':
            self.results['ecsServiceMinimumHealthyPercent'] = [
                0, f"schedulingStrategy={strategy} — check N/A"
            ]
            return
        dc = self.service.get('deploymentConfiguration') or {}
        mhp = dc.get('minimumHealthyPercent')
        if mhp == 0:
            self.results['ecsServiceMinimumHealthyPercent'] = [
                -1, "minimumHealthyPercent=0 — full outage possible during deploy"
            ]
        elif mhp is None:
            self.results['ecsServiceMinimumHealthyPercent'] = [
                0, "minimumHealthyPercent not set (default applied)"
            ]
        else:
            self.results['ecsServiceMinimumHealthyPercent'] = [
                1, f"minimumHealthyPercent={mhp}"
            ]

    # ------------------------------------------------------------------ #
    # #17 ecsServiceNetworkModeAwsvpc (cross-reference into task def)
    # ------------------------------------------------------------------ #
    def _checkEcsServiceNetworkModeAwsvpc(self):
        td = self._task_def
        if td is None:
            self.results['ecsServiceNetworkModeAwsvpc'] = [
                0, f"Task definition not found in cache: {self.service.get('taskDefinition')}"
            ]
            return
        network_mode = td.get('networkMode') or 'bridge'
        if network_mode == 'awsvpc':
            self.results['ecsServiceNetworkModeAwsvpc'] = [
                1, "Task definition uses awsvpc network mode"
            ]
        else:
            self.results['ecsServiceNetworkModeAwsvpc'] = [
                -1, f"Task definition networkMode={network_mode} (expected awsvpc)"
            ]

    # ------------------------------------------------------------------ #
    # #18 ecsTaskSetPublicIpDisabled
    # ------------------------------------------------------------------ #
    def _checkEcsTaskSetPublicIpDisabled(self):
        task_sets = self.service.get('_taskSets') or []
        if not task_sets:
            self.results['ecsTaskSetPublicIpDisabled'] = [
                0, "Service has no task sets (not EXTERNAL deployment controller)"
            ]
            return
        offenders = []
        for ts in task_sets:
            nc = ts.get('networkConfiguration') or {}
            av = nc.get('awsvpcConfiguration') or {}
            if av.get('assignPublicIp') == 'ENABLED':
                offenders.append(ts.get('id') or ts.get('taskSetArn', '?'))
        if offenders:
            self.results['ecsTaskSetPublicIpDisabled'] = [
                -1, f"Task set(s) with public IP: {', '.join(offenders[:5])}"
            ]
        else:
            self.results['ecsTaskSetPublicIpDisabled'] = [
                1, f"All {len(task_sets)} task set(s) have assignPublicIp disabled"
            ]

    # ------------------------------------------------------------------ #
    # #19 ecsServicePropagateTags
    # ------------------------------------------------------------------ #
    def _checkEcsServicePropagateTags(self):
        propagate = self.service.get('propagateTags')
        if propagate in ('SERVICE', 'TASK_DEFINITION'):
            self.results['ecsServicePropagateTags'] = [
                1, f"propagateTags={propagate}"
            ]
        else:
            self.results['ecsServicePropagateTags'] = [
                -1, f"propagateTags={propagate or 'NONE'} — tasks will not inherit tags"
            ]

    # ------------------------------------------------------------------ #
    # #37 ecsServiceCapacityProviderFargateSpot (Tier 2)
    # ------------------------------------------------------------------ #
    def _checkEcsServiceCapacityProviderFargateSpot(self):
        launch = self.service.get('launchType')
        strategy = self.service.get('capacityProviderStrategy') or []
        if launch != 'FARGATE' and not any(
            (cp.get('capacityProvider') or '').startswith('FARGATE') for cp in strategy
        ):
            self.results['ecsServiceCapacityProviderFargateSpot'] = [
                0, "Not a Fargate service"
            ]
            return
        providers = {cp.get('capacityProvider') for cp in strategy}
        if launch == 'FARGATE' and not strategy:
            # Pure FARGATE launch type, no explicit strategy — never uses SPOT
            self.results['ecsServiceCapacityProviderFargateSpot'] = [
                -1, "launchType=FARGATE with no FARGATE_SPOT in capacity-provider strategy"
            ]
            return
        if 'FARGATE_SPOT' in providers:
            self.results['ecsServiceCapacityProviderFargateSpot'] = [
                1, f"Strategy uses FARGATE_SPOT: {sorted(p for p in providers if p)}"
            ]
        else:
            self.results['ecsServiceCapacityProviderFargateSpot'] = [
                -1, f"Fargate service with no FARGATE_SPOT: {sorted(p for p in providers if p)}"
            ]

    # ------------------------------------------------------------------ #
    # #38 ecsServiceServiceDiscoveryConfigured (Tier 2)
    # ------------------------------------------------------------------ #
    def _checkEcsServiceServiceDiscoveryConfigured(self):
        registries = self.service.get('serviceRegistries') or []
        lbs = self.service.get('loadBalancers') or []
        sc = self.service.get('serviceConnectConfiguration') or {}
        sc_enabled = bool(sc.get('enabled'))
        if registries or lbs or sc_enabled:
            parts = []
            if registries:
                parts.append(f"{len(registries)} service registr(y|ies)")
            if lbs:
                parts.append(f"{len(lbs)} load balancer(s)")
            if sc_enabled:
                parts.append("Service Connect enabled")
            self.results['ecsServiceServiceDiscoveryConfigured'] = [
                1, "; ".join(parts)
            ]
        else:
            self.results['ecsServiceServiceDiscoveryConfigured'] = [
                -1, "No load balancer, Cloud Map registry, or Service Connect namespace"
            ]

    # ------------------------------------------------------------------ #
    # #39 ecsServiceStaleTaskDefinition (Tier 2)
    # ------------------------------------------------------------------ #
    def _checkEcsServiceStaleTaskDefinition(self):
        td_ref = self.service.get('taskDefinition') or ''
        try:
            fam, rev_str = td_ref.split('task-definition/', 1)[1].split(':', 1) if 'task-definition/' in td_ref \
                           else td_ref.rsplit(':', 1)
            current_rev = int(rev_str)
        except (ValueError, IndexError):
            self.results['ecsServiceStaleTaskDefinition'] = [
                0, f"Could not parse task-definition revision from {td_ref}"
            ]
            return
        latest = self.latest_revisions.get(fam)
        if latest is None:
            self.results['ecsServiceStaleTaskDefinition'] = [
                0, f"No latest revision cached for family {fam}"
            ]
            return
        lag = latest - current_rev
        if lag > self.STALE_REVISION_LAG:
            self.results['ecsServiceStaleTaskDefinition'] = [
                -1,
                f"Service uses {fam}:{current_rev}, {lag} revisions behind latest {fam}:{latest}"
            ]
        else:
            self.results['ecsServiceStaleTaskDefinition'] = [
                1,
                f"Service on {fam}:{current_rev} (latest {fam}:{latest}, lag={lag})"
            ]

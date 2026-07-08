# Amazon ECS — Comprehensive Check Research for service-screener-v2

## Summary

**Total checks identified: 42** (across 5 resource levels)
- Cluster-level: 7
- Service-level: 12
- Task Definition-level: 16
- ECR (supporting): 3
- Cross-cutting (Operational/Cost): 4

**Boto3 clients required:** `ecs`, `application-autoscaling`, `servicediscovery`, `elbv2`, `logs`, `ecr`

---

## Tier 1 — MUST-HAVE (26 checks)

These map to Security Hub controls, AWS Config rules, or represent clear security/reliability risks that are unambiguous to check programmatically.

---

### CLUSTER-LEVEL CHECKS (describe_clusters with include=['SETTINGS','CONFIGURATIONS','TAGS'])

| # | Check Name | API Calls | FAIL Condition | Sev | Pillar | Notes |
|---|-----------|-----------|----------------|-----|--------|-------|
| 1 | `ecsClusterContainerInsightsEnabled` | `ecs:DescribeClusters` (include=SETTINGS) | `settings` array does not contain `{name: 'containerInsights', value: 'enabled'}` or is missing entirely | M | O | **Security Hub ECS.12**, AWS Config `ecs-container-insights-enabled`. Essential for monitoring. |
| 2 | `ecsClusterExecuteCommandLogging` | `ecs:DescribeClusters` (include=CONFIGURATIONS) | `configuration.executeCommandConfiguration.logging` == `'NONE'` or missing when execute command is used by any service | M | S | ECS Exec without audit logs = untracked shell access to containers. Check if `logging` is `NONE` when any service has `enableExecuteCommand: true`. |
| 3 | `ecsClusterExecuteCommandEncryption` | `ecs:DescribeClusters` (include=CONFIGURATIONS) | `configuration.executeCommandConfiguration.kmsKeyId` is null/empty when execute command logging is enabled | L | S | KMS encryption for exec command sessions. Nice-to-have, not critical since sessions are already TLS-encrypted. |
| 4 | `ecsClusterManagedStorageEncryption` | `ecs:DescribeClusters` (include=CONFIGURATIONS) | `configuration.managedStorageConfiguration.fargateEphemeralStorageKmsKeyId` is null AND `configuration.managedStorageConfiguration.kmsKeyId` is null | M | S | Customer-managed KMS keys for Fargate ephemeral storage and EBS-backed tasks. Without this, uses AWS-managed keys (which is still encrypted, but no customer control). |
| 5 | `ecsClusterDefaultCapacityProviderStrategy` | `ecs:DescribeClusters` | `defaultCapacityProviderStrategy` is empty list AND `capacityProviders` is empty | M | R | No capacity provider strategy means tasks won't be automatically spread across providers. Required for Fargate Spot usage and proper scaling. |
| 6 | `ecsClusterNoRunningTasks` | `ecs:DescribeClusters` (include=STATISTICS) | `runningTasksCount` == 0 AND `activeServicesCount` > 0 | L | O | Cluster with services but no tasks running indicates a problem. |
| 7 | `ecsClusterTagging` | `ecs:DescribeClusters` (include=TAGS) | `tags` is empty or null | L | O | No tags = no cost allocation, no governance. Standard operational hygiene check. |

---

### SERVICE-LEVEL CHECKS (list_services + describe_services with include=['TAGS'])

| # | Check Name | API Calls | FAIL Condition | Sev | Pillar | Notes |
|---|-----------|-----------|----------------|-----|--------|-------|
| 8 | `ecsServicePublicIpDisabled` | `ecs:DescribeServices` | `networkConfiguration.awsvpcConfiguration.assignPublicIp` == `'ENABLED'` | H | S | **Security Hub ECS.2**. Fargate tasks with public IPs are directly exposed to the internet. Should use NAT Gateway or VPC endpoints. |
| 9 | `ecsServiceDeploymentCircuitBreakerEnabled` | `ecs:DescribeServices` | `deploymentConfiguration.deploymentCircuitBreaker.enable` is `false` or missing | M | R | Without circuit breaker, a bad deployment rolls forward indefinitely, consuming resources and causing extended outages. |
| 10 | `ecsServiceDeploymentCircuitBreakerRollback` | `ecs:DescribeServices` | Circuit breaker enabled but `deploymentConfiguration.deploymentCircuitBreaker.rollback` is `false` | L | R | Circuit breaker without automatic rollback still stops the bad deployment but requires manual intervention to restore. |
| 11 | `ecsServiceFargateLatestPlatformVersion` | `ecs:DescribeServices` | `launchType` == `'FARGATE'` AND `platformVersion` is not `'LATEST'` AND resolves to a version below current (1.4.0 for Linux) | H | S | **Security Hub ECS.10**, AWS Config `ecs-fargate-latest-platform-version`. Older platform versions miss security patches. Platform version 1.3.0 retiring June 2026. |
| 12 | `ecsServiceAutoScalingConfigured` | `application-autoscaling:DescribeScalableTargets` (ServiceNamespace='ecs') | No scalable target registered for the service (`service/{cluster}/{service}`) | M | R | Services without auto-scaling can't respond to traffic spikes or scale down during low traffic. |
| 13 | `ecsServiceDesiredCountZero` | `ecs:DescribeServices` | `desiredCount` == 0 AND `status` == 'ACTIVE' | L | O | Active service with 0 desired tasks — either intentionally scaled down or misconfigured. Informational. |
| 14 | `ecsServiceLoadBalancerHealthCheck` | `ecs:DescribeServices` + `elbv2:DescribeTargetGroups` | Service has `loadBalancers` configured but target group health check has overly permissive settings (e.g., `healthyThresholdCount` < 2 or no custom path) | L | R | Weak health checks can mark unhealthy containers as healthy. |
| 15 | `ecsServiceEBSVolumeEncryption` | `ecs:DescribeServices` | `volumeConfigurations[].managedEBSVolume.encrypted` is `false` or missing | H | S | Unencrypted EBS volumes attached to ECS tasks expose data at rest. |
| 16 | `ecsServiceMinimumHealthyPercent` | `ecs:DescribeServices` | `deploymentConfiguration.minimumHealthyPercent` == 0 for REPLICA scheduling strategy | M | R | Setting minimumHealthyPercent to 0 means ALL tasks can be killed during deployment — full outage window. |
| 17 | `ecsServiceNetworkModeAwsvpc` | `ecs:DescribeServices` (+ task def lookup) | Task definition `networkMode` is `bridge` or `host` (not `awsvpc`) | M | S | **Security Hub ECS.3** relates to `host` mode. `awsvpc` provides task-level security groups and ENI isolation. `host` mode shares host network namespace. |
| 18 | `ecsTaskSetPublicIpDisabled` | `ecs:DescribeTaskSets` | Task set has `networkConfiguration.awsvpcConfiguration.assignPublicIp` == `'ENABLED'` | H | S | **Security Hub ECS.16**. Same as ECS.2 but for task sets (EXTERNAL deployment controller). |
| 19 | `ecsServicePropagateTags` | `ecs:DescribeServices` | `propagateTags` is `'NONE'` or missing | L | O | Without tag propagation, individual tasks lack tags needed for cost allocation and governance. |

---

### TASK DEFINITION-LEVEL CHECKS (list_task_definition_families + describe_task_definition)

| # | Check Name | API Calls | FAIL Condition | Sev | Pillar | Notes |
|---|-----------|-----------|----------------|-----|--------|-------|
| 20 | `ecsTaskDefinitionNonRootUser` | `ecs:DescribeTaskDefinition` | Any container has `user` field empty/null or set to `'root'` or `'0'` | H | S | **Security Hub ECS.1**. Running as root inside containers amplifies escape vulnerabilities. |
| 21 | `ecsTaskDefinitionNoPrivilegedContainers` | `ecs:DescribeTaskDefinition` | Any container has `privileged: true` | H | S | **Security Hub ECS.4**, AWS Config `ecs-containers-nonprivileged`. Privileged containers have full host access — container escape is trivial. EC2 launch type only (Fargate blocks this). |
| 22 | `ecsTaskDefinitionReadonlyRootFilesystem` | `ecs:DescribeTaskDefinition` | Any container has `readonlyRootFilesystem: false` or missing (defaults to false) | H | S | **Security Hub ECS.5**, AWS Config `ecs-containers-readonly-access`. Writable root FS allows malware persistence, binary replacement, config tampering. |
| 23 | `ecsTaskDefinitionLoggingConfigured` | `ecs:DescribeTaskDefinition` | Any container has `logConfiguration` null or missing | H | O | **Security Hub ECS.9**, AWS Config `ecs-task-definition-log-configuration`. Without logging, incidents are uninvestigable. |
| 24 | `ecsTaskDefinitionNoSecretsInEnvVars` | `ecs:DescribeTaskDefinition` | Any container `environment` array has values matching secret patterns (AWS_SECRET_ACCESS_KEY, PASSWORD, API_KEY, TOKEN, etc.) | H | S | **Security Hub ECS.8**. Plaintext secrets in env vars are exposed via task metadata endpoint, describe-tasks API, console, CloudTrail. |
| 25 | `ecsTaskDefinitionHostNetworkModeUser` | `ecs:DescribeTaskDefinition` | `networkMode` == `'host'` AND any container has (`privileged` != true AND (`user` is null/empty OR `user` == 'root')) | H | S | **Security Hub ECS.3**, AWS Config `ecs-task-definition-user-for-host-mode-check`. Host network mode with root user = full host network access without restriction. |
| 26 | `ecsTaskDefinitionSeparateTaskAndExecutionRoles` | `ecs:DescribeTaskDefinition` | `taskRoleArn` == `executionRoleArn` (same role for both) OR `taskRoleArn` is null (no task role, meaning containers have no AWS API access control) | M | S | Execution role pulls images & sends logs; task role is what the app uses. Same role = over-privileged. Null task role means the execution role permissions leak to containers. |
| 27 | `ecsTaskDefinitionHealthCheckDefined` | `ecs:DescribeTaskDefinition` | All containers lack a `healthCheck` block (no command/interval/timeout defined) | M | R | Without container-level health checks, ECS relies only on process exit codes. Unhealthy but running containers continue serving traffic. |
| 28 | `ecsTaskDefinitionResourceLimits` | `ecs:DescribeTaskDefinition` | Task-level `cpu` or `memory` not defined (for Fargate these are required, but for EC2 launch type they're optional and often missing) | M | P | Without resource limits (EC2 launch type), a single container can starve others. For Fargate, check that values are reasonable vs. assigned. |
| 29 | `ecsTaskDefinitionNoHostPidMode` | `ecs:DescribeTaskDefinition` | `pidMode` == `'host'` | H | S | Host PID namespace sharing lets containers see and signal all host processes — container escape vector. |
| 30 | `ecsTaskDefinitionNoHostIpcMode` | `ecs:DescribeTaskDefinition` | `ipcMode` == `'host'` | H | S | Host IPC namespace sharing enables shared memory attacks between container and host. |
| 31 | `ecsTaskDefinitionLinuxCapabilities` | `ecs:DescribeTaskDefinition` | Any container's `linuxParameters.capabilities.add` includes dangerous capabilities: `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_RAWIO`, `DAC_OVERRIDE`, `NET_RAW` | M | S | Added Linux capabilities expand attack surface. `SYS_ADMIN` is nearly equivalent to privileged mode. |
| 32 | `ecsTaskDefinitionNoLatestTag` | `ecs:DescribeTaskDefinition` | Any container `image` field contains `:latest` tag or has no tag specified (implicit latest) | M | R | `:latest` tag is mutable — deployments are non-reproducible, debugging is impossible, and supply chain attacks easier. |
| 33 | `ecsTaskDefinitionEcrImageSource` | `ecs:DescribeTaskDefinition` | Any container `image` does NOT reference an ECR registry (not matching `*.dkr.ecr.*.amazonaws.com/*`) | L | S | Public registries (Docker Hub, quay.io) have no organizational control — supply chain risk. ECR provides scanning, IAM-controlled access, and image immutability. |
| 34 | `ecsTaskDefinitionLogDriverAwslogs` | `ecs:DescribeTaskDefinition` | Container has `logConfiguration` but `logDriver` is not `'awslogs'` and is not a supported secure driver (`awsfirelens`, `splunk`) | L | O | Some log drivers (e.g., `json-file`, `syslog`) may lose logs if the host is terminated. `awslogs` (CloudWatch) ensures log durability. |
| 35 | `ecsTaskDefinitionSecretReferences` | `ecs:DescribeTaskDefinition` | Container uses `secrets` array with `valueFrom` pointing to non-existent Secrets Manager/SSM parameters (validation via describing the referenced secrets) | L | R | Broken secret references cause task launch failures. Detected via `secretsmanager:DescribeSecret` or `ssm:GetParameter`. |

---

## Tier 2 — NICE-TO-HAVE (16 checks)

These are valuable but either lower severity, more opinionated, or require additional API calls that add complexity.

---

### CLUSTER-LEVEL (additional)

| # | Check Name | API Calls | FAIL Condition | Sev | Pillar | Notes |
|---|-----------|-----------|----------------|-----|--------|-------|
| 36 | `ecsClusterServiceConnectDefaults` | `ecs:DescribeClusters` | `serviceConnectDefaults` is null (no default namespace) AND cluster has multiple services | L | O | Service Connect defaults reduce boilerplate. Not a security issue. |

---

### SERVICE-LEVEL (additional)

| # | Check Name | API Calls | FAIL Condition | Sev | Pillar | Notes |
|---|-----------|-----------|----------------|-----|--------|-------|
| 37 | `ecsServiceCapacityProviderFargateSpot` | `ecs:DescribeServices` | Service uses only `FARGATE` capacity provider with no `FARGATE_SPOT` in strategy | L | C | Fargate Spot can save up to 70% for fault-tolerant workloads. Informational/cost advisory. |
| 38 | `ecsServiceServiceDiscoveryConfigured` | `ecs:DescribeServices` + `servicediscovery:ListNamespaces` | Service has empty `serviceRegistries` AND no Service Connect AND no load balancer (orphan service with no discoverability) | L | R | Services with no discovery mechanism are unreachable by other services. |
| 39 | `ecsServiceStaleTaskDefinition` | `ecs:DescribeServices` + `ecs:ListTaskDefinitions` | Service references a task definition revision that is > 5 revisions behind the latest ACTIVE revision in the same family | L | O | Running very old task definitions may indicate forgotten services or missed security patches. |

---

### TASK DEFINITION-LEVEL (additional)

| # | Check Name | API Calls | FAIL Condition | Sev | Pillar | Notes |
|---|-----------|-----------|----------------|-----|--------|-------|
| 40 | `ecsTaskDefinitionSensitiveHostPaths` | `ecs:DescribeTaskDefinition` | `volumes[].host.sourcePath` contains sensitive paths: `/`, `/etc`, `/proc`, `/sys`, `/var/run/docker.sock`, `/root` | M | S | Bind-mounting sensitive host paths into containers provides escape routes. EC2 launch type only. |
| 41 | `ecsTaskDefinitionUlimitsConfigured` | `ecs:DescribeTaskDefinition` | Container defines `ulimits` with `nofile` hardLimit > 65536 or `nproc` hardLimit > 4096 (excessively permissive) | L | P | Overly generous ulimits can amplify resource exhaustion attacks. Most environments don't need > 65536 file descriptors. |
| 42 | `ecsTaskDefinitionEphemeralStorageEncryption` | `ecs:DescribeTaskDefinition` | `ephemeralStorage.sizeInGiB` > 20 (default) but cluster-level `fargateEphemeralStorageKmsKeyId` is not set | M | S | Enlarged ephemeral storage (>20 GiB) for Fargate tasks should be encrypted with CMK for sensitive workloads. Requires cross-referencing cluster config. |

---

### ECR CHECKS (supporting — images referenced in task definitions)

| # | Check Name | API Calls | FAIL Condition | Sev | Pillar | Notes |
|---|-----------|-----------|----------------|-----|--------|-------|
| 43 | `ecsEcrImageTagImmutability` | `ecr:DescribeRepositories` | `imageTagMutability` == `'MUTABLE'` for repositories referenced in active task definitions | M | S | Mutable tags allow image replacement after deployment — supply chain risk. An attacker who compromises push access can silently replace tagged images. |
| 44 | `ecsEcrImageScanOnPush` | `ecr:DescribeRepositories` | `imageScanningConfiguration.scanOnPush` == `false` | M | S | Without scan-on-push, vulnerabilities in pushed images go undetected until manual scan. |
| 45 | `ecsEcrRepositoryLifecyclePolicy` | `ecr:GetLifecyclePolicy` | No lifecycle policy configured (raises `LifecyclePolicyNotFoundException`) | L | C | Without lifecycle policies, repositories grow unbounded — storage cost and clutter. |

---

## Detailed Implementation Notes

### API Call Strategy

```python
# Cluster enumeration
clusters = ecs.list_clusters()['clusterArns']
cluster_details = ecs.describe_clusters(
    clusters=clusters,
    include=['SETTINGS', 'CONFIGURATIONS', 'STATISTICS', 'TAGS', 'ATTACHMENTS']
)

# Service enumeration (per cluster, paginated)
service_arns = ecs.list_services(cluster=cluster_arn, maxResults=100)
service_details = ecs.describe_services(
    cluster=cluster_arn,
    services=service_arns[:10],  # max 10 per call
    include=['TAGS']
)

# Task definition enumeration (only ACTIVE, latest revision per family)
families = ecs.list_task_definition_families(status='ACTIVE')
for family in families:
    td = ecs.describe_task_definition(taskDefinition=family, include=['TAGS'])

# Auto-scaling check
targets = autoscaling.describe_scalable_targets(
    ServiceNamespace='ecs'
)

# ECR repos (for referenced images)
repos = ecr.describe_repositories()
```

### Key API Response Structures

#### describe_clusters (with SETTINGS + CONFIGURATIONS)
```json
{
  "settings": [{"name": "containerInsights", "value": "enabled|disabled"}],
  "configuration": {
    "executeCommandConfiguration": {
      "kmsKeyId": "arn:aws:kms:...",
      "logging": "NONE|DEFAULT|OVERRIDE",
      "logConfiguration": {
        "cloudWatchLogGroupName": "/ecs/exec/...",
        "cloudWatchEncryptionEnabled": true,
        "s3BucketName": "...",
        "s3EncryptionEnabled": true
      }
    },
    "managedStorageConfiguration": {
      "fargateEphemeralStorageKmsKeyId": "arn:aws:kms:...",
      "kmsKeyId": "arn:aws:kms:..."
    }
  },
  "capacityProviders": ["FARGATE", "FARGATE_SPOT"],
  "defaultCapacityProviderStrategy": [{"capacityProvider": "FARGATE", "weight": 1, "base": 1}],
  "serviceConnectDefaults": {"namespace": "arn:aws:servicediscovery:..."}
}
```

#### describe_services
```json
{
  "networkConfiguration": {
    "awsvpcConfiguration": {
      "assignPublicIp": "ENABLED|DISABLED",
      "subnets": [...],
      "securityGroups": [...]
    }
  },
  "deploymentConfiguration": {
    "deploymentCircuitBreaker": {"enable": true, "rollback": true},
    "maximumPercent": 200,
    "minimumHealthyPercent": 100,
    "alarms": {"alarmNames": [...], "enable": true, "rollback": true}
  },
  "launchType": "FARGATE|EC2",
  "platformVersion": "LATEST|1.4.0|1.3.0",
  "loadBalancers": [{"targetGroupArn": "...", "containerName": "...", "containerPort": 80}],
  "serviceRegistries": [{"registryArn": "..."}],
  "desiredCount": 2,
  "enableExecuteCommand": true,
  "propagateTags": "NONE|TASK_DEFINITION|SERVICE",
  "volumeConfigurations": [{"managedEBSVolume": {"encrypted": true, "kmsKeyId": "..."}}]
}
```

#### describe_task_definition (containerDefinitions[])
```json
{
  "taskRoleArn": "arn:aws:iam::...:role/task-role",
  "executionRoleArn": "arn:aws:iam::...:role/execution-role",
  "networkMode": "awsvpc|bridge|host|none",
  "pidMode": "host|task",
  "ipcMode": "host|task|none",
  "ephemeralStorage": {"sizeInGiB": 20},
  "containerDefinitions": [{
    "name": "app",
    "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:v1.2.3",
    "privileged": false,
    "readonlyRootFilesystem": true,
    "user": "1000:1000",
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {"awslogs-group": "/ecs/myapp", "awslogs-region": "us-east-1"}
    },
    "environment": [{"name": "DB_HOST", "value": "db.example.com"}],
    "secrets": [{"name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:..."}],
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost/ || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3
    },
    "linuxParameters": {
      "capabilities": {"add": [], "drop": ["ALL"]},
      "initProcessEnabled": true
    },
    "ulimits": [{"name": "nofile", "softLimit": 1024, "hardLimit": 65536}]
  }],
  "volumes": [{"name": "data", "host": {"sourcePath": "/mnt/data"}}]
}
```

---

## Secret Detection Patterns (for check #24)

```python
SECRET_PATTERNS = [
    r'AWS_SECRET_ACCESS_KEY',
    r'AWS_SESSION_TOKEN', 
    r'.*PASSWORD.*',
    r'.*SECRET.*',
    r'.*API_KEY.*',
    r'.*PRIVATE_KEY.*',
    r'.*TOKEN.*',  # but exclude benign like AWS_DEFAULT_REGION
    r'.*CREDENTIALS.*',
    r'.*CONNECTION_STRING.*',
]

# Value patterns (detect actual secret values)
SECRET_VALUE_PATTERNS = [
    r'^AKIA[0-9A-Z]{16}$',  # AWS access key
    r'^[A-Za-z0-9/+=]{40}$',  # AWS secret key length
    r'^(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$',  # Base64 encoded secrets
]
```

---

## Cross-reference: Security Hub Controls Mapped

| Security Hub | Our Check | Status |
|---|---|---|
| ECS.1 (non-root user) | `ecsTaskDefinitionNonRootUser` | ✅ Tier 1 |
| ECS.2 (no public IP) | `ecsServicePublicIpDisabled` | ✅ Tier 1 |
| ECS.3 (host network mode) | `ecsTaskDefinitionHostNetworkModeUser` | ✅ Tier 1 |
| ECS.4 (privileged mode) | `ecsTaskDefinitionNoPrivilegedContainers` | ✅ Tier 1 |
| ECS.5 (read-only root FS) | `ecsTaskDefinitionReadonlyRootFilesystem` | ✅ Tier 1 |
| ECS.8 (secrets in env vars) | `ecsTaskDefinitionNoSecretsInEnvVars` | ✅ Tier 1 |
| ECS.9 (logging) | `ecsTaskDefinitionLoggingConfigured` | ✅ Tier 1 |
| ECS.10 (latest platform ver) | `ecsServiceFargateLatestPlatformVersion` | ✅ Tier 1 |
| ECS.12 (container insights) | `ecsClusterContainerInsightsEnabled` | ✅ Tier 1 |
| ECS.16 (task set public IP) | `ecsTaskSetPublicIpDisabled` | ✅ Tier 1 |

---

## Pillar Distribution

| Pillar | Count | Checks |
|--------|-------|--------|
| **Security (S)** | 22 | #2,3,4,8,11,15,17,18,20,21,22,24,25,26,29,30,31,33,40,42,43,44 |
| **Reliability (R)** | 9 | #5,9,10,12,14,16,27,35,38 |
| **Operations (O)** | 8 | #1,6,7,13,19,23,34,36 |
| **Performance (P)** | 2 | #28,41 |
| **Cost (C)** | 2 | #37,45 |

---

## Severity Distribution

| Severity | Count | 
|----------|-------|
| **HIGH** | 14 | 
| **MEDIUM** | 17 |
| **LOW** | 14 |

---

## Checks Explicitly NOT Recommended (noise / not API-checkable)

| Idea | Reason to Skip |
|------|----------------|
| Task CPU/memory right-sizing vs CloudWatch metrics | Requires CloudWatch GetMetricData over time + subjective threshold — complex, opinionated |
| Security group rules analysis | Already covered by EC2/VPC security group checks in other services |
| VPC endpoint for ECR/S3/logs | Belongs to VPC service checks, not ECS-specific |
| Task execution role overly permissive (IAM policy analysis) | Requires recursive IAM policy evaluation — belongs to IAM scanner, exponential complexity |
| Container image vulnerability scan results | Requires Inspector/ECR scan results — separate service, already exists |
| Service mesh (App Mesh) configuration | Deprecated in favor of Service Connect; too niche |
| Logging blocking mode check | Prowler has `ecs_task_definitions_logging_block_mode` — very niche edge case, only relevant if `logConfiguration.options` has `mode: blocking` in awslogs driver |

---

## Implementation Priority Recommendation

### Phase 1 (MVP — 15 checks, highest value):
1. `ecsClusterContainerInsightsEnabled` (Security Hub ECS.12)
2. `ecsServicePublicIpDisabled` (Security Hub ECS.2)
3. `ecsTaskSetPublicIpDisabled` (Security Hub ECS.16)
4. `ecsServiceFargateLatestPlatformVersion` (Security Hub ECS.10)
5. `ecsTaskDefinitionNonRootUser` (Security Hub ECS.1)
6. `ecsTaskDefinitionNoPrivilegedContainers` (Security Hub ECS.4)
7. `ecsTaskDefinitionReadonlyRootFilesystem` (Security Hub ECS.5)
8. `ecsTaskDefinitionLoggingConfigured` (Security Hub ECS.9)
9. `ecsTaskDefinitionNoSecretsInEnvVars` (Security Hub ECS.8)
10. `ecsTaskDefinitionHostNetworkModeUser` (Security Hub ECS.3)
11. `ecsServiceDeploymentCircuitBreakerEnabled` (Reliability)
12. `ecsTaskDefinitionNoHostPidMode` (Security)
13. `ecsTaskDefinitionNoHostIpcMode` (Security)
14. `ecsServiceEBSVolumeEncryption` (Security)
15. `ecsClusterManagedStorageEncryption` (Security)

### Phase 2 (Complete — remaining 30 checks):
All remaining Tier 1 + Tier 2 checks.

---

## Notes on Platform Version Checking

The current LATEST platform versions:
- **Linux**: 1.4.0 (current revision varies)
- **Windows**: 1.0.0

When `platformVersion` == `'LATEST'`, ECS automatically uses the latest. The check should PASS for:
- `platformVersion` is `'LATEST'` (string literal)
- `platformVersion` is `'1.4.0'` (explicit current version, Linux)
- `platformVersion` is null (defaults to LATEST for new services)

FAIL for:
- `platformVersion` is `'1.3.0'` (retiring June 2026)
- `platformVersion` is `'1.2.0'` or `'1.1.0'` or `'1.0.0'` (very old)

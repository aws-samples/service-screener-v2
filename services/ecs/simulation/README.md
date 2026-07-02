# ECS Service Screener Simulation

Scripts to spin up an intentionally-misconfigured Amazon ECS cluster, task
definition, and service that exercise the majority of the 42 checks in the
`ecs` service.

## Files

| File | Purpose |
|---|---|
| `create_test_resources.sh` | Provisions the misconfigured ECS resources. |
| `cleanup_test_resources.sh` | Tears down everything using the manifest emitted by the create script. |

## What gets created

- **IAM role** with an inline `Action:*/Resource:*` policy. Reused as both the
  execution role and the task role — this trips check #26
  (`ecsTaskDefinitionSeparateTaskAndExecutionRoles`).
- **CloudWatch log group** at `/ecs/ss-test-ecs-<TS>` — target for the
  `awslogs` driver. Present so checks #23 and #34 pass, keeping the failure
  set focused on the misconfigurations we chose.
- **ECS Fargate cluster** with no Container Insights, no capacity providers,
  no `managedStorageConfiguration.kmsKeyId`, and no tags — fires checks #1,
  #4, #5, #7.
- **Task definition** (`ss-test-ecs-td-<TS>`) with a single container:
  - `image: nginx:latest` (fires #32 `:latest`, #33 non-ECR)
  - `user` unset (fires #20 non-root)
  - `readonlyRootFilesystem: false` (fires #22 writable rootfs)
  - `environment` includes `DB_PASSWORD`, `API_KEY`, and a value matching an
    AWS access-key-ID pattern (fires #24 secrets in env vars)
  - `linuxParameters.capabilities.add: [SYS_ADMIN, NET_RAW]` (fires #31)
  - no `healthCheck` (fires #27)
  - `ephemeralStorage.sizeInGiB: 30` with no cluster CMK (fires #42)
  - task role == execution role (fires #26)
- **ECS service** (`ss-test-ecs-svc-<TS>`) with `desiredCount=0` (so no
  billable Fargate tasks are launched) and:
  - `assignPublicIp: ENABLED` (fires #8)
  - `deploymentCircuitBreaker.enable: false` (fires #9)
  - No Application Auto Scaling target (fires #12)
  - `desiredCount=0`, `ACTIVE` (fires #13)
  - `minimumHealthyPercent: 0` (fires #16)
  - `propagateTags: NONE` (fires #19)
  - `launchType: FARGATE` with no `FARGATE_SPOT` (fires #37)
  - No load balancer, service registry, or Service Connect (fires #38)

## What is NOT simulated (documented gaps)

| Check | Reason |
|---|---|
| #2 `ecsClusterExecuteCommandLogging` | Requires a service with `enableExecuteCommand=true`. Not created because it's an operational feature outside the failure set we target. |
| #3 `ecsClusterExecuteCommandEncryption` | Same as above. |
| #6 `ecsClusterNoRunningTasks` | Would require an ACTIVE service with 0 running tasks; our service has `desiredCount=0` (no running tasks) *and* our cluster reports `activeServicesCount=1` — this actually fires it. |
| #10 `ecsServiceDeploymentCircuitBreakerRollback` | Skipped by design: rollback check is N/A when the circuit breaker is off (which we set). |
| #11 `ecsServiceFargateLatestPlatformVersion` | Passes because we set `platformVersion=LATEST`. Older versions like `1.3.0` are rejected by the API in newer regions. |
| #14 `ecsServiceLoadBalancerHealthCheck` | Service has no LB → N/A. |
| #15 `ecsServiceEBSVolumeEncryption` | Service has no managed EBS volume → N/A. |
| #17 `ecsServiceNetworkModeAwsvpc` | Passes because Fargate requires `awsvpc`. |
| #18 `ecsTaskSetPublicIpDisabled` | Requires EXTERNAL deployment controller — out of scope for basic Fargate. |
| #21 `ecsTaskDefinitionNoPrivilegedContainers` | Fargate rejects `privileged=true` at register time; cannot be simulated on Fargate. |
| #25 `ecsTaskDefinitionHostNetworkModeUser` | Requires `networkMode: host` — Fargate rejects it. |
| #29 `ecsTaskDefinitionNoHostPidMode`, #30 `ecsTaskDefinitionNoHostIpcMode` | Fargate rejects `pidMode: host` and `ipcMode: host`. |
| #35 `ecsTaskDefinitionSecretReferences` | Would require registering a task def with a `secrets[]` entry pointing at a non-existent secret. Out of scope. |
| #36 `ecsClusterServiceConnectDefaults` | Requires 2+ services in one cluster. |
| #39 `ecsServiceStaleTaskDefinition` | Requires more than 5 revisions of a family — trivial to add manually if needed. |
| #40 `ecsTaskDefinitionSensitiveHostPaths` | Requires EC2 launch type with bind-mounted `/etc`/`/proc`/etc. Fargate rejects host volumes. |
| #41 `ecsTaskDefinitionUlimitsConfigured` | Would require an ulimit with `nofile.hardLimit > 65536`. Trivially added. |

To exercise the Fargate-incompatible checks (privileged, host modes, sensitive
paths, ulimits, EC2-only), you'd need to spin up an EC2 launch-type cluster
with a container instance registered — a much larger simulation.

## Usage

```bash
# Provision
./create_test_resources.sh --region ap-southeast-1

# Wait ~30s for IAM/service to stabilise, then scan
sleep 30
cd ../../..
python3 main.py --regions ap-southeast-1 --services ecs --beta 1 --sequential 1

# Teardown (auto-detects the latest manifest in CWD)
cd services/ecs/simulation
./cleanup_test_resources.sh --region ap-southeast-1
```

## Cost

The service is created with `desiredCount=0`, so no Fargate tasks are
launched. The only ongoing costs are:

- **CloudWatch log group**: free unless logs are ingested (they won't be —
  no tasks run).
- **ECS cluster**: free (Fargate clusters have no fixed cost).
- **IAM role**: free.

Total: **$0.00 per hour** as long as you don't scale the service up.

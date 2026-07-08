# Step Functions Simulation Testing

Scripts that create four intentionally-insecure Step Functions state machines
so every `sfn*` service-screener check that can be forced through the AWS API
is validated end-to-end. Covers Phase 1 (checks 13-24) plus Phase 2
(checks 25-28).

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| IAM role `ss-test-sfn-role-*` | Trust `states.amazonaws.com`; inline `Action:*, Resource:*` | #14 (Phase 1), **#25 (Phase 2)** |
| CloudWatch log group `/aws/vendedlogs/states/ss-test-sfn-logged-*` | Destination for SM #3 | — |
| EventBridge connection `ss-test-sfn-conn-*` | API_KEY auth, dummy value; needed for `http:invoke` ConnectionArn validation | — |
| SM #1 `ss-test-sfn-standard-*` (STANDARD) | `logging.level=OFF`, `tracing.enabled=false`, no CMK, no tags, two Task states without Retry/Catch, no top-level `TimeoutSeconds` | Phase 1 checks (see table below) |
| SM #2 `ss-test-sfn-express-*` (EXPRESS) | Same as SM #1 but `type=EXPRESS` | Phase 1 #21 (sfnExpressWorkflowNoLogging) |
| SM #3 `ss-test-sfn-logged-*` (STANDARD) | `logging.level=ALL` + `includeExecutionData=true`, no CMK | **#27 (Phase 2)** |
| SM #4 `ss-test-sfn-http-*` (STANDARD) | Single Task with `arn:aws:states:::http:invoke` and **dynamic** `ApiEndpoint.$` (Step Functions rejects `http://` at create time via SCHEMA_VALIDATION_FAILED — the check's FAIL branch is unreachable via the API) | **#28 (Phase 2, INFO branch)** |

All four state machines share the same overprivileged role, so each fires
Phase 2 check #25 (sfnIAMRoleAllowsPassRole). None of them have CloudWatch
alarms, so each fires Phase 2 check #26 (sfnNoCloudWatchAlarm).

## Coverage vs. Spec

### Phase 1 (checks 13-24)

| # | Check | Simulated? |
|---:|---|---|
| 13 | sfnEncryptionAtRest | ✓ FAIL (all four SMs) |
| 14 | sfnRoleOverprivileged | ✓ FAIL |
| 15 | sfnLoggingDisabled | ✓ FAIL (SM #1, #2, #4) |
| 16 | sfnLoggingLevelWeak | ✗ SM #1/#2/#4 use `OFF` (falls to #15); SM #3 uses `ALL` (PASS) — add a 5th SM with `level=ERROR` to force |
| 17 | sfnTracingDisabled | ✓ FAIL |
| 18 | sfnNoRetryPolicy | ✓ FAIL (SM #1/#2/#3) |
| 19 | sfnNoCatchHandler | ✓ FAIL (SM #1/#2/#3) |
| 20 | sfnNoTimeout | ✓ FAIL |
| 21 | sfnExpressWorkflowNoLogging | ✓ FAIL (SM #2) |
| 22 | sfnStatusNotActive | ✗ (transient state during delete only) |
| 23 | sfnUnusedStateMachine | ✗ (new SM is < 90 days old) |
| 24 | sfnResourcesWithoutTags | ✓ FAIL |

### Phase 2 (checks 25-28)

| # | Check | Simulated? |
|---:|---|---|
| 25 | sfnIAMRoleAllowsPassRole | ✓ FAIL — the wildcard `Action:*, Resource:*` inline policy is treated as granting `iam:PassRole` on `*` |
| 26 | sfnNoCloudWatchAlarm | ✓ FAIL (no alarms exist for any SM) |
| 27 | sfnLoggingWithoutEncryption | ✓ FAIL (SM #3: `includeExecutionData=true` + `AWS_OWNED_KEY`) |
| 28 | sfnHttpTaskNoTLS | ✗ FAIL / ✓ INFO — Step Functions rejects a static `ApiEndpoint` with scheme `http` at CreateStateMachine time (SCHEMA_VALIDATION_FAILED). SM #4 uses a dynamic `ApiEndpoint.$` reference so the check reports its INFO branch ("cannot verify scheme statically"). The FAIL branch is defense-in-depth for legacy resources and is not reachable via the current API. |

**Directly simulated (FAIL): 12 of 16 checks (Phase 1 + Phase 2).**
**Exercised (INFO or PASS with expected reason): 15 of 16.**

## Cost

State machines with zero executions have **no standing charges**. IAM roles,
log groups without ingested data, and idle EventBridge connections are all
free. Total cost per test run: **$0** if you clean up promptly.

## Usage

```bash
cd services/stepfunctions/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1
# … wait ~30s for IAM propagation …
cd ../../..
python3 main.py --regions ap-southeast-1 --services stepfunctions --beta 1 --sequential 1
cd services/stepfunctions/simulation
./cleanup_test_resources.sh --force
```

## Notes

- SM #1/#2 reference an SNS topic ARN that intentionally doesn't exist
  (`ss-test-sim-topic-does-not-exist`). Creation succeeds because Step
  Functions validates ASL syntax and select managed-service parameters,
  not target resource existence at Task runtime. The state machines are
  never invoked.
- SM #4's `Authentication.ConnectionArn` **is** validated at create time,
  which is why the simulation provisions a real EventBridge connection
  with API_KEY auth and a dummy key value. The state machine is never
  executed, so no API call is ever made against the (fake) endpoint.
- SM #3's log group destination is validated at create time. The log group
  is created in Step 2 of the script.
- If cleanup fails to delete the IAM role because a state-machine delete
  hasn't fully propagated, wait ~30 seconds and re-run cleanup.

## IAM Permissions Required

- `iam:CreateRole`, `iam:DeleteRole`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:DetachRolePolicy`,
  `iam:GetRole`, `iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`,
  `iam:ListPolicies`
- `states:CreateStateMachine`, `states:DeleteStateMachine`,
  `states:ListStateMachines`, `states:DescribeStateMachine`,
  `states:ListTagsForResource`, `states:ListExecutions`,
  `states:ValidateStateMachineDefinition`
- `logs:CreateLogGroup`, `logs:DeleteLogGroup`, `logs:DescribeLogGroups`
- `events:CreateConnection`, `events:DeleteConnection`
- `cloudwatch:DescribeAlarmsForMetric`, `cloudwatch:DescribeAlarms`
- `sts:GetCallerIdentity`

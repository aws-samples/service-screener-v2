# Step Functions Simulation Testing

Scripts that create two intentionally-insecure Step Functions state machines
so the 12 `sfn*` service-screener checks can be validated end-to-end.

## Resources Created

All prefixed with `ss-test-`:

| Resource | Configuration | Directly Validates |
|---|---|---|
| IAM role `ss-test-sfn-role-*` | Trust `states.amazonaws.com`; inline `Action:*, Resource:*` | #2 |
| STANDARD state machine `ss-test-sfn-standard-*` | `logging.level=OFF`, `tracing.enabled=false`, no encryption CMK, no tags, two Task states without Retry/Catch, no top-level `TimeoutSeconds` | #1, #3, #5, #6, #7, #8, #12 |
| EXPRESS state machine `ss-test-sfn-express-*` | Same as STANDARD but `type=EXPRESS`; the extra failure mode is that EXPRESS retains no execution history in the service itself | #9 (plus most of the above) |

`sfnLoggingLevelWeak` (#4) fires only when logging is ENABLED at a weak
level; since our test uses `level=OFF`, it is intentionally covered by #3
and #4 reports INFO ("Logging is fully OFF — see sfnLoggingDisabled").

## Coverage vs. Spec

| # | Check | Simulated? |
|---:|---|---|
| 1 | sfnEncryptionAtRest | ✓ FAIL |
| 2 | sfnRoleOverprivileged | ✓ FAIL |
| 3 | sfnLoggingDisabled | ✓ FAIL |
| 4 | sfnLoggingLevelWeak | ✗ (mutually exclusive with #3; documented) |
| 5 | sfnTracingDisabled | ✓ FAIL |
| 6 | sfnNoRetryPolicy | ✓ FAIL |
| 7 | sfnNoCatchHandler | ✓ FAIL |
| 8 | sfnNoTimeout | ✓ FAIL |
| 9 | sfnExpressWorkflowNoLogging | ✓ FAIL (EXPRESS SM) |
| 10 | sfnStatusNotActive | ✗ (only leaves ACTIVE during in-flight delete) |
| 11 | sfnUnusedStateMachine | ✗ (new SM is < 90 days old — cannot fast-forward) |
| 12 | sfnResourcesWithoutTags | ✓ FAIL |

**Directly simulated: 9 of 12.** The three unsimulatable checks:

- **#4 sfnLoggingLevelWeak** — This check specifically distinguishes "logging
  enabled but weak" from "logging disabled". Enabling the SM with
  `level=ERROR` + `includeExecutionData=false` would fire it, but the same
  test would then NOT fire #3. If you want to validate both, create a third
  state machine with `level=ERROR` logging (needs a CloudWatch log group).
- **#10 sfnStatusNotActive** — Non-ACTIVE state is a transient value observed
  only during a delete. Not simulatable in a repeatable script.
- **#11 sfnUnusedStateMachine** — The check compares creation date to 90
  days. Simulation resources are fresh, so the check reports INFO ("new").

## Cost

State machines with zero executions have **no standing charges**. IAM roles
are free. Total cost per test run: **$0** if you clean up promptly.

## Usage

```bash
cd services/stepfunctions/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh
# … wait ~60s for IAM propagation …
cd ../../..
python3 main.py --regions us-east-1 --services stepfunctions --beta 1 --sequential 1
cd services/stepfunctions/simulation
./cleanup_test_resources.sh --force
```

## Notes

- The state machine definitions reference an SNS topic ARN that intentionally
  doesn't exist (`ss-test-sim-topic-does-not-exist`). Creation succeeds
  because Step Functions validates syntax, not target resource existence.
  The machines are never invoked.
- `--skip-resource-in-use-check` is not needed for SFN deletions — DELETING
  status is reported by the check as FAIL (`sfnStatusNotActive`) but the
  delete completes asynchronously without blocking.
- If the cleanup fails to delete the IAM role because a delete of the state
  machine hasn't fully propagated, wait ~30 seconds and re-run cleanup.

## IAM Permissions Required

- `iam:CreateRole`, `iam:DeleteRole`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`,
  `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:DetachRolePolicy`
- `states:CreateStateMachine`, `states:DeleteStateMachine`,
  `states:ListStateMachines`, `states:DescribeStateMachine`,
  `states:ListTagsForResource`, `states:ListExecutions`
- `sts:GetCallerIdentity`

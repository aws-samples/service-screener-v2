import datetime
import json

from services.Evaluator import Evaluator
from services.bedrock.drivers.BedrockAgent import _inspectRoleForBroadPolicies


class StepfunctionsCommon(Evaluator):
    """
    All Step Functions checks (12 reporter keys).

    Input:
      sm         -- output of DescribeStateMachine plus injected fields:
                    sm['_tags'] (list of {'key','value'})
                    sm['_mostRecentExecution'] (datetime or None)
      sfnClient  -- boto3 stepfunctions client (unused by checks today but kept
                    for future per-check API calls)
      iamClient  -- boto3 iam client for role analysis
    """

    # States that can raise service errors — these are the ones that need
    # Retry/Catch/Timeout hygiene. Non-execution states (Pass, Choice, Wait,
    # Succeed, Fail) never fail with a service error.
    ERRORABLE_STATE_TYPES = {'Task', 'Parallel', 'Map'}

    WEAK_LOG_LEVELS = {'ERROR', 'FATAL'}

    UNUSED_DAYS = 90

    BROAD_ACTIONS = {'*', 'states:*', 'iam:*', 's3:*', 'kms:*', 'lambda:*', 'dynamodb:*'}

    def __init__(self, sm, sfnClient, iamClient):
        super().__init__()
        self.sm = sm
        self.sfnClient = sfnClient
        self.iamClient = iamClient

        name = sm.get('name') or sm.get('stateMachineArn', 'unknown')
        self._resourceName = name

        self.addII('name', name)
        self.addII('stateMachineArn', sm.get('stateMachineArn', 'N/A'))
        self.addII('type', sm.get('type', 'N/A'))
        self.addII('status', sm.get('status', 'N/A'))
        self.addII('roleArn', sm.get('roleArn', 'N/A'))
        self.addII('creationDate', str(sm.get('creationDate', 'N/A')))

        # Parse definition once; None if unparseable
        self._definition = self._parseDefinition(sm.get('definition', ''))

    # ------------------------------------------------------------------ #
    # 1. Encryption at rest
    # ------------------------------------------------------------------ #
    def _checkSfnEncryptionAtRest(self):
        enc = self.sm.get('encryptionConfiguration') or {}
        encType = enc.get('type')
        if encType == 'CUSTOMER_MANAGED_KMS_KEY':
            self.results['sfnEncryptionAtRest'] = [
                1, f"CMK: {enc.get('kmsKeyId', 'set')}"
            ]
        else:
            self.results['sfnEncryptionAtRest'] = [
                -1, f"Encryption type: {encType or 'AWS_OWNED_KEY'} (no CMK)"
            ]

    # ------------------------------------------------------------------ #
    # 2. Role overprivileged
    # ------------------------------------------------------------------ #
    def _checkSfnRoleOverprivileged(self):
        roleArn = self.sm.get('roleArn')
        if not roleArn:
            self.results['sfnRoleOverprivileged'] = [0, "No execution role to inspect"]
            return

        roleName = self._roleNameFromArn(roleArn)
        if not roleName:
            self.results['sfnRoleOverprivileged'] = [
                0, f"Could not parse role ARN: {roleArn}"
            ]
            return

        findings = _inspectRoleForBroadPolicies(
            self.iamClient, roleName, self.BROAD_ACTIONS
        )
        if findings:
            self.results['sfnRoleOverprivileged'] = [
                -1, "Overly permissive: " + "; ".join(findings)
            ]
        else:
            self.results['sfnRoleOverprivileged'] = [1, "Role appears scoped"]

    # ------------------------------------------------------------------ #
    # 3. Logging disabled
    # ------------------------------------------------------------------ #
    def _checkSfnLoggingDisabled(self):
        level = self._loggingLevel()
        if level == 'OFF':
            self.results['sfnLoggingDisabled'] = [
                -1, "loggingConfiguration.level=OFF"
            ]
        else:
            self.results['sfnLoggingDisabled'] = [1, f"Log level: {level}"]

    # ------------------------------------------------------------------ #
    # 4. Logging level weak (ERROR/FATAL) or execution data omitted
    # ------------------------------------------------------------------ #
    def _checkSfnLoggingLevelWeak(self):
        cfg = self.sm.get('loggingConfiguration') or {}
        level = cfg.get('level', 'OFF')
        includeData = cfg.get('includeExecutionData', False)

        if level == 'OFF':
            # Distinct concern from #3; if fully off, mark as pass here (already flagged by #3)
            self.results['sfnLoggingLevelWeak'] = [
                0, "Logging is fully OFF — see sfnLoggingDisabled"
            ]
            return

        issues = []
        if level in self.WEAK_LOG_LEVELS:
            issues.append(f"level={level}")
        if not includeData:
            issues.append("includeExecutionData=false")

        if issues:
            self.results['sfnLoggingLevelWeak'] = [
                -1, "Weak logging: " + ", ".join(issues)
            ]
        else:
            self.results['sfnLoggingLevelWeak'] = [
                1, f"level={level}, includeExecutionData=True"
            ]

    # ------------------------------------------------------------------ #
    # 5. X-Ray tracing disabled
    # ------------------------------------------------------------------ #
    def _checkSfnTracingDisabled(self):
        tracing = self.sm.get('tracingConfiguration') or {}
        if tracing.get('enabled'):
            self.results['sfnTracingDisabled'] = [1, "X-Ray tracing enabled"]
        else:
            self.results['sfnTracingDisabled'] = [-1, "X-Ray tracing disabled"]

    # ------------------------------------------------------------------ #
    # 6. No retry policy on errorable states
    # ------------------------------------------------------------------ #
    def _checkSfnNoRetryPolicy(self):
        missing = self._statesMissingField('Retry')
        if missing is None:
            self.results['sfnNoRetryPolicy'] = [0, "Could not parse state machine definition"]
            return
        if not missing:
            self.results['sfnNoRetryPolicy'] = [
                1, "All Task/Parallel/Map states have Retry, or none exist"
            ]
        else:
            self.results['sfnNoRetryPolicy'] = [
                -1, f"State(s) without Retry: {', '.join(missing[:8])}"
                + (f" (+{len(missing)-8} more)" if len(missing) > 8 else "")
            ]

    # ------------------------------------------------------------------ #
    # 7. No catch handler on errorable states
    # ------------------------------------------------------------------ #
    def _checkSfnNoCatchHandler(self):
        missing = self._statesMissingField('Catch')
        if missing is None:
            self.results['sfnNoCatchHandler'] = [0, "Could not parse state machine definition"]
            return
        if not missing:
            self.results['sfnNoCatchHandler'] = [
                1, "All Task/Parallel/Map states have Catch, or none exist"
            ]
        else:
            self.results['sfnNoCatchHandler'] = [
                -1, f"State(s) without Catch: {', '.join(missing[:8])}"
                + (f" (+{len(missing)-8} more)" if len(missing) > 8 else "")
            ]

    # ------------------------------------------------------------------ #
    # 8. No top-level TimeoutSeconds
    # ------------------------------------------------------------------ #
    def _checkSfnNoTimeout(self):
        if self._definition is None:
            self.results['sfnNoTimeout'] = [0, "Could not parse state machine definition"]
            return
        if 'TimeoutSeconds' in self._definition:
            self.results['sfnNoTimeout'] = [
                1, f"TimeoutSeconds={self._definition['TimeoutSeconds']}"
            ]
        else:
            self.results['sfnNoTimeout'] = [
                -1, "No top-level TimeoutSeconds in definition"
            ]

    # ------------------------------------------------------------------ #
    # 9. EXPRESS workflow with logging OFF
    # ------------------------------------------------------------------ #
    def _checkSfnExpressWorkflowNoLogging(self):
        smType = self.sm.get('type', 'STANDARD')
        level = self._loggingLevel()

        if smType != 'EXPRESS':
            self.results['sfnExpressWorkflowNoLogging'] = [
                0, f"Not an EXPRESS workflow (type={smType})"
            ]
            return

        if level == 'OFF':
            self.results['sfnExpressWorkflowNoLogging'] = [
                -1, "EXPRESS workflow with logging=OFF — no execution history retained anywhere"
            ]
        else:
            self.results['sfnExpressWorkflowNoLogging'] = [
                1, f"EXPRESS workflow with logging level={level}"
            ]

    # ------------------------------------------------------------------ #
    # 10. Status not ACTIVE
    # ------------------------------------------------------------------ #
    def _checkSfnStatusNotActive(self):
        status = self.sm.get('status', 'UNKNOWN')
        if status == 'ACTIVE':
            self.results['sfnStatusNotActive'] = [1, f"Status: {status}"]
        else:
            self.results['sfnStatusNotActive'] = [-1, f"Status: {status}"]

    # ------------------------------------------------------------------ #
    # 11. Unused state machine (no executions in 90 days)
    # ------------------------------------------------------------------ #
    def _checkSfnUnusedStateMachine(self):
        last = self.sm.get('_mostRecentExecution')
        if last is None:
            # Two possibilities: never executed, or listExecutions failed.
            # Only flag as FAIL if the state machine is old enough that we'd
            # expect executions by now (older than UNUSED_DAYS since creation).
            created = self.sm.get('creationDate')
            if isinstance(created, datetime.datetime):
                age_days = (self._nowUtc() - self._asAware(created)).days
                if age_days > self.UNUSED_DAYS:
                    self.results['sfnUnusedStateMachine'] = [
                        -1,
                        f"No executions in the last page; state machine is {age_days} days old"
                    ]
                    return
            self.results['sfnUnusedStateMachine'] = [
                0, "No executions recorded (state machine is new or list_executions unavailable)"
            ]
            return

        if not isinstance(last, datetime.datetime):
            self.results['sfnUnusedStateMachine'] = [
                0, f"Unparseable execution timestamp: {last}"
            ]
            return

        age = self._nowUtc() - self._asAware(last)
        if age.days > self.UNUSED_DAYS:
            self.results['sfnUnusedStateMachine'] = [
                -1,
                f"Last execution {age.days} days ago (> {self.UNUSED_DAYS}d threshold)"
            ]
        else:
            self.results['sfnUnusedStateMachine'] = [
                1, f"Last execution {age.days} day(s) ago"
            ]

    # ------------------------------------------------------------------ #
    # 12. No tags
    # ------------------------------------------------------------------ #
    def _checkSfnResourcesWithoutTags(self):
        tags = self.sm.get('_tags') or []
        if not tags:
            self.results['sfnResourcesWithoutTags'] = [-1, "No tags applied"]
        else:
            keys = [t.get('key') for t in tags if t.get('key')]
            self.results['sfnResourcesWithoutTags'] = [
                1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
            ]

    # ------------------------------------------------------------------ #
    # 13. Task states with .waitForTaskToken but no HeartbeatSeconds
    # ------------------------------------------------------------------ #
    def _checkSfnNoHeartbeat(self):
        if self._definition is None:
            self.results['sfnNoHeartbeat'] = [0, "Could not parse state machine definition"]
            return

        missing = []
        found = []
        for fqName, stateDef in self._iterStates(self._definition):
            if stateDef.get('Type') != 'Task':
                continue
            resource = stateDef.get('Resource') or ''
            if '.waitForTaskToken' not in resource:
                continue
            found.append(fqName)
            if 'HeartbeatSeconds' not in stateDef and 'HeartbeatSecondsPath' not in stateDef:
                missing.append(fqName)

        if not found:
            self.results['sfnNoHeartbeat'] = [
                1, "No .waitForTaskToken tasks in this state machine"
            ]
            return

        if missing:
            self.results['sfnNoHeartbeat'] = [
                -1,
                f"Callback task(s) without HeartbeatSeconds: {', '.join(missing[:8])}"
                + (f" (+{len(missing)-8} more)" if len(missing) > 8 else "")
            ]
        else:
            self.results['sfnNoHeartbeat'] = [
                1, f"All {len(found)} .waitForTaskToken task(s) set HeartbeatSeconds"
            ]

    # ------------------------------------------------------------------ #
    # 14. Large-payload risk (heuristic)
    # ------------------------------------------------------------------ #
    def _checkSfnLargePayloadRisk(self):
        raw = self.sm.get('definition', '')
        if not raw:
            self.results['sfnLargePayloadRisk'] = [0, "Definition unavailable"]
            return

        # Serialise if we have a dict; otherwise use the raw string.
        raw_str = raw if isinstance(raw, str) else json.dumps(raw)
        size = len(raw_str)
        has_s3 = ('arn:aws:s3' in raw_str) or ('s3:getObject' in raw_str.lower()) \
                 or ('s3:putObject' in raw_str.lower())

        if size > 50 * 1024 and not has_s3:
            self.results['sfnLargePayloadRisk'] = [
                0,
                f"Definition is {size} bytes with no S3 integration reference "
                "(inline payloads risk hitting the 256KB state I/O limit)"
            ]
        else:
            self.results['sfnLargePayloadRisk'] = [
                1,
                f"Definition {size} bytes"
                + (" (S3 offload pattern referenced)" if has_s3 else "")
            ]

    # ------------------------------------------------------------------ #
    # 15. Map states without MaxConcurrency
    # ------------------------------------------------------------------ #
    def _checkSfnMapNoConcurrencyLimit(self):
        if self._definition is None:
            self.results['sfnMapNoConcurrencyLimit'] = [
                0, "Could not parse state machine definition"
            ]
            return

        unbounded = []
        found = 0
        for fqName, stateDef in self._iterStates(self._definition):
            if stateDef.get('Type') != 'Map':
                continue
            found += 1
            if 'MaxConcurrency' not in stateDef and 'MaxConcurrencyPath' not in stateDef:
                unbounded.append(fqName)

        if found == 0:
            self.results['sfnMapNoConcurrencyLimit'] = [
                1, "No Map states in this state machine"
            ]
        elif unbounded:
            self.results['sfnMapNoConcurrencyLimit'] = [
                -1,
                f"Map state(s) without MaxConcurrency: {', '.join(unbounded[:8])}"
                + (f" (+{len(unbounded)-8} more)" if len(unbounded) > 8 else "")
            ]
        else:
            self.results['sfnMapNoConcurrencyLimit'] = [
                1, f"All {found} Map state(s) set MaxConcurrency"
            ]

    # ------------------------------------------------------------------ #
    # 16. Task states without per-task timeout
    # ------------------------------------------------------------------ #
    def _checkSfnTaskNoTimeout(self):
        if self._definition is None:
            self.results['sfnTaskNoTimeout'] = [
                0, "Could not parse state machine definition"
            ]
            return

        missing = []
        total = 0
        for fqName, stateDef in self._iterStates(self._definition):
            if stateDef.get('Type') != 'Task':
                continue
            total += 1
            # Accept either TimeoutSeconds/TimeoutSecondsPath or HeartbeatSeconds/Path
            has_timeout = any(k in stateDef for k in (
                'TimeoutSeconds', 'TimeoutSecondsPath',
                'HeartbeatSeconds', 'HeartbeatSecondsPath',
            ))
            if not has_timeout:
                missing.append(fqName)

        if total == 0:
            self.results['sfnTaskNoTimeout'] = [
                1, "No Task states in this state machine"
            ]
        elif missing:
            self.results['sfnTaskNoTimeout'] = [
                -1,
                f"Task state(s) without TimeoutSeconds/HeartbeatSeconds: "
                f"{', '.join(missing[:8])}"
                + (f" (+{len(missing)-8} more)" if len(missing) > 8 else "")
            ]
        else:
            self.results['sfnTaskNoTimeout'] = [
                1, f"All {total} Task state(s) have TimeoutSeconds or HeartbeatSeconds"
            ]

    # ------------------------------------------------------------------ #
    # Helper: yield every state (fully-qualified name + definition dict)
    # from the top-level state machine, recursing into Parallel.Branches
    # and Map.Iterator/ItemProcessor.
    # ------------------------------------------------------------------ #
    def _iterStates(self, definition, prefix=''):
        if not isinstance(definition, dict):
            return
        states = definition.get('States', {}) or {}
        for name, stateDef in states.items():
            if not isinstance(stateDef, dict):
                continue
            fq = f"{prefix}{name}" if prefix else name
            yield fq, stateDef
            stype = stateDef.get('Type')
            if stype == 'Parallel':
                for i, branch in enumerate(stateDef.get('Branches', []) or []):
                    yield from self._iterStates(branch, prefix=f"{fq}.branch{i}.")
            elif stype == 'Map':
                sub = stateDef.get('ItemProcessor') or stateDef.get('Iterator')
                if isinstance(sub, dict):
                    yield from self._iterStates(sub, prefix=f"{fq}.iter.")

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parseDefinition(raw):
        if not raw:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    def _loggingLevel(self):
        cfg = self.sm.get('loggingConfiguration') or {}
        return cfg.get('level', 'OFF')

    def _statesMissingField(self, fieldName):
        """
        Return a list of Task/Parallel/Map state names that DO NOT have the
        given field (Retry or Catch). Recurses into Parallel.Branches and
        Map.Iterator/ItemProcessor. Returns None if the definition is not
        parseable.
        """
        if self._definition is None:
            return None
        missing = []
        self._walkStates(self._definition, fieldName, missing)
        return missing

    def _walkStates(self, definition, fieldName, missing, prefix=''):
        states = definition.get('States', {}) if isinstance(definition, dict) else {}
        for stateName, stateDef in states.items():
            if not isinstance(stateDef, dict):
                continue
            fqName = f"{prefix}{stateName}" if prefix else stateName
            stateType = stateDef.get('Type')

            if stateType in self.ERRORABLE_STATE_TYPES:
                if fieldName not in stateDef:
                    missing.append(fqName)

            # Recurse into sub-workflows
            if stateType == 'Parallel':
                for i, branch in enumerate(stateDef.get('Branches', []) or []):
                    self._walkStates(branch, fieldName, missing, prefix=f"{fqName}.branch{i}.")
            elif stateType == 'Map':
                # Distributed Map (ItemProcessor) or classic (Iterator)
                sub = stateDef.get('ItemProcessor') or stateDef.get('Iterator')
                if isinstance(sub, dict):
                    self._walkStates(sub, fieldName, missing, prefix=f"{fqName}.iter.")

    @staticmethod
    def _roleNameFromArn(arn):
        if not arn or ':role/' not in arn:
            return None
        return arn.split(':role/', 1)[1].split('/')[-1]

    @staticmethod
    def _nowUtc():
        return datetime.datetime.now(datetime.timezone.utc)

    @staticmethod
    def _asAware(dt):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    # ------------------------------------------------------------------ #
    # 17. Definition validation errors (ValidateStateMachineDefinition)
    # ------------------------------------------------------------------ #
    def _checkSfnDefinitionValidationErrors(self):
        vr = self.sm.get('_validationResult') or {}
        diagnostics = vr.get('diagnostics') or []
        errors = [d for d in diagnostics if d.get('severity') == 'ERROR']
        if not vr:
            self.results['sfnDefinitionValidationErrors'] = [
                0, "Validation API could not be called"
            ]
            return
        if errors:
            codes = [d.get('code', '?') for d in errors[:5]]
            self.results['sfnDefinitionValidationErrors'] = [
                -1,
                f"{len(errors)} validation error(s): {', '.join(codes)}"
                + (f" (+{len(errors)-5} more)" if len(errors) > 5 else "")
            ]
        else:
            self.results['sfnDefinitionValidationErrors'] = [
                1, "No ERROR-severity validation diagnostics"
            ]

    # ------------------------------------------------------------------ #
    # 18. Choice state without Default branch
    # ------------------------------------------------------------------ #
    def _checkSfnChoiceNoDefault(self):
        if self._definition is None:
            self.results['sfnChoiceNoDefault'] = [
                0, "Could not parse state machine definition"
            ]
            return
        missing = []
        total = 0
        for fq, s in self._iterStates(self._definition):
            if s.get('Type') != 'Choice':
                continue
            total += 1
            if not s.get('Default'):
                missing.append(fq)

        if total == 0:
            self.results['sfnChoiceNoDefault'] = [1, "No Choice states"]
        elif missing:
            self.results['sfnChoiceNoDefault'] = [
                -1,
                f"Choice state(s) without Default: {', '.join(missing[:8])}"
                + (f" (+{len(missing)-8} more)" if len(missing) > 8 else "")
            ]
        else:
            self.results['sfnChoiceNoDefault'] = [
                1, f"All {total} Choice state(s) have Default"
            ]

    # ------------------------------------------------------------------ #
    # 19. Execution role does not exist
    # ------------------------------------------------------------------ #
    def _checkSfnRoleDoesNotExist(self):
        status = self.sm.get('_roleExists')
        roleArn = self.sm.get('roleArn', '(no role)')
        if status == 'missing':
            self.results['sfnRoleDoesNotExist'] = [
                -1, f"IAM role does not exist: {roleArn}"
            ]
        elif status == 'exists':
            self.results['sfnRoleDoesNotExist'] = [1, "Execution role exists"]
        elif status == 'cross_account':
            self.results['sfnRoleDoesNotExist'] = [
                0, f"Cross-account role — cannot verify: {roleArn}"
            ]
        else:
            self.results['sfnRoleDoesNotExist'] = [
                0, "Could not verify role existence (permission or arn parse failure)"
            ]

    # ------------------------------------------------------------------ #
    # 20. Unreachable states (graph reachability from StartAt)
    # ------------------------------------------------------------------ #
    def _checkSfnUnreachableStates(self):
        if self._definition is None:
            self.results['sfnUnreachableStates'] = [
                0, "Could not parse state machine definition"
            ]
            return

        unreachable = self._findUnreachableStates(self._definition)
        if unreachable is None:
            self.results['sfnUnreachableStates'] = [
                0, "Could not compute reachability (missing StartAt)"
            ]
            return
        if unreachable:
            self.results['sfnUnreachableStates'] = [
                -1,
                f"Unreachable state(s): {', '.join(sorted(unreachable)[:8])}"
                + (f" (+{len(unreachable)-8} more)" if len(unreachable) > 8 else "")
            ]
        else:
            self.results['sfnUnreachableStates'] = [
                1, "All states reachable from StartAt"
            ]

    # ------------------------------------------------------------------ #
    # 21. Parallel state without Catch
    # ------------------------------------------------------------------ #
    def _checkSfnParallelNoCatch(self):
        if self._definition is None:
            self.results['sfnParallelNoCatch'] = [
                0, "Could not parse state machine definition"
            ]
            return
        missing = []
        total = 0
        for fq, s in self._iterStates(self._definition):
            if s.get('Type') != 'Parallel':
                continue
            total += 1
            if not s.get('Catch'):
                missing.append(fq)
        if total == 0:
            self.results['sfnParallelNoCatch'] = [1, "No Parallel states"]
        elif missing:
            self.results['sfnParallelNoCatch'] = [
                -1,
                f"Parallel state(s) without Catch: {', '.join(missing[:8])}"
            ]
        else:
            self.results['sfnParallelNoCatch'] = [
                1, f"All {total} Parallel state(s) have Catch"
            ]

    # ------------------------------------------------------------------ #
    # 22. Map state without Catch
    # ------------------------------------------------------------------ #
    def _checkSfnMapNoCatch(self):
        if self._definition is None:
            self.results['sfnMapNoCatch'] = [
                0, "Could not parse state machine definition"
            ]
            return
        missing = []
        total = 0
        for fq, s in self._iterStates(self._definition):
            if s.get('Type') != 'Map':
                continue
            total += 1
            if not s.get('Catch'):
                missing.append(fq)
        if total == 0:
            self.results['sfnMapNoCatch'] = [1, "No Map states"]
        elif missing:
            self.results['sfnMapNoCatch'] = [
                -1,
                f"Map state(s) without Catch: {', '.join(missing[:8])}"
            ]
        else:
            self.results['sfnMapNoCatch'] = [
                1, f"All {total} Map state(s) have Catch"
            ]

    # ------------------------------------------------------------------ #
    # 23. Retry configuration with no back-off and aggressive attempts
    # ------------------------------------------------------------------ #
    def _checkSfnRetryNoBackoff(self):
        if self._definition is None:
            self.results['sfnRetryNoBackoff'] = [
                0, "Could not parse state machine definition"
            ]
            return
        offenders = []
        for fq, s in self._iterStates(self._definition):
            for retry in (s.get('Retry') or []):
                if not isinstance(retry, dict):
                    continue
                backoff = retry.get('BackoffRate')
                # Only fail when BackoffRate is *explicitly* 1.0 AND MaxAttempts > 3.
                try:
                    br = float(backoff) if backoff is not None else None
                except (TypeError, ValueError):
                    br = None
                try:
                    ma = int(retry.get('MaxAttempts', 3))
                except (TypeError, ValueError):
                    ma = 3
                if br is not None and br <= 1.0 and ma > 3:
                    offenders.append(f"{fq}(BackoffRate={br},MaxAttempts={ma})")
        if offenders:
            self.results['sfnRetryNoBackoff'] = [
                -1,
                f"Retry without back-off: {', '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['sfnRetryNoBackoff'] = [
                1, "All Retry blocks use exponential back-off (or acceptable attempt counts)"
            ]

    # ------------------------------------------------------------------ #
    # 24. Configured log group does not exist
    # ------------------------------------------------------------------ #
    def _checkSfnLogGroupDoesNotExist(self):
        status = self.sm.get('_logGroupExists')
        if status is None:
            self.results['sfnLogGroupDoesNotExist'] = [
                0, "No CloudWatch log destination configured"
            ]
        elif status is True:
            self.results['sfnLogGroupDoesNotExist'] = [
                1, "Configured log group exists"
            ]
        elif status is False:
            self.results['sfnLogGroupDoesNotExist'] = [
                -1, "Log group referenced by loggingConfiguration does not exist"
            ]
        else:
            self.results['sfnLogGroupDoesNotExist'] = [
                0, "Could not verify log group (permission or parse failure)"
            ]

    # ------------------------------------------------------------------ #
    # Reachability helper for check #20
    # ------------------------------------------------------------------ #
    def _findUnreachableStates(self, definition):
        """
        Return a set of state names not reachable from StartAt, or None
        if the definition has no StartAt / no States. Reachability walks
        Next, Default, Choice.Choices[*].Next, Catch[*].Next, and descends
        into Parallel.Branches and Map.Iterator/ItemProcessor sub-workflows
        (treating branches as reachable when the Parallel/Map is reachable).
        """
        if not isinstance(definition, dict):
            return None
        start = definition.get('StartAt')
        states = definition.get('States') or {}
        if not start or not states:
            return None

        reachable = set()
        stack = [start]
        while stack:
            name = stack.pop()
            if name in reachable or name not in states:
                continue
            reachable.add(name)
            s = states.get(name) or {}
            # Transitions
            nxt = s.get('Next')
            if nxt:
                stack.append(nxt)
            dflt = s.get('Default')
            if dflt:
                stack.append(dflt)
            for c in (s.get('Choices') or []):
                if isinstance(c, dict) and c.get('Next'):
                    stack.append(c['Next'])
            for c in (s.get('Catch') or []):
                if isinstance(c, dict) and c.get('Next'):
                    stack.append(c['Next'])
            # Parallel / Map sub-workflows: their sub-states are reachable
            # when the parent is reachable; walk sub-definitions and add
            # their StartAt + all states (they can't be reached from the
            # parent scope by name, but they ARE alive as long as the
            # parent is).
            if s.get('Type') == 'Parallel':
                for branch in (s.get('Branches') or []):
                    if isinstance(branch, dict):
                        sub_states = branch.get('States') or {}
                        reachable.update(sub_states.keys())
            elif s.get('Type') == 'Map':
                sub = s.get('ItemProcessor') or s.get('Iterator') or {}
                if isinstance(sub, dict):
                    sub_states = sub.get('States') or {}
                    reachable.update(sub_states.keys())
        return set(states.keys()) - reachable

    # ==================================================================== #
    # Phase 2 additions (checks 25-28)
    # ==================================================================== #

    # ------------------------------------------------------------------ #
    # 25. Execution role grants iam:PassRole on a wildcard resource
    # ------------------------------------------------------------------ #
    def _checkSfnIAMRoleAllowsPassRole(self):
        role_arn = self.sm.get('roleArn')
        if not role_arn:
            self.results['sfnIAMRoleAllowsPassRole'] = [
                0, "No execution role to inspect"
            ]
            return
        docs = self.sm.get('_rolePolicies') or []
        if not docs:
            self.results['sfnIAMRoleAllowsPassRole'] = [
                0, "Role policies not available (cross-account or lookup failed)"
            ]
            return

        offenders = []
        for i, doc in enumerate(docs):
            stmts = doc.get('Statement', [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if not isinstance(stmt, dict) or stmt.get('Effect') != 'Allow':
                    continue
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                actset = {a.lower() for a in actions if isinstance(a, str)}
                if 'iam:passrole' not in actset and '*' not in actset:
                    continue
                resources = stmt.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                if '*' in resources or any('role/*' in r for r in resources if isinstance(r, str)):
                    offenders.append(stmt.get('Sid', f'stmt{i}'))
                    break

        if offenders:
            self.results['sfnIAMRoleAllowsPassRole'] = [
                -1,
                f"Role policy grants iam:PassRole on wildcard Resource: "
                f"{', '.join(offenders[:3])}"
            ]
        else:
            self.results['sfnIAMRoleAllowsPassRole'] = [
                1, "No iam:PassRole with wildcard Resource found"
            ]

    # ------------------------------------------------------------------ #
    # 26. No CloudWatch alarms on failure metrics
    # ------------------------------------------------------------------ #
    def _checkSfnNoCloudWatchAlarm(self):
        status = self.sm.get('_hasFailureAlarms')
        if status is None:
            self.results['sfnNoCloudWatchAlarm'] = [
                0, "Could not enumerate CloudWatch alarms (permission?)"
            ]
        elif status is True:
            self.results['sfnNoCloudWatchAlarm'] = [
                1, "At least one alarm on ExecutionsFailed/TimedOut/Aborted"
            ]
        else:
            self.results['sfnNoCloudWatchAlarm'] = [
                -1,
                "No CloudWatch alarms on ExecutionsFailed / ExecutionsTimedOut / "
                "ExecutionsAborted for this state machine"
            ]

    # ------------------------------------------------------------------ #
    # 27. Execution data logged but state machine not CMK-encrypted
    # ------------------------------------------------------------------ #
    def _checkSfnLoggingWithoutEncryption(self):
        log_cfg = self.sm.get('loggingConfiguration') or {}
        enc_cfg = self.sm.get('encryptionConfiguration') or {}
        includes_data = bool(log_cfg.get('includeExecutionData'))
        is_cmk = enc_cfg.get('type') == 'CUSTOMER_MANAGED_KMS_KEY'

        if not includes_data:
            self.results['sfnLoggingWithoutEncryption'] = [
                0, "includeExecutionData=false — data not written to logs"
            ]
        elif is_cmk:
            self.results['sfnLoggingWithoutEncryption'] = [
                1, "Execution data logged with CMK protection"
            ]
        else:
            self.results['sfnLoggingWithoutEncryption'] = [
                -1,
                "includeExecutionData=true with AWS_OWNED_KEY encryption "
                "(sensitive payloads logged without customer-managed key)"
            ]

    # ------------------------------------------------------------------ #
    # 28. http:invoke Task with plain HTTP endpoint
    # ------------------------------------------------------------------ #
    def _checkSfnHttpTaskNoTLS(self):
        if self._definition is None:
            self.results['sfnHttpTaskNoTLS'] = [
                0, "Could not parse state machine definition"
            ]
            return

        http_offenders = []
        dynamic_endpoints = 0
        http_task_count = 0
        for fq, s in self._iterStates(self._definition):
            if s.get('Type') != 'Task':
                continue
            resource = s.get('Resource') or ''
            if 'http:invoke' not in resource:
                continue
            http_task_count += 1
            params = s.get('Parameters') or {}
            static_endpoint = params.get('ApiEndpoint')
            if static_endpoint and isinstance(static_endpoint, str):
                if static_endpoint.lower().startswith('http://'):
                    http_offenders.append(f"{fq}({static_endpoint})")
            elif 'ApiEndpoint.$' in params:
                dynamic_endpoints += 1

        if http_task_count == 0:
            self.results['sfnHttpTaskNoTLS'] = [
                1, "No http:invoke Task states"
            ]
        elif http_offenders:
            self.results['sfnHttpTaskNoTLS'] = [
                -1,
                f"http:invoke Task(s) with http:// endpoint: {', '.join(http_offenders[:3])}"
            ]
        elif dynamic_endpoints:
            self.results['sfnHttpTaskNoTLS'] = [
                0,
                f"{dynamic_endpoints} http:invoke Task(s) use dynamic ApiEndpoint.$ "
                "(cannot verify scheme statically)"
            ]
        else:
            self.results['sfnHttpTaskNoTLS'] = [
                1, f"All {http_task_count} http:invoke Task(s) use https:// endpoints"
            ]

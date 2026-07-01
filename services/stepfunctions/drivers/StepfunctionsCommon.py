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

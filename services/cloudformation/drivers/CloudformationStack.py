import re
from datetime import datetime, timezone

from services.Evaluator import Evaluator


## Parameter names that suggest the value is a credential. Matched
## case-insensitively against the ParameterKey.
SECRET_NAME_RE = re.compile(
    r'(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|'
    r'access[_-]?key|client[_-]?secret|credential)', re.IGNORECASE)

## Names that match the pattern above but describe metadata ABOUT a secret
## (where it lives, how long it is, how it rotates), not the secret itself.
## "DbPasswordSecretArn", "SecretName", "PasswordLength", "TokenTtl" ...
SECRET_NAME_EXCLUDE_RE = re.compile(
    r'(arn|name|id|ids|length|len|ttl|policy|rotation|rotationdays|expiry|'
    r'expiration|enabled|enable|type|path|parameter|param|version|kms|'
    r'kmskey|kmskeyid|keyid|duration|validity|header|count|days|minutes|'
    r'seconds|hours|url|uri|endpoint|location|ref|reference|identifier)$',
    re.IGNORECASE)

## Values that are clearly not a secret.
NON_SECRET_VALUES = ('', 'true', 'false', 'yes', 'no', 'none', 'null',
                     'enabled', 'disabled')


def plaintextSecretParams(stack):
    """
    Return the ParameterKeys of `stack` (a describe_stacks entry) whose name
    looks like a credential AND whose value describe_stacks returns in clear
    text. A NoEcho parameter is returned masked as '****' and is skipped; an
    SSM parameter-type parameter (ResolvedValue present) holds a parameter
    NAME, not the value, and is skipped; a dynamic reference or ARN is skipped.
    """
    found = []
    for p in stack.get('Parameters') or []:
        key = p.get('ParameterKey') or ''
        if not key or not SECRET_NAME_RE.search(key):
            continue
        if SECRET_NAME_EXCLUDE_RE.search(key):
            continue
        if p.get('UsePreviousValue') and 'ParameterValue' not in p:
            continue
        if 'ResolvedValue' in p:
            continue
        value = p.get('ParameterValue')
        if not isinstance(value, str):
            continue
        v = value.strip()
        if v.lower() in NON_SECRET_VALUES:
            continue
        if set(v) == {'*'}:
            continue
        if v.startswith('{{resolve:') or v.startswith('arn:'):
            continue
        found.append(key)
    return found


class CloudformationStack(Evaluator):
    """
    Per-stack AWS CloudFormation checks (11).

    Input:
      stack -- a describe_stacks entry plus '_region', '_tags' and
               '_stackPolicy', from services/cloudformation/Cloudformation.py.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.

    Review-mandated corrections applied:
      - drift is read from DriftInformation.StackDriftStatus, which
        describe_stacks already returns. detect_stack_drift is NOT called: it is
        a write operation that initiates a billed async detection run.
      - cfnDriftNeverChecked added, because NOT_CHECKED is the common real-world
        value and is a distinct (and arguably more useful) finding from DRIFTED.
      - cfnIAMCapabilityGranted demoted to INFO (most stacks legitimately need
        CAPABILITY_IAM).
      - cfnNestedStacksDeep DROPPED: 'depth > 3' is an arbitrary threshold with
        no AWS guidance behind it, and computing true depth needs recursive
        ParentId resolution across every stack. Nested stacks are skipped at
        discovery instead.
    """

    ## A stack untouched for longer than this is worth reviewing: either it is
    ## abandoned, or its template has drifted from how the account is now run.
    STALE_DAYS = 365

    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, stack, cfnClient):
        super().__init__()
        self.stack = stack
        self.cfnClient = cfnClient

        self.name = stack.get('StackName', 'unknown')
        self._resourceName = self.name

        self.status = stack.get('StackStatus') or ''
        self.driftInfo = stack.get('DriftInformation') or {}
        self.stackPolicy = stack.get('_stackPolicy')
        self.tags = stack.get('_tags') or []
        self.capabilities = stack.get('Capabilities') or []

        self.addII('stackName', self.name)
        self.addII('region', stack.get('_region', 'N/A'))
        self.addII('stackStatus', self.status or 'N/A')
        self.addII('driftStatus',
                   self.driftInfo.get('StackDriftStatus', 'N/A'))
        self.addII('terminationProtection',
                   str(stack.get('EnableTerminationProtection', 'N/A')))
        self.addII('capabilities', ', '.join(self.capabilities) or 'none')
        self.addII('notificationCount',
                   str(len(stack.get('NotificationARNs') or [])))
        self.addII('lastUpdated',
                   self._formatDate(stack.get('LastUpdatedTime')
                                    or stack.get('CreationTime')))
        self.addII('tagCount', str(len(self.tags)))

    # ------------------------------------------------------------------ #
    # 1. Termination protection
    # ------------------------------------------------------------------ #
    def _checkCfnTerminationProtectionDisabled(self):
        if self.stack.get('EnableTerminationProtection') is True:
            self.results['cfnTerminationProtectionDisabled'] = [
                1, f"Stack '{self.name}' has termination protection enabled"
            ]
        else:
            self.results['cfnTerminationProtectionDisabled'] = [
                -1,
                f"Stack '{self.name}' has termination protection disabled — a "
                "single delete-stack call removes every resource it manages, and "
                "for a stack that owns a database or a bucket that is "
                "unrecoverable"
            ]

    # ------------------------------------------------------------------ #
    # 2. Drift detected
    # ------------------------------------------------------------------ #
    def _checkCfnDriftDetected(self):
        """
        Reads the DriftInformation that describe_stacks already returned. Does
        NOT call detect_stack_drift — see the class docstring.
        """
        drift = self.driftInfo.get('StackDriftStatus')
        if drift == 'DRIFTED':
            checked = self._formatDate(self.driftInfo.get('LastCheckTimestamp'))
            self.results['cfnDriftDetected'] = [
                -1,
                f"Stack '{self.name}' is DRIFTED (last checked {checked}) — the "
                "live resources no longer match the template, so the template is "
                "not a reliable description of what is deployed and the next "
                "update may revert or clash with the manual change"
            ]
        elif drift == 'IN_SYNC':
            self.results['cfnDriftDetected'] = [
                1, f"Stack '{self.name}' is IN_SYNC with its template"
            ]
        else:
            ## NOT_CHECKED / UNKNOWN is reported by cfnDriftNeverChecked.
            self.results['cfnDriftDetected'] = [
                0,
                f"Stack '{self.name}' drift status is {drift or 'not reported'} — "
                "see cfnDriftNeverChecked"
            ]

    # ------------------------------------------------------------------ #
    # 3. Drift never checked
    # ------------------------------------------------------------------ #
    def _checkCfnDriftNeverChecked(self):
        drift = self.driftInfo.get('StackDriftStatus')
        if drift in ('DRIFTED', 'IN_SYNC'):
            self.results['cfnDriftNeverChecked'] = [
                1,
                f"Stack '{self.name}' has been checked for drift (status {drift})"
            ]
        else:
            self.results['cfnDriftNeverChecked'] = [
                -1,
                f"Stack '{self.name}' has never been checked for drift (status "
                f"{drift or 'NOT_CHECKED'}) — whether the live resources still "
                "match the template is simply unknown, so infrastructure-as-code "
                "provides no assurance about this stack"
            ]

    # ------------------------------------------------------------------ #
    # 4. Failed rollback
    # ------------------------------------------------------------------ #
    def _checkCfnRollbackFailed(self):
        if 'ROLLBACK_FAILED' in self.status:
            self.results['cfnRollbackFailed'] = [
                -1,
                f"Stack '{self.name}' is in {self.status} — a failed rollback "
                "leaves the stack in an inconsistent state that blocks all further "
                "updates until it is manually continued or the stack is recreated"
            ]
        elif self.status.endswith('_FAILED'):
            self.results['cfnRollbackFailed'] = [
                -1,
                f"Stack '{self.name}' is in {self.status} — the last operation did "
                "not complete, so the deployed resources may not match the "
                "template"
            ]
        else:
            self.results['cfnRollbackFailed'] = [
                1, f"Stack '{self.name}' is in {self.status}"
            ]

    # ------------------------------------------------------------------ #
    # 5. No stack policy
    # ------------------------------------------------------------------ #
    def _checkCfnStackPolicyMissing(self):
        ## get_stack_policy is sampled (see Cloudformation.STACK_POLICY_SAMPLE_LIMIT)
        ## because it has no bulk API and costs ~1s per stack. Stacks beyond the
        ## cap report INFO saying so, rather than a guessed pass or fail.
        if self.stack.get('_stackPolicyNotSampled'):
            self.results['cfnStackPolicyMissing'] = [
                0,
                f"Stack policy for '{self.name}' was not sampled — the lookup "
                "needs one API call per stack and is capped; re-run against this "
                "stack specifically if the answer matters"
            ]
        elif self.stackPolicy is None:
            self.results['cfnStackPolicyMissing'] = [
                0, f"Stack policy for '{self.name}' could not be read"
            ]
        elif self.stackPolicy:
            self.results['cfnStackPolicyMissing'] = [
                1, f"Stack '{self.name}' has a stack policy"
            ]
        else:
            self.results['cfnStackPolicyMissing'] = [
                -1,
                f"Stack '{self.name}' has no stack policy — nothing prevents a "
                "routine update from replacing or deleting a stateful resource "
                "such as a database, which a stack policy exists to protect "
                "against"
            ]

    # ------------------------------------------------------------------ #
    # 6. No rollback configuration
    # ------------------------------------------------------------------ #
    def _checkCfnNoRollbackConfiguration(self):
        rollback = self.stack.get('RollbackConfiguration') or {}
        alarms = rollback.get('RollbackTriggers') or []
        window = rollback.get('MonitoringTimeInMinutes')

        if alarms:
            self.results['cfnNoRollbackConfiguration'] = [
                1,
                f"Stack '{self.name}' monitors {len(alarms)} rollback trigger(s)"
                + (f" for {window} minute(s)" if window else "")
            ]
        else:
            self.results['cfnNoRollbackConfiguration'] = [
                -1,
                f"Stack '{self.name}' has no rollback triggers — a deployment that "
                "succeeds structurally but breaks the application is not rolled "
                "back automatically, because nothing is watching an alarm during "
                "the update"
            ]

    # ------------------------------------------------------------------ #
    # 7. No notifications
    # ------------------------------------------------------------------ #
    def _checkCfnNoNotifications(self):
        arns = self.stack.get('NotificationARNs') or []
        if arns:
            self.results['cfnNoNotifications'] = [
                1, f"Stack '{self.name}' notifies {len(arns)} SNS topic(s)"
            ]
        else:
            self.results['cfnNoNotifications'] = [
                -1,
                f"Stack '{self.name}' has no NotificationARNs — stack events, "
                "including a failed update or an unexpected resource replacement, "
                "are visible only to somebody watching the console at the time"
            ]

    # ------------------------------------------------------------------ #
    # 8. Stale stack
    # ------------------------------------------------------------------ #
    def _checkCfnOldStackUnupdated(self):
        when = self.stack.get('LastUpdatedTime') or self.stack.get('CreationTime')
        days = self._ageInDays(when)
        if days is None:
            self.results['cfnOldStackUnupdated'] = [
                0, f"Stack '{self.name}' reports no update or creation time"
            ]
        elif days > self.STALE_DAYS:
            self.results['cfnOldStackUnupdated'] = [
                -1,
                f"Stack '{self.name}' has not been updated in {days} days — its "
                "template encodes the practices and AMIs of that time, and nobody "
                "has verified since then that redeploying it would still work"
            ]
        else:
            self.results['cfnOldStackUnupdated'] = [
                1, f"Stack '{self.name}' was last updated {days} day(s) ago"
            ]

    # ------------------------------------------------------------------ #
    # 9. IAM capability granted
    # ------------------------------------------------------------------ #
    def _checkCfnIAMCapabilityGranted(self):
        """
        INFO, not FAIL. Any stack that creates a role or policy legitimately
        requires CAPABILITY_IAM, which is most stacks. Reported so that stacks
        able to mint IAM principals can be identified during a privilege review.
        """
        iamCaps = [c for c in self.capabilities if 'IAM' in c]
        if iamCaps:
            self.results['cfnIAMCapabilityGranted'] = [
                0,
                f"Stack '{self.name}' was deployed with "
                + self._joinNames(iamCaps)
                + " — it can create IAM identities and policies, so its template "
                "is part of the account's privilege surface"
            ]
        else:
            self.results['cfnIAMCapabilityGranted'] = [
                1, f"Stack '{self.name}' has no IAM capability"
            ]

    # ------------------------------------------------------------------ #
    # 10. No tags
    # ------------------------------------------------------------------ #
    def _checkCfnNoTags(self):
        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['cfnNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['cfnNoTags'] = [
                -1,
                f"Stack '{self.name}' has no tags — CloudFormation propagates "
                "stack tags to every resource it creates, so tagging the stack is "
                "the cheapest way to tag a whole deployment at once"
            ]

    # ------------------------------------------------------------------ #
    # 11. Secret-like parameters visible in clear text
    # ------------------------------------------------------------------ #
    def _checkCfnPlaintextSecretParams(self):
        """
        Reads the Parameters describe_stacks already returned. The parameter
        VALUE is never copied into the message, only its key.
        """
        params = self.stack.get('Parameters') or []
        exposed = plaintextSecretParams(self.stack)
        if exposed:
            self.results['cfnPlaintextSecretParams'] = [
                -1,
                f"Stack '{self.name}' returns secret-like parameter(s) "
                + self._joinNames(exposed)
                + " in clear text — anyone allowed cloudformation:DescribeStacks "
                "can read the value. Declare them NoEcho, or better, resolve the "
                "secret from Secrets Manager or SSM SecureString with a dynamic "
                "reference"
            ]
        elif params:
            self.results['cfnPlaintextSecretParams'] = [
                1,
                f"Stack '{self.name}' has no secret-like parameter returned in "
                "clear text"
            ]
        else:
            self.results['cfnPlaintextSecretParams'] = [
                1, f"Stack '{self.name}' has no parameters"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _ageInDays(self, value):
        if not isinstance(value, datetime):
            return None
        when = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - when).days

    def _formatDate(self, value):
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d')
        return 'never'

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown

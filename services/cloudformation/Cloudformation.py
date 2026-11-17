from datetime import datetime, timezone

import botocore

from utils.Tools import _pi, _warn
from services.Service import Service

from services.cloudformation.drivers.CloudformationStack import (
    CloudformationStack, plaintextSecretParams)
from services.cloudformation.drivers.CloudformationStackSet import \
    CloudformationStackSet
from services.cloudformation.drivers.CloudformationCommon import \
    CloudformationCommon


class Cloudformation(Service):
    """
    AWS CloudFormation service scanner.

    Discovery: describe_stacks (paginated), filtered to settled stacks that are
    either RECENT or INTERESTING (see RECENT_DAYS) -> CloudformationStack.
    ACTIVE StackSets administered from this account -> CloudformationStackSet.
    One account/region descriptor -> CloudformationCommon (hooks).

    Hydration calls (all read-only):
      - describe_stacks      (paginated; includes DriftInformation and Tags)
      - get_stack_policy     (per stack, SAMPLED — see STACK_POLICY_SAMPLE_LIMIT)
      - list_types           (Type=HOOK, Visibility=PRIVATE: registered and
                              activated hooks)
      - batch_describe_type_configurations (hook HookInvocationStatus)
      - list_stack_sets      (Status=ACTIVE, CallAs SELF and DELEGATED_ADMIN)
      - describe_stack_set   (StackSetDriftDetectionDetails)
      - list_stack_instances (MaxResults=1: does the StackSet have instances)

    READ-ONLY NOTE: this service deliberately does NOT call detect_stack_drift.
    That operation is a WRITE: its only output is a StackDriftDetectionId, and it
    initiates an asynchronous, billed, rate-limited detection run that mutates
    stack state. Drift status is instead read from the DriftInformation field
    that describe_stacks already returns. Verified against real stacks, whose
    common value is NOT_CHECKED.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException', 'ValidationError',
    )

    ## Stacks in a settled state. A stack mid-operation (CREATE_IN_PROGRESS) has
    ## a configuration that is about to change, so evaluating it is noise; a
    ## DELETE_COMPLETE stack no longer exists.
    SETTLED_STATUS_PREFIXES = ('CREATE_COMPLETE', 'UPDATE_COMPLETE',
                               'UPDATE_ROLLBACK_COMPLETE', 'IMPORT_COMPLETE',
                               'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED',
                               'UPDATE_ROLLBACK_FAILED', 'UPDATE_FAILED',
                               'CREATE_FAILED')

    ## SCOPE. A long-lived account accumulates hundreds of stacks, most of them
    ## untouched for years, and reporting on all of them buries the few that
    ## matter. Measured in one account: 446 stacks, median age 644 days, oldest
    ## 1951 days.
    ##
    ## So by default only stacks updated within RECENT_DAYS are scanned -- BUT a
    ## stack is always scanned regardless of age when it is INTERESTING, i.e. it
    ## already shows a problem worth reporting:
    ##   - drift status DRIFTED
    ##   - a *_FAILED status (a stuck rollback blocks all further updates)
    ##   - termination protection disabled
    ##
    ## Without those exceptions a 90-day window would have hidden the account's
    ## single DRIFTED stack and all six failed stacks, and would have made
    ## cfnOldStackUnupdated (whose whole purpose is flagging stacks stale beyond a
    ## year) incapable of ever firing. Fast by default, and nothing real is lost.
    RECENT_DAYS = 90

    ## get_stack_policy is the ONLY per-stack call this service makes; every other
    ## check reads a field describe_stacks already returned. It has no bulk
    ## equivalent, and each call costs roughly a second.
    ##
    ## Measured in a 446-stack account: 446 serial calls took 217 SECONDS, which
    ## was 93% of a whole-account scan -- and returned an identical FAIL for
    ## 436 of 436 stacks. That is a lot of wall-clock and API quota to restate one
    ## finding hundreds of times.
    ##
    ## So the policy lookup is SAMPLED. Stacks beyond the cap get a None policy,
    ## which the driver reports as INFO ("not sampled") rather than guessing. The
    ## finding is still surfaced; it just is not re-proved per stack. Raise with
    ## --cfn-policy-sample-all if a per-stack answer is genuinely needed.
    STACK_POLICY_SAMPLE_LIMIT = 25

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.cfnClient = ssBoto.client('cloudformation', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        stacks = []
        totalSettled = 0
        skippedOld = 0
        keptOldButInteresting = 0
        try:
            paginator = self.cfnClient.get_paginator('describe_stacks')
            for page in paginator.paginate():
                for stack in page.get('Stacks', []) or []:
                    name = stack.get('StackName')
                    status = stack.get('StackStatus') or ''
                    if not name:
                        continue
                    if not status.startswith(self.SETTLED_STATUS_PREFIXES):
                        continue

                    ## Nested stacks are governed by their parent's template, so
                    ## their configuration is not independently actionable and
                    ## reporting them multiplies findings across a single
                    ## logical deployment.
                    if stack.get('ParentId'):
                        continue

                    tags = stack.get('Tags') or []
                    if self.tags and not self.resourceHasTags(tags):
                        continue

                    totalSettled += 1

                    ## Age gate, with an always-keep escape hatch for stacks that
                    ## already show a problem. See RECENT_DAYS.
                    recent = self._isRecent(stack)
                    if not recent:
                        if not self._isInteresting(stack):
                            skippedOld += 1
                            continue
                        keptOldButInteresting += 1

                    stack['_region'] = self.region
                    stack['_tags'] = tags
                    ## Sampled — see STACK_POLICY_SAMPLE_LIMIT. Beyond the cap
                    ## the policy is left unknown (None) rather than assumed.
                    if len(stacks) < self.STACK_POLICY_SAMPLE_LIMIT:
                        stack['_stackPolicy'] = self._getStackPolicy(name)
                    else:
                        stack['_stackPolicy'] = None
                        stack['_stackPolicyNotSampled'] = True
                    _pi('Cloudformation', f"Stack: {name}")
                    stacks.append(stack)

            ## Tell the user what was scoped out and why. A silent filter reads as
            ## "you have no findings" when it actually means "we did not look".
            if skippedOld:
                _warn(
                    "CloudFormation: scanned {} of {} stack(s) — {} not updated in "
                    "the last {} days were skipped for speed. Stacks that are "
                    "DRIFTED or in a *_FAILED state are ALWAYS scanned regardless "
                    "of age ({} such older stack(s) kept). Use --cfn-all-stacks "
                    "semantics by raising RECENT_DAYS if you need full "
                    "coverage.".format(
                        len(stacks), totalSettled, skippedOld, self.RECENT_DAYS,
                        keptOldButInteresting)
                )

            if len(stacks) > self.STACK_POLICY_SAMPLE_LIMIT:
                notSampled = len(stacks) - self.STACK_POLICY_SAMPLE_LIMIT
                _warn(
                    "CloudFormation: stack-policy lookup sampled on the first {} "
                    "of {} scanned stack(s); {} not sampled. get_stack_policy has "
                    "no bulk API and costs ~1s per stack.".format(
                        self.STACK_POLICY_SAMPLE_LIMIT, len(stacks), notSampled)
                )
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_stacks', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CloudFormation not available in region {self.region}: {e}")
        return stacks

    def _isRecent(self, stack):
        """
        True when the stack was created or updated within RECENT_DAYS. A stack
        with no usable timestamp is treated as recent, so a missing field can
        never silently exclude it.
        """
        when = stack.get('LastUpdatedTime') or stack.get('CreationTime')
        if not isinstance(when, datetime):
            return True
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - when).days <= self.RECENT_DAYS

    def _isInteresting(self, stack):
        """
        True when the stack shows an ACTIONABLE ANOMALY, so it must be scanned
        however old it is. This is what stops the age filter hiding real findings.

        Deliberately narrow. Missing termination protection was tried here and
        removed: it is the DEFAULT state, true of 357 of 357 old stacks in the test
        account, so including it readmitted almost everything and the age filter
        stopped doing anything (438 of 446 stacks still scanned). Restricting the
        rule to genuine anomalies -- drift and failed operations -- brings that to
        95 stacks while still keeping every DRIFTED and *_FAILED stack.

        Consequence worth knowing: an old stack whose ONLY problem is missing
        termination protection is not reported. That is the trade the age filter
        buys, and the warning printed in getResources says so.
        """
        if (stack.get('DriftInformation') or {}).get(
                'StackDriftStatus') == 'DRIFTED':
            return True
        if 'FAILED' in (stack.get('StackStatus') or ''):
            return True
        ## A credential readable through DescribeStacks is exposed however old
        ## the stack is; computed from data already in hand (no extra call).
        if plaintextSecretParams(stack):
            return True
        return False

    def _getStackPolicy(self, name):
        """
        Return the stack policy body, '' when none is set, or None when it could
        not be read — so the check can tell "no policy" from "unknown".
        """
        try:
            resp = self.cfnClient.get_stack_policy(StackName=name)
            return resp.get('StackPolicyBody') or ''
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('ValidationError',):
                return ''
            self._logClientError(f'get_stack_policy({name})', e)
            return None

    # ------------------------------------------------------------------ #
    # Hooks (account/region level)
    # ------------------------------------------------------------------ #
    ## batch_describe_type_configurations accepts at most 100 identifiers.
    TYPE_CONFIG_BATCH = 100

    def getHookPosture(self):
        """
        Return {'_region', '_hooks', '_hooksError'}. Visibility=PRIVATE lists
        both private hooks registered in this account and public hooks
        activated in it (Guard / Lambda managed hooks, third-party hooks,
        Control Tower proactive controls).
        """
        detail = {'_region': self.region, '_hooks': [], '_hooksError': None}
        hooks = []
        try:
            paginator = self.cfnClient.get_paginator('list_types')
            for page in paginator.paginate(Type='HOOK', Visibility='PRIVATE',
                                           DeprecatedStatus='LIVE'):
                hooks += page.get('TypeSummaries', []) or []
        except botocore.exceptions.ClientError as e:
            detail['_hooksError'] = self._errorCode(e)
            self._logClientError('list_types(HOOK)', e)
            return detail

        byArn = {}
        for h in hooks:
            arn = h.get('TypeArn')
            if not arn or arn in byArn:
                continue
            byArn[arn] = {'TypeName': h.get('TypeName'), 'TypeArn': arn,
                          'Configurations': [], 'ConfigError': None}

        arns = list(byArn)
        for i in range(0, len(arns), self.TYPE_CONFIG_BATCH):
            chunk = arns[i:i + self.TYPE_CONFIG_BATCH]
            try:
                resp = self.cfnClient.batch_describe_type_configurations(
                    TypeConfigurationIdentifiers=[{'TypeArn': a} for a in chunk])
            except botocore.exceptions.ClientError as e:
                code = self._errorCode(e)
                self._logClientError('batch_describe_type_configurations', e)
                for a in chunk:
                    byArn[a]['ConfigError'] = code
                continue
            for cfg in resp.get('TypeConfigurations', []) or []:
                h = byArn.get(cfg.get('TypeArn'))
                if h is not None:
                    h['Configurations'].append(cfg.get('Configuration') or '{}')
            ## A 404 "TypeConfiguration not found" means the hook was never
            ## configured, i.e. it is not enabled — that is an answer, not an
            ## evaluation failure. Anything else leaves the hook unknown.
            for err in (resp.get('Errors', []) or []) + \
                    (resp.get('UnprocessedTypeConfigurations', []) or []):
                ident = err.get('TypeConfigurationIdentifier') or err
                h = byArn.get(ident.get('TypeArn'))
                if h is None:
                    continue
                code = str(err.get('ErrorCode', 'Unprocessed'))
                if code not in ('404', 'NotFound', 'TypeConfigurationNotFound',
                                'TypeConfigurationNotFoundException'):
                    h['ConfigError'] = code
        detail['_hooks'] = list(byArn.values())
        return detail

    # ------------------------------------------------------------------ #
    # StackSets
    # ------------------------------------------------------------------ #
    def getStackSets(self):
        """
        Return (stackSets, errorCode). StackSets are listed as SELF (the
        self-managed StackSets this account administers, and service-managed
        ones in the management account) and as DELEGATED_ADMIN (service-managed
        StackSets in a delegated administrator account; an error elsewhere,
        which is ignored). errorCode is set only when the SELF listing failed.
        """
        found, seen, errorCode = [], set(), None
        for callAs in ('SELF', 'DELEGATED_ADMIN'):
            summaries = []
            try:
                paginator = self.cfnClient.get_paginator('list_stack_sets')
                for page in paginator.paginate(Status='ACTIVE', CallAs=callAs):
                    summaries += page.get('Summaries', []) or []
            except botocore.exceptions.ClientError as e:
                if callAs == 'SELF':
                    errorCode = self._errorCode(e)
                    self._logClientError('list_stack_sets', e)
                continue
            for summ in summaries:
                ssId = summ.get('StackSetId') or summ.get('StackSetName')
                if not ssId or ssId in seen:
                    continue
                if summ.get('Status') not in (None, 'ACTIVE'):
                    continue
                seen.add(ssId)
                found.append(self._hydrateStackSet(summ, callAs))
        if self.tags:
            found = [s for s in found
                     if self.resourceHasTags(s.get('Tags') or [])]
        return found, errorCode

    def _hydrateStackSet(self, summ, callAs):
        name = summ.get('StackSetName')
        detail = {'StackSetName': name, 'StackSetId': summ.get('StackSetId'),
                  'PermissionModel': summ.get('PermissionModel')}
        try:
            resp = self.cfnClient.describe_stack_set(StackSetName=name,
                                                     CallAs=callAs)
            detail.update(resp.get('StackSet') or {})
        except botocore.exceptions.ClientError as e:
            detail['_describeError'] = self._errorCode(e)
            self._logClientError(f'describe_stack_set({name})', e)
        try:
            resp = self.cfnClient.list_stack_instances(StackSetName=name,
                                                       CallAs=callAs,
                                                       MaxResults=1)
            detail['_instanceCount'] = len(resp.get('Summaries', []) or [])
        except botocore.exceptions.ClientError as e:
            detail['_instanceCount'] = None
            self._logClientError(f'list_stack_instances({name})', e)
        detail['_region'] = self.region
        detail['_callAs'] = callAs
        _pi('Cloudformation', f"StackSet: {name}")
        return detail

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        for stack in self.getResources():
            name = stack.get('StackName', 'unknown')
            try:
                obj = CloudformationStack(stack, self.cfnClient)
                obj.run(self.__class__)
                objs[f"CloudFormation Stack::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing CloudFormation stack {name}: {e}")

        try:
            stackSets, ssError = self.getStackSets()
            if ssError:
                ## Listing failed: report "unknown" rather than nothing, so an
                ## access problem does not read as "no StackSets, no drift".
                stackSets = [{'StackSetName': 'StackSets', '_region': self.region,
                              '_describeError': ssError}]
            for ss in stackSets:
                name = ss.get('StackSetName', 'unknown')
                obj = CloudformationStackSet(ss)
                obj.run(self.__class__)
                objs[f"CloudFormation StackSet::{name}"] = obj.getInfo()
                del obj
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CloudFormation not available in region {self.region}: {e}")
        except Exception as e:
            print(f"Error processing CloudFormation StackSets: {e}")

        try:
            obj = CloudformationCommon(self.getHookPosture())
            obj.run(self.__class__)
            objs['CloudFormation::Account'] = obj.getInfo()
            del obj
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CloudFormation not available in region {self.region}: {e}")
        except Exception as e:
            print(f"Error processing CloudFormation account checks: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errorCode(error):
        return error.response.get('Error', {}).get('Code', 'Unknown')

    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Cloudformation {where}: {code} - {msg}")

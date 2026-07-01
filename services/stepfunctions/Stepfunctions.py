import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

from services.stepfunctions.drivers.StepfunctionsCommon import StepfunctionsCommon


class Stepfunctions(Service):
    """
    AWS Step Functions service scanner.

    Discovers every state machine in the region via list_state_machines and
    hydrates each with:
      - describe_state_machine (definition + logging/tracing/encryption config)
      - list_tags_for_resource (tag-based governance)
      - list_executions (single-page recency probe for the unused check)
      - validate_state_machine_definition (structural validation)
      - iam.get_role                     (execution role existence check)
      - logs.describe_log_groups         (log-group existence check when logging on)
    """

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.sfnClient = ssBoto.client('stepfunctions', config=self.bConfig)
        # IAM is global but the client honours regional signing; used for role analysis.
        self.iamClient = ssBoto.client('iam', config=self.bConfig)
        # CloudWatch Logs client for log-group existence probe (check #24).
        self.logsClient = ssBoto.client('logs', config=self.bConfig)
        # CloudWatch client for alarm coverage check (#26).
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        stateMachines = []
        try:
            paginator = self.sfnClient.get_paginator('list_state_machines')
            for page in paginator.paginate():
                for summary in page.get('stateMachines', []):
                    arn = summary.get('stateMachineArn')
                    if not arn:
                        continue
                    detail = self._describeStateMachine(arn)
                    if detail is None:
                        continue

                    # Tag filtering (respects --tags flag)
                    if self.tags:
                        tags = self._listTags(arn)
                        if not self.resourceHasTags(tags):
                            continue
                        detail['_tags'] = tags
                    else:
                        detail['_tags'] = self._listTags(arn)

                    detail['_mostRecentExecution'] = self._mostRecentExecution(arn)
                    detail['_validationResult'] = self._validateDefinition(detail)
                    detail['_roleExists'] = self._roleExistsFor(detail.get('roleArn'))
                    detail['_logGroupExists'] = self._logGroupExistsFor(detail)
                    detail['_currentAccount'] = self._currentAccount()
                    detail['_rolePolicies'] = self._fetchRolePolicies(detail.get('roleArn'))
                    detail['_hasFailureAlarms'] = self._hasFailureAlarms(arn)

                    _pi('Stepfunctions', f"State machine: {detail.get('name', arn)}")
                    stateMachines.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_state_machines', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Step Functions not available in region {self.region}: {e}")
        return stateMachines

    def _describeStateMachine(self, arn):
        try:
            return self.sfnClient.describe_state_machine(stateMachineArn=arn)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_state_machine({arn})', e)
            return None

    def _listTags(self, arn):
        try:
            resp = self.sfnClient.list_tags_for_resource(resourceArn=arn)
            return resp.get('tags', [])
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_resource({arn})', e)
            return []

    def _mostRecentExecution(self, arn):
        """Return the startDate of the most recent execution, or None if none exist / call fails."""
        try:
            resp = self.sfnClient.list_executions(stateMachineArn=arn, maxResults=1)
            executions = resp.get('executions', [])
            if not executions:
                return None
            return executions[0].get('startDate')
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_executions({arn})', e)
            return None

    # ------------------------------------------------------------------ #
    # Phase-1 extension APIs (checks 17-24)
    # ------------------------------------------------------------------ #
    def _validateDefinition(self, detail):
        """Return the ValidateStateMachineDefinition response, or {} on failure."""
        definition = detail.get('definition')
        smType = detail.get('type', 'STANDARD')
        if not definition:
            return {}
        try:
            return self.sfnClient.validate_state_machine_definition(
                definition=definition, type=smType
            )
        except botocore.exceptions.ClientError as e:
            self._logClientError('validate_state_machine_definition', e)
            return {}

    def _roleExistsFor(self, roleArn):
        """
        Return a status string:
          'exists'          - iam:GetRole succeeded
          'missing'         - iam returned NoSuchEntity
          'cross_account'   - role belongs to a different account (skipped)
          'unknown'         - lookup could not complete (AccessDenied etc.)
        """
        if not roleArn or ':role/' not in roleArn:
            return 'unknown'

        # ARN: arn:aws:iam::<acct>:role/<name>
        parts = roleArn.split(':')
        if len(parts) < 5:
            return 'unknown'
        acct = parts[4]
        me = self._currentAccount()
        if me and acct != me:
            return 'cross_account'

        roleName = roleArn.split(':role/', 1)[1].split('/')[-1]
        try:
            self.iamClient.get_role(RoleName=roleName)
            return 'exists'
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('NoSuchEntity', 'NoSuchEntityException'):
                return 'missing'
            if code in ('AccessDenied', 'AccessDeniedException',
                        'UnauthorizedOperation'):
                return 'unknown'
            self._logClientError(f'iam.get_role({roleName})', e)
            return 'unknown'

    def _logGroupExistsFor(self, detail):
        """
        For state machines with logging enabled, verify the CloudWatch log
        group ARN exists. Returns:
          None    - logging not configured for this SM (check is N/A)
          True    - log group exists
          False   - log group does not exist (config drift)
          'unknown' - lookup could not complete
        """
        cfg = detail.get('loggingConfiguration') or {}
        dests = cfg.get('destinations') or []
        if not dests:
            return None

        # destinations[0].cloudWatchLogsLogGroup.logGroupArn
        log_group_arn = None
        for d in dests:
            cwlg = d.get('cloudWatchLogsLogGroup') or {}
            arn = cwlg.get('logGroupArn')
            if arn:
                log_group_arn = arn
                break
        if not log_group_arn:
            return None

        # Log-group ARN: arn:aws:logs:region:account:log-group:<name>[:*]
        try:
            name = log_group_arn.split(':log-group:', 1)[1].rstrip(':*').rstrip(':')
        except IndexError:
            return 'unknown'

        try:
            resp = self.logsClient.describe_log_groups(logGroupNamePrefix=name)
            groups = resp.get('logGroups', []) or []
            for g in groups:
                if g.get('logGroupName') == name:
                    return True
            return False
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('AccessDenied', 'AccessDeniedException'):
                return 'unknown'
            self._logClientError(f'logs.describe_log_groups({name})', e)
            return 'unknown'

    def _currentAccount(self):
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    def _fetchRolePolicies(self, roleArn):
        """Return a list of policy documents (parsed JSON) attached to the SM's role.
        Same-account only; cross-account or missing roles → empty list."""
        import json as _json
        if not roleArn or ':role/' not in roleArn:
            return []
        parts = roleArn.split(':')
        if len(parts) >= 5:
            acct = parts[4]
            me = self._currentAccount()
            if me and acct and acct != me:
                return []
        roleName = roleArn.split(':role/', 1)[1].split('/')[-1]
        docs = []
        try:
            inline = self.iamClient.list_role_policies(RoleName=roleName)
            for policyName in inline.get('PolicyNames', []) or []:
                try:
                    p = self.iamClient.get_role_policy(
                        RoleName=roleName, PolicyName=policyName
                    )
                    doc = p.get('PolicyDocument')
                    if isinstance(doc, str):
                        try: doc = _json.loads(doc)
                        except (ValueError, TypeError): doc = None
                    if isinstance(doc, dict):
                        docs.append(doc)
                except botocore.exceptions.ClientError:
                    continue
            attached = self.iamClient.list_attached_role_policies(RoleName=roleName)
            for p in attached.get('AttachedPolicies', []) or []:
                arn = p.get('PolicyArn')
                if not arn:
                    continue
                try:
                    pol = self.iamClient.get_policy(PolicyArn=arn)
                    versionId = (pol.get('Policy') or {}).get('DefaultVersionId')
                    if not versionId:
                        continue
                    ver = self.iamClient.get_policy_version(
                        PolicyArn=arn, VersionId=versionId
                    )
                    doc = (ver.get('PolicyVersion') or {}).get('Document')
                    if isinstance(doc, str):
                        try: doc = _json.loads(doc)
                        except (ValueError, TypeError): doc = None
                    if isinstance(doc, dict):
                        docs.append(doc)
                except botocore.exceptions.ClientError:
                    continue
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code not in ('AccessDenied', 'AccessDeniedException',
                            'NoSuchEntity', 'NoSuchEntityException'):
                self._logClientError(f'iam policy fetch for role {roleName}', e)
        return docs

    def _hasFailureAlarms(self, smArn):
        """Return True if there's at least one CloudWatch alarm on any of the
        failure-related SFN metrics (ExecutionsFailed, ExecutionsTimedOut,
        ExecutionsAborted) whose Dimensions target this state machine."""
        for metric in ('ExecutionsFailed', 'ExecutionsTimedOut', 'ExecutionsAborted'):
            try:
                resp = self.cwClient.describe_alarms_for_metric(
                    MetricName=metric,
                    Namespace='AWS/States',
                    Dimensions=[{'Name': 'StateMachineArn', 'Value': smArn}],
                )
                if resp.get('MetricAlarms') or resp.get('CompositeAlarms'):
                    return True
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', '')
                if code in ('AccessDenied', 'AccessDeniedException'):
                    return None  # unknown — driver degrades to INFO
                self._logClientError(f'cloudwatch.describe_alarms_for_metric({metric})', e)
        return False

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        stateMachines = self.getResources()

        for sm in stateMachines:
            try:
                name = sm.get('name') or sm.get('stateMachineArn', 'unknown')
                _pi('Stepfunctions', f"Analyzing: {name}")
                obj = StepfunctionsCommon(sm, self.sfnClient, self.iamClient)
                obj.run(self.__class__)
                objs[f"Stepfunctions::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Stepfunctions {sm.get('stateMachineArn')}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Stepfunctions {where}: {code} - {msg}")

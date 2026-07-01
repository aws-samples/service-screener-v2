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
    """

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.sfnClient = ssBoto.client('stepfunctions', config=self.bConfig)
        # IAM is global but the client honours regional signing; used for role analysis.
        self.iamClient = ssBoto.client('iam', config=self.bConfig)

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

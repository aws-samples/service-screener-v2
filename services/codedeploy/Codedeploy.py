import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.codedeploy.drivers.CodedeployDeploymentGroup import CodedeployDeploymentGroup


class Codedeploy(Service):
    """
    AWS CodeDeploy service scanner.

    One check subject: the deployment group (per application). Checks live in
    CodedeployDeploymentGroup.

    Hydration calls (all read-only):
      - list_applications            (paginated)
      - list_deployment_groups       (paginated, per application)
      - batch_get_deployment_groups  (batched, BATCH_SIZE names per call)
      - get_deployment_group         (fallback only, per group, when the batch
                                      call fails or omits a group)
      - list_tags_for_resource       (only when --tags filtering is requested)

    When a deployment group's configuration cannot be read, the group is still
    reported, carrying '_error' = <error code>, so the checks record
    'Unable to evaluate' rather than a silent PASS.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## batch_get_deployment_groups accepts up to 100 group names per call.
    BATCH_SIZE = 100

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.cdClient = ssBoto.client('codedeploy', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        groups = []
        for app in self._listApplications():
            names = self._listDeploymentGroups(app)
            if not names:
                continue

            ids = [f"{app}/{n}" for n in names]
            pending = set(self.registerItems('CodedeployDeploymentGroup', ids))
            toFetch = [n for n in names if f"{app}/{n}" in pending]

            ## Already-checkpointed groups are not re-read, but still need a
            ## lightweight entry so advise() builds the driver and
            ## Evaluator.run() restores their cached results (otherwise a
            ## resumed scan silently drops them from the report).
            for n in names:
                if f"{app}/{n}" not in pending:
                    groups.append({'applicationName': app, 'deploymentGroupName': n,
                                   '_region': self.region})

            for info in self._getDeploymentGroups(app, toFetch):
                if self.tags and not info.get('_error'):
                    tags = self._getTags(app, info.get('deploymentGroupName'))
                    if not self.resourceHasTags(tags):
                        continue
                    info['_tags'] = tags
                info['_region'] = self.region
                _pi('Codedeploy', f"Deployment group: {app}/{info.get('deploymentGroupName')}")
                groups.append(info)
        return groups

    def _listApplications(self):
        apps = []
        try:
            paginator = self.cdClient.get_paginator('list_applications')
            for page in paginator.paginate():
                apps += page.get('applications', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_applications', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CodeDeploy not available in region {self.region}: {e}")
        return apps

    def _listDeploymentGroups(self, app):
        names = []
        try:
            paginator = self.cdClient.get_paginator('list_deployment_groups')
            for page in paginator.paginate(applicationName=app):
                names += page.get('deploymentGroups', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_deployment_groups', e)
        return names

    def _getDeploymentGroups(self, app, names):
        """Return one dict per requested group name: the deploymentGroupInfo,
        or a stub {'applicationName', 'deploymentGroupName', '_error': code}
        when it could not be read."""
        out = []
        for i in range(0, len(names), self.BATCH_SIZE):
            batch = names[i:i + self.BATCH_SIZE]
            found = {}
            try:
                resp = self.cdClient.batch_get_deployment_groups(
                    applicationName=app, deploymentGroupNames=batch)
                for info in resp.get('deploymentGroupsInfo', []) or []:
                    if info.get('deploymentGroupName'):
                        found[info['deploymentGroupName']] = info
            except botocore.exceptions.ClientError as e:
                ## Fall through to per-group get_deployment_group (same IAM
                ## action, codedeploy:GetDeploymentGroup).
                self._logClientError('batch_get_deployment_groups', e)

            for name in batch:
                if name in found:
                    out.append(found[name])
                    continue
                try:
                    info = self.cdClient.get_deployment_group(
                        applicationName=app, deploymentGroupName=name
                    ).get('deploymentGroupInfo') or {}
                    info.setdefault('applicationName', app)
                    info.setdefault('deploymentGroupName', name)
                    out.append(info)
                except botocore.exceptions.ClientError as e:
                    self._logClientError('get_deployment_group', e)
                    out.append({
                        'applicationName': app,
                        'deploymentGroupName': name,
                        '_error': e.response.get('Error', {}).get('Code', 'Unknown'),
                    })
        return out

    def _getTags(self, app, name):
        arn = 'arn:{}:codedeploy:{}:{}:deploymentgroup:{}/{}'.format(
            self._partition(), self.region,
            (Config.get('stsInfo', {}) or {}).get('Account', ''), app, name)
        try:
            resp = self.cdClient.list_tags_for_resource(ResourceArn=arn)
            return resp.get('Tags', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_tags_for_resource', e)
            return []

    def _partition(self):
        if self.region.startswith('cn-'):
            return 'aws-cn'
        if self.region.startswith('us-gov-'):
            return 'aws-us-gov'
        return 'aws'

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        for group in self.getResources():
            name = f"{group.get('applicationName', 'unknown')}/{group.get('deploymentGroupName', 'unknown')}"
            try:
                _pi('Codedeploy', f"Analyzing deployment group: {name}")
                obj = CodedeployDeploymentGroup(group, self.cdClient)
                obj.run(self.__class__)
                objs[f"CodeDeploy DeploymentGroup::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing CodeDeploy deployment group {name}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES or code == 'NotImplemented':
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Codedeploy {where}: {code} - {msg}")

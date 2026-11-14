import botocore

from utils.Tools import _pi
from services.Service import Service

from services.athena.drivers.AthenaWorkgroup import AthenaWorkgroup


class Athena(Service):
    """
    Amazon Athena service scanner.

    Discovery: list_work_groups (paginated) -> get_work_group per workgroup.

    All checks are per-workgroup, so there is one driver.

    Hydration calls (all read-only):
      - list_work_groups
      - get_work_group          (per workgroup)
      - list_tags_for_resource  (per workgroup)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException', 'InvalidRequestException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.athenaClient = ssBoto.client('athena', config=self.bConfig)
        ## Needed to resolve the output-location bucket for the S3 encryption
        ## check. Created here so the driver does not build its own client.
        self.s3Client = ssBoto.client('s3', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        workgroups = []
        try:
            summaries = self._listWorkgroupSummaries()
            pendingNames = {s.get('Name') for s in self.registerItems(
                'AthenaWorkgroup', summaries, idFn=lambda s: s.get('Name')
            )}

            for summary in summaries:
                name = summary.get('Name')
                if not name:
                    continue

                if name not in pendingNames:
                    ## Already checkpointed - skip get_work_group + list_tags_for_resource.
                    ## Inject '_name' so it matches what the driver used as _resourceName
                    ## when this workgroup was originally checkpointed.
                    cached = dict(summary)
                    cached['_name'] = name
                    workgroups.append(cached)
                    continue

                detail = self._getWorkgroup(name, summary)
                if detail is None:
                    continue
                _pi('Athena', f"Workgroup: {name}")
                workgroups.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_work_groups', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Athena not available in region {self.region}: {e}")
        return workgroups

    def _listWorkgroupSummaries(self):
        """
        list_work_groups has no paginator in some botocore versions (verified:
        raises OperationNotPageableError against the installed botocore), so
        page manually with NextToken rather than relying on get_paginator.
        """
        summaries, nextToken = [], None
        while True:
            kwargs = {'MaxResults': 50}
            if nextToken:
                kwargs['NextToken'] = nextToken
            resp = self.athenaClient.list_work_groups(**kwargs)
            summaries += resp.get('WorkGroups', []) or []
            nextToken = resp.get('NextToken')
            if not nextToken:
                break
        return summaries

    def _getWorkgroup(self, name, summary):
        try:
            resp = self.athenaClient.get_work_group(WorkGroup=name)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_work_group({name})', e)
            return None

        detail = resp.get('WorkGroup') or {}
        if not detail:
            return None

        tags = self._listTags(detail.get('WorkGroupArn') or self._buildArn(name),
                             name)

        ## Optional --filters tag filtering.
        if self.tags and not self.resourceHasTags(tags):
            return None

        detail['_name'] = name
        detail['_tags'] = tags
        detail['_region'] = self.region
        return detail

    def _buildArn(self, name):
        from utils.Config import Config
        info = Config.get('stsInfo', {})
        account = info.get('Account') if isinstance(info, dict) else None
        if not account:
            return None
        return f"arn:aws:athena:{self.region}:{account}:workgroup/{name}"

    def _listTags(self, arn, name):
        if not arn:
            return []
        try:
            resp = self.athenaClient.list_tags_for_resource(ResourceARN=arn)
            return resp.get('Tags', []) or []
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('ResourceNotFoundException', 'InvalidRequestException'):
                return []
            self._logClientError(f'list_tags_for_resource({name})', e)
            return []

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        for workgroup in self.getResources():
            name = workgroup.get('_name', 'unknown')
            try:
                _pi('Athena', f"Analyzing workgroup: {name}")
                obj = AthenaWorkgroup(workgroup, self.athenaClient, self.s3Client)
                obj.run(self.__class__)
                objs[f"Athena Workgroup::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Athena workgroup {name}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Athena {where}: {code} - {msg}")

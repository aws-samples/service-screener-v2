import botocore

from utils.Tools import _pi
from services.Service import Service

from services.dms.drivers.DmsEndpoint import DmsEndpoint


class Dms(Service):
    """
    AWS Database Migration Service scanner.

    Discovers every DMS endpoint in the region and runs the per-endpoint
    checks in DmsEndpoint.

    Hydration calls (all read-only):
      - describe_endpoints       (paginated)
      - list_tags_for_resource   (only when --tags filtering is requested)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AccessDeniedFault', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.dmsClient = ssBoto.client('dms', config=self.bConfig)

    def getResources(self):
        endpoints = []
        try:
            paginator = self.dmsClient.get_paginator('describe_endpoints')
            for page in paginator.paginate():
                endpoints.extend(page.get('Endpoints', []) or [])
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_endpoints', e)
            return []
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"DMS not available in region {self.region}: {e}")
            return []

        endpoints = [e for e in endpoints if e.get('EndpointIdentifier')]

        if self.tags:
            filtered = []
            for ep in endpoints:
                try:
                    resp = self.dmsClient.list_tags_for_resource(ResourceArn=ep.get('EndpointArn'))
                except botocore.exceptions.ClientError as e:
                    ## Tags unknown -> cannot prove the endpoint matches the filter.
                    self._logClientError(f"list_tags_for_resource({ep.get('EndpointIdentifier')})", e)
                    continue
                tags = [{'Key': t.get('Key'), 'Value': t.get('Value')}
                        for t in resp.get('TagList', []) or []]
                if self.resourceHasTags(tags):
                    filtered.append(ep)
            endpoints = filtered

        return endpoints

    def advise(self):
        objs = {}
        endpoints = self.getResources()

        for ep in endpoints:
            name = ep.get('EndpointIdentifier')
            try:
                _pi('DMS', f"Endpoint: {name}")
                obj = DmsEndpoint(ep, self.dmsClient)
                obj.run(self.__class__)
                objs[f"Endpoint::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing DMS endpoint {name}: {e}")

        return objs

    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"DMS {where}: {code} - {msg}")

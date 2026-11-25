import botocore

from utils.Tools import _pi
from services.Service import Service

from services.transfer.drivers.TransferServer import TransferServer


class Transfer(Service):
    """
    AWS Transfer Family scanner.

    Discovery (read-only):
      - list_servers    (paginated)
      - describe_server (per server; returns Protocols, SecurityPolicyName, Tags)
    """

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.transferClient = ssBoto.client('transfer', config=self.bConfig)

    def getResources(self):
        servers = []
        try:
            paginator = self.transferClient.get_paginator('list_servers')
            for page in paginator.paginate():
                servers += page.get('Servers', []) or []
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Transfer Family not available in region {self.region}: {e}")
            return []
        except botocore.exceptions.ClientError as e:
            err = e.response.get('Error', {})
            print(f"Transfer list_servers: {err.get('Code')} - {err.get('Message')}")
            return []

        arr = []
        for s in servers:
            serverId = s.get('ServerId')
            if not serverId:
                continue
            detail = {'ServerId': serverId, 'Arn': s.get('Arn'), '_error': None}
            try:
                resp = self.transferClient.describe_server(ServerId=serverId)
                detail.update(resp.get('Server', {}) or {})
            except botocore.exceptions.ClientError as e:
                detail['_error'] = e.response.get('Error', {}).get('Code', 'Unknown')

            if self.tags:
                ## Tags only come from describe_server; if it failed we cannot
                ## tell whether the server matches the filter, so skip it.
                if detail['_error'] or not self.resourceHasTags(detail.get('Tags', [])):
                    continue
            arr.append(detail)
        return arr

    def advise(self):
        objs = {}
        for server in self.getResources():
            serverId = server['ServerId']
            _pi('Transfer', serverId)
            obj = TransferServer(server, self.transferClient)
            obj.run(self.__class__)
            objs[f"Server::{serverId}"] = obj.getInfo()
            del obj
        return objs

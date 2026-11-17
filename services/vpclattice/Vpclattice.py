import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.vpclattice.drivers.VpclatticeServiceNetwork import VpclatticeServiceNetwork
from services.vpclattice.drivers.VpclatticeService import VpclatticeService


class Vpclattice(Service):
    """
    Amazon VPC Lattice service scanner.

    Two resource types, one driver each:
      VpclatticeServiceNetwork -- per service network
      VpclatticeService        -- per service

    Hydration calls (all read-only):
      - list_service_networks / get_service_network (paginated)
      - list_services / get_service                 (paginated)
      - list_tags_for_resource                      (only with --tags filter)
    Driver calls (read-only): get_auth_policy, list_access_log_subscriptions,
    list_service_network_service_associations.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    # CREATE_FAILED resources never became usable. DELETE_FAILED resources are
    # still evaluated: they continue to exist and may still route traffic.
    SKIP_STATUSES = ('DELETE_IN_PROGRESS', 'CREATE_FAILED')

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.latticeClient = ssBoto.client('vpc-lattice', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        return {
            'serviceNetworks': self._list('list_service_networks', 'get_service_network',
                                          'serviceNetworkIdentifier'),
            'services': self._list('list_services', 'get_service', 'serviceIdentifier'),
        }

    def _list(self, listOp, getOp, idParam):
        out = []
        try:
            paginator = self.latticeClient.get_paginator(listOp)
            for page in paginator.paginate():
                for item in page.get('items', []) or []:
                    if item.get('status') in self.SKIP_STATUSES:
                        continue
                    ident = item.get('arn') or item.get('id')
                    if not ident:
                        continue
                    if self.tags and not self.resourceHasTags(self._tags_of(item.get('arn'))):
                        continue
                    detail = dict(item)
                    try:
                        resp = getattr(self.latticeClient, getOp)(**{idParam: ident})
                        resp.pop('ResponseMetadata', None)
                        detail.update(resp)
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(f'{getOp}({ident})', e)
                    _pi('Vpclattice', f"{listOp[5:]}: {detail.get('name', ident)}")
                    out.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError(listOp, e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"VPC Lattice not available in region {self.region}: {e}")
        return out

    def _tags_of(self, arn):
        if not arn:
            return []
        try:
            tags = self.latticeClient.list_tags_for_resource(resourceArn=arn).get('tags', {}) or {}
            return [{'Key': k, 'Value': v} for k, v in tags.items()]
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_resource({arn})', e)
            return []

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        res = self.getResources()
        accountId = (Config.get('stsInfo', {}) or {}).get('Account')

        for sn in res['serviceNetworks']:
            try:
                obj = VpclatticeServiceNetwork(sn, self.latticeClient, accountId)
                obj.run(self.__class__)
                objs[f"ServiceNetwork::{sn.get('name') or sn.get('id')}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing VPC Lattice service network {sn.get('id')}: {e}")

        for svc in res['services']:
            try:
                obj = VpclatticeService(svc, self.latticeClient, accountId)
                obj.run(self.__class__)
                objs[f"Service::{svc.get('name') or svc.get('id')}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing VPC Lattice service {svc.get('id')}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Vpclattice {where}: {code} - {msg}")

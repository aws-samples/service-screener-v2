import botocore

from services.vpclattice.drivers.VpclatticeBase import VpclatticeBase


class VpclatticeService(VpclatticeBase):
    """
    Per VPC Lattice service checks.

    Input: resource = vpc-lattice.get_service output (falls back to the
    list_services summary if get_service failed).

    Access logs: a service-network access log subscription (log type SERVICE)
    records every request routed through that network to the service
    (each entry carries serviceArn), so a service without its own subscription
    is still covered when every network it is associated with logs.
    """

    kindLabel = 'service'

    def __init__(self, resource, client, accountId=None):
        super().__init__(resource, client, accountId)
        self.addII('status', self.resource.get('status'))

    def _checkLatticeAuthTypeNone(self):
        self._evaluateAuthType()

    def _listAssociatedNetworks(self):
        """Return (list of serviceNetwork identifiers, None) or (None, code)."""
        nets = []
        try:
            paginator = self.client.get_paginator('list_service_network_service_associations')
            for page in paginator.paginate(serviceIdentifier=self.identifier):
                for a in page.get('items', []) or []:
                    if a.get('status') in ('DELETE_IN_PROGRESS', 'DELETE_FAILED', 'CREATE_FAILED'):
                        continue
                    ident = a.get('serviceNetworkArn') or a.get('serviceNetworkId')
                    if ident:
                        nets.append(ident)
        except botocore.exceptions.ClientError as e:
            return None, self._errCode(e)
        return nets, None

    def _checkLatticeAccessLogsDisabled(self):
        key = 'latticeAccessLogsDisabled'
        if self._sharedFromOtherAccount():
            self.results[key] = [0, f"Shared from account {self._ownerAccount()}; evaluate in the owner account"]
            return

        subs, err = self._ownAccessLogs()
        if err:
            self.results[key] = [0, f'Unable to evaluate ({err})']
            return
        if subs:
            self.results[key] = [1, f'{len(subs)} access log subscription(s) configured on the service']
            return

        nets, err = self._listAssociatedNetworks()
        if err:
            self.results[key] = [0, f'Unable to evaluate (no service-level access log; '
                                    f'service network associations unreadable: {err})']
            return

        unlogged, unreadable = [], []
        for net in nets:
            try:
                netSubs = self._listAccessLogSubscriptions(net)
            except botocore.exceptions.ClientError as e:
                unreadable.append(f'{net.split("/")[-1]} ({self._errCode(e)})')
                continue
            if not self._coversServiceTraffic(netSubs):
                unlogged.append(net.split('/')[-1])

        if nets and not unlogged and not unreadable:
            self.results[key] = [
                1,
                f'No service-level subscription, but all {len(nets)} associated service network(s) '
                'log service traffic'
            ]
            return
        if not nets:
            # An unassociated service cannot receive VPC Lattice traffic, so
            # there is nothing to log yet.
            self.results[key] = [
                0,
                'The service has no access log subscription but is not associated with any service '
                'network, so it receives no traffic; enable access logs before associating it'
            ]
            return
        if unlogged:
            self.results[key] = [
                -1,
                'The service has no access log subscription; associated service network(s) without '
                f'service access logs: {", ".join(unlogged[:5])} - requests to it are not recorded'
            ]
            return
        self.results[key] = [
            0,
            'Unable to evaluate (no service-level access log; access logs of associated service '
            f'network(s) unreadable: {", ".join(unreadable[:5])})'
        ]

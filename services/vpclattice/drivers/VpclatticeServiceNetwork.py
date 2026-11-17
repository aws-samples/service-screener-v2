from services.vpclattice.drivers.VpclatticeBase import VpclatticeBase


class VpclatticeServiceNetwork(VpclatticeBase):
    """
    Per VPC Lattice service network checks.

    Input: resource = vpc-lattice.get_service_network output (falls back to the
    list_service_networks summary if get_service_network failed).
    """

    kindLabel = 'service network'

    def __init__(self, resource, client, accountId=None):
        super().__init__(resource, client, accountId)
        self.addII('numberOfAssociatedServices', self.resource.get('numberOfAssociatedServices'))
        self.addII('numberOfAssociatedVPCs', self.resource.get('numberOfAssociatedVPCs'))

    def _checkLatticeAuthTypeNone(self):
        self._evaluateAuthType()

    def _checkLatticeAccessLogsDisabled(self):
        key = 'latticeAccessLogsDisabled'
        if self._sharedFromOtherAccount():
            self.results[key] = [0, f"Shared from account {self._ownerAccount()}; evaluate in the owner account"]
            return

        subs, err = self._ownAccessLogs()
        if err:
            self.results[key] = [0, f'Unable to evaluate ({err})']
            return
        if not subs:
            self.results[key] = [
                -1,
                'The service network has no access log subscription: requests to its services '
                'are not recorded to CloudWatch Logs, S3 or Firehose'
            ]
            return

        serviceSubs = self._coversServiceTraffic(subs)
        services = self.resource.get('numberOfAssociatedServices')
        if not serviceSubs and isinstance(services, int) and services > 0:
            self.results[key] = [
                -1,
                f'The service network logs resource-configuration traffic only (serviceNetworkLogType '
                f'RESOURCE); requests to its {services} associated service(s) are not logged'
            ]
            return
        self.results[key] = [1, f'{len(subs)} access log subscription(s) configured']

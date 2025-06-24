from .ElasticacheCommon import ElasticacheCommon


class ElasticacheMemcached(ElasticacheCommon):
    defaultPort = 11211
    def __init__(self, cluster, client, driver_info):
        super().__init__(cluster, client, driver_info)
        self._resourceName = self.cluster['ARN']
        # self.init()

    def _checkDefaultPort(self):
        # Memcached returns ConfigurationEndpoint with port information
        # self.cluster.get('ConfigurationEndpoint').get('Port')
        # self.cluster.get('CacheNodes')[0].get('Endpoint').get('Port')
        dport = self.cluster.get('ConfigurationEndpoint').get('Port')
        if dport == ElasticacheMemcached.defaultPort:
            self.results['DefaultPort'] = [-1, ElasticacheMemcached.defaultPort]
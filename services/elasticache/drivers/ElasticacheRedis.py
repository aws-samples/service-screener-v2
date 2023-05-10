from .ElasticacheCommon import ElasticacheCommon


class ElasticacheRedis(ElasticacheCommon):
    defaultPort = 6379
    def __init__(self, cluster, client, driver_info):
        super().__init__(cluster, client, driver_info)
        # self.init()

    def _checkDefaultPort(self):
        ports_in_cluster = [node.get('Endpoint').get(
            'Port') for node in self.cluster.get('CacheNodes')]
        if any(port == ElasticacheRedis.defaultPort for port in ports_in_cluster):
            self.results['DefaultPort'] = [-1, ElasticacheRedis.defaultPort]
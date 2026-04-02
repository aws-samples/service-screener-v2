from services.Evaluator import Evaluator


class ElasticacheServerless(Evaluator):
    def __init__(self, cache, client):
        super().__init__()
        self.cache = cache
        self.client = client

        self._resourceName = cache['ServerlessCacheName']
    
    def _checkServerlessReadReplica(self):
        """
        Check if serverless cache has reader endpoint configured.
        Reader endpoints improve read performance by distributing traffic.
        """
        if not self.cache.get('ReaderEndpoint'):
            self.results['ServerlessReadReplica'] = [-1, 'No reader endpoint configured']
        
        return

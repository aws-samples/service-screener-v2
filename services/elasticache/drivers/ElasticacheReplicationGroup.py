from services.Evaluator import Evaluator


class ElasticacheReplicationGroup(Evaluator):
    def __init__(self, group, client):
        super().__init__()
        self.group = group
        self.client = client

        self._resourceName = group['ReplicationGroupId']
    
    def _checkHasReadReplica(self):
        hasReplica = False
        for nodeGroup in self.group.get('NodeGroups'):
            for member in nodeGroup.get('NodeGroupMembers'):
                if member.get('CurrentRole') == 'replica':
                    hasReplica = True
                    break
                
            if hasReplica:
                break
                    
        if not hasReplica:
            self.results['EnableReadReplica'] = [-1, '']
        
        return
    
    def _checkSlowLog(self):
        if len(self.group.get('LogDeliveryConfigurations')) == 0:
            self.results['EnableSlowLog'] = [-1, '']
            return
        
        for config in self.group.get('LogDeliveryConfigurations'):
            if config.get('LogType') == 'slow-log' and config.get('Status') in ['disabling', 'error']:
                self.results['EnableSlowLog'] = [-1, config.get('Status').capitalize()]
                
        return
        
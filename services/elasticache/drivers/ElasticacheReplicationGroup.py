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

    def _checkClusterModeEnabled(self):
        """
        Check if cluster mode is enabled for Redis replication group.
        Cluster mode provides horizontal scaling and better data distribution.
        """
        if not self.group.get('ClusterEnabled'):
            self.results['ClusterModeEnabled'] = [-1, 'Cluster mode is disabled']

        return

    def _checkMultiAZEnabled(self):
        """
        Check if Multi-AZ with automatic failover is enabled.
        Verifies both automatic failover and Multi-AZ configuration.
        """
        # Check automatic failover status
        auto_failover = self.group.get('AutomaticFailover', '')
        if auto_failover != 'enabled':
            self.results['MultiAZEnabled'] = [-1, f'Automatic failover is {auto_failover}']
            return

        # Check Multi-AZ status
        multi_az = self.group.get('MultiAZ', '')
        if multi_az != 'enabled':
            self.results['MultiAZEnabled'] = [-1, f'Multi-AZ is {multi_az}']
            return

        # Verify nodes are distributed across multiple AZs
        azs = set()
        for nodeGroup in self.group.get('NodeGroups', []):
            for member in nodeGroup.get('NodeGroupMembers', []):
                az = member.get('PreferredAvailabilityZone')
                if az:
                    azs.add(az)

        if len(azs) < 2:
            self.results['MultiAZEnabled'] = [-1, f'Nodes are in only {len(azs)} availability zone(s)']

        return

    def _checkBackupEnabled(self):
        """
        Check if automatic backups are enabled with appropriate retention.
        Minimum recommended retention is 7 days for production workloads.
        """
        retention = self.group.get('SnapshotRetentionLimit', 0)

        if retention == 0:
            self.results['BackupEnabled'] = [-1, 'Automatic backups are disabled']

        return

    def _checkGlobalDatastoreConfig(self):
        """
        Check if replication group is part of a global datastore with proper multi-region configuration.
        Global datastores provide cross-region disaster recovery and low-latency reads.
        """
        global_info = self.group.get('GlobalReplicationGroupInfo')

        # If not part of global datastore, skip check (not required for all workloads)
        if not global_info:
            return

        # If part of global datastore, verify configuration
        global_rg_id = global_info.get('GlobalReplicationGroupId')

        if not global_rg_id:
            return

        try:
            # Get global datastore details
            response = self.client.describe_global_replication_groups(
                GlobalReplicationGroupId=global_rg_id,
                ShowMemberInfo=True
            )

            if not response.get('GlobalReplicationGroups'):
                return

            global_rg = response['GlobalReplicationGroups'][0]
            members = global_rg.get('Members', [])

            # Verify at least 2 regions for true multi-region DR capability
            if len(members) < 2:
                self.results['GlobalDatastoreConfig'] = [-1, f'Global datastore has only {len(members)} region(s), recommend at least 2 for disaster recovery']

        except Exception as e:
            # Silently skip if global datastore cannot be accessed
            pass

        return


        
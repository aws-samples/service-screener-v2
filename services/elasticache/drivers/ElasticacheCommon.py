from services.Evaluator import Evaluator
from packaging.version import Version

from utils.Tools import _pr


class ElasticacheCommon(Evaluator):
    def __init__(self, cluster, client, driver_info):
        super().__init__()
        self.cluster = cluster
        self.client = client
        self.driver_info = driver_info

    def _checkEngineVersion(self):
        cluster_engine_version = Version(self.cluster.get('EngineVersion'))
        engine_versions = self.driver_info.get(
            'engine_veresions').get(self.cluster.get('Engine'))
        # highlight if not listed and not a top-3 redis patch version
        if cluster_engine_version not in engine_versions and not any([cluster_engine_version >= i for i in engine_versions[:3]]):
            self.results['EngineVersionUnlisted'] = [-1,
                                                     f"using {self.cluster.get('EngineVersion')}"]
            return
        # highlight if not a top 3 version
        if not any([cluster_engine_version >= i for i in engine_versions[:3]]):
            self.results['EngineVersion'] = [-1,
                                             f"using {self.cluster.get('EngineVersion')}"]

    def _checkEncryption(self):
        stringBuild = []
        if self.cluster.get('TransitEncryptionEnabled') is not True:
            stringBuild.append('in transit')
        if self.cluster.get('AtRestEncryptionEnabled') is not True:
            stringBuild.append('at rest')
        
        ## TODO, need to flag as long as one hit
        if len(stringBuild) > 0:
            self.results['EncInTransitAndRest'] = [-1,
                                                   f"Not using encryption {' and '.join(stringBuild)}"]

    def _checkDefaultParamGroup(self):
        if self.cluster.get('CacheParameterGroup').get('CacheParameterGroupName').startswith("default."):
            self.results['DefaultParamGroup'] = [-1, ""]

    def _checkRInstanceFamily(self):
        instance_type = self.cluster.get('CacheNodeType').lstrip('cache.')
        if instance_type[0] != 'r':
            self.results['RInstanceType'] = [-1, instance_type]

    def _checkLatestInstanceFamily(self):
        instance_type = self.cluster.get('CacheNodeType').lstrip('cache.')
        if instance_type.split('.')[0] not in self.driver_info.get('latest_instances').get(self.cluster.get('Engine')):
            self.results['LatestInstance'] = [-1, instance_type]

    def _checkClusterNotification(self):
        if self.cluster.get('NotificationConfiguration') is None:
            self.results['EnableNotification'] = [-1, '']
        return
    def _checkIdleTimeout(self):
        """
        Check if server-side idle timeout is properly configured.
        Only checks non-default parameter groups.
        Recommended timeout: 300-600 seconds.
        """
        param_group_name = self.cluster.get('CacheParameterGroup', {}).get('CacheParameterGroupName')

        # Skip if using default parameter group (already flagged by DefaultParamGroup check)
        if param_group_name and param_group_name.startswith('default.'):
            return

        # Only check Redis clusters (Memcached doesn't have timeout parameter)
        if self.cluster.get('Engine') != 'redis':
            return

        try:
            response = self.client.describe_cache_parameters(
                CacheParameterGroupName=param_group_name,
                Source='user'
            )

            # Find the timeout parameter
            timeout_param = next(
                (p for p in response.get('Parameters', []) if p.get('ParameterName') == 'timeout'),
                None
            )

            if timeout_param:
                timeout_value = int(timeout_param.get('ParameterValue', '0'))
                if timeout_value == 0:
                    self.results['IdleTimeout'] = [-1, 'Idle timeout is disabled (0 seconds)']
                elif timeout_value > 600:
                    self.results['IdleTimeout'] = [-1, f'Idle timeout is too high ({timeout_value} seconds, recommend 300-600)']
        except Exception as e:
            # Silently skip if parameter group cannot be accessed
            pass

        return


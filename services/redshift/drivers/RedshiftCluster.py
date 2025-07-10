import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

class RedshiftCluster(Evaluator):
    
    def __init__(self, cluster, rsClient):
        super().__init__()
        self.init()
        
        self.cluster = cluster
        self.rsClient = rsClient
        self._resourceName = cluster['ClusterIdentifier']
        
        # Cache parameter group data to avoid multiple API calls
        self._parameter_cache = {}
        self._preload_parameter_groups()
        
    def _preload_parameter_groups(self):
        """Cache parameter group data for all cluster parameter groups"""
        try:
            for param_group in self.cluster.get('ClusterParameterGroups', []):
                group_name = param_group['ParameterGroupName']
                if group_name not in self._parameter_cache:
                    resp = self.rsClient.describe_cluster_parameters(
                        ParameterGroupName=group_name
                    )
                    # Create lookup dict for faster parameter access
                    params = {p['ParameterName']: p['ParameterValue'] 
                             for p in resp.get('Parameters', [])}
                    self._parameter_cache[group_name] = params
        except Exception as e:
            print(f"Error preloading parameter groups: {e}")
            self._parameter_cache = {}
    
    def _get_parameter_value(self, param_name):
        """Get parameter value from cache"""
        for group_name, params in self._parameter_cache.items():
            if param_name in params:
                return params[param_name]
        return None
    
    def _checkCluster(self):
        """Check cluster configuration settings"""
        # Check public accessibility
        if self.cluster.get('PubliclyAccessible', False):
            self.results['PubliclyAccessible'] = [-1, "Redshift cluster is publicly accessible"]
        
        # Check automated snapshot retention
        retention_period = self.cluster.get('AutomatedSnapshotRetentionPeriod', 0)
        if retention_period < 7:
            self.results['AutomaticSnapshots'] = [-1, f"Automatic snapshot retention is {retention_period} days (< 7)"]
        
        # Check cross-region snapshot copy
        snapshot_copy = self.cluster.get('ClusterSnapshotCopyStatus', {})
        if not snapshot_copy.get('DestinationRegion'):
            self.results['CrossRegionSnapshots'] = [-1, "Cross-region snapshots are not enabled"]
        
        # Check maintenance window
        if not self.cluster.get('PreferredMaintenanceWindow'):
            self.results['MaintenanceWindow'] = [-1, "Maintenance window is not configured"]

        # Check version upgrade setting
        if not self.cluster.get('AllowVersionUpgrade', False):
            self.results['AutomaticUpgrades'] = [-1, "AllowVersionUpgrade is disabled"]
        
        # Check enhanced VPC routing
        if not self.cluster.get('EnhancedVpcRouting', False):
            self.results['EnhancedVpcRouting'] = [-1, "EnhancedVpcRouting is disabled"]
        
        # Check default master username
        if self.cluster.get('MasterUsername') == 'awsuser':
            self.results['DefaultAdminUsername'] = [-1, "Default master username is awsuser"]
        
        # Check default database name
        if self.cluster.get('DBName') == 'dev':
            self.results['DefaultDatabaseName'] = [-1, "Default DB name is dev"]
        
        # Check encryption at rest
        if not self.cluster.get('Encrypted', False):
            self.results['EncryptedAtRest'] = [-1, "Encryption is not enabled"]
        
        # Check KMS encryption
        if not self.cluster.get('KmsKeyId'):
            self.results['EncryptedWithKMS'] = [-1, "Encryption is not done with KMS"]

        # Check AZ relocation
        az_status = self.cluster.get('AvailabilityZoneRelocationStatus', '')
        if az_status != 'enabled':
            self.results['AZRelocation'] = [-1, f"AZ Relocation is {az_status or 'not enabled'}"]
    
    def _checkParameterGroups(self):
        """Check parameter group settings using cached data"""
        self.results['EncryptedInTransit'] = [-1, "Redshift cluster is not encrypted in transit"]

        # Use cached parameter data instead of API call
        require_ssl = self._get_parameter_value('require_ssl')
        if require_ssl == 'true':
            self.results['EncryptedInTransit'] = [1, "Redshift cluster is encrypted in transit"]
    
    def _checkLoggingStatus(self):
        """Check audit logging status"""
        try:
            resp = self.rsClient.describe_logging_status(
                ClusterIdentifier=self.cluster['ClusterIdentifier']
            )
            if not resp.get('LoggingEnabled', False):
                self.results['AuditLogging'] = [-1, "Audit Logging is not enabled"]
            else:
                # Check if logs are going to S3
                bucket_name = resp.get('BucketName')
                if bucket_name:
                    self.results['AuditLogging'] = [1, f"Audit logging enabled to S3: {bucket_name}"]
                else:
                    self.results['AuditLogging'] = [0, "Audit logging enabled but no S3 bucket specified"]
                    
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ClusterNotFoundFault':
                print(f"Cluster {self.cluster['ClusterIdentifier']} not found")
            else:
                print(f"Error checking logging status: {e}")
            self.results['AuditLogging'] = [0, "Unable to check logging status"]

    def _checkIAMRoles(self):
        """Check if IAM roles are attached to the cluster"""
        roles_attached = self.cluster.get('IamRoles', [])
        if not roles_attached:
            self.results['IAMRoles'] = [-1, "No IAM roles attached"]
        else:
            role_count = len(roles_attached)
            self.results['IAMRoles'] = [1, f"{role_count} IAM role(s) attached"]

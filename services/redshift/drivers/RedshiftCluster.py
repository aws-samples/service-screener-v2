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
        # print(self.cluster)
        return
    
    def _checkCluster(self):

        # check if publicly accessible
        if self.cluster['PubliclyAccessible']:
            self.results['PubliclyAccessible'] = [-1, "Redshift cluster is publicly accessible"]
        
        # check if automated snapshot is enabled
        try:
            if self.cluster['AutomatedSnapshotRetentionPeriod'] < 7:
                self.results['AutomaticSnapshots'] = [-1, "Automatic snapshot retention is < 7 days"]
        
        except Exception as e:
            print(f"Error: {e}")
            self.results['AutomaticSnapshots'] = [-1, "Automatic snapshots is disabled"]
        
        # Check if cross-region snapshot copy is configured
        try:
            if not self.cluster.get('ClusterSnapshotCopyStatus', {}).get('DestinationRegion'):
                self.results['CrossRegionSnapshots'] = [-1, "Cross-region snapshots are not enabled"]

        except Exception as e:
            print(f"Error: {e}")
            self.results['CrossRegionSnapshots'] = [-1, "Error checking cross-region snapshots"]
        
        # Check if cluster is running the latest version
        # try:
        #     # Get available cluster versions
        #     versions = self.rsClient.describe_cluster_versions()
        #     latest_version = versions['ClusterVersions'][-1]['ClusterVersion']
        #     current_version = self.cluster['ClusterVersion']

        #     print(versions)
            
        #     if current_version < latest_version:
        #         self.results['ClusterVersion'] = [-1, f"Cluster is not on latest version. Current: {current_version}, Latest: {latest_version}"]
        # except Exception as e:
        #     print(f"Error checking cluster version: {e}")
        #     return None
    
        # Check if maintenance window is configured
        try:
            if not self.cluster.get('PreferredMaintenanceWindow'):
                self.results['MaintenanceWindow'] = [-1, "Maintenance window is not configured"]
        except Exception as e:
            print(f"Error checking maintenance window: {e}")
            return None

        # check if allowversionupgrade is enabled
        try:
            if not self.cluster['AllowVersionUpgrade']:
                self.results['AutomaticUpgrades'] = [-1, "AllowVersionUpgrade is disabled"]
        
        except Exception as e:
            print(f"Error: {e}")
            return None
        
        # check if enhancedvpcrouting is enabled
        try:
            if not self.cluster['EnhancedVpcRouting']:
                self.results['EnhancedVpcRouting'] = [-1, "EnhancedVpcRouting is disabled"]
        
        except Exception as e:
            print(f"Error: {e}")
            return None
        
        # check if default masterusername is used
        try:
            if self.cluster['MasterUsername'] == 'awsuser':
                self.results['DefaultAdminUsername'] = [-1, "Default master username is awsuser"]
        
        except Exception as e:
            print(f"Error: {e}")
            return None
        
        # check if default dbname is used
        try:
            if self.cluster['DBName'] == 'dev':
                self.results['DefaultDatabaseName'] = [-1, "Default DB name is dev"]

        except Exception as e:
            print(f"Error: {e}")
            return None
        
        # chech if encryption is enabled
        try:
            if not self.cluster['Encrypted']:
                self.results['EncryptedAtRest'] = [-1, "Encryption is not enabled"]
        
        except Exception as e:
            print(f"Error: {e}")
            return None
        
        # check if encryption is done with KMS
        try:
            if self.cluster.get('KmsKeyId', '') == '':
                self.results['EncryptedWithKMS'] = [-1, "Encryption is not done with KMS"]

        except Exception as e:
            print(f"Error: {e}")
            return None


        # # check if default port is used
        # try:
        #     if self.cluster['Endpoint']['Port'] == 5439:
        #         self.results['DefaultPort'] = [-1, "Default port is 5439"]

        # except Exception as e:
        #     print(f"Error: {e}")
        #     return None

        # check if AZ Relocation is enabled
        try:
            print(self.cluster['AvailabilityZoneRelocationStatus'])
            if not self.cluster['AvailabilityZoneRelocationStatus'] == 'enabled':
                self.results['AZRelocation'] = [-1, "AZ Relocation is not enabled"]

        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def _checkParameterGroups(self):
        self.results['EncryptedInTransit'] = [-1, "Redshift cluster is not encrypted in transit"]

        try:
            resp = self.rsClient.describe_cluster_parameters(
                ParameterGroupName=self.cluster['ClusterParameterGroups'][0]['ParameterGroupName']
            )
            for parameter in resp['Parameters']:
                if(parameter['ParameterName'] == 'require_ssl' and parameter['ParameterValue'] == 'true'):
                    self.results['EncryptedInTransit'] = [1, "Redshift cluster is encrypted in transit"]
                    return
                
        except self.rsClient.exceptions.ClusterNotFoundFault:
            print(f"Error: Cluster not found.")
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def _checkLoggingStatus(self):
        
        try:
            resp = self.rsClient.describe_logging_status(
                ClusterIdentifier=self.cluster['ClusterIdentifier']
            )
            if not resp['LoggingEnabled']:
                self.results['AuditLogging'] = [-1, "Audit Logging is not enabled"]
            return

        except self.rsClient.exceptions.ClusterNotFoundFault:
            print(f"Error: Cluster not found.")
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None

    # Check if IAM Roles is enforced
    def _checkIAMRoles(self):
        try:
            roles_attached = self.cluster.get('IamRoles', [])
            if not roles_attached:
                self.results['IAMRoles'] = [-1, "No IAM roles attached."]
        except Exception as e:
            print(f"Error: {e}")
            self.results['IAMRoles'] = [-1, "Error checking IAMRoles"]

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
        # Check VPC deployment
        vpc_id = self.cluster.get('VpcId')
        if not vpc_id:
            self.results['VpcDeployment'] = [-1, "Cluster is not deployed in VPC (EC2-Classic)"]
        else:
            self.results['VpcDeployment'] = [1, f"Cluster deployed in VPC: {vpc_id}"]
        
        # Check VPC security groups attachment
        vpc_security_groups = self.cluster.get('VpcSecurityGroups', [])
        if not vpc_security_groups:
            self.results['SecurityGroups'] = [-1, "No VPC security groups attached to cluster"]
        else:
            # Extract security group IDs
            sg_ids = [sg['VpcSecurityGroupId'] for sg in vpc_security_groups if sg.get('VpcSecurityGroupId')]
            if sg_ids:
                self.results['SecurityGroups'] = [1, f"VPC security groups attached: {', '.join(sg_ids)}"]
            else:
                self.results['SecurityGroups'] = [-1, "No valid VPC security group IDs found"]
        
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
    
    def _checkAdvisorRecommendations(self):
        """Check for unaddressed Redshift Advisor recommendations"""
        try:
            resp = self.rsClient.list_recommendations(
                ClusterIdentifier=self.cluster['ClusterIdentifier']
            )
            
            recommendations = resp.get('Recommendations', [])
            
            if not recommendations:
                self.results['AdvisorRecommendations'] = [1, "No outstanding Advisor recommendations"]
                return
            
            # Categorize recommendations by impact ranking
            high_impact = []
            medium_impact = []
            low_impact = []
            
            for rec in recommendations:
                impact = rec.get('ImpactRanking', '').lower()
                rec_id = rec.get('RecommendationId', 'Unknown')
                
                if impact == 'high':
                    high_impact.append(rec_id)
                elif impact == 'medium':
                    medium_impact.append(rec_id)
                else:
                    low_impact.append(rec_id)
            
            # Report based on highest impact level
            if high_impact:
                count = len(high_impact)
                self.results['AdvisorRecommendations'] = [
                    -1, 
                    f"{count} high-impact recommendation(s) need attention"
                ]
            elif medium_impact:
                count = len(medium_impact)
                self.results['AdvisorRecommendations'] = [
                    0, 
                    f"{count} medium-impact recommendation(s) exist"
                ]
            else:
                count = len(low_impact)
                self.results['AdvisorRecommendations'] = [
                    0, 
                    f"{count} low-impact recommendation(s) exist"
                ]
                
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ClusterNotFoundFault':
                self.results['AdvisorRecommendations'] = [
                    0, 
                    f"Cluster {self.cluster['ClusterIdentifier']} not found"
                ]
            elif error_code == 'UnsupportedOperationFault':
                # API not available in this region or for this cluster type
                self.results['AdvisorRecommendations'] = [
                    0, 
                    "Advisor recommendations not available for this cluster"
                ]
            else:
                self.results['AdvisorRecommendations'] = [
                    0, 
                    f"Unable to check Advisor recommendations: {error_code}"
                ]
        except Exception as e:
            self.results['AdvisorRecommendations'] = [
                0, 
                f"Error checking Advisor recommendations: {str(e)}"
            ]
    
    def _checkEventNotifications(self):
        """Validate SNS event notifications are configured for cluster events"""
        try:
            resp = self.rsClient.describe_event_subscriptions()
            subscriptions = resp.get('EventSubscriptionsList', [])
            
            # Check if any subscription covers this cluster
            cluster_subscriptions = []
            for sub in subscriptions:
                source_ids = sub.get('SourceIdsList', [])
                # Subscription applies if cluster is in source list or source list is empty (all clusters)
                if self.cluster['ClusterIdentifier'] in source_ids or not source_ids:
                    cluster_subscriptions.append(sub['CustSubscriptionId'])
            
            if cluster_subscriptions:
                self.results['EventNotifications'] = [
                    1, 
                    f"Event notifications configured: {', '.join(cluster_subscriptions)}"
                ]
            else:
                self.results['EventNotifications'] = [
                    -1, 
                    "No SNS event notifications configured for this cluster"
                ]
                
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            self.results['EventNotifications'] = [
                0, 
                f"Unable to check event subscriptions: {error_code}"
            ]
        except Exception as e:
            self.results['EventNotifications'] = [
                0, 
                f"Error checking event notifications: {str(e)}"
            ]
    
    def _checkQueryMonitoringRules(self):
        """Validate Query Monitoring Rules are configured in WLM"""
        # Get WLM configuration from cached parameter data
        wlm_config = self._get_parameter_value('wlm_json_configuration')
        
        if not wlm_config:
            self.results['QueryMonitoringRules'] = [
                -1, 
                "WLM configuration not found"
            ]
            return
        
        try:
            import json
            wlm = json.loads(wlm_config)
            
            # Check if any queue has query monitoring rules
            has_qmr = False
            total_rules = 0
            
            for queue in wlm:
                # Validate queue is a dict before accessing fields
                if not isinstance(queue, dict):
                    raise TypeError(f"WLM queue must be a dict, got {type(queue).__name__}")
                
                if 'rules' in queue and queue['rules']:
                    has_qmr = True
                    total_rules += len(queue['rules'])
            
            if has_qmr:
                self.results['QueryMonitoringRules'] = [
                    1, 
                    f"Query Monitoring Rules configured ({total_rules} rule(s))"
                ]
            else:
                self.results['QueryMonitoringRules'] = [
                    -1, 
                    "No Query Monitoring Rules configured in WLM"
                ]
                
        except json.JSONDecodeError:
            self.results['QueryMonitoringRules'] = [
                0, 
                "Unable to parse WLM configuration"
            ]
        except Exception as e:
            self.results['QueryMonitoringRules'] = [
                0, 
                f"Error checking Query Monitoring Rules: {str(e)}"
            ]

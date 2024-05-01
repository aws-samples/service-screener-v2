import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

###### TO DO #####
## Import modules that needed for this driver
## Example
## from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

###### TO DO #####
## Replace ServiceDriver with

class RedshiftCluster(Evaluator):
    
    ###### TO DO #####
    ## Replace resource variable to meaningful name
    ## Modify based on your need
    def __init__(self, cluster, rsClient):
        super().__init__()
        self.init()
        
        self.cluster = cluster
        self.rsClient = rsClient
        # print(self.cluster)
        return
    
    ###### TO DO #####
    ## Change the method name to meaningful name
    ## Check methods name must follow _check[Description]
    def _checkPubliclyAcessible(self):
        # resp = self.rsClient.describe_clusters(
        #         ClusterIdentifier=self.cluster['ClusterIdentifier']
        #     )
        if self.cluster['PubliclyAccessible']:
            self.results['PubliclyAccessible'] = [-1, "Redshift cluster is publicly accessible"]
        
        # check if automated snapshot is enabled
        try:
            if self.cluster['AutomatedSnapshotRetentionPeriod'] < 7:
                print(self.cluster['AutomatedSnapshotRetentionPeriod'])
                self.results['AutomaticSnapshots'] = [-1, "Automatic snapshot retention is < 7 days"]
        
        except Exception as e:
            print(f"Error: {e}")
            self.results['AutomaticSnapshots'] = [-1, "Automatic snapshots is disabled"]
        
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
                self.results['Encryption'] = [-1, "Encryption is not enabled"]
        
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
        
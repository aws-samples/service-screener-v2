import boto3
import botocore

from services.Evaluator import Evaluator


class ConnectionDriver(Evaluator):
    """
    Driver for checking AWS Glue database connection security settings.
    
    This driver evaluates database connection security configurations:
    - SSL enablement for JDBC connections
    """
    
    def __init__(self, connection, glueClient):
        """
        Initialize ConnectionDriver.
        
        Args:
            connection (dict): Database connection from get_connections()
            glueClient: Boto3 Glue client for API calls
        """
        super().__init__()
        self.connection = connection
        self.glueClient = glueClient
        
        # Set resource name to the connection name
        self._resourceName = f"Connection::{connection['Name']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('connectionName', connection['Name'])
        self.addII('connectionType', connection.get('ConnectionType', 'N/A'))
        self.addII('creationTime', connection.get('CreationTime'))
        self.addII('lastUpdatedTime', connection.get('LastUpdatedTime'))
    
    def _checkSslEnabled(self):
        """
        Check if SSL is enabled for database connections.
        
        For JDBC connections, verifies that JDBC_ENFORCE_SSL property is set to 'true'.
        
        Validates: Requirements 4.4, 6.1, 6.3, 6.4
        Reporter JSON key: SslEnabled
        """
        try:
            connectionType = self.connection.get('ConnectionType', '')
            connectionProperties = self.connection.get('ConnectionProperties', {})
            
            # SSL check is primarily relevant for JDBC connections
            if connectionType == 'JDBC':
                sslEnabled = connectionProperties.get('JDBC_ENFORCE_SSL', 'false')
                
                if sslEnabled.lower() == 'true':
                    self.results['SslEnabled'] = [1, 'Enabled']
                else:
                    self.results['SslEnabled'] = [-1, 'Disabled']
            else:
                # For non-JDBC connections, report as informational
                self.results['SslEnabled'] = [0, f'Not applicable for {connectionType} connection']
                
        except Exception as e:
            print(f"Error checking SSL enabled: {e}")
            self.results['SslEnabled'] = [0, f'Error: {str(e)}']

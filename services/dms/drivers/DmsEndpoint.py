from services.Evaluator import Evaluator


class DmsEndpoint(Evaluator):
    """
    Checks for one AWS DMS endpoint (raw describe_endpoints item).
    """

    ## Engines whose connection to the database server is protected by the
    ## endpoint-level SslMode setting (see "Using SSL with AWS DMS").
    SSLMODE_ENGINES = {
        'mysql', 'mariadb', 'aurora', 'aurora-serverless', 'aurora-postgresql',
        'postgres', 'oracle', 'sqlserver', 'azuredb', 'azure-sql-managed-instance',
        'db2', 'mongodb', 'docdb', 'documentdb', 'babelfish', 'gcp-mysql',
    }

    ## Engines where SslMode does not govern transport encryption: the DMS
    ## connection goes to an AWS service API over HTTPS, or (Redshift) DMS does
    ## not support SSL on the endpoint and stages data through S3 instead.
    SSLMODE_NOT_APPLICABLE = {
        's3', 'dynamodb', 'kinesis', 'elasticsearch', 'opensearch', 'neptune',
        'redshift', 'redshift-serverless', 'timestream', 'lakehouse', 's3tables',
    }

    def __init__(self, endpoint, dmsClient):
        super().__init__()
        self.endpoint = endpoint
        self.dmsClient = dmsClient
        self._resourceName = endpoint.get('EndpointIdentifier')

        self.addII('endpointArn', endpoint.get('EndpointArn', 'N/A'))
        self.addII('endpointType', endpoint.get('EndpointType', 'N/A'))
        self.addII('engineName', endpoint.get('EngineName', 'N/A'))
        self.addII('sslMode', endpoint.get('SslMode', 'N/A'))

    def _checkDmsEndpointSslNone(self):
        ep = self.endpoint
        engine = (ep.get('EngineName') or '').lower()
        sslMode = (ep.get('SslMode') or '').lower()
        key = 'dmsEndpointSslNone'

        if engine == 'kafka':
            proto = ((ep.get('KafkaSettings') or {}).get('SecurityProtocol') or '').lower()
            if proto == 'plaintext':
                self.results[key] = [-1, 'Kafka endpoint uses SecurityProtocol=plaintext (no TLS)']
            elif proto:
                self.results[key] = [1, f'Kafka endpoint uses SecurityProtocol={proto}']
            else:
                self.results[key] = [0, 'Unable to evaluate (Kafka SecurityProtocol not reported)']
            return

        if engine == 'redis':
            proto = ((ep.get('RedisSettings') or {}).get('SslSecurityProtocol') or '').lower()
            if proto == 'plaintext':
                self.results[key] = [-1, 'Redis endpoint uses SslSecurityProtocol=plaintext (no TLS)']
            elif proto:
                self.results[key] = [1, f'Redis endpoint uses SslSecurityProtocol={proto}']
            else:
                self.results[key] = [0, 'Unable to evaluate (Redis SslSecurityProtocol not reported)']
            return

        if engine in self.SSLMODE_NOT_APPLICABLE:
            self.results[key] = [0, f'SslMode not applicable for engine {engine}']
            return

        if engine not in self.SSLMODE_ENGINES:
            self.results[key] = [0, f'Unable to evaluate (SSL support for engine {engine or "unknown"} not confirmed; SslMode={sslMode or "unset"})']
            return

        if not sslMode:
            self.results[key] = [0, 'Unable to evaluate (SslMode not reported)']
        elif sslMode == 'none':
            self.results[key] = [-1, f'{engine} endpoint has SslMode=none (connection not encrypted with TLS)']
        else:
            self.results[key] = [1, f'SslMode={sslMode}']

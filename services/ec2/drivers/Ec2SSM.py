import re

import botocore

from services.Evaluator import Evaluator

# Windows services that accept interactive remote logins (lower-cased service names)
REMOTE_LOGIN_SERVICES = {'termservice': 'RDP (TermService)', 'sshd': 'OpenSSH (sshd)'}

# Default listener ports of self-managed databases / caches / search engines
DATASTORE_PORTS = {3306: 'MySQL/MariaDB', 5432: 'PostgreSQL', 1433: 'SQL Server', 1521: 'Oracle',
                   27017: 'MongoDB', 6379: 'Redis/Valkey', 11211: 'Memcached', 9042: 'Cassandra',
                   9200: 'Elasticsearch/OpenSearch'}
# An ingress permission counts only when it targets a narrow, explicit port range
# (all-traffic / wide ranges are not evidence of a data store).
DATASTORE_MAX_RANGE = 10
# Server packages / Windows programs in SSM Inventory AWS:Application (client
# libraries and tools such as mysql-client / postgresql-libs do not match).
DATASTORE_PACKAGES = [re.compile(p) for p in (
    r'^(mysql|mysql-community|mariadb|percona-server)-server(-[\d.]+)?$',
    r'^postgresql\d*-server$', r'^postgresql-\d+$',
    r'^redis\d*$', r'^redis-server$', r'^valkey(-server)?$',
    r'^mongodb(-org)?-server$', r'^memcached$', r'^cassandra$', r'^elasticsearch$', r'^opensearch$',
    r'^oracle-database-(ee|se2|xe|free)',
    r'^microsoft sql server 20\d\d \(64-bit\)$',
)]


class Ec2SSM(Evaluator):
    """Check if an EC2 instance is managed by AWS Systems Manager.

    ssmManagedSet is None when ssm:DescribeInstanceInformation could not be read
    (ssmError holds the error code); pingStatus maps instance ID -> PingStatus."""

    def __init__(self, instanceId, ssmManagedSet, instanceData=None, ssmError=None, pingStatus=None,
                 ssmClient=None, platformType=None, securityGroups=None):
        super().__init__()
        self.instanceId = instanceId
        self.ssmManagedSet = ssmManagedSet
        self.instanceData = instanceData
        self.ssmError = ssmError
        self.pingStatus = pingStatus or {}
        self.ssmClient = ssmClient
        self.platformType = platformType or {}
        self.securityGroups = securityGroups

        self._resourceName = instanceId

        self.init()

    def _checkSSMManaged(self):
        """Flag instances not registered with SSM (no patching/compliance visibility)"""
        if self.ssmManagedSet is None:
            return  # lookup failed - skip rather than flag every instance
        if self.instanceId not in self.ssmManagedSet:
            self.results['EC2SSMNotManaged'] = [-1, 'Not managed']

    def _checkEc2InstanceWithKeyPair(self):
        """Running instance that Session Manager can reach (SSM-managed, agent Online)
        but was still launched with an SSH key pair. KeyName only reflects the
        launch-time key - whether sshd still accepts it cannot be seen from the API."""
        key = 'ec2InstanceWithKeyPair'
        inst = self.instanceData
        if not inst or (inst.get('State') or {}).get('Name') != 'running':
            return
        keyName = inst.get('KeyName')
        if not keyName:
            self.results[key] = [1, 'No key pair']
            return
        if self.ssmManagedSet is None:
            self.results[key] = [0, f"Unable to evaluate ({self.ssmError or 'SSM managed instances not readable'}); key pair '{keyName}'"]
            return
        if self.instanceId not in self.ssmManagedSet:
            self.results[key] = [0, f"Key pair '{keyName}'; not SSM-managed, so the SSH key may be the only access path"]
            return
        ping = self.pingStatus.get(self.instanceId)
        if ping and ping != 'Online':
            self.results[key] = [0, f"Key pair '{keyName}'; SSM agent PingStatus={ping}"]
            return
        self.results[key] = [-1, f"Key pair '{keyName}' while Session Manager is available; remove the key from authorized_keys and launch without a key pair"]

    def _listInventory(self, typeName):
        entries, token, meta = [], None, {}
        while True:
            kwargs = {'InstanceId': self.instanceId, 'TypeName': typeName, 'MaxResults': 50}
            if token:
                kwargs['NextToken'] = token
            resp = self.ssmClient.list_inventory_entries(**kwargs)
            entries.extend(resp.get('Entries', []) or [])
            if resp.get('CaptureTime'):
                meta['CaptureTime'] = resp['CaptureTime']
            token = resp.get('NextToken')
            if not token:
                return entries, meta

    def _checkEc2SshdRunning(self):
        """SSM-managed instance (Session Manager available) still running an
        interactive remote-login service. Uses SSM Inventory AWS:Service, which
        Systems Manager collects for Windows only - Linux daemons are not inventoried,
        so Linux/macOS instances are reported as not evaluable."""
        key = 'ec2SshdRunning'
        inst = self.instanceData
        if not inst or (inst.get('State') or {}).get('Name') != 'running':
            return
        if self.ssmManagedSet is None:
            self.results[key] = [0, f"Unable to evaluate ({self.ssmError or 'SSM managed instances not readable'})"]
            return
        if self.instanceId not in self.ssmManagedSet:
            self.results[key] = [0, 'Not evaluable: not SSM-managed (no inventory)']
            return
        platform = self.platformType.get(self.instanceId)
        if platform != 'Windows':
            self.results[key] = [0, f"Not evaluable: SSM AWS:Service inventory is Windows-only (platform {platform or 'unknown'})"]
            return
        if self.ssmClient is None:
            return
        try:
            entries, meta = self._listInventory('AWS:Service')
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return
        if not entries:
            self.results[key] = [0, 'Unable to evaluate (AWS:Service inventory not collected)']
            return

        running = sorted({REMOTE_LOGIN_SERVICES[str(e.get('Name', '')).lower()] for e in entries
                          if str(e.get('Name', '')).lower() in REMOTE_LOGIN_SERVICES
                          and str(e.get('Status', '')).lower() == 'running'})
        captured = f" (inventory {meta['CaptureTime']})" if meta.get('CaptureTime') else ''
        if running:
            self.results[key] = [-1, f"{', '.join(running)} running while Session Manager is available{captured}"]
        else:
            self.results[key] = [1, f"No RDP/SSH service running{captured}"]

    def _datastorePorts(self):
        hits = set()
        for sg in self.securityGroups or []:
            for perm in sg.get('IpPermissions', []) or []:
                if str(perm.get('IpProtocol')) != 'tcp':
                    continue
                lo, hi = perm.get('FromPort'), perm.get('ToPort')
                if lo is None or hi is None or hi - lo > DATASTORE_MAX_RANGE:
                    continue
                for port, name in DATASTORE_PORTS.items():
                    if lo <= port <= hi:
                        hits.add(f"{name} {port} ({sg.get('GroupId')})")
        return sorted(hits)

    def _checkSelfManagedDataStoreOnEc2(self):
        """Heuristic: the instance runs a self-managed database / cache. Evidence:
        (a) SSM Inventory AWS:Application lists a database / cache server package
        (SSM-managed instances only), or (b) an attached security group explicitly
        opens a default data-store port (narrow TCP range). When inventory is
        available and shows no server package, the port evidence alone is INFO
        (e.g. a proxy, or a security group shared with a managed database)."""
        key = 'selfManagedDataStoreOnEc2'
        inst = self.instanceData
        if not inst or self.securityGroups is None:
            return
        ports = self._datastorePorts()

        packages, invNote = None, ''
        if self.ssmClient is not None and self.ssmManagedSet and self.instanceId in self.ssmManagedSet:
            try:
                entries, meta = self._listInventory('AWS:Application')
                if entries:
                    packages = sorted({str(e.get('Name', '')) for e in entries
                                       if any(p.search(str(e.get('Name', '')).lower()) for p in DATASTORE_PACKAGES)})
                else:
                    invNote = '; AWS:Application inventory not collected'
            except botocore.exceptions.ClientError as e:
                invNote = f"; inventory not readable ({e.response['Error']['Code']})"

        if packages:
            self.results[key] = [-1, f"Data store server package(s) installed: {', '.join(packages[:5])}" +
                                 (f"; security group opens {', '.join(ports[:3])}" if ports else '')]
        elif ports and packages is not None:
            self.results[key] = [0, f"Security group opens {', '.join(ports[:5])} but SSM Inventory shows no data store server package"]
        elif ports:
            self.results[key] = [-1, f"Security group opens data store port(s) {', '.join(ports[:5])} (port heuristic{invNote or '; instance not SSM-managed, no inventory'})"]
        else:
            self.results[key] = [1, f"No data store ports or packages detected{invNote}"]

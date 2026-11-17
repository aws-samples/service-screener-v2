import botocore

from services.Evaluator import Evaluator

# Windows services that accept interactive remote logins (lower-cased service names)
REMOTE_LOGIN_SERVICES = {'termservice': 'RDP (TermService)', 'sshd': 'OpenSSH (sshd)'}


class Ec2SSM(Evaluator):
    """Check if an EC2 instance is managed by AWS Systems Manager.

    ssmManagedSet is None when ssm:DescribeInstanceInformation could not be read
    (ssmError holds the error code); pingStatus maps instance ID -> PingStatus."""

    def __init__(self, instanceId, ssmManagedSet, instanceData=None, ssmError=None, pingStatus=None,
                 ssmClient=None, platformType=None):
        super().__init__()
        self.instanceId = instanceId
        self.ssmManagedSet = ssmManagedSet
        self.instanceData = instanceData
        self.ssmError = ssmError
        self.pingStatus = pingStatus or {}
        self.ssmClient = ssmClient
        self.platformType = platformType or {}

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

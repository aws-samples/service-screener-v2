import botocore

from services.Evaluator import Evaluator

class Ec2SSM(Evaluator):
    """Check if an EC2 instance is managed by AWS Systems Manager.

    ssmManagedSet is None when ssm:DescribeInstanceInformation could not be read
    (ssmError holds the error code); pingStatus maps instance ID -> PingStatus."""

    def __init__(self, instanceId, ssmManagedSet, instanceData=None, ssmError=None, pingStatus=None):
        super().__init__()
        self.instanceId = instanceId
        self.ssmManagedSet = ssmManagedSet
        self.instanceData = instanceData
        self.ssmError = ssmError
        self.pingStatus = pingStatus or {}

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

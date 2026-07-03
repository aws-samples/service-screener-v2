import botocore

from services.Evaluator import Evaluator

class Ec2SSM(Evaluator):
    """Check if an EC2 instance is managed by AWS Systems Manager."""
    
    def __init__(self, instanceId, ssmManagedSet):
        super().__init__()
        self.instanceId = instanceId
        self.ssmManagedSet = ssmManagedSet

        self._resourceName = instanceId

        self.init()
        
    def _checkSSMManaged(self):
        """Flag instances not registered with SSM (no patching/compliance visibility)"""
        if self.instanceId not in self.ssmManagedSet:
            self.results['EC2SSMNotManaged'] = [-1, 'Not managed']

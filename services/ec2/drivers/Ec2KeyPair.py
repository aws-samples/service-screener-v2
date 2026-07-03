import botocore

from services.Evaluator import Evaluator

class Ec2KeyPair(Evaluator):
    """Check for EC2 key pairs that are not associated with any running instance."""
    
    def __init__(self, keyPair, instanceKeyNames):
        super().__init__()
        self.keyPair = keyPair
        self.instanceKeyNames = instanceKeyNames

        self._resourceName = keyPair['KeyName']

        self.init()
        
    def _checkKeyPairInUse(self):
        """Flag key pairs not attached to any running instance"""
        keyName = self.keyPair['KeyName']
        if keyName not in self.instanceKeyNames:
            self.results['EC2KeyPairNotInUse'] = [-1, keyName]

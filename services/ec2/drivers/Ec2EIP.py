import boto3
import botocore

from utils.Config import Config
from services.Service import Service

from services.Evaluator import Evaluator

class Ec2EIP(Evaluator):
    def __init__(self, eip):
        super().__init__()
        self.eip = eip

        self._resourceName = eip['PublicIp']

        self.init()
        
    def _checkEIPInUse(self):
        if 'AssociationId' not in self.eip:
            self.results['EC2EIPNotInUse'] = [-1, self.eip['PublicIp']]
        
        return
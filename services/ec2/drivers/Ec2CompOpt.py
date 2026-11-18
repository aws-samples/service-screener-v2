import boto3
import botocore

from utils.Config import Config
from services.Service import Service

from services.Evaluator import Evaluator
from services.ec2.drivers.Ec2Regional import compOptEnrollmentStatus

class Ec2CompOpt(Evaluator):
    def __init__(self, compOptClient):
        super().__init__()
        self.compOptClient = compOptClient

        self._resourceName = 'ComputeOptimizer'

        self.init()
    
    def _checkComputeOptimizerEnabled(self):
        result = compOptEnrollmentStatus(self, self.compOptClient)
        
        if result['status'] != 'Active':
            self.results['ComputeOptimizerEnabled'] = [-1,result['status']]
import urllib.parse
from datetime import date

import boto3
import botocore

from utils.Config import Config
from utils.Policy import Policy
from utils.Tools import _warn
from services.Evaluator import Evaluator

class S3Macie(Evaluator):
    def __init__(self, macieV2Client):
        super().__init__()
        self.macieV2Client = macieV2Client
        
        self.init()
    
    def _checkMacieEnable(self):
        try:
            self.macieV2Client.list_findings()
        except self.macieV2Client.exceptions.AccessDeniedException as e:
            self.results['MacieToEnable'] = [-1, None]
        except botocore.exceptions.EndpointConnectionError as connErr:
            _warn(str(connErr))
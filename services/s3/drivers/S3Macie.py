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
        
        self._resourceName = 'Macie'

        self.init()
    
    def _checkMacieEnable(self):
        try:
            self.macieV2Client.list_findings()
        except self.macieV2Client.exceptions.AccessDeniedException as e:
            self.results['MacieToEnable'] = [-1, None]
        except botocore.exceptions.EndpointConnectionError as connErr:
            # Handle regions where Macie2 is not available
            # Service unavailability is environmental, not a finding - just log and skip
            _warn(f"Macie2 service not available in this region: {str(connErr)}")
            # Don't create result entry - this prevents "rule not available in reporter" warning
            return
        except Exception as e:
            # Handle any other unexpected errors
            # Operational errors are not findings - just log and skip
            _warn(f"Error checking Macie2 status: {str(e)}")
            # Don't create result entry - this prevents "rule not available in reporter" warning
            return
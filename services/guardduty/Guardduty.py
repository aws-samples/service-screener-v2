import os
from utils.Tools import _warn
from botocore.exceptions import ClientError, EndpointConnectionError
import boto3
from services.Service import Service
from services.guardduty.drivers.GuarddutyDriver import GuarddutyDriver

from utils.Tools import _pi

class Guardduty(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.guardduty_client = ssBoto.client('guardduty', config=self.bConfig)

    def get_resources(self):
        try:
            results = self.guardduty_client.list_detectors()
            detector_ids = results['DetectorIds']
        except ClientError as e:
            _warn("(Not showstopper: Services not available: {}".format(e))
            return []
        return detector_ids

    def advise(self):
        objs = {}
        detectors = self.get_resources()
        for detector in detectors:
            _pi("GuardDuty", detector)
            obj = GuarddutyDriver(detector, self.guardduty_client, self.region)
            obj.run(self.__class__)
            objs[f"Detector::{detector}"] = obj.getInfo()
        return objs
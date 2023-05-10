import os
from botocore.exceptions import ClientError
import boto3
from services.Service import Service
from services.guardduty.drivers.GuarddutyDriver import GuarddutyDriver

class Guardduty(Service):
    def __init__(self, region):
        super().__init__(region)
        self.guardduty_client = boto3.client('guardduty', config=self.bConfig)

    def get_resources(self):
        results = self.guardduty_client.list_detectors()
        detector_ids = results['DetectorIds']
        return detector_ids

    def advise(self):
        objs = {}
        detectors = self.get_resources()
        for detector in detectors:
            print(f"... (GuardDuty) inspecting {detector}")
            obj = GuarddutyDriver(detector, self.guardduty_client, self.region)
            obj.run()
            objs[f"Detector::{detector}"] = obj.getInfo()
        return objs
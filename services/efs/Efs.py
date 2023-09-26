import os
import boto3

# from botocore.config import Config
from services.Service import Service
from utils.Config import Config as Config_int

from services.efs.drivers.EfsDriver import EfsDriver

class Efs(Service):
    def __init__(self, region):
        super().__init__(region)

        self.efs_client = boto3.client('efs', config=self.bConfig)

    def get_resources(self):
        resources = self.efs_client.describe_file_systems()
        results = resources['FileSystems']

        if not self.tags:
            return results

        filtered_results = []
        for efs in results:
            if self.resource_has_tags(efs['Tags']):
                filtered_results.append(efs)

        return filtered_results

    def advise(self):
        objs = {}

        efs_list = self.get_resources()
        driver = 'EfsDriver'
        if globals().get(driver):
            for efs in efs_list:
                print('... (EFS) inspecting ' + efs['FileSystemId'])
                obj = globals()[driver](efs, self.efs_client)
                obj.run(self.__class__)

                objs['EFS::' + efs['FileSystemId']] = obj.getInfo()
                del obj

        return objs


if __name__ == "__main__":
    Config_int.init()
    o = Efs('ap-southeast-1')
    out = o.advise()
    print(out)

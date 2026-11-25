import botocore

from services.Service import Service
from utils.Config import Config
from utils.Tools import _pi

from services.fsx.drivers.FsxFileSystem import FsxFileSystem


class Fsx(Service):
    """
    Amazon FSx scanner (Windows File Server, Lustre, NetApp ONTAP, OpenZFS).

    Read-only calls: fsx.describe_file_systems (paginated).
    """

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.fsxClient = ssBoto.client('fsx', config=self.bConfig)

    def getResources(self):
        arr = []
        try:
            paginator = self.fsxClient.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                for fs in page.get('FileSystems', []):
                    if self.tags and not self.resourceHasTags(fs.get('Tags', [])):
                        continue
                    arr.append(fs)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"FSx not available in region {self.region}: {e}")
        except botocore.exceptions.ClientError as e:
            print(f"(Not showstopper): Error during fsx describe_file_systems: {e.response['Error']['Code']}")
        return arr

    def advise(self):
        objs = {}
        for fs in self.getResources():
            fsId = fs.get('FileSystemId', 'unknown')
            _pi('FSx', fsId)
            obj = FsxFileSystem(fs, self.fsxClient)
            obj.run(self.__class__)
            objs[f"FileSystem::{fsId}"] = obj.getInfo()
            del obj
        return objs


if __name__ == "__main__":
    Config.init()
    o = Fsx('us-east-1')
    print(o.advise())

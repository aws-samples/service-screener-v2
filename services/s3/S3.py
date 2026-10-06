import botocore
import json
import time
import concurrent.futures as cf

from utils.Config import Config
from utils.Tools import _pr, _warn
from services.Service import Service
from botocore.config import Config as bConfig

# import drivers here
from services.s3.drivers.S3Bucket import S3Bucket
from services.s3.drivers.S3Control import S3Control
from services.s3.drivers.S3Macie import S3Macie

from utils.Tools import _pi

class S3(Service):
    def __init__(self, region):
        super().__init__(region)
        self.region = region
        # conf = bConfig(region_name=region)
        # print(self.bConfig)
        
        ssBoto = self.ssBoto
        self.s3Client = ssBoto.client('s3', config=self.bConfig)
        self.s3Control = ssBoto.client('s3control', config=self.bConfig)
        self.macieV2Client = ssBoto.client('macie2', config=self.bConfig)
        
        # buckets = Config.get('s3::buckets', [])
    
    def getResources(self):
        buckets = Config.get('s3::buckets', {})
        unableToListBucket = Config.get('s3::bucketUnableToList', False)
        if not buckets and not unableToListBucket:
            try:
                buckets = {}
                results = self.s3Client.list_buckets()
                
                arr = results.get('Buckets')
                # NOTE: list_buckets paginates via 'Marker'/'IsTruncated' (previously
                # mis-keyed as 'Maker', so pagination never ran and buckets beyond the
                # first page were silently dropped).
                while results.get('IsTruncated'):
                    results = self.s3Client.list_buckets(
                        Marker = results.get('NextMarker') or arr[-1]['Name']
                    )
                    arr = arr + results.get('Buckets')
                
                # Resolve each bucket's region. get_bucket_location is a per-bucket
                # network round-trip and list_buckets is account-global, so this is
                # the single biggest batch of serial S3 calls in the scan. Fetch them
                # concurrently with a bounded thread pool (I/O-bound, so threads help),
                # then group the results single-threaded to keep the grouping dict safe
                # and the output deterministic.
                def _resolveLocation(bucket):
                    try:
                        loc = self.s3Client.get_bucket_location(Bucket=bucket['Name'])
                        reg = loc.get('LocationConstraint') or 'us-east-1'
                        return (bucket, reg, None)
                    except Exception as e:
                        # Preserve original behaviour: default to us-east-1 on error.
                        return (bucket, 'us-east-1', e)

                # Cap workers so we don't open an unbounded number of connections on
                # very large accounts; min() keeps it small for small accounts.
                maxWorkers = min(16, max(1, len(arr)))
                with cf.ThreadPoolExecutor(max_workers=maxWorkers) as executor:
                    located = list(executor.map(_resolveLocation, arr))

                # Serial grouping (deterministic order, follows the original arr order).
                for bucket, reg, err in located:
                    if err is not None:
                        print(f"Error getting location for {bucket['Name']}: {err}")
                    else:
                        # Cache under the same key the replication check reads so it
                        # reuses this instead of refetching the source location.
                        Config.set(f's3::bucket_region::{bucket["Name"]}', reg)

                    if reg not in buckets:
                        buckets[reg] = []
                    buckets[reg].append(bucket)
                
            except botocore.exceptions.ClientError as e:
                Config.set('s3::bucketUnableToList', True)
                ecode = e.response['Error']['Code']
                emsg = e.response['Error']['Message']
                print('s3', ecode, emsg)
                
            Config.set('s3::buckets', buckets)
            
        if self.region in buckets:
            _buckets = buckets[self.region]
        else:
            return []
            
        if not self.tags:
            return _buckets
        
        filteredBuckets = []
        for bucket in _buckets:
            try:
                result = self.s3Client.get_bucket_tagging(Bucket = bucket['Name'])
                tags =result.get('TagSet')
                if self.resourceHasTags(tags):
                    filteredBuckets.append(bucket)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchTagSet':
                    emsg = e.response['Error']
                    _warn("S3 Error:({}, {}) is not being handled by S3::Service, please submit an issue to github.".format(emsg['Code'], emsg['Message']))
        
        return filteredBuckets    
    
    def advise(self):
        objs = {}
        accountScanned = Config.get('S3_HasAccountScanned', False)
        if accountScanned == False:
            _pi('S3Account')
            obj = S3Control(self.s3Control)
            obj.run(self.__class__)
            objs["Account::Control"] = obj.getInfo()
            
            Config.set('S3_HasAccountScanned', True)
            del obj
        
        objs = {}
        buckets = self.getResources()
        
        # Buckets are processed one at a time here on purpose. The outer
        # multiprocessing Pool in main.py parallelizes only across SERVICES
        # (one process for s3), so it gives S3 no internal parallelism. The real
        # per-bucket API fan-out IS already concurrent: Evaluator.run() runs each
        # bucket's checks in its own ThreadPoolExecutor. This loop is NOT safe to
        # parallelize across buckets without changes to shared framework code
        # (Evaluator/Config/Checkpoint/CustomPage all do lock-free writes per
        # bucket), so it stays serial. The account-wide bucket-location fetch,
        # which was the one safe batch of parallelism owned by S3, is parallelized
        # in getResources() instead.
        for bucket in buckets:
            _pi('S3Bucket', bucket['Name'])
            obj = S3Bucket(bucket['Name'], self.s3Client)
            obj.run(self.__class__)
            
            objs["Bucket::" + bucket['Name']] = obj.getInfo()
            del obj
        
        _pi('S3Macie')
        obj = S3Macie(self.macieV2Client)
        obj.run(self.__class__)
        objs["Macie"] = obj.getInfo()
        return objs

        
if __name__ == "__main__":
    Config.init()
    o = S3('ap-southeast-1')
    o.advise()
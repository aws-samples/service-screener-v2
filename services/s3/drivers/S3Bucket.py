import urllib.parse
from datetime import date

import boto3
import botocore
import json

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

# Lists to store buckets missing specific lifecycle rules
buckets_missing_abort_mpu = []
buckets_missing_expire_noncurrent = []
buckets_missing_transition_rules = []

class S3Bucket(Evaluator):
    def __init__(self, bucket, s3Client):
        super().__init__()
        self.bucket = bucket
        self.s3Client = s3Client
        
        self.init()

    def _checkEncrypted(self):
        self.results['ServerSideEncrypted'] = [1, 'On']
        try:
            resp = self.s3Client.get_bucket_encryption(
                Bucket=self.bucket
            )
            if "kms" not in resp.get('ServerSideEncryptionConfiguration').get('Rules')[0].get('ApplyServerSideEncryptionByDefault').get('SSEAlgorithm'):
                self.results['SSEWithKMS'] = [1, 'On']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                self.results['ServerSideEncrypted'] = [-1, 'Off']

    def _checkPublicAcessBlock(self):
        self.results['PublicAccessBlock'] = [-1, 'Off']
        try:
            resp = self.s3Client.get_public_access_block(
                Bucket=self.bucket
            )
            
            for param, val in resp['PublicAccessBlockConfiguration'].items():
                if val == False:
                   return
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                return
        
        self.results['PublicAccessBlock'] = [1, 'On']
    
    def _checkMfaDeleteAndVersioning(self):
        self.results['MFADelete'] = [-1, 'Off']
        self.results['BucketVersioning'] = [-1, 'Off']
        
        try:
            resp = self.s3Client.get_bucket_versioning(
                Bucket=self.bucket
            )
            if resp.get('Status') == "MFADelete":
                self.results['MFADelete'] = [1, 'On']
            
            if resp.get('Status') == "Enabled":
                self.results['BucketVersioning'] = [1, 'On']
        except botocore.exceptions.ClientError as e:
            print("[{}] Unable to get Bucket Versioning Informaton, skip".format(self.bucket))

    def _checkObjectLock(self):
        self.results['ObjectLock'] = [1, 'On']
        try:
            resp = self.s3Client.get_object_lock_configuration(
                Bucket=self.bucket
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] ==  'ObjectLockConfigurationNotFoundError':
                self.results['ObjectLock'] = [-1, 'Off']

    def _checkBucketReplication(self):
        try:
            self.results['BucketReplication'] = [1, 'On']

            resp = self.s3Client.get_bucket_replication(
                Bucket=self.bucket
            )
            source_loc = self.s3Client.get_bucket_location(
                Bucket=self.bucket
            )
            target_bucket = resp.get('ReplicationConfiguration').get('Rules')[0].get('Destination').get('Bucket').split(':')[-1]     
            target_loc = self.s3Client.get_bucket_location(
                Bucket=target_bucket
            )
            if source_loc.get('LocationConstraint') != target_loc.get('LocationConstraint'):
                self.results['CrossRegionReplication'] = [1, 'On']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ReplicationConfigurationNotFoundError':
                self.results['BucketReplication'] = [-1, 'Off']

        

    def _checkLifecycle(self):
        self.results['BucketLifecycle'] = [1, 'On']
        try:
            resp = self.s3Client.get_bucket_lifecycle(
                Bucket=self.bucket
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] ==  'NoSuchLifecycleConfiguration':
                self.results['BucketLifecycle'] = [-1, 'Off']

    def _checkLogging(self):
        self.results['BucketLogging'] = [1, 'On']
        try:
            resp = self.s3Client.get_bucket_logging(
                Bucket=self.bucket
            )
            ele = resp.get('LoggingEnabled')
            if not ele:
                self.results['BucketLogging'] = [-1, 'Off']
        except botocore.exceptions.ClientError as e:
            print("[{}] Unable to get Logging Informaton, skip".format(self.bucket))
    
    def _checkEventNotif(self):
        self.results['EventNotification'] = [1, 'On']
        try:
            resp = self.s3Client.get_bucket_notification_configuration(
                Bucket=self.bucket
            )
            self.results['EventNotification'] = [-1, 'On']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] ==  'NoSuchNotificationConfiguration':
                self.results['EventNotification'] = [-1, 'Off']

    def _checkACL(self):
        try:
            resp = self.s3Client.get_bucket_acl(
                Bucket=self.bucket
            )
            self.results['AccessControlList'] = [-1, 'Enabled']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] ==  'NoSuchAcl':
                self.results['AccessControlList'] = [1, 'Disabled']
    
    def _checkIntelligentTiering(self): 
        try:
            self.results['ObjectsInIntelligentTier'] = [1,'On'] 
            resp = self.s3Client.list_objects(
                Bucket = self.bucket,
                MaxKeys = 1000
            )
            if not resp.get('Contents'):
                return
            for object in resp.get('Contents'):
                if object['StorageClass'] != "INTELLIGENTTIERING":
                    self.results['ObjectsInIntelligentTier'] = [-1,'Off']
                    return 
        except botocore.exceptions.ClientError as e:
            print("[{}] Unable to get Tier Informaton, skip".format(self.bucket))
            
    def _checkTls(self):
        self.results['TlsEnforced'] = [-1, 'Off']
        try:
            resp = self.s3Client.get_bucket_policy(
                Bucket=self.bucket
            )
            policy = json.loads(resp.get('Policy'))
            for obj in policy['Statement']: 
                if 'Condition' not in obj:
                    continue

                cc = json.loads(json.dumps(obj['Condition']))

                if obj['Effect'] == "Deny":
                    for cond in cc:
                        if 'aws:SecureTransport' in cond and cond['aws:SecureTransport'] == "false":
                            self.results['TlsEnforced'] = [1, 'On']
                            return

                if obj['Effect'] == "Allow":
                    for cond in cc:
                        if 'aws:SecureTransport' in cond and cond['aws:SecureTransport'] == "true":
                            self.results['TlsEnforced'] = [1, 'On']
                            return
        except botocore.exceptions.ClientError as e:
            return
        
## Everything below is for cost optimization checks     
# 
#    

    def _checkMultiUploadLifecycle(self):
        try:
            resp = self.s3Client.get_bucket_lifecycle_configuration(Bucket=self.bucket)
            
            # Check if any rule contains 'AbortIncompleteMultipartUpload'
            has_abort_mpu = any('AbortIncompleteMultipartUpload' in rule for rule in resp.get('Rules', []))
            
            # Set result based on presence of the rule
            self.results['MultiUploadLifecycle'] = [1, 'On'] if has_abort_mpu else [-1, 'Off']
            
            # If the rule is missing, add the bucket to the list
            if not has_abort_mpu:
                buckets_missing_abort_mpu.append(self.bucket)
            
            # Count the number of buckets missing the rule
            count_missing_abort_mpu = len(buckets_missing_abort_mpu)
            
            # Store data in self.charts
            self.charts["MultiUploadLifecycleChart"] = {
                "BucketsMissingAbortMPU": count_missing_abort_mpu
            }

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                self.results['MultiUploadLifecycle'] = [-1, 'Off']
                buckets_missing_abort_mpu.append(self.bucket)
                count_missing_abort_mpu = len(buckets_missing_abort_mpu)
                self.charts["MultiUploadLifecycleChart"] = {
                    "BucketsMissingAbortMPU": count_missing_abort_mpu
                }



    def _checkExpireNonCurrentLifecycle(self):
        try:
            resp = self.s3Client.get_bucket_lifecycle_configuration(Bucket=self.bucket)
            
            has_noncurrent_expiration = any('NoncurrentVersionExpiration' in rule for rule in resp.get('Rules', []))
            
            self.results['ExpireNonCurrentLifecycle'] = [1, 'On'] if has_noncurrent_expiration else [-1, 'Off']

            if not has_noncurrent_expiration:
                buckets_missing_expire_noncurrent.append(self.bucket)
            
            count_missing_expire_noncurrent = len(buckets_missing_expire_noncurrent)
            
            self.charts["ExpireNonCurrentLifecycleChart"] = {
                "BucketsMissingExpireNonCurrent": count_missing_expire_noncurrent
            }

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                self.results['ExpireNonCurrentLifecycle'] = [-1, 'Off']
                buckets_missing_expire_noncurrent.append(self.bucket)
                count_missing_expire_noncurrent = len(buckets_missing_expire_noncurrent)
                self.charts["ExpireNonCurrentLifecycleChart"] = {
                    "BucketsMissingExpireNonCurrent": count_missing_expire_noncurrent
                }


    def _checkTransitionNonCurrentLifecycle(self):
        try:
            resp = self.s3Client.get_bucket_lifecycle_configuration(Bucket=self.bucket)
            
            has_noncurrent_transition = any('NoncurrentVersionTransition' in rule for rule in resp.get('Rules', []))
            
            self.results['TransitionNonCurrentLifecycle'] = [1, 'On'] if has_noncurrent_transition else [-1, 'Off']
            
            if not has_noncurrent_transition:
                buckets_missing_transition_rules.append(self.bucket)
            
            count_missing_transition_rules = len(buckets_missing_transition_rules)
            
            self.charts["TransitionNonCurrentLifecycleChart"] = {
                "BucketsMissingTransitionRules": count_missing_transition_rules
            }

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                self.results['TransitionNonCurrentLifecycle'] = [-1, 'Off']
                buckets_missing_transition_rules.append(self.bucket)
                count_missing_transition_rules = len(buckets_missing_transition_rules)
                self.charts["TransitionNonCurrentLifecycleChart"] = {
                    "BucketsMissingTransitionRules": count_missing_transition_rules
                }

    def getChart(self):
            return self.charts


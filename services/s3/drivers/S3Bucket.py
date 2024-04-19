import urllib.parse
from datetime import date

import boto3
import botocore
import json

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

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
            target_loc = resp.get('ReplicationConfiguration').get('Rules')[0].get('Destination').get('Bucket')
            if source_loc.get('LocationConstraint') != target_loc.split('.')[1]:
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

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

        self._resourceName = bucket
        
        self.init()

    def policyAllowsPublicRead(self, policy_document):
        """
        Check if the policy allows public read access
        
        Args:
            policy_document (str): The bucket policy as a string
        
        Returns:
            bool: True if policy allows public read access, False otherwise
        """
        if not policy_document:
            return False
            
        try:
            policy = json.loads(policy_document)
            
            # Check for public read in policy
            for statement in policy['Statement']:
                principal = statement.get('Principal', {})
                if (principal == '*' or principal.get('AWS') == '*') and \
                   statement['Effect'] == 'Allow' and \
                   any(action in ['s3:GetObject', 's3:GetObjectVersion', 's3:ListBucket'] 
                       for action in (statement.get('Action', []) if isinstance(statement.get('Action', []), list) 
                                    else [statement.get('Action', [])])):
                    return True
                    
            return False
            
        except (json.JSONDecodeError, KeyError):
            return False
    
    def policyAllowsPublicWrite(self, policy_document):
        """
        Check if the policy allows public write access
        
        Args:
            policy_document (str): The bucket policy as a string
        
        Returns:
            bool: True if policy allows public write access, False otherwise
        """
        if not policy_document:
            return False
            
        try:
            policy = json.loads(policy_document)
            
            # Check for public write in policy
            for statement in policy['Statement']:
                principal = statement.get('Principal', {})
                if (principal == '*' or principal.get('AWS') == '*') and \
                   statement['Effect'] == 'Allow' and \
                   any(action in ['s3:PutObject', 's3:DeleteObject'] 
                       for action in (statement.get('Action', []) if isinstance(statement.get('Action', []), list) 
                                    else [statement.get('Action', [])])):
                    return True
                    
            return False
            
        except (json.JSONDecodeError, KeyError):
            return False

    def getBucketPolicy(self):
        try:
            policy = self.s3Client.get_bucket_policy(
                Bucket=self.bucket
            )
            return policy['Policy']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return None
    
    def aclAllowsPublicRead(self, bucket_acl):
        acl_allows_public_read = False
        for grant in bucket_acl['Grants']:
            if grant['Grantee']['Type'] == 'Group' and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers' and grant['Permission'] == 'READ':
                acl_allows_public_read = True
                break
        return acl_allows_public_read
    
    def aclAllowsPublicWrite(self, bucket_acl):
        acl_allows_public_write = False
        for grant in bucket_acl['Grants']:
            if grant['Grantee']['Type'] == 'Group' and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers' and grant['Permission'] == 'WRITE':
                acl_allows_public_write = True
                break
        return acl_allows_public_write 

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

    def _checkAccess(self):
        self.results['PublicAccessBlock'] = [1, 'On']
        
        try:
            resp = self.s3Client.get_public_access_block(
                Bucket=self.bucket
            )
            public_policy_restricted = resp['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
            for param, val in resp['PublicAccessBlockConfiguration'].items():
                if val == False:
                   self.results['PublicAccessBlock'] = [-1, 'Off']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                return

        public_acl_restricted = False
        bucket_acl = None
        try:
            bucket_acl = self.s3Client.get_bucket_acl(
                Bucket=self.bucket
            )
            self.results['AccessControlList'] = [-1, 'Enabled']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchAcl':
                public_acl_restricted = True
                self.results['AccessControlList'] = [1, 'Disabled']
                # Don't return - continue with public access checks

        policy = self.getBucketPolicy()    

        if (public_policy_restricted or not self.policyAllowsPublicRead(policy)) and (public_acl_restricted or not self.aclAllowsPublicRead(bucket_acl)):
            self.results['PublicReadAccessBlock'] = [1, 'Prohibited'] 
        else:
            self.results['PublicReadAccessBlock'] = [-1, 'NotProhibited'] 
        
        # check if S3 bucket has prohibited public writes 
        if (public_policy_restricted or not self.policyAllowsPublicWrite(policy)) and (public_acl_restricted or not self.aclAllowsPublicWrite(bucket_acl)):
            self.results['PublicWriteAccessBlock'] = [1, 'Prohibited'] 
        else:
            self.results['PublicWriteAccessBlock'] = [-1, 'NotProhibited'] 

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
            resp = self.s3Client.get_bucket_replication(
                Bucket=self.bucket
            )
            self.results['BucketReplication'] = [1, 'On']
            
            # Check if cross-region replication
            rules = resp.get('ReplicationConfiguration', {}).get('Rules', [])
            if rules:
                target_bucket = rules[0].get('Destination', {}).get('Bucket', '').split(':')[-1]
                if target_bucket:
                    # Use cached bucket location if available
                    source_region = Config.get(f's3::bucket_region::{self.bucket}')
                    if not source_region:
                        source_loc = self.s3Client.get_bucket_location(Bucket=self.bucket)
                        source_region = source_loc.get('LocationConstraint') or 'us-east-1'
                        Config.set(f's3::bucket_region::{self.bucket}', source_region)
                    
                    target_loc = self.s3Client.get_bucket_location(Bucket=target_bucket)
                    target_region = target_loc.get('LocationConstraint') or 'us-east-1'
                    
                    if source_region != target_region:
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
        try:
            resp = self.s3Client.get_bucket_notification_configuration(
                Bucket=self.bucket
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] ==  'NoSuchNotificationConfiguration':
                self.results['EventNotification'] = [-1, 'Off']
    
    def _checkIntelligentTiering(self): 
        try:
            resp = self.s3Client.list_objects_v2(
                Bucket=self.bucket,
                MaxKeys=10  # Check only first 10 objects for performance
            )
            
            contents = resp.get('Contents', [])
            if not contents:
                self.results['ObjectsInIntelligentTier'] = [1, 'No Objects']
                return
            
            for obj in contents:
                storage_class = obj.get('StorageClass', 'STANDARD')
                if storage_class != 'INTELLIGENT_TIERING':
                    self.results['ObjectsInIntelligentTier'] = [-1, f'Mixed storage classes (found {storage_class})']
                    return
            
            self.results['ObjectsInIntelligentTier'] = [1, f'Sample of {len(contents)} objects in Intelligent Tiering']
            
        except botocore.exceptions.ClientError as e:
            print("[{}] Unable to get Tier Information, skip".format(self.bucket))
            self.results['ObjectsInIntelligentTier'] = [0, 'Unable to check']
            
    def _checkTls(self):
        self.results['TlsEnforced'] = [-1, 'Off']
        
        policy_str = self.getBucketPolicy()
        if not policy_str:
            return
            
        try:
            policy = json.loads(policy_str)
            for statement in policy['Statement']: 
                condition = statement.get('Condition', {})
                if not condition:
                    continue

                bool_conditions = condition.get('Bool', {})
                secure_transport = bool_conditions.get('aws:SecureTransport')
                
                if statement['Effect'] == "Deny" and secure_transport == "false":
                    self.results['TlsEnforced'] = [1, 'On']
                    return
                elif statement['Effect'] == "Allow" and secure_transport == "true":
                    self.results['TlsEnforced'] = [1, 'On']
                    return
                    
        except (json.JSONDecodeError, KeyError):
            return

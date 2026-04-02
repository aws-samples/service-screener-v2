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
        
        public_policy_restricted = False
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

        # Check public read access (handle None bucket_acl)
        policy_blocks_read = not self.policyAllowsPublicRead(policy)
        acl_blocks_read = public_acl_restricted or (bucket_acl and not self.aclAllowsPublicRead(bucket_acl))
        
        if (public_policy_restricted or policy_blocks_read) and acl_blocks_read:
            self.results['PublicReadAccessBlock'] = [1, 'Prohibited'] 
        else:
            self.results['PublicReadAccessBlock'] = [-1, 'NotProhibited'] 
        
        # Check public write access (handle None bucket_acl)
        policy_blocks_write = not self.policyAllowsPublicWrite(policy)
        acl_blocks_write = public_acl_restricted or (bucket_acl and not self.aclAllowsPublicWrite(bucket_acl))
        
        if (public_policy_restricted or policy_blocks_write) and acl_blocks_write:
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

    def _checkBucketOwnerEnforced(self):
        """
        Check if Bucket Owner Enforced setting is enabled.
        This setting disables ACLs and ensures bucket owner has full control.
        """
        self.results['BucketOwnerEnforced'] = [-1, 'Off']
        
        try:
            resp = self.s3Client.get_bucket_ownership_controls(Bucket=self.bucket)
            ownership = resp.get('OwnershipControls', {}).get('Rules', [])
            
            if ownership and len(ownership) > 0:
                object_ownership = ownership[0].get('ObjectOwnership')
                if object_ownership == 'BucketOwnerEnforced':
                    self.results['BucketOwnerEnforced'] = [1, 'On']
                else:
                    self.results['BucketOwnerEnforced'] = [-1, f'Set to {object_ownership}']
                    
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'OwnershipControlsNotFoundError':
                # No ownership controls configured - ACLs are still enabled
                self.results['BucketOwnerEnforced'] = [-1, 'Not Configured']
            else:
                # Other errors - unable to check
                print(f"[{self.bucket}] Unable to get Ownership Controls: {e.response['Error']['Code']}")

    def _checkTransferAcceleration(self):
        """
        Check if Transfer Acceleration is enabled for the bucket.
        Transfer Acceleration uses CloudFront edge locations for faster uploads/downloads.
        """
        self.results['TransferAcceleration'] = [-1, 'Off']
        
        try:
            resp = self.s3Client.get_bucket_accelerate_configuration(Bucket=self.bucket)
            status = resp.get('Status')
            
            if status == 'Enabled':
                self.results['TransferAcceleration'] = [1, 'On']
            elif status == 'Suspended':
                self.results['TransferAcceleration'] = [-1, 'Suspended']
            # If no Status field, it means acceleration is not configured (default Off)
                
        except botocore.exceptions.ClientError as e:
            # Empty response or error means acceleration not configured
            print(f"[{self.bucket}] Unable to get Transfer Acceleration config: {e.response['Error']['Code']}")

    def _checkCloudWatchRequestMetrics(self):
        """
        Check if CloudWatch request metrics are enabled for the bucket.
        Request metrics provide visibility into bucket operations and access patterns.
        """
        self.results['CloudWatchRequestMetrics'] = [-1, 'Off']
        
        try:
            resp = self.s3Client.list_bucket_metrics_configurations(Bucket=self.bucket)
            metrics_configs = resp.get('MetricsConfigurationList', [])
            
            if metrics_configs and len(metrics_configs) > 0:
                self.results['CloudWatchRequestMetrics'] = [1, f'{len(metrics_configs)} configuration(s)']
            # Empty list means no metrics configured
                
        except botocore.exceptions.ClientError as e:
            print(f"[{self.bucket}] Unable to get CloudWatch Metrics config: {e.response['Error']['Code']}")

    def _checkWildcardPrincipalsActions(self):
        """
        Check for wildcard principals or wildcard actions in bucket policy Allow statements.
        Wildcard principals ("*") grant access to anyone, and wildcard actions grant all permissions.
        This is a critical security risk and common source of data breaches.
        """
        self.results['WildcardPrincipalsActions'] = [1, 'No risky wildcards']
        
        policy_str = self.getBucketPolicy()
        if not policy_str:
            # No policy means no wildcard risk
            return
            
        try:
            policy = json.loads(policy_str)
            risky_statements = []
            
            for idx, statement in enumerate(policy.get('Statement', [])):
                effect = statement.get('Effect')
                
                # Only check Allow statements (Deny with wildcards is actually restrictive)
                if effect != 'Allow':
                    continue
                
                # Check for wildcard principals
                principal = statement.get('Principal', {})
                has_wildcard_principal = False
                
                if principal == '*':
                    has_wildcard_principal = True
                elif isinstance(principal, dict):
                    # Check various principal formats
                    aws_principal = principal.get('AWS', '')
                    if aws_principal == '*' or (isinstance(aws_principal, list) and '*' in aws_principal):
                        has_wildcard_principal = True
                
                # Check for wildcard actions
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                has_wildcard_action = False
                for action in actions:
                    if action == '*' or action == 's3:*':
                        has_wildcard_action = True
                        break
                
                # Check if there are mitigating conditions
                has_conditions = bool(statement.get('Condition'))
                
                # Flag risky wildcards (wildcards without strong conditions)
                if has_wildcard_principal or has_wildcard_action:
                    risk_type = []
                    if has_wildcard_principal:
                        risk_type.append('wildcard principal')
                    if has_wildcard_action:
                        risk_type.append('wildcard action')
                    
                    risk_desc = ' and '.join(risk_type)
                    if has_conditions:
                        risky_statements.append(f"Statement {idx}: {risk_desc} (has conditions)")
                    else:
                        risky_statements.append(f"Statement {idx}: {risk_desc} (no conditions)")
            
            if risky_statements:
                self.results['WildcardPrincipalsActions'] = [-1, '; '.join(risky_statements)]
                
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[{self.bucket}] Unable to parse bucket policy: {e}")

    def _checkSSECBlocking(self):
        """
        Check if SSE-C (Server-Side Encryption with Customer-Provided Keys) is blocked.
        AWS recommends blocking SSE-C and using SSE-S3 or SSE-KMS instead to reduce
        operational complexity and key management risks.
        """
        self.results['SSECBlocking'] = [-1, 'SSE-C not blocked']
        
        # Check if bucket policy blocks SSE-C
        policy_blocks_ssec = False
        policy_str = self.getBucketPolicy()
        
        if policy_str:
            try:
                policy = json.loads(policy_str)
                
                for statement in policy.get('Statement', []):
                    effect = statement.get('Effect')
                    
                    # Look for Deny statements that block SSE-C
                    if effect == 'Deny':
                        condition = statement.get('Condition', {})
                        
                        # Check for SSE-C blocking conditions
                        string_equals = condition.get('StringEquals', {})
                        string_not_equals = condition.get('StringNotEquals', {})
                        
                        # Common pattern: Deny if SSE-C algorithm is specified
                        if 's3:x-amz-server-side-encryption-customer-algorithm' in string_equals:
                            policy_blocks_ssec = True
                            break
                        
                        # Alternative pattern: Deny if not using SSE-S3 or SSE-KMS
                        sse_algorithm = string_not_equals.get('s3:x-amz-server-side-encryption', '')
                        if sse_algorithm:
                            # If the policy denies anything that's not SSE-S3 or KMS, it blocks SSE-C
                            if isinstance(sse_algorithm, str) and sse_algorithm in ['AES256', 'aws:kms']:
                                policy_blocks_ssec = True
                                break
                            elif isinstance(sse_algorithm, list) and any(alg in ['AES256', 'aws:kms'] for alg in sse_algorithm):
                                policy_blocks_ssec = True
                                break
                            
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[{self.bucket}] Unable to parse bucket policy for SSE-C check: {e}")
        
        # Check if default encryption is configured (SSE-S3 or SSE-KMS)
        has_default_encryption = False
        try:
            resp = self.s3Client.get_bucket_encryption(Bucket=self.bucket)
            rules = resp.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            
            if rules:
                sse_algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')
                if sse_algorithm in ['AES256', 'aws:kms']:
                    has_default_encryption = True
                    
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                print(f"[{self.bucket}] Unable to get encryption config: {e.response['Error']['Code']}")
        
        # Evaluate SSE-C blocking status
        if policy_blocks_ssec and has_default_encryption:
            self.results['SSECBlocking'] = [1, 'SSE-C blocked (policy + default encryption)']
        elif policy_blocks_ssec:
            self.results['SSECBlocking'] = [1, 'SSE-C blocked (policy only)']
        elif has_default_encryption:
            self.results['SSECBlocking'] = [-1, 'Default encryption set but no policy blocking SSE-C']
        # else: remains as 'SSE-C not blocked'

    def _checkPublicAccessDocumentation(self):
        """
        Check if public buckets have proper approval documentation via tags.
        Public access should be intentional and documented with approval tags.
        """
        self.results['PublicAccessDocumentation'] = [1, 'Not public or documented']
        
        # First, determine if bucket is public
        is_public = False
        
        # Check if PublicReadAccessBlock or PublicWriteAccessBlock failed
        if 'PublicReadAccessBlock' in self.results and self.results['PublicReadAccessBlock'][0] == -1:
            is_public = True
        elif 'PublicWriteAccessBlock' in self.results and self.results['PublicWriteAccessBlock'][0] == -1:
            is_public = True
        
        # If not public, pass the check
        if not is_public:
            return
        
        # Bucket is public - check for approval tags
        try:
            resp = self.s3Client.get_bucket_tagging(Bucket=self.bucket)
            tags = resp.get('TagSet', [])
            
            # Look for approval tags
            has_approval = False
            approval_tags = ['PublicAccessApproved', 'PublicApproved', 'ApprovedPublic']
            
            for tag in tags:
                key = tag.get('Key', '')
                value = tag.get('Value', '')
                
                # Check if any approval tag exists with value 'true' or 'yes'
                if key in approval_tags and value.lower() in ['true', 'yes', '1']:
                    has_approval = True
                    break
            
            if has_approval:
                self.results['PublicAccessDocumentation'] = [1, 'Public with approval tag']
            else:
                self.results['PublicAccessDocumentation'] = [-1, 'Public without approval tag']
                
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchTagSet':
                # No tags means no approval documentation
                self.results['PublicAccessDocumentation'] = [-1, 'Public without tags']
            else:
                print(f"[{self.bucket}] Unable to get tags: {e.response['Error']['Code']}")
                self.results['PublicAccessDocumentation'] = [-1, 'Public, unable to check tags']

    def _checkUnpredictableBucketNames(self):
        """
        Check if bucket name follows unpredictable naming patterns.
        Predictable names (sequential numbers, dates, common words) make enumeration easier.
        This is a defense-in-depth measure - proper access controls are more important.
        """
        import re
        
        self.results['UnpredictableBucketNames'] = [1, 'Unpredictable']
        
        bucket_name = self.bucket.lower()
        predictability_issues = []
        
        # Check for sequential numbers (3+ digits in a row)
        if re.search(r'\d{3,}', bucket_name):
            predictability_issues.append('sequential numbers')
        
        # Check for date patterns (YYYY, YYYYMM, YYYYMMDD, YYYY-MM-DD)
        date_patterns = [
            r'20\d{2}',  # Years 2000-2099
            r'19\d{2}',  # Years 1900-1999
            r'20\d{6}',  # YYYYMMDD
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
        ]
        for pattern in date_patterns:
            if re.search(pattern, bucket_name):
                predictability_issues.append('date pattern')
                break
        
        # Check for common words (simplified list)
        common_words = [
            'test', 'demo', 'prod', 'production', 'dev', 'development',
            'staging', 'stage', 'backup', 'data', 'logs', 'temp',
            'bucket', 'storage', 'files', 'assets', 'images', 'videos'
        ]
        for word in common_words:
            if word in bucket_name:
                predictability_issues.append(f'common word: {word}')
                break
        
        # Check for very short names (< 10 chars, easier to guess)
        if len(bucket_name) < 10:
            predictability_issues.append('short name')
        
        # Check for simple patterns (repeated characters, simple sequences)
        if re.search(r'(.)\1{2,}', bucket_name):  # 3+ repeated chars
            predictability_issues.append('repeated characters')
        
        # If issues found, flag as predictable
        if predictability_issues:
            issues_str = ', '.join(predictability_issues[:3])  # Limit to first 3
            self.results['UnpredictableBucketNames'] = [-1, f'Predictable: {issues_str}']

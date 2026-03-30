import boto3
import botocore

from services.Evaluator import Evaluator


class JobDriver(Evaluator):
    """
    Driver for checking AWS Glue ETL job security configurations.
    
    This driver evaluates ETL job security settings:
    - S3 encryption
    - CloudWatch logs encryption
    - Job bookmark encryption
    - Logging enablement
    """
    
    def __init__(self, job, glueClient):
        """
        Initialize JobDriver.
        
        Args:
            job (dict): ETL job configuration from get_job() or list_jobs()
            glueClient: Boto3 Glue client for API calls
        """
        super().__init__()
        self.job = job
        self.glueClient = glueClient
        
        # Set resource name to unique identifier
        self._resourceName = f"Job::{job['Name']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('jobName', job['Name'])
        self.addII('role', job.get('Role'))
        self.addII('createdOn', str(job.get('CreatedOn', 'N/A')))
        self.addII('lastModifiedOn', str(job.get('LastModifiedOn', 'N/A')))
        self.addII('securityConfiguration', job.get('SecurityConfiguration', 'None'))
        
        # Cache security configuration details
        self._securityConfig = None
        self._securityConfigFetched = False
    
    def _getSecurityConfiguration(self):
        """
        Fetch and cache the security configuration details.
        
        Returns:
            dict: Security configuration details or None if not configured
        """
        if self._securityConfigFetched:
            return self._securityConfig
        
        self._securityConfigFetched = True
        
        securityConfigName = self.job.get('SecurityConfiguration')
        if not securityConfigName:
            return None
        
        try:
            response = self.glueClient.get_security_configuration(Name=securityConfigName)
            self._securityConfig = response.get('SecurityConfiguration', {})
            return self._securityConfig
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'EntityNotFoundException':
                print(f"Security configuration '{securityConfigName}' not found for job {self.job['Name']}")
            elif error_code != 'AccessDenied':
                print(f"Error fetching security configuration: {error_code}")
            return None
        except Exception as e:
            print(f"Unexpected error fetching security configuration: {e}")
            return None
    
    def _checkS3Encryption(self):
        """
        Check if S3 encryption is enabled for the ETL job.
        
        Validates: Requirements 4.8
        Reporter JSON key: JobS3Encryption
        """
        try:
            securityConfig = self._getSecurityConfiguration()
            
            if not securityConfig:
                self.results['JobS3Encryption'] = [-1, 'No Security Configuration']
                return
            
            encryptionConfig = securityConfig.get('EncryptionConfiguration', {})
            s3Encryption = encryptionConfig.get('S3Encryption', [])
            
            if not s3Encryption:
                self.results['JobS3Encryption'] = [-1, 'S3 Encryption Not Configured']
                return
            
            # Check if any S3 encryption is enabled (not DISABLED)
            for s3Config in s3Encryption:
                encryptionMode = s3Config.get('S3EncryptionMode', 'DISABLED')
                if encryptionMode != 'DISABLED':
                    kmsKeyArn = s3Config.get('KmsKeyArn', 'N/A')
                    self.results['JobS3Encryption'] = [1, f'Enabled (Mode: {encryptionMode}, KMS Key: {kmsKeyArn})']
                    return
            
            # All encryption modes are DISABLED
            self.results['JobS3Encryption'] = [-1, 'S3 Encryption Disabled']
            
        except Exception as e:
            print(f"Error checking S3 encryption for job {self.job['Name']}: {e}")
            self.results['JobS3Encryption'] = [0, f'Error: {str(e)}']
    
    def _checkCloudWatchLogsEncryption(self):
        """
        Check if CloudWatch logs encryption is enabled for the ETL job.
        
        Validates: Requirements 4.9
        Reporter JSON key: JobCloudWatchLogsEncryption
        """
        try:
            securityConfig = self._getSecurityConfiguration()
            
            if not securityConfig:
                self.results['JobCloudWatchLogsEncryption'] = [-1, 'No Security Configuration']
                return
            
            encryptionConfig = securityConfig.get('EncryptionConfiguration', {})
            cloudWatchEncryption = encryptionConfig.get('CloudWatchEncryption', {})
            
            encryptionMode = cloudWatchEncryption.get('CloudWatchEncryptionMode', 'DISABLED')
            
            if encryptionMode == 'SSE-KMS':
                kmsKeyArn = cloudWatchEncryption.get('KmsKeyArn', 'N/A')
                self.results['JobCloudWatchLogsEncryption'] = [1, f'Enabled (Mode: {encryptionMode}, KMS Key: {kmsKeyArn})']
            elif encryptionMode == 'DISABLED':
                self.results['JobCloudWatchLogsEncryption'] = [-1, 'CloudWatch Logs Encryption Disabled']
            else:
                self.results['JobCloudWatchLogsEncryption'] = [0, f'Unknown mode: {encryptionMode}']
            
        except Exception as e:
            print(f"Error checking CloudWatch logs encryption for job {self.job['Name']}: {e}")
            self.results['JobCloudWatchLogsEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkBookmarkEncryption(self):
        """
        Check if job bookmark encryption is enabled for the ETL job.
        
        Validates: Requirements 4.10
        Reporter JSON key: JobBookmarkEncryption
        """
        try:
            securityConfig = self._getSecurityConfiguration()
            
            if not securityConfig:
                self.results['JobBookmarkEncryption'] = [-1, 'No Security Configuration']
                return
            
            encryptionConfig = securityConfig.get('EncryptionConfiguration', {})
            bookmarkEncryption = encryptionConfig.get('JobBookmarksEncryption', {})
            
            encryptionMode = bookmarkEncryption.get('JobBookmarksEncryptionMode', 'DISABLED')
            
            if encryptionMode == 'CSE-KMS':
                kmsKeyArn = bookmarkEncryption.get('KmsKeyArn', 'N/A')
                self.results['JobBookmarkEncryption'] = [1, f'Enabled (Mode: {encryptionMode}, KMS Key: {kmsKeyArn})']
            elif encryptionMode == 'DISABLED':
                self.results['JobBookmarkEncryption'] = [-1, 'Job Bookmark Encryption Disabled']
            else:
                self.results['JobBookmarkEncryption'] = [0, f'Unknown mode: {encryptionMode}']
            
        except Exception as e:
            print(f"Error checking bookmark encryption for job {self.job['Name']}: {e}")
            self.results['JobBookmarkEncryption'] = [0, f'Error: {str(e)}']
    
    def _checkLoggingEnabled(self):
        """
        Check if logging is enabled for the ETL job.
        
        This checks if continuous logging is configured via the LogUri parameter.
        
        Validates: Requirements 4.11
        Reporter JSON key: JobLoggingEnabled
        """
        try:
            logUri = self.job.get('LogUri')
            
            if logUri:
                self.results['JobLoggingEnabled'] = [1, f'Enabled (LogUri: {logUri})']
            else:
                self.results['JobLoggingEnabled'] = [-1, 'Logging Not Configured']
            
        except Exception as e:
            print(f"Error checking logging for job {self.job['Name']}: {e}")
            self.results['JobLoggingEnabled'] = [0, f'Error: {str(e)}']
    
    def _checkJobBookmarkEnabled(self):
        """
        Check if job bookmarks are enabled for the ETL job.
        
        Job bookmarks help track processed data and prevent duplicate processing.
        This is separate from bookmark encryption - a job can have bookmarks enabled
        but not encrypted.
        
        Reporter JSON key: JobBookmarkEnabled
        """
        try:
            defaultArgs = self.job.get('DefaultArguments', {})
            bookmarkOption = defaultArgs.get('--job-bookmark-option', 'job-bookmark-disable')
            
            # Valid enabled options: job-bookmark-enable, job-bookmark-pause
            # Disabled option: job-bookmark-disable
            if bookmarkOption in ['job-bookmark-enable', 'job-bookmark-pause']:
                self.results['JobBookmarkEnabled'] = [1, f'Enabled (Option: {bookmarkOption})']
            elif bookmarkOption == 'job-bookmark-disable':
                self.results['JobBookmarkEnabled'] = [-1, 'Job Bookmarks Disabled']
            else:
                self.results['JobBookmarkEnabled'] = [0, f'Unknown option: {bookmarkOption}']
            
        except Exception as e:
            print(f"Error checking job bookmark enablement for job {self.job['Name']}: {e}")
            self.results['JobBookmarkEnabled'] = [0, f'Error: {str(e)}']
    
    def _checkGlueVersionCurrent(self):
        """
        Check if the ETL job is using a current Glue version.
        
        Flags jobs using deprecated versions (0.9, 1.0) or old versions.
        Recommends using latest stable versions (4.0, 3.0) for performance and features.
        
        Reporter JSON key: GlueVersionCurrent
        """
        try:
            glueVersion = self.job.get('GlueVersion', '0.9')  # Default to 0.9 if not set
            
            # Define version categories
            DEPRECATED_VERSIONS = ['0.9', '1.0']
            LATEST_VERSIONS = ['4.0', '3.0']
            OLD_VERSIONS = ['2.0']
            
            if glueVersion in DEPRECATED_VERSIONS:
                self.results['GlueVersionCurrent'] = [-1, f'Deprecated version: {glueVersion} (Upgrade recommended)']
            elif glueVersion in LATEST_VERSIONS:
                self.results['GlueVersionCurrent'] = [1, f'Current version: {glueVersion}']
            elif glueVersion in OLD_VERSIONS:
                self.results['GlueVersionCurrent'] = [-1, f'Old version: {glueVersion} (Consider upgrading to 3.0 or 4.0)']
            else:
                # Unknown version - could be newer or custom
                self.results['GlueVersionCurrent'] = [0, f'Version: {glueVersion} (Verify if current)']
            
        except Exception as e:
            print(f"Error checking Glue version for job {self.job['Name']}: {e}")
            self.results['GlueVersionCurrent'] = [0, f'Error: {str(e)}']


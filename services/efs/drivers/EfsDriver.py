from services.Evaluator import Evaluator

import botocore

class EfsDriver(Evaluator):
    def __init__(self, efs, efs_client):
        self.efs = efs
        self.efs_client = efs_client
        self.__config_prefix = 'efs::'

        self.results = {}

        self._resourceName = efs['FileSystemId']

        self.init()

    def _checkEncrypted(self):
        self.results['EncryptedAtRest'] = [1, 'Enabled']
        if self.efs['Encrypted'] != 1:
            self.results['EncryptedAtRest'] = [-1, 'Disabled']

    def _checkLifecycle_configuration(self):
        self.results['Lifecycle'] = [1, 'Enabled']
        efs_id = self.efs['FileSystemId']

        life_cycle = self.efs_client.describe_lifecycle_configuration(
            FileSystemId=efs_id
        )

        if len(life_cycle['LifecyclePolicies']) == 0:
            self.results['EnabledLifecycle'] = [-1, 'Disabled']

    def _checkBackupPolicy(self):
        self.results['AutomatedBackup'] = [1, 'Enabled']
        efs_id = self.efs['FileSystemId']

        try:
            backup = self.efs_client.describe_backup_policy(
                FileSystemId=efs_id
            )
        except self.efs_client.exceptions.PolicyNotFound as e:
            print("(Not showstopper): Error encounter during efs describe_backup_policy {}".format(e.response['Error']['Code']))
            return
        

        if backup['BackupPolicy']['Status'] == 'DISABLED':
            self.results['AutomatedBackup'] = [-1, 'Disabled']

    def _checkSingleAZ(self):
        if 'AvailabilityZoneName' in self.efs:
            self.results['IsSingleAZ'] = [-1, self.efs['AvailabilityZoneName']]

    def _checkElasticThroughput(self):
        """Check if file system uses Elastic throughput mode"""
        self.results['ElasticThroughput'] = [1, 'Enabled']
        
        throughput_mode = self.efs.get('ThroughputMode', '')
        if throughput_mode != 'elastic':
            self.results['ElasticThroughput'] = [-1, f'Using {throughput_mode} mode']

    def _checkReplicationEnabled(self):
        """Check if file system has replication configured"""
        # Default to fail state - replication not configured
        self.results['ReplicationEnabled'] = [-1, 'Not configured']
        efs_id = self.efs['FileSystemId']

        try:
            replication = self.efs_client.describe_replication_configurations(
                FileSystemId=efs_id
            )
            
            # Replication response structure: Replications[0].Destinations[0].Region
            # We check for at least one replication with at least one destination
            if 'Replications' in replication and len(replication['Replications']) > 0:
                destinations = replication['Replications'][0].get('Destinations', [])
                if len(destinations) > 0:
                    # Extract destination region for informational message
                    dest_region = destinations[0].get('Region', 'Unknown')
                    self.results['ReplicationEnabled'] = [1, f'Enabled to {dest_region}']
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            print(f"(Not showstopper): Error during efs describe_replication_configurations: {error_code}")
            # If error occurs, keep the default [-1, 'Not configured'] result

    def _checkThroughputModeOptimized(self):
        """Check if throughput mode is optimized for workload"""
        throughput_mode = self.efs.get('ThroughputMode', '')
        
        # Validate throughput mode is present before evaluation
        if not throughput_mode:
            self.results['ThroughputModeOptimized'] = [-1, 'Throughput mode not specified']
            return
        
        # Elastic mode is recommended for most workloads (automatic scaling)
        if throughput_mode == 'elastic':
            self.results['ThroughputModeOptimized'] = [1, 'Using Elastic mode (recommended)']
        # Provisioned mode may be over-provisioned or under-provisioned
        elif throughput_mode == 'provisioned':
            provisioned_throughput = self.efs.get('ProvisionedThroughputInMibps', 0)
            self.results['ThroughputModeOptimized'] = [-1, f'Using Provisioned mode ({provisioned_throughput} MiB/s)']
        # Bursting mode is legacy and not recommended for production
        elif throughput_mode == 'bursting':
            self.results['ThroughputModeOptimized'] = [-1, 'Using Bursting mode']
        else:
            # Handle unexpected throughput mode values
            self.results['ThroughputModeOptimized'] = [-1, f'Unknown mode: {throughput_mode}']

    def _checkFileSystemPolicy(self):
        """Check if file system has IAM policy configured"""
        # Default to fail state - no policy configured
        self.results['FileSystemPolicy'] = [-1, 'No policy configured']
        efs_id = self.efs['FileSystemId']

        try:
            policy_response = self.efs_client.describe_file_system_policy(
                FileSystemId=efs_id
            )
            
            # If API call succeeds and returns a policy, mark as pass
            if 'Policy' in policy_response and policy_response['Policy']:
                self.results['FileSystemPolicy'] = [1, 'Policy configured']
        except self.efs_client.exceptions.PolicyNotFound:
            # Expected exception when no policy exists - keep default fail result
            pass
        except botocore.exceptions.ClientError as e:
            # Handle other API errors (permissions, throttling, etc.)
            error_code = e.response['Error']['Code']
            if error_code != 'PolicyNotFound':
                print(f"(Not showstopper): Error during efs describe_file_system_policy: {error_code}")

    def _checkMountTargetSecurityGroups(self):
        """Check if mount targets have security groups attached"""
        # Default to pass state - assume all mount targets have security groups
        self.results['MountTargetSecurityGroups'] = [1, 'All mount targets have security groups']
        efs_id = self.efs['FileSystemId']

        try:
            mount_targets = self.efs_client.describe_mount_targets(
                FileSystemId=efs_id
            )
            
            # Validate mount targets exist before checking security groups
            if 'MountTargets' not in mount_targets or len(mount_targets['MountTargets']) == 0:
                self.results['MountTargetSecurityGroups'] = [-1, 'No mount targets found']
                return
            
            # Iterate through each mount target to verify security group attachment
            mount_targets_without_sg = []
            for mt in mount_targets['MountTargets']:
                try:
                    mount_target_id = mt.get('MountTargetId', 'Unknown')
                    # Security groups are returned directly in the mount target response
                    security_groups = mt.get('SecurityGroups', [])
                    
                    # Flag mount targets with no security groups attached
                    if not security_groups or len(security_groups) == 0:
                        mount_targets_without_sg.append(mount_target_id)
                except (KeyError, TypeError) as e:
                    # Handle malformed mount target data gracefully
                    print(f"(Not showstopper): Error processing mount target data: {str(e)}")
                    continue
            
            # Report failure if any mount targets lack security groups
            if mount_targets_without_sg:
                self.results['MountTargetSecurityGroups'] = [
                    -1, 
                    f'{len(mount_targets_without_sg)} mount target(s) without security groups'
                ]
        except botocore.exceptions.ClientError as e:
            # Handle API errors (permissions, throttling, etc.)
            error_code = e.response['Error']['Code']
            print(f"(Not showstopper): Error during efs describe_mount_targets: {error_code}")
            self.results['MountTargetSecurityGroups'] = [-1, 'Error checking mount targets']
        except Exception as e:
            # Catch any unexpected errors to prevent check failure
            print(f"(Not showstopper): Unexpected error in _checkMountTargetSecurityGroups: {str(e)}")
            self.results['MountTargetSecurityGroups'] = [-1, 'Unexpected error checking mount targets']


    # ========== TIER 2 CHECKS ==========

    def _checkAccessPointsConfigured(self):
        """Check if file system has access points configured"""
        # Default to fail state - no access points configured
        self.results['AccessPointsConfigured'] = [-1, 'No access points configured']
        efs_id = self.efs['FileSystemId']

        try:
            access_points = self.efs_client.describe_access_points(
                FileSystemId=efs_id
            )
            
            # Check if any access points exist for this file system
            if 'AccessPoints' in access_points and len(access_points['AccessPoints']) > 0:
                num_access_points = len(access_points['AccessPoints'])
                self.results['AccessPointsConfigured'] = [1, f'{num_access_points} access point(s) configured']
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            print(f"(Not showstopper): Error during efs describe_access_points: {error_code}")
            # If error occurs, keep the default [-1, 'No access points configured'] result

    def _checkComprehensiveSecurity(self):
        """Check if all three security controls are in place (defense-in-depth)"""
        # This is a composite check that depends on other checks
        # We need to verify: security groups + IAM policy + access points
        
        # Default to fail state
        self.results['ComprehensiveSecurity'] = [-1, 'Not all security controls in place']
        efs_id = self.efs['FileSystemId']
        
        missing_controls = []
        
        # Check 1: Security groups on mount targets
        has_security_groups = False
        try:
            mount_targets = self.efs_client.describe_mount_targets(FileSystemId=efs_id)
            if 'MountTargets' in mount_targets and len(mount_targets['MountTargets']) > 0:
                # Check if all mount targets have security groups
                all_have_sg = all(
                    mt.get('SecurityGroups') and len(mt.get('SecurityGroups', [])) > 0 
                    for mt in mount_targets['MountTargets']
                )
                has_security_groups = all_have_sg
            if not has_security_groups:
                missing_controls.append('security groups')
        except botocore.exceptions.ClientError:
            missing_controls.append('security groups')
        
        # Check 2: IAM file system policy
        has_policy = False
        try:
            policy_response = self.efs_client.describe_file_system_policy(FileSystemId=efs_id)
            if 'Policy' in policy_response and policy_response['Policy']:
                has_policy = True
        except self.efs_client.exceptions.PolicyNotFound:
            missing_controls.append('IAM policy')
        except botocore.exceptions.ClientError:
            missing_controls.append('IAM policy')
        
        if not has_policy and 'IAM policy' not in missing_controls:
            missing_controls.append('IAM policy')
        
        # Check 3: Access points
        has_access_points = False
        try:
            access_points = self.efs_client.describe_access_points(FileSystemId=efs_id)
            if 'AccessPoints' in access_points and len(access_points['AccessPoints']) > 0:
                has_access_points = True
            if not has_access_points:
                missing_controls.append('access points')
        except botocore.exceptions.ClientError:
            missing_controls.append('access points')
        
        # If all three controls are in place, mark as pass
        if not missing_controls:
            self.results['ComprehensiveSecurity'] = [1, 'All three security controls configured']
        else:
            # Report which controls are missing
            missing_str = ', '.join(missing_controls)
            self.results['ComprehensiveSecurity'] = [-1, f'Missing: {missing_str}']

    def _checkTLSRequired(self):
        """Check if file system policy requires TLS for all connections"""
        # Default to fail state - TLS not required via policy
        self.results['TLSRequired'] = [-1, 'TLS not required via policy']
        efs_id = self.efs['FileSystemId']

        try:
            policy_response = self.efs_client.describe_file_system_policy(
                FileSystemId=efs_id
            )
            
            # Check if policy exists
            if 'Policy' not in policy_response or not policy_response['Policy']:
                self.results['TLSRequired'] = [-1, 'No policy configured']
                return
            
            # Parse the policy JSON to check for aws:SecureTransport condition
            import json
            try:
                policy = json.loads(policy_response['Policy'])
                
                # Look for aws:SecureTransport condition in policy statements
                # A proper TLS-required policy should deny access when SecureTransport is false
                has_tls_requirement = False
                
                if 'Statement' in policy:
                    for statement in policy['Statement']:
                        # Check for Deny effect with SecureTransport condition
                        if statement.get('Effect') == 'Deny':
                            condition = statement.get('Condition', {})
                            # Check for Bool condition with aws:SecureTransport = false
                            if 'Bool' in condition:
                                secure_transport = condition['Bool'].get('aws:SecureTransport')
                                if secure_transport == 'false' or secure_transport is False:
                                    has_tls_requirement = True
                                    break
                
                if has_tls_requirement:
                    self.results['TLSRequired'] = [1, 'TLS required via policy']
                else:
                    self.results['TLSRequired'] = [-1, 'Policy exists but does not require TLS']
                    
            except json.JSONDecodeError as e:
                print(f"(Not showstopper): Error parsing file system policy JSON: {str(e)}")
                self.results['TLSRequired'] = [-1, 'Error parsing policy']
                
        except self.efs_client.exceptions.PolicyNotFound:
            # No policy exists - keep default fail result
            self.results['TLSRequired'] = [-1, 'No policy configured']
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code != 'PolicyNotFound':
                print(f"(Not showstopper): Error during efs describe_file_system_policy: {error_code}")

    def _checkPerformanceModeOptimized(self):
        """Check if performance mode is appropriate for workload"""
        performance_mode = self.efs.get('PerformanceMode', '')
        
        # Validate performance mode is present
        if not performance_mode:
            self.results['PerformanceModeOptimized'] = [-1, 'Performance mode not specified']
            return
        
        # General Purpose is recommended for most workloads (lower latency)
        if performance_mode == 'generalPurpose':
            self.results['PerformanceModeOptimized'] = [1, 'Using General Purpose mode (recommended)']
        # Max I/O is for highly parallelized workloads (higher latency, higher throughput)
        elif performance_mode == 'maxIO':
            # This is informational - Max I/O may be appropriate for some workloads
            self.results['PerformanceModeOptimized'] = [-1, 'Using Max I/O mode (ensure this matches workload)']
        else:
            # Handle unexpected performance mode values
            self.results['PerformanceModeOptimized'] = [-1, f'Unknown mode: {performance_mode}']

    # ========== TIER 3 CHECKS ==========

    def _checkStorageOptimization(self):
        """Check if storage distribution is optimized for cost"""
        # Default to pass state - assume storage is optimized
        self.results['StorageOptimization'] = [1, 'Storage distribution appears optimized']
        
        # Get size information from file system data
        size_in_bytes = self.efs.get('SizeInBytes', {})
        
        # Extract storage class sizes
        value_in_standard = size_in_bytes.get('Value', 0)
        value_in_ia = size_in_bytes.get('ValueInIA', 0)
        value_in_standard_only = size_in_bytes.get('ValueInStandard', 0)
        
        # Calculate total size
        total_size = value_in_standard
        
        # If no data in file system, skip check
        if total_size == 0:
            self.results['StorageOptimization'] = [1, 'File system is empty']
            return
        
        # Check if lifecycle management is enabled
        efs_id = self.efs['FileSystemId']
        lifecycle_enabled = False
        
        try:
            life_cycle = self.efs_client.describe_lifecycle_configuration(
                FileSystemId=efs_id
            )
            if 'LifecyclePolicies' in life_cycle and len(life_cycle['LifecyclePolicies']) > 0:
                lifecycle_enabled = True
        except botocore.exceptions.ClientError:
            pass
        
        # If lifecycle is enabled but no data in IA, flag for review
        if lifecycle_enabled and value_in_ia == 0 and total_size > 0:
            # Calculate percentage in Standard
            standard_gb = value_in_standard_only / (1024**3) if value_in_standard_only > 0 else 0
            self.results['StorageOptimization'] = [
                -1, 
                f'Lifecycle enabled but no data in IA ({standard_gb:.2f} GB in Standard)'
            ]
        # If lifecycle is not enabled and significant data exists, recommend enabling it
        elif not lifecycle_enabled and total_size > (10 * 1024**3):  # More than 10 GB
            total_gb = total_size / (1024**3)
            self.results['StorageOptimization'] = [
                -1, 
                f'Consider enabling lifecycle management ({total_gb:.2f} GB in Standard)'
            ]
        # If data is distributed across storage classes, report the distribution
        elif value_in_ia > 0:
            ia_percentage = (value_in_ia / total_size) * 100 if total_size > 0 else 0
            ia_gb = value_in_ia / (1024**3)
            self.results['StorageOptimization'] = [
                1, 
                f'Storage optimized: {ia_percentage:.1f}% in IA ({ia_gb:.2f} GB)'
            ]

    def _checkNoSensitiveDataInTags(self):
        """Check if tags contain sensitive data patterns"""
        # Default to pass state - assume no sensitive data in tags
        self.results['NoSensitiveDataInTags'] = [1, 'No sensitive data patterns detected in tags']
        
        # Get tags from file system data
        tags = self.efs.get('Tags', [])
        
        # If no tags, pass the check
        if not tags or len(tags) == 0:
            self.results['NoSensitiveDataInTags'] = [1, 'No tags configured']
            return
        
        # Define patterns for sensitive data
        # These are common patterns that might indicate sensitive information
        sensitive_patterns = [
            'password', 'passwd', 'pwd',
            'secret', 'api_key', 'apikey', 'api-key',
            'token', 'auth', 'credential', 'cred',
            'private', 'key', 'access_key', 'accesskey',
            'ssn', 'social_security',
            'credit_card', 'creditcard', 'cc_number',
            'email', 'phone', 'address',
            'confidential', 'sensitive'
        ]
        
        # Check each tag for sensitive patterns
        suspicious_tags = []
        for tag in tags:
            tag_key = tag.get('Key', '').lower()
            tag_value = str(tag.get('Value', '')).lower()
            
            # Check if key or value contains sensitive patterns
            for pattern in sensitive_patterns:
                if pattern in tag_key or pattern in tag_value:
                    suspicious_tags.append(f"{tag.get('Key', 'Unknown')}")
                    break
        
        # If suspicious tags found, flag for review
        if suspicious_tags:
            # Limit to first 3 tags in message to avoid overly long messages
            tag_list = ', '.join(suspicious_tags[:3])
            if len(suspicious_tags) > 3:
                tag_list += f' (+{len(suspicious_tags) - 3} more)'
            
            self.results['NoSensitiveDataInTags'] = [
                -1, 
                f'Potential sensitive data in tags: {tag_list}'
            ]

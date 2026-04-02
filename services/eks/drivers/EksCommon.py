## https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html

import boto3
import botocore

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class EksCommon(Evaluator):
    OUTBOUNDSGMINIMALRULES = {
        'tcp': [10250, 53, 443],
        'udp': [53]
    }
    
    def __init__(self, eksCluster, clusterInfo, eksClient, ec2Client, iamClient):
        super().__init__()
        self.cluster = eksCluster
        self.clusterInfo = clusterInfo
        self.eksClient = eksClient
        self.ec2Client = ec2Client
        self.iamClient = iamClient

        self._resourceName = eksCluster
        
        self.init()
        
    def getNewerVersionCnt(self, versionList, clusterVersion):
        newerVersionCnt = 0
        for version in versionList:
            if clusterVersion < version:
                newerVersionCnt += 1
        
        return newerVersionCnt
        
    def getVersions(self):
        versionList = Config.get('EKSVersionList', False)
        
        if versionList is False:
            versionList = []
            addonList = []
            results = self.eksClient.describe_addon_versions()
            addonList = results.get('addons')
            
            while results.get('nextToken') is not None:
                results = self.eksClient.describe_addon_versions(
                    nextToken = results.get('nextToken')
                )
                addonList = addonList + results.get('addons')
                
            for addon in addonList:
                for addonVersion in addon.get('addonVersions'):
                    for compatibility in addonVersion.get('compatibilities'):
                        versionList = versionList + [compatibility.get('clusterVersion')]
                        
            
            versionSet = set(versionList)
            uniqVersionList = list(versionSet)
            uniqVersionList.sort(reverse=True)
            
            Config.set('EKSVersionList', uniqVersionList)
            
            return uniqVersionList
        else:
            return versionList
            
    def getLatestVersion(self, versionList):
        return versionList[0]
        
        
    def _checkClusterVersion(self):
        clusterVersion = self.clusterInfo.get('version')
        
        versionList = self.getVersions()
        newVersionCnt = self.getNewerVersionCnt(versionList, clusterVersion)
        latestVersion = self.getLatestVersion(versionList)
        
        if newVersionCnt >= 3:
            self.results['eksClusterVersionEol'] = [-1, "Current: " + clusterVersion + ", Latest: " + latestVersion]
        elif newVersionCnt > 0 and newVersionCnt < 3:
            self.results['eksClusterVersionUpdate'] = [-1, "Current: " + clusterVersion + ", Latest: " + latestVersion]
                
        return
    
    def clusterSGInboundRuleCheck(self, rule, sgID, accountId):
        if len(rule.get('UserIdGroupPairs')) == 0:
            ## No SG Group found means the source is not from self SG, Flagged
            return False
        else:
            ## Check is the only self SG assigned into the rules
            for group in rule.get('UserIdGroupPairs'):
                if group.get('GroupId') != sgID or group.get('UserId') != accountId:
                    return False
                    
        return True
        
    def clusterSGOutboundRuleCheck(self, rule, sgID, accountId):
        minimalPort = self.OUTBOUNDSGMINIMALRULES
        
        if len(rule.get('UserIdGroupPairs')) == 0:
            return False
        else:
            ## EKS Cluster SG Outbound minimal requirement is listed in the minimal port
            if rule.get('IpProtocol') in list(minimalPort.keys()) and rule.get('FromPort') in minimalPort.get(rule.get('IpProtocol')):
                ## Check is the only self SG assigned into the rules
                for group in rule.get('UserIdGroupPairs'):
                    if group.get('GroupId') != sgID or group.get('UserId') != accountId:
                        return False
            else:
                return False
        
        return True
    
    def _checkClusterSecurityGroup(self):
        stsInfo = Config.get('stsInfo', False)
        if stsInfo is False:
            print("Unable to get Account ID, skipped Cluster Security Group check")
            return
        
        sgID =  self.clusterInfo.get('resourcesVpcConfig').get('clusterSecurityGroupId')
        if sgID is None:
            print("Cluster security group not found for cluster " + self.cluster + ". skipped Cluster Security Group check")
            return
        
        accountId = Config.get('stsInfo', False).get('Account')
        
        response = self.ec2Client.describe_security_groups(
            GroupIds = [sgID]
        )
        sgInfos = response.get('SecurityGroups')
        
        for info in sgInfos:
            ## Inbound Rule Checking
            inboundRules = info.get('IpPermissions')
            ## EKS Cluster SG Inbound Rules should point to only itself
            for rule in inboundRules:
                result = self.clusterSGInboundRuleCheck(rule, sgID, accountId)
                if not result:
                    self.results['eksClusterSGRestriction'] = [-1, sgID]
                    return
            
            ## Outbound Rule Checking
            outboundRules = info.get('IpPermissionsEgress')
            
            for rule in outboundRules:
                result = self.clusterSGOutboundRuleCheck(rule, sgID, accountId)
                if not result:
                    self.results['eksClusterSGRestriction'] = [-1, sgID]
                    return
                        
        return
    
    def _checkPublicClusterEndpoint(self):
        if self.clusterInfo.get('resourcesVpcConfig').get('endpointPublicAccess'):
            self.results['eksEndpointPublicAccess'] = [-1, 'Enabled']
        
        return
    
    def _checkEnvelopeEncryption(self):
        if self.clusterInfo.get('encryptionConfig') is None:
            self.results['eksSecretsEncryption'] = [-1, 'Disabled']
        
        return
    
    def _checkClusterLogging(self):
        for logConfig in self.clusterInfo.get('logging').get('clusterLogging'):
            if logConfig.get('enabled') is False:
                self.results['eksClusterLogging'] = [-1, 'Disabled']
                return
        
        return
    
    def inlinePolicyLeastPrivilege(self, roleName):
        response = self.iamClient.list_role_policies(
            RoleName = roleName    
        )
        
        for policyName in response.get('PolicyNames'):
            policyResp = self.iamClient.get_role_policy(
                RoleName=roleName,
                PolicyName=policyName
            )
            document = policyResp.get('PolicyDocument')
            
            pObj = Policy(document)
            pObj.inspectAccess()
            if pObj.hasFullAccessToOneResource() or pObj.hasFullAccessAdmin():
                return False
        
        return True
        
    def attachedPolicyLeastPrivilege(self, roleName):
        response = self.iamClient.list_attached_role_policies(
            RoleName = roleName    
        )
        
        for policy in response.get('AttachedPolicies'):
            policyInfoResp = self.iamClient.get_policy(
                PolicyArn=policy.get('PolicyArn')
            )
            
            policyInfo = policyInfoResp.get('Policy')
            if len(policyInfo) == 0:
                print("Skipped. Unable to retrieve policy information for " + policy.get('PolicyArn'))
                continue
            
            policyArn = policyInfo.get('Arn')
            policyVersion = policyInfo.get('DefaultVersionId')
            
            policyResp = self.iamClient.get_policy_version(
                PolicyArn=policyArn,
                VersionId=policyVersion
            )
            
            if len(policyResp.get('PolicyVersion')) == 0:
                print("Skipped. Unable to retrieve policy permission for " + policy.get('PolicyArn') + " version " + policyVersion)
                continue
                
            document = policyResp.get('PolicyVersion').get('Document')
            
            pObj = Policy(document)
            pObj.inspectAccess()
            if pObj.hasFullAccessToOneResource() or pObj.hasFullAccessAdmin():
                return False
                
        return True
        
    def _checkRoleLeastPrivilege(self):
        roleName = self.clusterInfo.get('roleArn').split('role/', 1)[1]
        
        result = self.inlinePolicyLeastPrivilege(roleName)
        if result is False:
            self.results['eksClusterRoleLeastPrivilege'] = [-1, roleName]
            return
        
        result = self.attachedPolicyLeastPrivilege(roleName)
        if result is False:
            self.results['eksClusterRoleLeastPrivilege'] = [-1, roleName]
            return
        
        return
        
        
        
        
        
        

    def _checkNoManagedNodeGroups(self):
        """
        Check if cluster has managed node groups.
        Managed node groups provide automated provisioning and lifecycle management.
        """
        try:
            response = self.eksClient.list_nodegroups(
                clusterName=self.cluster
            )
            
            nodeGroups = response.get('nodegroups', [])
            
            # Flag if cluster has no managed node groups
            if len(nodeGroups) == 0:
                self.results['eksNoManagedNodeGroups'] = [-1, 'No managed node groups']
                
        except botocore.exceptions.ClientError as e:
            print(f"Error checking managed node groups for cluster {self.cluster}: {e}")
        except Exception as e:
            print(f"Unexpected error checking managed node groups for cluster {self.cluster}: {e}")
            
        return
    
    def _checkNodeGroupSingleAZ(self):
        """
        Check if node groups span multiple availability zones.
        Multi-AZ deployment is critical for high availability.
        """
        try:
            # Get list of node groups
            response = self.eksClient.list_nodegroups(
                clusterName=self.cluster
            )
            
            nodeGroups = response.get('nodegroups', [])
            
            for nodeGroupName in nodeGroups:
                try:
                    # Get node group details
                    ngResponse = self.eksClient.describe_nodegroup(
                        clusterName=self.cluster,
                        nodegroupName=nodeGroupName
                    )
                    
                    nodeGroup = ngResponse.get('nodegroup', {})
                    subnets = nodeGroup.get('subnets', [])
                    
                    if len(subnets) == 0:
                        continue
                    
                    # Get subnet details to determine AZs
                    subnetResponse = self.ec2Client.describe_subnets(
                        SubnetIds=subnets
                    )
                    
                    # Extract unique availability zones
                    azs = set()
                    for subnet in subnetResponse.get('Subnets', []):
                        azs.add(subnet.get('AvailabilityZone'))
                    
                    # Flag if node group is in single AZ
                    if len(azs) == 1:
                        self.results['eksNodeGroupSingleAZ'] = [-1, f'{nodeGroupName} (AZ: {list(azs)[0]})']
                        
                except botocore.exceptions.ClientError as e:
                    print(f"Error checking AZ configuration for node group {nodeGroupName}: {e}")
                except Exception as e:
                    print(f"Unexpected error checking node group {nodeGroupName}: {e}")
                    
        except botocore.exceptions.ClientError as e:
            print(f"Error listing node groups for cluster {self.cluster}: {e}")
        except Exception as e:
            print(f"Unexpected error listing node groups for cluster {self.cluster}: {e}")
            
        return
    
    def _checkClusterLoggingIncomplete(self):
        """
        Check if all control plane log types are enabled.
        All log types (api, audit, authenticator, controllerManager, scheduler) should be enabled.
        """
        try:
            # Required log types for comprehensive monitoring
            requiredLogTypes = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
            
            logging = self.clusterInfo.get('logging', {})
            clusterLogging = logging.get('clusterLogging', [])
            
            # Collect enabled log types
            enabledLogTypes = set()
            for logConfig in clusterLogging:
                if logConfig.get('enabled', False):
                    types = logConfig.get('types', [])
                    enabledLogTypes.update(types)
            
            # Check if any required log types are missing
            missingLogTypes = []
            for logType in requiredLogTypes:
                if logType not in enabledLogTypes:
                    missingLogTypes.append(logType)
            
            # Flag if any log types are disabled
            if len(missingLogTypes) > 0:
                self.results['eksClusterLoggingIncomplete'] = [-1, f'Missing: {", ".join(missingLogTypes)}']
                
        except Exception as e:
            print(f"Error checking cluster logging for cluster {self.cluster}: {e}")
            
        return
    
    def _checkSecretsEncryptionNoKMS(self):
        """
        Check if customer-managed KMS key is used for secrets encryption.
        Customer-managed keys provide better control and are important for compliance.
        """
        try:
            encryptionConfig = self.clusterInfo.get('encryptionConfig')
            
            # If no encryption config, flag it
            if encryptionConfig is None or len(encryptionConfig) == 0:
                self.results['eksSecretsEncryptionNoKMS'] = [-1, 'No encryption configured']
                return
            
            # Check if KMS key is configured
            hasKmsKey = False
            for config in encryptionConfig:
                provider = config.get('provider', {})
                keyArn = provider.get('keyArn')
                
                if keyArn:
                    hasKmsKey = True
                    # Optionally check if it's a customer-managed key (not AWS-managed)
                    # AWS-managed keys have format: arn:aws:kms:region:account:alias/aws/eks
                    if '/alias/aws/' in keyArn:
                        self.results['eksSecretsEncryptionNoKMS'] = [-1, 'Using AWS-managed key']
                        return
            
            # Flag if no KMS key found
            if not hasKmsKey:
                self.results['eksSecretsEncryptionNoKMS'] = [-1, 'No KMS key configured']
                
        except Exception as e:
            print(f"Error checking secrets encryption for cluster {self.cluster}: {e}")
            
        return
    
    def _checkNoSpotInstances(self):
        """
        Check if any node groups use Spot instances.
        Spot instances can provide significant cost savings (up to 90%) for fault-tolerant workloads.
        """
        try:
            # Get list of node groups
            response = self.eksClient.list_nodegroups(
                clusterName=self.cluster
            )
            
            nodeGroups = response.get('nodegroups', [])
            
            # Track if any node group uses Spot
            hasSpotInstances = False
            
            for nodeGroupName in nodeGroups:
                try:
                    # Get node group details
                    ngResponse = self.eksClient.describe_nodegroup(
                        clusterName=self.cluster,
                        nodegroupName=nodeGroupName
                    )
                    
                    nodeGroup = ngResponse.get('nodegroup', {})
                    capacityType = nodeGroup.get('capacityType', 'ON_DEMAND')
                    
                    # Check if this node group uses Spot
                    if capacityType == 'SPOT':
                        hasSpotInstances = True
                        break
                        
                except botocore.exceptions.ClientError as e:
                    print(f"Error checking capacity type for node group {nodeGroupName}: {e}")
                except Exception as e:
                    print(f"Unexpected error checking node group {nodeGroupName}: {e}")
            
            # Flag if no Spot instances are used
            if not hasSpotInstances:
                self.results['eksNoSpotInstances'] = [-1, 'No Spot instances configured']
                
        except botocore.exceptions.ClientError as e:
            print(f"Error listing node groups for cluster {self.cluster}: {e}")
        except Exception as e:
            print(f"Unexpected error checking Spot instances for cluster {self.cluster}: {e}")
            
        return
    
    def _checkNoKarpenter(self):
        """
        Check if Karpenter add-on is installed.
        Karpenter provides efficient node provisioning and significant cost optimization.
        """
        try:
            # Get list of installed add-ons
            response = self.eksClient.list_addons(
                clusterName=self.cluster
            )
            
            addons = response.get('addons', [])
            
            # Check if Karpenter add-on is installed
            # Karpenter add-on name might be 'karpenter' or similar
            hasKarpenter = False
            for addon in addons:
                if 'karpenter' in addon.lower():
                    hasKarpenter = True
                    break
            
            # Flag if Karpenter is not installed
            if not hasKarpenter:
                self.results['eksNoKarpenter'] = [-1, 'Karpenter add-on not installed']
                
        except botocore.exceptions.ClientError as e:
            print(f"Error checking add-ons for cluster {self.cluster}: {e}")
        except Exception as e:
            print(f"Unexpected error checking Karpenter for cluster {self.cluster}: {e}")
            
        return

    
    def _checkAutoModeNotEnabled(self):
        """
        Check if EKS Auto Mode is enabled.
        Auto Mode provides fully managed compute, networking, and storage.
        """
        try:
            # Check if computeConfig exists and is enabled
            # Note: This is a newer feature, may not be available in all API versions
            computeConfig = self.clusterInfo.get('computeConfig')
            
            if computeConfig is None:
                # Auto Mode not available or not configured
                self.results['eksAutoModeNotEnabled'] = [-1, 'Auto Mode not configured']
                return
            
            # Check if Auto Mode is enabled
            enabled = computeConfig.get('enabled', False)
            
            if not enabled:
                self.results['eksAutoModeNotEnabled'] = [-1, 'Auto Mode available but not enabled']
                
        except Exception as e:
            print(f"Error checking Auto Mode for cluster {self.cluster}: {e}")
            
        return
    
    def _checkNoIRSAConfigured(self):
        """
        Check if OIDC provider is configured for IAM Roles for Service Accounts (IRSA).
        IRSA provides pod-level IAM permissions, which is more secure than node-level roles.
        """
        try:
            # Check if OIDC issuer is configured
            identity = self.clusterInfo.get('identity')
            
            if identity is None:
                self.results['eksNoIRSAConfigured'] = [-1, 'No identity configuration found']
                return
            
            oidc = identity.get('oidc')
            
            if oidc is None:
                self.results['eksNoIRSAConfigured'] = [-1, 'OIDC provider not configured']
                return
            
            issuer = oidc.get('issuer')
            
            if issuer is None or issuer == '':
                self.results['eksNoIRSAConfigured'] = [-1, 'OIDC issuer not configured']
                return
            
            # OIDC provider is configured - IRSA is available
            # Note: We cannot check if service accounts are actually using IRSA without Kubernetes API
            
        except Exception as e:
            print(f"Error checking IRSA configuration for cluster {self.cluster}: {e}")
            
        return
    
    def _checkNoAutoscaling(self):
        """
        Check if cluster has autoscaling configured.
        Checks for Karpenter add-on OR node group autoscaling (min < max).
        """
        try:
            # Check 1: Look for Karpenter add-on
            response = self.eksClient.list_addons(
                clusterName=self.cluster
            )
            
            addons = response.get('addons', [])
            
            # Check if Karpenter is installed
            hasKarpenter = False
            for addon in addons:
                if 'karpenter' in addon.lower():
                    hasKarpenter = True
                    break
            
            if hasKarpenter:
                # Karpenter provides autoscaling
                return
            
            # Check 2: Look for node group autoscaling
            ngResponse = self.eksClient.list_nodegroups(
                clusterName=self.cluster
            )
            
            nodeGroups = ngResponse.get('nodegroups', [])
            
            hasAutoscaling = False
            
            for nodeGroupName in nodeGroups:
                try:
                    ngDetailResponse = self.eksClient.describe_nodegroup(
                        clusterName=self.cluster,
                        nodegroupName=nodeGroupName
                    )
                    
                    nodeGroup = ngDetailResponse.get('nodegroup', {})
                    scalingConfig = nodeGroup.get('scalingConfig', {})
                    
                    minSize = scalingConfig.get('minSize', 0)
                    maxSize = scalingConfig.get('maxSize', 0)
                    
                    # If min < max, autoscaling is configured
                    if minSize < maxSize:
                        hasAutoscaling = True
                        break
                        
                except botocore.exceptions.ClientError as e:
                    print(f"Error checking node group {nodeGroupName}: {e}")
                except Exception as e:
                    print(f"Unexpected error checking node group {nodeGroupName}: {e}")
            
            # Flag if no autoscaling found
            if not hasAutoscaling:
                self.results['eksNoAutoscaling'] = [-1, 'No Karpenter and no node group autoscaling']
                
        except botocore.exceptions.ClientError as e:
            print(f"Error checking autoscaling for cluster {self.cluster}: {e}")
        except Exception as e:
            print(f"Unexpected error checking autoscaling for cluster {self.cluster}: {e}")
            
        return
    
    def _checkNoManagedStorageDrivers(self):
        """
        Check if EBS or EFS CSI driver add-ons are installed.
        Managed storage drivers are important for persistent storage and data durability.
        """
        try:
            # Get list of installed add-ons
            response = self.eksClient.list_addons(
                clusterName=self.cluster
            )
            
            addons = response.get('addons', [])
            
            # Check for EBS CSI driver
            hasEbsDriver = False
            for addon in addons:
                if 'ebs-csi-driver' in addon.lower() or 'aws-ebs-csi-driver' in addon.lower():
                    hasEbsDriver = True
                    break
            
            # Check for EFS CSI driver
            hasEfsDriver = False
            for addon in addons:
                if 'efs-csi-driver' in addon.lower() or 'aws-efs-csi-driver' in addon.lower():
                    hasEfsDriver = True
                    break
            
            # Flag if neither driver is installed
            if not hasEbsDriver and not hasEfsDriver:
                self.results['eksNoManagedStorageDrivers'] = [-1, 'No EBS or EFS CSI driver installed']
                
        except botocore.exceptions.ClientError as e:
            print(f"Error checking storage drivers for cluster {self.cluster}: {e}")
        except Exception as e:
            print(f"Unexpected error checking storage drivers for cluster {self.cluster}: {e}")
            
        return

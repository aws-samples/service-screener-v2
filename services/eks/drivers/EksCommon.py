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
    
    def __init__(self, eksCluster, clusterInfo, eksClient, ec2Client, iamClient, ssmClient=None):
        super().__init__()
        self.ssmClient = ssmClient
        self.cluster = eksCluster
        self.clusterInfo = clusterInfo
        self.eksClient = eksClient
        self.ec2Client = ec2Client
        self.iamClient = iamClient

        self._resourceName = eksCluster

        self.init()

    # ------------------------------------------------------------------ #
    # Read-once accessors. Several checks read the same node groups / add-ons;
    # account-level data (IAM, public SSM parameters, subnets) is shared by all
    # clusters in the scan. Exceptions are cached and re-raised to each caller.
    # ------------------------------------------------------------------ #
    def _clusterListPage(self, op, token=None):
        """One page of list_nodegroups / list_addons for this cluster."""
        kw = {'clusterName': self.cluster}
        if token is not None:
            kw['nextToken'] = token
        return self._memo((op, self.cluster, token), lambda: getattr(self.eksClient, op)(**kw))

    def _clusterListPages(self, op):
        """Yields every page of `op`, like get_paginator(op).paginate(clusterName=...)."""
        token = None
        while True:
            page = self._clusterListPage(op, token)
            yield page
            token = page.get('nextToken')
            if not token:
                return

    def _describeNodegroup(self, nodegroupName):
        return self._memo(('describe_nodegroup', self.cluster, nodegroupName),
                          lambda: self.eksClient.describe_nodegroup(clusterName=self.cluster, nodegroupName=nodegroupName))

    def _describeSubnets(self, subnetIds):
        key = ('ec2.describe_subnets', self.ec2Client.meta.region_name, tuple(subnetIds))
        return self._sharedMemo(key, lambda: self.ec2Client.describe_subnets(SubnetIds=subnetIds))

    def _iamShared(self, op, **kw):
        key = ('iam.' + op, self.iamClient.meta.region_name, tuple(sorted(kw.items())))
        return self._sharedMemo(key, lambda: getattr(self.iamClient, op)(**kw))

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
    
    def _checkPublicEndpointNoCidrRestriction(self):
        # If the public endpoint is enabled, it should be restricted to
        # specific CIDRs rather than open to the entire internet (0.0.0.0/0).
        vpcConfig = self.clusterInfo.get('resourcesVpcConfig', {})
        if not vpcConfig.get('endpointPublicAccess'):
            return

        publicAccessCidrs = vpcConfig.get('publicAccessCidrs', [])
        if not publicAccessCidrs or '0.0.0.0/0' in publicAccessCidrs:
            self.results['eksPublicEndpointNoCidrRestriction'] = [-1, 'Unrestricted (0.0.0.0/0)']

        return

    def _checkAuthenticationMode(self):
        # Clusters should use the EKS access entries API for authentication
        # (API or API_AND_CONFIG_MAP) rather than the legacy aws-auth
        # ConfigMap (CONFIG_MAP), which is harder to audit and manage.
        accessConfig = self.clusterInfo.get('accessConfig') or {}
        authMode = accessConfig.get('authenticationMode')

        # authMode is None on older API responses / very old clusters; only
        # flag when we can positively confirm CONFIG_MAP is in use.
        if authMode == 'CONFIG_MAP':
            self.results['eksAuthModeConfigMap'] = [-1, 'CONFIG_MAP']

        return

    def _checkClusterTags(self):
        # Clusters should be tagged for cost allocation and governance.
        tags = self.clusterInfo.get('tags') or {}
        if len(tags) == 0:
            self.results['eksClusterNoTags'] = [-1, 'No tags']

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
        response = self._iamShared('list_role_policies', RoleName=roleName)
        
        for policyName in response.get('PolicyNames'):
            policyResp = self._iamShared('get_role_policy', RoleName=roleName, PolicyName=policyName)
            document = policyResp.get('PolicyDocument')
            
            pObj = Policy(document)
            pObj.inspectAccess()
            if pObj.hasFullAccessToOneResource() or pObj.hasFullAccessAdmin():
                return False
        
        return True
        
    def attachedPolicyLeastPrivilege(self, roleName):
        response = self._iamShared('list_attached_role_policies', RoleName=roleName)
        
        for policy in response.get('AttachedPolicies'):
            policyInfoResp = self._iamShared('get_policy', PolicyArn=policy.get('PolicyArn'))
            
            policyInfo = policyInfoResp.get('Policy')
            if len(policyInfo) == 0:
                print("Skipped. Unable to retrieve policy information for " + policy.get('PolicyArn'))
                continue
            
            policyArn = policyInfo.get('Arn')
            policyVersion = policyInfo.get('DefaultVersionId')
            
            policyResp = self._iamShared('get_policy_version', PolicyArn=policyArn, VersionId=policyVersion)
            
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
            response = self._clusterListPage('list_nodegroups')
            
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
            response = self._clusterListPage('list_nodegroups')
            
            nodeGroups = response.get('nodegroups', [])
            
            for nodeGroupName in nodeGroups:
                try:
                    # Get node group details
                    ngResponse = self._describeNodegroup(nodeGroupName)
                    
                    nodeGroup = ngResponse.get('nodegroup', {})
                    subnets = nodeGroup.get('subnets', [])
                    
                    if len(subnets) == 0:
                        continue
                    
                    # Get subnet details to determine AZs
                    subnetResponse = self._describeSubnets(subnets)
                    
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
            response = self._clusterListPage('list_nodegroups')
            
            nodeGroups = response.get('nodegroups', [])
            
            # Track if any node group uses Spot
            hasSpotInstances = False
            
            for nodeGroupName in nodeGroups:
                try:
                    # Get node group details
                    ngResponse = self._describeNodegroup(nodeGroupName)
                    
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
            response = self._clusterListPage('list_addons')
            
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
    
    def _errCode(self, e):
        try:
            return e.response.get('Error', {}).get('Code') or 'ClientError'
        except Exception:
            return 'Error'

    def _checkNoIRSAConfigured(self):
        """
        Pod-level workload identity (FND02-BP10).
        PASS when the cluster has at least one working workload identity mechanism:
          - IRSA: the cluster OIDC issuer is registered as an IAM OIDC identity provider
            (an issuer URL alone exists on every cluster and does not enable IRSA), or
          - EKS Pod Identity: pod identity associations exist, or the
            eks-pod-identity-agent add-on is installed / EKS Auto Mode (agent built in).
        FAIL only when none of these are present. If a source cannot be read and no
        mechanism was found, the result is 0 (Unable to evaluate).
        """
        evidence = []
        unable = []

        identity = self.clusterInfo.get('identity') or {}
        issuer = (identity.get('oidc') or {}).get('issuer') or ''

        if issuer:
            host = issuer.split('://', 1)[-1].rstrip('/').lower()
            try:
                providers = self._iamShared('list_open_id_connect_providers').get('OpenIDConnectProviderList', []) or []
                for p in providers:
                    arn = (p.get('Arn') or '').lower()
                    if arn.endswith(':oidc-provider/' + host):
                        evidence.append('IRSA (IAM OIDC provider registered)')
                        break
            except botocore.exceptions.ClientError as e:
                unable.append('iam:' + self._errCode(e))

        try:
            paginator = self.eksClient.get_paginator('list_pod_identity_associations')
            assocCnt = 0
            for page in paginator.paginate(clusterName=self.cluster):
                assocCnt += len(page.get('associations', []) or [])
                if assocCnt > 0:
                    break
            if assocCnt > 0:
                evidence.append('EKS Pod Identity associations')
        except botocore.exceptions.ClientError as e:
            unable.append('eks:' + self._errCode(e))

        if (self.clusterInfo.get('computeConfig') or {}).get('enabled') is True:
            evidence.append('EKS Auto Mode (Pod Identity agent built in)')
        else:
            try:
                for page in self._clusterListPages('list_addons'):
                    if 'eks-pod-identity-agent' in (page.get('addons', []) or []):
                        evidence.append('eks-pod-identity-agent add-on')
                        break
            except botocore.exceptions.ClientError as e:
                unable.append('eks:' + self._errCode(e))

        if evidence:
            self.results['eksNoIRSAConfigured'] = [1, 'Workload identity: ' + ', '.join(evidence)]
        elif unable:
            self.results['eksNoIRSAConfigured'] = [0, 'Unable to evaluate (' + ', '.join(sorted(set(unable))) + ')']
        elif not issuer:
            self.results['eksNoIRSAConfigured'] = [-1, 'No OIDC issuer and no EKS Pod Identity configured']
        else:
            self.results['eksNoIRSAConfigured'] = [-1, 'OIDC issuer not registered as IAM OIDC provider and no EKS Pod Identity configured']

        return

    ## SSM public parameters holding the latest EKS-optimized AMI release per amiType.
    ## {v} is the node group Kubernetes version. Bottlerocket parameters hold the
    ## Bottlerocket image version, which is what EKS reports as releaseVersion.
    AMI_RELEASE_SSM_PATHS = {
        'AL2_x86_64': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2/recommended/release_version',
        'AL2_x86_64_GPU': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2-gpu/recommended/release_version',
        'AL2_ARM_64': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2-arm64/recommended/release_version',
        'AL2023_x86_64_STANDARD': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2023/x86_64/standard/recommended/release_version',
        'AL2023_ARM_64_STANDARD': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2023/arm64/standard/recommended/release_version',
        'AL2023_x86_64_NEURON': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2023/x86_64/neuron/recommended/release_version',
        'AL2023_x86_64_NVIDIA': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2023/x86_64/nvidia/recommended/release_version',
        'AL2023_ARM_64_NVIDIA': '/aws/service/eks/optimized-ami/{v}/amazon-linux-2023/arm64/nvidia/recommended/release_version',
        'BOTTLEROCKET_x86_64': '/aws/service/bottlerocket/aws-k8s-{v}/x86_64/latest/image_version',
        'BOTTLEROCKET_ARM_64': '/aws/service/bottlerocket/aws-k8s-{v}/arm64/latest/image_version',
        'BOTTLEROCKET_x86_64_FIPS': '/aws/service/bottlerocket/aws-k8s-{v}-fips/x86_64/latest/image_version',
        'BOTTLEROCKET_ARM_64_FIPS': '/aws/service/bottlerocket/aws-k8s-{v}-fips/arm64/latest/image_version',
        'BOTTLEROCKET_x86_64_NVIDIA': '/aws/service/bottlerocket/aws-k8s-{v}-nvidia/x86_64/latest/image_version',
        'BOTTLEROCKET_ARM_64_NVIDIA': '/aws/service/bottlerocket/aws-k8s-{v}-nvidia/arm64/latest/image_version',
        'BOTTLEROCKET_x86_64_NVIDIA_FIPS': '/aws/service/bottlerocket/aws-k8s-{v}-nvidia-fips/x86_64/latest/image_version',
        'BOTTLEROCKET_ARM_64_NVIDIA_FIPS': '/aws/service/bottlerocket/aws-k8s-{v}-nvidia-fips/arm64/latest/image_version',
    }

    @staticmethod
    def parseReleaseVersion(release, bottlerocket=False):
        """'1.31.2-20241121' -> ((1, 31, 2), 20241121); Bottlerocket '1.20.3-5d9ac849' -> ((1, 20, 3), 0).
        Returns None when the string cannot be parsed."""
        if not release or not isinstance(release, str):
            return None
        parts = release.strip().split('-', 1)
        try:
            ver = tuple(int(x) for x in parts[0].lstrip('v').split('.'))
        except ValueError:
            return None
        if bottlerocket:
            return (ver, 0)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        return (ver, int(parts[1]))

    def _latestAmiRelease(self, path):
        ## Public AWS parameter: identical for every cluster in the region, so read once per scan.
        key = ('ssm.get_parameter', self.ssmClient.meta.region_name, path)
        try:
            val = self._sharedMemo(key, lambda: self.ssmClient.get_parameter(Name=path))['Parameter']['Value']
            out = (val, None)
        except botocore.exceptions.ClientError as e:
            out = (None, self._errCode(e))
        return out

    def _checkNodeGroupAmiOutdated(self):
        """
        Managed node groups should run the latest EKS-optimized AMI release for their
        Kubernetes version and amiType (SEC06-BP01). The latest release is read from
        the public SSM parameters published by AWS. CUSTOM (launch template AMI) and
        Windows node groups are not evaluable and are skipped.
        """
        try:
            nodeGroups = []
            for page in self._clusterListPages('list_nodegroups'):
                nodeGroups += page.get('nodegroups', []) or []
        except botocore.exceptions.ClientError as e:
            self.results['eksNodeGroupAmiOutdated'] = [0, 'Unable to evaluate (' + self._errCode(e) + ')']
            return

        if not nodeGroups:
            return

        if self.ssmClient is None:
            self.results['eksNodeGroupAmiOutdated'] = [0, 'Unable to evaluate (no SSM client)']
            return

        outdated, current, skipped, unable = [], [], [], []
        for ngName in nodeGroups:
            try:
                ng = self._describeNodegroup(ngName).get('nodegroup', {}) or {}
            except botocore.exceptions.ClientError as e:
                unable.append(ngName + ' (' + self._errCode(e) + ')')
                continue

            amiType = ng.get('amiType')
            pathTpl = self.AMI_RELEASE_SSM_PATHS.get(amiType)
            if pathTpl is None:
                skipped.append(ngName + ' (' + str(amiType) + ')')
                continue

            k8sVersion = ng.get('version') or (self.clusterInfo or {}).get('version')
            release = ng.get('releaseVersion')
            if not k8sVersion or not release:
                unable.append(ngName + ' (missing version/releaseVersion)')
                continue

            latest, err = self._latestAmiRelease(pathTpl.format(v=k8sVersion))
            if latest is None:
                unable.append(ngName + ' (' + str(err) + ')')
                continue

            isBr = amiType.startswith('BOTTLEROCKET')
            cur = self.parseReleaseVersion(release, isBr)
            lat = self.parseReleaseVersion(latest, isBr)
            if cur is None or lat is None:
                unable.append(ngName + ' (unparseable release ' + str(release) + ' / ' + str(latest) + ')')
                continue

            if cur < lat:
                outdated.append(ngName + ': ' + release + ' < ' + latest)
            else:
                current.append(ngName)

        if outdated:
            self.results['eksNodeGroupAmiOutdated'] = [-1, '; '.join(outdated)]
        elif unable:
            self.results['eksNodeGroupAmiOutdated'] = [0, 'Unable to evaluate (' + '; '.join(unable) + ')']
        elif current:
            msg = 'Latest AMI release: ' + ', '.join(current)
            if skipped:
                msg += '. Not evaluated: ' + ', '.join(skipped)
            self.results['eksNodeGroupAmiOutdated'] = [1, msg]
        else:
            self.results['eksNodeGroupAmiOutdated'] = [0, 'Not evaluable (CUSTOM/Windows AMI): ' + ', '.join(skipped)]

        return
    
    def _checkNoAutoscaling(self):
        """
        Check if cluster has autoscaling configured.
        Checks for Karpenter add-on OR node group autoscaling (min < max).
        """
        try:
            # Check 1: Look for Karpenter add-on
            response = self._clusterListPage('list_addons')
            
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
            ngResponse = self._clusterListPage('list_nodegroups')
            
            nodeGroups = ngResponse.get('nodegroups', [])
            
            hasAutoscaling = False
            
            for nodeGroupName in nodeGroups:
                try:
                    ngDetailResponse = self._describeNodegroup(nodeGroupName)
                    
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
            response = self._clusterListPage('list_addons')
            
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

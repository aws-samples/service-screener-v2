## https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html

import boto3
import botocore
import re

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class EksCommon(Evaluator):
    OUTBOUNDSGMINIMALRULES = {
        'tcp': [10250, 53, 443],
        'udp': [53]
    }
    
    def __init__(self, eksCluster, clusterInfo, eksClient, ec2Client, iamClient, k8sClient):
        super().__init__()
        self.cluster = eksCluster
        self.clusterInfo = clusterInfo
        self.eksClient = eksClient
        self.ec2Client = ec2Client
        self.iamClient = iamClient
        self.k8sClient = k8sClient(cluster_info=self.clusterInfo)
        self.nodegroups_list = self.__get_nodegroups()
        
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

    def __get_nodegroups(self) -> list:
        """
        Retrieve a list of all managed node groups in the EKS cluster.

        This method uses the EKS client to list all managed node groups associated with the cluster.
        It handles pagination by continuing to make API calls until all node groups have been retrieved.

        Returns:
            list: A list of node group names (strings) in the cluster.

        Note:
            - This method only retrieves managed node groups. Self-managed node groups are not included.
            - The method handles pagination internally, making multiple API calls if necessary.

        Example:
            self.__get_node_groups()
            ['nodegroup-1', 'nodegroup-2', 'nodegroup-3']
        """

        _cluster_name = self.clusterInfo.get("name")
        nodegroups_list = list()
        next_token = True
        while next_token:
            nodegroups = self.eksClient.list_nodegroups(  # Self-managed node groups are not listed
                clusterName=_cluster_name,
            )
            nodegroups_list.extend(nodegroups.get("nodegroups"))

            if not nodegroups.get("nextToken"):
                next_token = False

        return nodegroups_list

    def _checkSpotUsage(self):
        """
        Check if the EKS cluster leverages Spot instances for deeper discounts on fault-tolerant workloads (EKS-25).

        This function examines all managed node groups in the cluster to determine if they are using
        Spot instances. It identifies and reports any node groups that are not using Spot capacity.

        Spot instances can offer significant cost savings for fault-tolerant workloads, as they use
        spare EC2 capacity at discounted rates. However, they can be interrupted with short notice,
        so they are best suited for flexible, stateless applications.

        Reference:
            https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html
        """
        try:
            _cluster_name = self.clusterInfo.get("name")

            mng_wo_spot = []  # Empty list for Managed Node Groups with Capacity Type != SPOT

            if len(self.nodegroups_list) != 0:
                for each_nodegroup in self.nodegroups_list:
                    each_nodegroup_detail = self.get_nodegroup_details(each_nodegroup)
                    if self.check_capacity_type(each_nodegroup_detail, "SPOT"):
                        mng_wo_spot.append(each_nodegroup)

            if mng_wo_spot:
                self.results['eksNodeGroupSpotInstanceUsage'] = [-1, str(mng_wo_spot)]

        except Exception as e:
            print(f"Error Checking Spot Instance Usage {e}")

    def _checkCostVisibility(self):
        """
        Check if a cost visibility tool is implemented for the EKS cluster (EKS-10).

        This function verifies the implementation of a cost monitoring solution for Amazon EKS.
        It specifically checks for the installation of Kubecost, which is one of the recommended
        tools for cost visibility in EKS clusters.

        The function delegates the actual check to the __kube_cost method, which verifies
        if the Kubecost addon is installed in the cluster so that we can implement more the checks
        in the future if needed.

        Note:
            - This check only verifies Kubecost installation and does not check for other
              cost visibility solutions like AWS Billing split cost allocation data.

        Reference:
            https://docs.aws.amazon.com/eks/latest/userguide/cost-monitoring.html
        """
        plugins = {"kube-cost": self.__kube_cost()}

        self.results['eksCostVisibilityPlugins'] = [-1, str(plugins)]

    def __kube_cost(self):
        """
        Check if the Kubecost plugin is installed in the EKS cluster.

        This function queries the list of addons installed in the EKS cluster
        and checks for the presence of the Kubecost addon.

        Returns:
            bool: True if the Kubecost plugin is installed, False otherwise.

        Raises:
            Exception: If there's an error while checking for the Kubecost plugin installation.
            This exception is caught and printed, and the function implicitly returns None in this case.

        Note:
            - The function uses a hardcoded addon name 'kubecost_kubecost'.
            - TODO to move this constant to a separate constants.py file.
            - The function relies on self.clusterInfo and self.eksClient being properly initialized.
            - If the addon is not found, a message is printed to stdout before returning False.
        """
        try:
            kube_cost_addon_name = "kubecost_kubecost"  # TODO Move to constants.py

            _cluster_name = self.clusterInfo.get("name")

            addons = self.eksClient.list_addons(
                clusterName=_cluster_name
            ).get("addons")

            return kube_cost_addon_name in addons

        except Exception as e:
            print(f"Error checking Kube Cost Plugin installation: {e}")

    def _checkAMIs(self) -> bool:
        """
        Check if all nodegroups in the EKS cluster are using EKS-optimized AMI or Bottlerocket for host OS (EKS-13).

        This function iterates through all nodegroups in the cluster and checks their AMI type.
        It specifically looks for nodegroups that are not using Bottlerocket OS, which is
        identified by an AMI type starting with "Bottlerocket".

        Returns:
            bool: True if all nodegroups are using Bottlerocket OS, False otherwise.

        Note:
            - The function assumes that AMI types starting with "Bottlerocket" are compliant.
            - EKS-optimized AMIs are not explicitly checked.
        """
        try:
            _cluster_name = self.clusterInfo.get("name")
            regex_pattern = r"^Bottlerocket"
            nodegroups_not_using_bottlerocket = []

            if len(self.nodegroups_list) != 0:
                for each_nodegroup in self.nodegroups_list:
                    each_nodegroup_ami_type = self.get_nodegroup_details(each_nodegroup)["nodegroup"]["amiType"]
                    # each_nodegroup_ami_type = self.eksClient.describe_nodegroup(
                    #     clusterName=_cluster_name,
                    #     nodegroupName=each_nodegroup
                    # )["nodegroup"]["amiType"]

                    if not re.match(regex_pattern, each_nodegroup_ami_type):
                        nodegroups_not_using_bottlerocket.append(each_nodegroup)

            if nodegroups_not_using_bottlerocket:
                self.results["eksNodegroupsWithoutBottleRocketAMI"] = [-1, str(nodegroups_not_using_bottlerocket)]
        except Exception as e:
            print(f"Error checking node group AMIs: {e}")

    def _checkAutoScaling(self):
        """
        Check if a Pod Autoscaler (Cluster Autoscaler or Karpenter) is installed in the cluster (EKS-31).

        This function searches for pods in the 'kube-system' namespace whose names contain
        either 'cluster-autoscaler' or 'karpenter', indicating the presence of an autoscaler.

        Returns:
            bool: False if an autoscaler is found, implying the check passes.
                  The function doesn't explicitly return True, which may be a bug.

        Raises:
            Exception: If there's an error while checking for the pod autoscaler.
        """
        karpenter_installed = False
        cluster_autoscaler_installed = False
        try:
            regex_cluster_autoscaler = r'\bcluster-autoscaler\b'

            # Check for Karpenter
            # Assumping if the karpenter is in separate namespace
            pods = self.k8sClient.CoreV1Client.list_namespaced_pod("karpenter").items
            if not len(pods) == 0:
                karpenter_installed = True

            # Check for Cluster Autoscaler
            pods = self.k8sClient.CoreV1Client.list_namespaced_pod("kube-system").items
            for each_pod in pods:
                pod_name = each_pod.metadata.name
                installed = re.search(regex_cluster_autoscaler, pod_name)
                if installed:
                    cluster_autoscaler_installed = True

            if not (karpenter_installed or cluster_autoscaler_installed):
                self.results["eksCheckAutoScaling"] = [-1, ""]

        except Exception as e:
            print(f"Error checking pod autoscaler: {e}")
            pass

    def _checkAutoMountServiceAccountToken(self):
        """
        Check if pods have opted out of automounting service account tokens (EKS-16).

        This function iterates through all pods in all namespaces and checks whether they have
        opted out of automounting API credentials. A pod is considered to have opted out if:
        - The pod spec explicitly sets automountServiceAccountToken: false, or
        - The pod spec doesn't set automountServiceAccountToken, but the associated ServiceAccount sets it to false.

        The function prints the status for each pod, indicating whether it has opted out or not.

        Reference:
        https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting

        Raises:
            Exception: If there's an error while checking the automount status of service account tokens.

        Returns:
            None
        """
        try:
            # List all pods in all namespaces
            pods = self.k8sClient.CoreV1Client.list_pod_for_all_namespaces(watch=False)

            results = []

            for pod in pods.items:
                pod_name = pod.metadata.name
                namespace = pod.metadata.namespace

                # Check pod spec for automountServiceAccountToken
                pod_automount = pod.spec.automount_service_account_token

                # Check service account for automountServiceAccountToken
                sa_name = pod.spec.service_account_name or "default"
                sa = self.k8sClient.CoreV1Client.read_namespaced_service_account(sa_name, namespace)
                sa_automount = sa.automount_service_account_token

                if pod_automount is False or (pod_automount is None and sa_automount is False):
                    pass
                else:
                    results.append(pod_name)

            if results:
                self.results["eksAutoMountServiceAccountToken"] = [-1, str(results)]

        except Exception as e:
            print(f"Error checking Automount Service Account Token: {e}")

    def _checkPodSecurityStandards(self):
        """
        Check Pod Security Standards enforcement for all namespaces in the Kubernetes cluster.

        This method iterates through all namespaces and checks if the 'pod-security.kubernetes.io/enforce'
        label is set. If the label is present, it prints the enforcement level. If not, it prints a message
        indicating that Pod Security Standards are not enforced for that namespace.

        Note:
            - TODO: Implement check if Open Policy Agent Gatekeeper exists

        """
        try:
            namespace_list = self.k8sClient.CoreV1Client.list_namespace()
            namespaces_wo_pod_security = []
            for namespace in namespace_list.items:
                labels = namespace.metadata.labels
                print(labels)
                if not labels and "pod-security.kubernetes.io/enforce" in labels:
                    namespaces_wo_pod_security.append(namespace.metadata.name)
            # if namespaces_wo_pod_security:
            self.results["eksPodSecurityStandards"] = [-1, str(namespaces_wo_pod_security)]

        except Exception as e:
            print(f"Error checking Pod Security Standards: {e}")

    def _checkNamespaceResourceQuotas(self):
        """
        Check if resource quotas are configured for all namespaces in the EKS cluster.

        This function implements the EKS-26 control, which requires configuring resource quotas
        for namespaces. It retrieves all namespaces in the cluster and checks if each namespace
        has at least one ResourceQuota object defined.

        The function uses the Kubernetes API to list all namespaces and their associated
        ResourceQuota objects. It then identifies namespaces without any resource quotas and
        stores them in the results.

        Returns:
            None

        Reference:
            https://kubernetes.io/docs/concepts/policy/resource-quotas/
        """

        # Get all namespaces
        namespaces = self.k8sClient.CoreV1Client.list_namespace()
        namespaces_wo_resource_quota = list()

        for each_namespace in namespaces.items:
            namespace = each_namespace.metadata.name

            # Get resource quotas for the namespace
            quotas = self.k8sClient.CoreV1Client.list_namespaced_resource_quota(namespace)

            if not quotas.items:
                namespaces_wo_resource_quota.append(namespace)

        if namespaces_wo_resource_quota:
            self.results["eksNamespaceResourceQuotas"] = [-1, str(namespaces_wo_resource_quota)]

    def _checkAddonsNodeGroups(self):
        # Define the add-ons to check
        addons = ["coredns", "cluster-autoscaler", "karpenter"]  # TODO Move this into constants.py
        cluster_addons = self.eksClient.list_addons(clusterName=self.clusterInfo.get("name")).get("addons")

        print(f"Cluster Addons - {cluster_addons}")

        nodes = self.k8sClient.CoreV1Client.list_node().items

        # for node in nodes:
            # print(f"Node - {node.metadata}")
            # labels = node.metadata.labels.get("eks.amazonaws.com/nodegroup")

        self.__check_karpenter()
    def __check_core_dns(self):
        pass

    def __check_cluster_autoscaler(self):
        pass
    def __check_karpenter(self):
        """
        Assumpting the karpenter is in seperate namespace.

        :return:
        """

        nodegroups = list()

        try:
            pods = self.k8sClient.CoreV1Client.list_namespaced_pod("karpenter").items
            if not len(pods) == 0:
                for each_pod in pods:
                    nodegroup_name = (self.k8sClient.CoreV1Client.read_node(each_pod.spec.node_name).metadata.labels.get
                              ("eks.amazonaws.com/nodegroup"))

                    if nodegroup_name:
                        nodegroups.append(nodegroup_name)
        except Exception as e:
            print(f"Error Checking Karpenter Details {e}")

        if not len(nodegroups) == 0:
            for each_nodegroup in nodegroups:
                details = self.get_nodegroup_details(each_nodegroup)
                self.check_instance_type(details)
                self.check_capacity_type(details, "ON-DEMAND")

    def get_nodegroup_details(self, nodegroup) -> dict:
        return self.eksClient.describe_nodegroup(clusterName=self.clusterInfo.get("name"), nodegroupName=nodegroup)

    def check_instance_type(self,details) -> bool:
        return all(self.is_graviton_instance(instance_type=it) for it in details['nodegroup']['instanceTypes'])

    @staticmethod
    def check_capacity_type(details, capacity_type) -> bool:
        return details["nodegroup"]["capacityType"] == capacity_type

    @staticmethod
    def is_graviton_instance(instance_type):
        # Graviton instance types
        return re.search(r'g[^.]*\.', instance_type)
## https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html

import boto3
import botocore
import re
import json

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

from kubernetes import client as k8sClient

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
        self.nodegroups_list = self.__get_node_groups()
        
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

    def __get_node_groups(self):
        _cluster_name = self.clusterInfo.get("name")
        nodegroups_list = list()
        nextToken = True
        while nextToken:
            nodegroups = self.eksClient.list_nodegroups(  # Self-managed node groups are not listed
                clusterName=_cluster_name,
            )
            nodegroups_list.extend(nodegroups.get("nodegroups"))

            if not nodegroups.get("nextToken"):
                nextToken = False

        return nodegroups_list

    def _checkSpotUsage(self) -> bool:
        """EKS-25 Leverage spot instances for  deeper discount for fault-tolerant workload.

        https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html

        :return: bool
        """

        print("EKS-25 Leverage spot instances for  deeper discount for fault-tolerant workload")
        _cluster_name = self.clusterInfo.get("name")

        mng_wo_spot = []  # Empty list for Managed Node Groups with Capacity Type != SPOT

        if len(self.nodegroups_list) != 0:
            for each_nodegroup in self.nodegroups_list:
                each_nodegroup_detail = self.eksClient.describe_nodegroup(
                    clusterName=_cluster_name,
                    nodegroupName=each_nodegroup
                )

                if each_nodegroup_detail.get("nodegroup").get("capacityType") != "SPOT":
                    mng_wo_spot.append(each_nodegroup)

        if len(mng_wo_spot) != 0:
            print("Node Groups without Spot Instance")
            print(mng_wo_spot)  # TODO To print out to the result thingy

        print("Spot Instance Usage Check Completed")

        return len(mng_wo_spot) == 0

    def _checkCostVisibility(self) -> bool:
        """
        EKS-10 Implement a tool for cost  visibility

        https://docs.aws.amazon.com/eks/latest/userguide/cost-monitoring.html
        :return: bool
        """
        print("EKS-10 Implement a tool for cost  visibility")

        return self.__kube_cost()

    def __kube_cost(self) -> bool:
        """
        Check if Kube Cost plugin is installed.

        :return: bool
        """
        print("Checking if Kube Cost Plugin is installed")

        kube_cost_addon_name = "kubecost_kubecost"  # TODO Move to constants.py

        _cluster_name = self.clusterInfo.get("name")

        addons = self.eksClient.list_addons(
            clusterName=_cluster_name
        ).get("addons")

        if kube_cost_addon_name not in addons:
            print(f"{_cluster_name} - Kube Cost Plugin is not installed")
            return False

        return True

    def _checkAMIs(self) -> bool:
        """
        EKS-13 Use EKS-optimized AMI or Bottlerocket for host OS

        :return:
        """
        _cluster_name = self.clusterInfo.get("name")

        regex_pattern = r"^Bottlerocket"

        nodegroups_not_using_bottlerocket = list()

        if len(self.nodegroups_list) != 0:
            for each_nodegroup in self.nodegroups_list:
                each_nodegroup_amitype = self.eksClient.describe_nodegroup(
                    clusterName=_cluster_name,
                    nodegroupName=each_nodegroup
                )["nodegroup"]["amiType"]

                if not re.match(regex_pattern, each_nodegroup_amitype):
                    nodegroups_not_using_bottlerocket.append(each_nodegroup)

        return len(nodegroups_not_using_bottlerocket) == 0
        
    def _checkAuthenticationMode(self):
        authenticationMode = self.clusterInfo.get('accessConfig').get('authenticationMode')
        if authenticationMode != 'API' and authenticationMode != 'API_AND_CONFIG_MAP':
            self.results['eksAuthenticationMode'] = [-1, 'Disabled']
        return

    def _checkPermissionToAccessCluster(self):
        try :
            self.k8sClient.CoreV1Client.list_namespace()
        except k8sClient.exceptions.ApiException:
            self.results['eksPermissionToAccessCluster'] = [-1, 'No permission']
        except:
            print("Unknown error")
        return
    
    def _checkImplementedPodDisruptionBudget(self):
        try:
            haveCustomPDB = False #Check if cluster include any clustom Pod Disruption Budget outside kube-system namespace

            for pdb in self.k8sClient.PolicyV1Client.list_pod_disruption_budget_for_all_namespaces().items:
                if pdb.metadata.namespace != 'kube-system':
                    haveCustomPDB = True
                    break

            if not haveCustomPDB:
                self.results['eksImplementedPodDisruptionBudget'] = [-1, 'Disabled']

        except k8sClient.exceptions.ApiException:
            print('No permission to access cluster, skipping Implemented Pod Disruption Budget check')
        except:
            print("Unknown error")
        
        return
    
    def _checkDefaultDenyIngressNetworkPolicy(self):
        try:
            haveDefaultDenyIngressNP = False 

            for networkPolicy in self.k8sClient.NetworkingV1Client.list_network_policy_for_all_namespaces().items:
                npSelectAllPod = not networkPolicy.spec.pod_selector.match_expressions and not networkPolicy.spec.pod_selector.match_labels
                npIsIngressRule = 'Ingress' in networkPolicy.spec.policy_types
                npIsDenyAll = not networkPolicy.spec.ingress

                if npSelectAllPod and npIsIngressRule and npIsDenyAll:
                    haveDefaultDenyIngressNP = True
                    break

            if not haveDefaultDenyIngressNP:
                self.results['eksDefaultDenyIngressNetworkPolicy'] = [-1, 'Disabled']

        except k8sClient.exceptions.ApiException:
            print('No permission to access cluster, skipping Implemented Default Deny Ingress Network Policy check')
        except:
            print("Unknown error")
        
        return
    
    def _checkDefinedResourceRequestAndLimit(self):
        try:
            haveViolatedContainer = False # Violated container is the container without resource request and limit defined

            for pod in self.k8sClient.CoreV1Client.list_pod_for_all_namespaces().items:
                if pod.metadata.namespace != 'kube-system':
                    for container in pod.spec.containers:
                        if not container.resources.limits and not container.resources.requests:
                            haveViolatedContainer = True
                if haveViolatedContainer:
                    break

            if haveViolatedContainer:
                self.results['eksDefinedResourceRequestAndLimit'] = [-1, 'Disabled']

        except k8sClient.exceptions.ApiException:
            print('No permission to access cluster, skipping Defined Resource Request And Limit For Container check')
        except:
            print("Unknown error")
        
        return
    
    def _checkDefinedLimitRange(self):
        try:
            limitRangeExist = False

            if self.k8sClient.CoreV1Client.list_limit_range_for_all_namespaces().items:
                limitRangeExist = True

            if not limitRangeExist:
                self.results['eksConfigureLimitRange'] = [-1, 'Disabled']

        except k8sClient.exceptions.ApiException:
            print('No permission to access cluster, skipping Defined LimitRange check')
        except:
            print("Unknown error")
        
        return

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
        
        
        
        
        
        
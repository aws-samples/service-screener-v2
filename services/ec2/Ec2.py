# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html

import boto3
import botocore
import requests
from datetime import date, datetime

import json
import time

from utils.Tools import _pi

from utils.Config import Config
from services.Service import Service
from services.ec2.drivers.Ec2Instance import Ec2Instance
from services.ec2.drivers.Ec2CompOpt import Ec2CompOpt
from services.ec2.drivers.Ec2EbsVolume import Ec2EbsVolume
from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup
from services.ec2.drivers.Ec2CostExplorerRecs import Ec2CostExplorerRecs
from services.ec2.drivers.Ec2EIP import Ec2EIP
from services.ec2.drivers.Ec2ElbCommon import Ec2ElbCommon
from services.ec2.drivers.Ec2ElbClassic import Ec2ElbClassic
from services.ec2.drivers.Ec2AutoScaling import Ec2AutoScaling
from services.ec2.drivers.Ec2EbsSnapshot import Ec2EbsSnapshot
from services.ec2.drivers.Ec2Vpc import Ec2Vpc
from services.ec2.drivers.Ec2NACL import Ec2NACL

class Ec2(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self.ssmClient = ssBoto.client('ssm', config=self.bConfig)
        self.compOptClient = ssBoto.client('compute-optimizer', config=self.bConfig)
        self.ceClient = ssBoto.client('ce', config=self.bConfig)
        self.elbClient = ssBoto.client('elbv2', config=self.bConfig)
        self.elbClassicClient = ssBoto.client('elb', config=self.bConfig)
        self.asgClient = ssBoto.client('autoscaling', config=self.bConfig)
        self.wafv2Client = ssBoto.client('wafv2', config=self.bConfig)
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        
        self.getOutdateSQLVersion()
        self.getWindowsVersion()
    
    def getOutdateSQLVersion(self):
        outdateVersion = Config.get('SQLEolVersion', None)
        if outdateVersion != None:
            return outdateVersion
        
        try:
            outdateVersion = 2012
            resp = requests.get("https://endoflife.date/api/mssqlserver.json", timeout=10)
            for prod in resp.json():
                if date.today() > datetime.strptime(prod['eol'], '%Y-%m-%d').date():
                    outdateVersion = prod['cycle'][0:4]
                    break
        except requests.exceptions.RequestException  as e:
            print("Unable to retrieve endoflife mssqlserver information, using default value: 2012")
        
        Config.set('SQLEolVersion', outdateVersion)
        
    
    def getWindowsVersion(self):
        outdateWindowsVersion = Config.get('WindowsEOLVersion', None)
        if outdateWindowsVersion != None:
            return outdateWindowsVersion
            
        mEOL = None
        mCycle = None
        arr = {}
        arr['2012'] = {'isOutdate': True, 'isLatest': False}
        arr['2023'] = {'isOutdate': False, 'isLatest': True}
        
        try:
            resp = requests.get("https://endoflife.date/api/windows-server.json",  timeout=10)
            for prod in resp.json():
                if prod['lts'] == 'false':
                    continue
                eolDate = datetime.strptime(prod['eol'], '%Y-%m-%d').date()
                isOutdate = True if date.today() > eolDate else False
                arr[prod['cycle']] = {'isOutdate': isOutdate, 'isLatest': False}
                
                if mEOL == None or eolDate > mEOL:
                    mCycle = prod['cycle']
                    mEOL = eolDate
                    
            arr[mCycle]['isLatest'] = True
            
        except requests.exceptions.RequestException as e:
            print("Unable to retrieve endoflife Windows Server information, using default value: 2012")
        
        Config.set('WindowsEolVersion', arr)
        
    
    # get EC2 Instance resources
    def getResources(self):
        filters = []
        if self.tags:
            filters = self.tags
                
        results = self.ec2Client.describe_instances(
            Filters = filters
        )
        
        arrs = results.get('Reservations')
        while results.get('NextToken') is not None:
            results = self.ec2Client.describe_instances(
                Filters = filters,
                NextToken = results.get('NextToken')
            )    
            arrs = arrs + results.get('Reservations')
        
        resources = []
        for arr in arrs:
            for instance in arr['Instances']:
                if instance['State']['Name'] != 'terminated':
                    resources.append(arr)
                    break
        
        return resources
    
    def getEC2SecurityGroups(self,instance):
        if 'SecurityGroups' not in instance:
            print(f"Security Group not found in {instance['InstanceId']}")
            return {}
        
        arr = []    
        filters = []
        groupIds = []
        if self.tags:
            filters = self.tags
        
        for group in instance['SecurityGroups']:
            groupIds.append(group['GroupId'])
        
        results = self.ec2Client.describe_security_groups(
            GroupIds=groupIds,
            Filters=filters
        )
        arr = results.get('SecurityGroups')
        
        while results.get('NextToken') is not None:
            results = self.ec2Client.describe_security_groups(
                GroupIds = groupIds,
                Filters=filters,
                NextToken = results.get('NextToken')
                )
            arr = arr + results.get('SecurityGroups')
        
        if not self.tags:
            return arr
        
        finalArr = []
        for i, detail in enumerate(arr):
            if 'Tags' in detail and self.resourceHasTags(detail['Tags']):
                finalArr.append(arr[i])
        
        return finalArr    
    
    def getEBSResources(self):
        filters = []
        
        if self.tags:
            filters = self.tags
        
        results = self.ec2Client.describe_volumes(
            Filters = filters
        )
        
        arr = results.get('Volumes')
        while results.get('NextToken') is not None:
            results = self.ec2Client.describe_volumes(
                Filters = filters,
                NextToken = results.get('NextToken')
            )    
            arr = arr + results.get('Reservations')

        return arr
        
    def getELB(self):
        results = self.elbClient.describe_load_balancers()
        
        arr = results.get('LoadBalancers')
        while results.get('NextMarker') is not None:
            results = self.elbClient.describe_load_balancers(
                Marker = results.get('NextMarker')
            )
            arr = arr + results.get('LoadBalancers')
            
        ## TO DO: support tagging later
        
        if not self.tags:
            return arr
        
        filteredResults = []
        for lb in arr:
            tagResults = self.elbClient.describe_tags(
                ResourceArns = [lb['LoadBalancerArn']]
            )
            tagDesc = tagResults.get('TagDescriptions')
            if len(tagDesc) > 0:
                for desc in tagDesc:
                    if self.resourceHasTags(desc['Tags']):
                        filteredResults.append(lb)
                        break
                    
        return filteredResults
        
    def getELBClassic(self):
        results = self.elbClassicClient.describe_load_balancers()
        
        arr = results.get('LoadBalancerDescriptions')
        while results.get('NextMarker') is not None:
            results = self.elbClient.describe_load_balancers(
                Marker = results.get('NextMarker')
            )
            
            arr = arr + results.get('LoadBalancerDescriptions')
            
        return arr
        
    def getELBSecurityGroup(self, elb):
        if 'SecurityGroups' not in elb:
            return []
        
        securityGroups = elb['SecurityGroups']
        groupIds = []
        arr = []
        for groupId in securityGroups:
            groupIds.append(groupId)
            
        if len(groupIds) == 0:
            return arr
        
        filters = []  
        if self.tags is not None:
            filters = self.tags
            
        results = self.ec2Client.describe_security_groups(
            GroupIds = groupIds,
            Filters = filters
        )
        
        arr = results.get('SecurityGroups')
        while results.get('NextToken') is not None:
            results = self.ec2Client.describe_security_groups(
                GroupIds = groupIds,
                Filters = filters,
                NextToken = results.get('NextToken')
            )
            arr = arr + results.get('SecurityGroups')
        
        if not self.tags:
            return arr
        
        finalArr = []
        for i, detail in enumerate(arr):
            if self.resourceHasTags(detail['Tags']):
                finalArr.append(arr[i])
            
        return arr
        
    def getASGResources(self):
        filters = []
        if self.tags:
            filters = self.tags
        
        results = self.asgClient.describe_auto_scaling_groups(
            Filters = filters
        )
        arr = results.get('AutoScalingGroups')
        while results.get('NextToken') is not None:
            results = self.asgClient.describe_auto_scaling_groups(
                Filters = filters,
                NextToken = results.get('NextToken')
            )
            
            arr = arr + results.get('AutoScalingGroups')
        
        return arr
        
    def getEIPResources(self):
        filters = []
        if self.tags:
            filters = self.tags
            
        result = self.ec2Client.describe_addresses(
            Filters = filters    
        )
        arr = result.get('Addresses')
        
        if not self.tags:
            return arr
        
        finalArr = []
        for i, detail in enumerate(arr):
            if 'Tags' in detail and self.resourceHasTags(detail['Tags']):
                finalArr.append(arr[i])
        
        return finalArr    
        
    def getDefaultSG(self):
        defaultSGs = {}
        result = self.ec2Client.describe_security_groups()
        for group in result.get('SecurityGroups'):
            if group.get('GroupName') == 'default':
                defaultSGs[group.get('GroupId')] = group
                
        while result.get('NextToken') is not None:
            result = self.ec2Client.describe_security_groups(
                NextToken = result.get('NextToken')
            )
            for group in result.get('SecurityGroups'):
                if group.get('GroupName') == 'default':
                    defaultSGs[group.get('GroupId')] = group
        
        if not self.tags:
            return defaultSGs
        
        finalArr = []
        
        for i, detail in defaultSGs.items():
            if 'Tags' in detail and self.resourceHasTags(detail['Tags']):
                finalArr.append(defaultSGs[i])
        
        return finalArr
        
    def getVpcs(self):
        filters = []
        if self.tags is not None:
            filters = self.tags
            
        result = self.ec2Client.describe_vpcs(
            Filters = filters
        )
        
        vpcList = result.get('Vpcs')
        while result.get('NextToken') is not None:
            result = self.ec2Client.describe_vpcs(
                Filters = filters,
                NextToken = result.get('NextToken')
            )
            vpcList = vpcList + result.get('Vpcs')
        
        return vpcList
        
    def getFlowLogs(self):
        ## No filter check in flow logs because the filter should be applied on VPC level
        result = self.ec2Client.describe_flow_logs()
        
        flowLogList = result.get('FlowLogs')
        while result.get('NextToken') is not None:
            result = self.ec2Client.describe_flow_logs(
                NextToken = result.get('NextToken')
            )
            flowLogList = flowLogList + result.get('FlowLogs')
        
        return flowLogList
        
    def getNetworkACLs(self):
        result = self.ec2Client.describe_network_acls()
        
        networkACLs = result.get('NetworkAcls')
        while result.get('NextToken') is not None:
            result = self.ec2Client.describe_network_acls(
                NextToken = result.get('NextToken')
            )
            networkACLs = networkACLs + result.get('NetworkAcls')
        return networkACLs
    
    def advise(self):
        objs = {}
        secGroups = {}
        
        # compute optimizer checks
        hasRunComputeOpt = Config.get('EC2_HasRunComputeOpt', False)
        if hasRunComputeOpt == False:
            try:
                compOptPath = "/aws/service/global-infrastructure/regions/" + self.region + "/services/compute-optimizer";
                compOptCheck = self.ssmClient.get_parameters_by_path(
                    Path = compOptPath    
                )
                
                if 'Parameters' in compOptCheck and len(compOptCheck['Parameters']) > 0:
                    _pi('Compute Optimizer Recommendations')
                    obj = Ec2CompOpt(self.compOptClient)
                    obj.run(self.__class__)
                    objs['ComputeOptimizer'] = obj.getInfo()
                    Config.set('EC2_HasRunComputeOpt', True)
                    
            except botocore.exceptions.ClientError as e:
                ecode = e.response['Error']['Code']
                emsg = e.response['Error']['Message']
                print(ecode, emsg)     
            except Exception as e:
                print(e)
                print("!!! Skipping compute optimizer check for <" + self.region + ">")
            
        
        #EC2 Cost Explorer checks
        hasRunRISP = Config.get('EC2_HasRunRISP', False)
        if hasRunRISP == False:
            _pi('Cost Explorer Recommendations')
            obj = Ec2CostExplorerRecs(self.ceClient)
            obj.run(self.__class__)
    
            objs['CostExplorer'] = obj.getInfo()
            Config.set('EC2_HasRunRISP', True)
        
        # EC2 instance checks
        instances = self.getResources()
        for instanceArr in instances:
            for instanceData in instanceArr['Instances']:
                _pi('EC2', instanceData['InstanceId'])
                obj = Ec2Instance(instanceData,self.ec2Client, self.cwClient)
                obj.run(self.__class__)
                
                objs[f"EC2::{instanceData['InstanceId']}"] = obj.getInfo()
                
                ## Gather SecGroups in dict first to prevent check same sec groups multiple time
                instanceSG = self.getEC2SecurityGroups(instanceData)
                for group in instanceSG:
                    secGroups[group['GroupId']] = group
            
        #EBS checks
        volumes = self.getEBSResources()
        for volume in volumes:
            _pi('EBS', volume['VolumeId'])
            obj = Ec2EbsVolume(volume,self.ec2Client, self.cwClient)
            obj.run(self.__class__)
            objs[f"EBS::{volume['VolumeId']}"] = obj.getInfo()

        #EBS Snapshots
        _pi('EBS::Snapshots')
        obj = Ec2EbsSnapshot(self.ec2Client)
        obj.run(self.__class__)
        objs["EBS::Snapshots"] = obj.getInfo()
        
        
        # ELB checks
        loadBalancers = self.getELB()
        for lb in loadBalancers:
            elbSGList = self.getELBSecurityGroup(lb)
            for group in elbSGList:
                secGroups[group['GroupId']] = group
            
            _pi('ELB::Load Balancer', lb['LoadBalancerName'])
            obj = Ec2ElbCommon(lb, elbSGList, self.elbClient, self.wafv2Client)
            obj.run(self.__class__)
            objs[f"ELB::{lb['LoadBalancerName']}"] = obj.getInfo()
            
        
        # ELB classic checks
        lbClassic = self.getELBClassic()
        for lb in lbClassic:
            _pi('ELB::Load Balancer Classic', lb['LoadBalancerName'])
            obj = Ec2ElbClassic(lb, self.elbClassicClient)
            obj.run(self.__class__)
            objs[f"ELB Classic::{lb['LoadBalancerName']}"] = obj.getInfo()
            
            elbSGList = self.getELBSecurityGroup(lb)
            for group in elbSGList:
                secGroups[group['GroupId']] = group
        
        # ASG checks
        autoScalingGroups = self.getASGResources()
        for group in autoScalingGroups:
            _pi('ASG::Auto Scaling Group', group['AutoScalingGroupName']);
            obj = Ec2AutoScaling(group, self.asgClient, self.elbClient, self.elbClassicClient, self.ec2Client)
            obj.run(self.__class__)
            objs[f"ASG::{group['AutoScalingGroupName']}"] = obj.getInfo()
        
        defaultSGs = self.getDefaultSG()
        if defaultSGs:
            for groupId in defaultSGs.keys():
                if groupId not in secGroups:
                    secGroups[groupId] = defaultSGs[groupId]
                    secGroups[groupId]['inUsed'] = 'False'
            
        # SG checks
        if secGroups:
            for group in secGroups.values():
                _pi('EC2::Security Group', group['GroupId'])
                obj = Ec2SecGroup(group, self.ec2Client)
                obj.run(self.__class__)
                
                objs[f"SG::{group['GroupId']}"] = obj.getInfo()
        
        # EIP checks    
        eips = self.getEIPResources()
        for eip in eips:
            _pi('Elastic IP Recommendations', eip['PublicIp'])
            obj = Ec2EIP(eip)
            obj.run(self.__class__)
            objs[f"ElasticIP::{eip['AllocationId']}"] = obj.getInfo()
            
        # VPC Checks
        vpcs = self.getVpcs()
        flowLogs = self.getFlowLogs()
        for vpc in vpcs:
            _pi('VPC::Virtual Private Cloud', vpc['VpcId'])
            obj = Ec2Vpc(vpc, flowLogs, self.ec2Client)
            obj.run(self.__class__)
            objs[f"VPC::{vpc['VpcId']}"] = obj.getInfo()
            
        # NACL Checks
        nacls = self.getNetworkACLs()
        for nacl in nacls:
            _pi('NACL::Network ACL', nacl['NetworkAclId'])
            obj = Ec2NACL(nacl, self.ec2Client)
            obj.run(self.__class__)
            objs[f"NACL::{nacl['NetworkAclId']}"] = obj.getInfo()
        
        
        return objs
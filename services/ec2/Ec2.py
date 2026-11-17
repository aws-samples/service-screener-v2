# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html

import boto3
import botocore
import requests
from datetime import date, datetime, timedelta

import re
import json
import time

from utils.Tools import _pi
from utils.Tools import _warn

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
from services.ec2.drivers.Ec2Regional import Ec2Regional
from services.ec2.drivers.Ec2KeyPair import Ec2KeyPair
from services.ec2.drivers.Ec2SSM import Ec2SSM
from services.ec2.drivers.Ec2Ami import Ec2Ami
from services.ec2.drivers.Ec2EbsSnapshotSharing import Ec2EbsSnapshotSharing
from services.ec2.drivers.Ec2LaunchTemplate import Ec2LaunchTemplate
from services.ec2.drivers.Ec2VpcEndpoint import Ec2VpcEndpoint
from services.ec2.drivers.Ec2NetworkInterface import Ec2NetworkInterface, classifyEni, getSubnetRouting

import concurrent.futures as cf

class Ec2(Service):
    CHARTSTYPE = {
        'EC2 Instance Family Pricing': 'bar',
        'EC2 Instance Utilization': 'bar'
    }

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
        self.rbinClient = ssBoto.client('rbin', config=self.bConfig)
        self.orgClient = ssBoto.client('organizations', config=self.bConfig)
        
        self.getOutdateSQLVersion()
        self.getWindowsVersion()

        self.setChartsType(self.CHARTSTYPE)
        self.setChartData({
            "EC2 Instance Utilization": {
                'Under Provisioned': 0,
                'Over Provisioned': 0,
                'Spiky': 0,
                'Right Sized': 0
            }
        })

        self.chartGen = None
    
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
    
    def _getAllSecurityGroupsCached(self):
        """One full-region describe_security_groups(), memoized per region and
        reused by getEC2SecurityGroups/getELBSecurityGroup/getDefaultSG instead
        of each doing its own describe_security_groups(GroupIds=...) call.
        Real fleets share a small number of SGs across many instances/ELBs -
        this call should scale with unique-SG count, not instance/ELB count."""
        cacheKey = 'ec2::allsgs::' + self.region
        cached = Config.get(cacheKey, None)
        if cached is not None:
            return cached

        byId = {}
        result = self.ec2Client.describe_security_groups()
        for group in result.get('SecurityGroups'):
            byId[group['GroupId']] = group

        while result.get('NextToken') is not None:
            result = self.ec2Client.describe_security_groups(
                NextToken = result.get('NextToken')
            )
            for group in result.get('SecurityGroups'):
                byId[group['GroupId']] = group

        Config.set(cacheKey, byId)
        return byId

    def getEC2SecurityGroups(self,instance):
        if 'SecurityGroups' not in instance:
            print(f"Security Group not found in {instance['InstanceId']}")
            return {}

        allSGs = self._getAllSecurityGroupsCached()
        arr = [allSGs[group['GroupId']] for group in instance['SecurityGroups'] if group['GroupId'] in allSGs]

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
            arr = arr + results.get('Volumes')

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

        # describe_tags accepts up to 20 ResourceArns per call - batch instead
        # of one call per load balancer.
        lbByArn = {lb['LoadBalancerArn']: lb for lb in arr}
        allArns = list(lbByArn.keys())

        filteredResults = []
        for i in range(0, len(allArns), 20):
            chunk = allArns[i:i+20]
            tagResults = self.elbClient.describe_tags(ResourceArns = chunk)
            for desc in tagResults.get('TagDescriptions', []):
                if self.resourceHasTags(desc['Tags']):
                    filteredResults.append(lbByArn[desc['ResourceArn']])

        return filteredResults
        
    def getELBClassic(self):
        results = self.elbClassicClient.describe_load_balancers()
        
        arr = results.get('LoadBalancerDescriptions')
        while results.get('NextMarker') is not None:
            # Classic LB pagination must use the classic (elb) client
            results = self.elbClassicClient.describe_load_balancers(
                Marker = results.get('NextMarker')
            )

            arr = arr + results.get('LoadBalancerDescriptions')
            
        return arr
        
    def getELBSecurityGroup(self, elb):
        if 'SecurityGroups' not in elb:
            return []

        groupIds = list(elb['SecurityGroups'])
        if len(groupIds) == 0:
            return []

        allSGs = self._getAllSecurityGroupsCached()
        arr = [allSGs[gid] for gid in groupIds if gid in allSGs]

        if not self.tags:
            return arr

        finalArr = []
        for i, detail in enumerate(arr):
            if self.resourceHasTags(detail['Tags']):
                finalArr.append(arr[i])

        return finalArr

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
        allSGs = self._getAllSecurityGroupsCached()
        defaultSGs = {gid: group for gid, group in allSGs.items() if group.get('GroupName') == 'default'}

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

    def getKeyPairs(self):
        filters = []
        if self.tags:
            filters = self.tags

        result = self.ec2Client.describe_key_pairs(
            Filters=filters
        )
        return result.get('KeyPairs', [])

    def getInstanceKeyNames(self, instances):
        """Collect all key names actively used by running/stopped instances"""
        keyNames = set()
        for instanceArr in instances:
            for instanceData in instanceArr['Instances']:
                keyName = instanceData.get('KeyName')
                if keyName:
                    keyNames.add(keyName)
        return keyNames

    def getSSMManagedInstances(self):
        """Get set of instance IDs managed by SSM.

        Returns a set of managed instance IDs on success, or None if the
        SSM API call fails (e.g. missing ssm:DescribeInstanceInformation
        permission, or SSM unavailable in the region). Returning None lets
        the caller skip the SSM check entirely instead of flagging every
        instance as unmanaged (false positives).
        """
        managedSet = set()
        pingStatus = {}
        self.ssmError = None
        self.ssmPingStatus = pingStatus
        try:
            # MaxResults=50 is the API maximum — request full pages to
            # minimize round-trips for large fleets.
            results = self.ssmClient.describe_instance_information(MaxResults=50)
            for info in results.get('InstanceInformationList', []):
                managedSet.add(info['InstanceId'])
                pingStatus[info['InstanceId']] = info.get('PingStatus')
            
            while results.get('NextToken'):
                results = self.ssmClient.describe_instance_information(
                    MaxResults=50,
                    NextToken=results['NextToken']
                )
                for info in results.get('InstanceInformationList', []):
                    managedSet.add(info['InstanceId'])
                    pingStatus[info['InstanceId']] = info.get('PingStatus')
        except botocore.exceptions.ClientError as e:
            self.ssmError = e.response['Error']['Code']
            _warn("Unable to retrieve SSM managed instances ({}); skipping SSM check to avoid false positives.".format(e.response['Error']['Code']))
            return None
        except Exception as e:
            self.ssmError = type(e).__name__
            _warn("Unable to retrieve SSM managed instances ({}); skipping SSM check to avoid false positives.".format(e))
            return None
        return managedSet

    def _ruleSelected(self, ruleName):
        """True when no --rules filter is set or ruleName is in it. Used to skip
        expensive pre-fetches whose only consumer is a single check."""
        rules = Config.get(self.RULESPREFIX, []) or []
        return not rules or ruleName.lower() in rules

    def getSelfImages(self):
        """AMIs owned by this account (paginated; tag filters applied)."""
        kwargs = {'Owners': ['self']}
        if self.tags:
            kwargs['Filters'] = self.tags
        images = []
        paginator = self.ec2Client.get_paginator('describe_images')
        for page in paginator.paginate(**kwargs):
            images.extend(page.get('Images', []))
        return images

    def getOrgContext(self):
        """Organization membership for outside-org sharing checks, cached per scan.
        inOrg: True / False / None (unknown). accounts: set of member account IDs, or
        None when not listable (only the management or a delegated admin account can
        call organizations:ListAccounts)."""
        cacheKey = 'ec2::orgContext'
        cached = Config.get(cacheKey, None)
        if cached is not None:
            return cached

        ctx = {'inOrg': None, 'accounts': None, 'error': None, 'orgId': None}
        try:
            org = self.orgClient.describe_organization()
            ctx['inOrg'] = True
            ctx['orgId'] = (org.get('Organization') or {}).get('Id')
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            if code == 'AWSOrganizationsNotInUseException':
                ctx['inOrg'] = False
            else:
                ctx['error'] = code
        except Exception as e:
            ctx['error'] = type(e).__name__

        if ctx['inOrg'] is True:
            try:
                accounts = set()
                paginator = self.orgClient.get_paginator('list_accounts')
                for page in paginator.paginate():
                    for acct in page.get('Accounts', []):
                        accounts.add(acct['Id'])
                ctx['accounts'] = accounts
            except botocore.exceptions.ClientError as e:
                ctx['accountsError'] = e.response['Error']['Code']
            except Exception as e:
                ctx['accountsError'] = type(e).__name__

        Config.set(cacheKey, ctx)
        return ctx

    def getSelfSnapshots(self):
        """Self-owned EBS snapshots (paginated; tag filters applied)."""
        kwargs = {'OwnerIds': ['self']}
        if self.tags:
            kwargs['Filters'] = self.tags
        snapshots = []
        paginator = self.ec2Client.get_paginator('describe_snapshots')
        for page in paginator.paginate(**kwargs):
            snapshots.extend(page.get('Snapshots', []))
        return snapshots

    def getSnapshotSharing(self, snapshots=None):
        """[(snapshot, {'perms': [...]} | {'error': code})] for every self-owned
        snapshot. describe_snapshot_attribute is one call per snapshot, so the
        calls are made concurrently (botocore clients are thread-safe)."""
        if snapshots is None:
            snapshots = Ec2.getSelfSnapshots(self)

        def fetch(snap):
            try:
                resp = self.ec2Client.describe_snapshot_attribute(
                    SnapshotId = snap['SnapshotId'],
                    Attribute = 'createVolumePermission'
                )
                return {'perms': resp.get('CreateVolumePermissions', [])}
            except botocore.exceptions.ClientError as e:
                return {'error': e.response['Error']['Code']}
            except Exception as e:
                return {'error': type(e).__name__}

        if not snapshots:
            return []
        with cf.ThreadPoolExecutor(max_workers=8) as executor:
            perms = list(executor.map(fetch, snapshots))
        return list(zip(snapshots, perms))

    def getImageLaunchPermissions(self, images):
        """{imageId: {'perms': [...]} | {'error': code}} - describe_image_attribute
        (launchPermission) is one call per AMI, so calls are made concurrently."""
        def fetch(image):
            try:
                resp = self.ec2Client.describe_image_attribute(
                    ImageId = image['ImageId'],
                    Attribute = 'launchPermission'
                )
                return {'perms': resp.get('LaunchPermissions', [])}
            except botocore.exceptions.ClientError as e:
                return {'error': e.response['Error']['Code']}
            except Exception as e:
                return {'error': type(e).__name__}

        if not images:
            return {}
        with cf.ThreadPoolExecutor(max_workers=8) as executor:
            perms = list(executor.map(fetch, images))
        return {img['ImageId']: p for img, p in zip(images, perms)}

    def getLaunchTemplates(self):
        kwargs = {}
        if self.tags:
            kwargs['Filters'] = self.tags
        templates = []
        paginator = self.ec2Client.get_paginator('describe_launch_templates')
        for page in paginator.paginate(**kwargs):
            templates.extend(page.get('LaunchTemplates', []))
        return templates

    def getVpcEndpoints(self):
        kwargs = {}
        if self.tags:
            kwargs['Filters'] = self.tags
        endpoints = []
        paginator = self.ec2Client.get_paginator('describe_vpc_endpoints')
        for page in paginator.paginate(**kwargs):
            endpoints.extend(page.get('VpcEndpoints', []))
        return endpoints

    def getEndpointPolicySupport(self, serviceNames):
        """({serviceName: VpcEndpointPolicySupported}, errorCode|None). Unknown /
        unavailable service names are looked up one by one so one bad name does
        not hide the rest."""
        names = sorted({n for n in serviceNames if n})
        support, error = {}, None

        def lookup(batch):
            out = {}
            paginator = self.ec2Client.get_paginator('describe_vpc_endpoint_services')
            for page in paginator.paginate(ServiceNames=batch):
                for d in page.get('ServiceDetails', []):
                    out[d.get('ServiceName')] = d.get('VpcEndpointPolicySupported')
            return out

        for i in range(0, len(names), 100):
            batch = names[i:i+100]
            try:
                support.update(lookup(batch))
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                if code != 'InvalidServiceName':
                    error = code
                    continue
                for name in batch:
                    try:
                        support.update(lookup([name]))
                    except botocore.exceptions.ClientError as e2:
                        error = e2.response['Error']['Code']
        return support, error

    def getNetworkInterfaces(self):
        enis = []
        paginator = self.ec2Client.get_paginator('describe_network_interfaces')
        for page in paginator.paginate():
            enis.extend(page.get('NetworkInterfaces', []))
        return enis

    def getChartGenCost(self):
        '''
        Generate Chart by EC2 Instance Type & Region
        Provide customer insight on percentage of older generation EC2 Instance Type
        '''
        def get_next_gen(instance_family):
            # Extract the numeric part from the instance family
            numeric_part = re.search(r'\d+', instance_family)
            if numeric_part:
                numeric_value = int(numeric_part.group())
                new_numeric_value = numeric_value + 1
                new_instance_family = re.sub(r'\d+', str(new_numeric_value), instance_family)
            else:
                # If no numeric part is found, assume it's the first generation
                new_instance_family = instance_family + '1'

            return new_instance_family

        # Define the time period for the this month
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        time_period = {
            'Start': start_date.strftime('%Y-%m-%d'),
            'End': end_date.strftime('%Y-%m-%d')
        }

        # Get the cost data for EC2 instances, grouped by instance type and region
        ec2_response = {}
        
        try:
            ec2_response = self.ceClient.get_cost_and_usage(
            TimePeriod=time_period,
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[
                {
                    'Type': 'DIMENSION',
                    'Key': 'INSTANCE_TYPE'
                },
                {
                    'Type': 'DIMENSION',
                    'Key': 'REGION'
                }
            ],
            Filter={
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': ['Amazon Elastic Compute Cloud - Compute']
                }
            }
        )
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
        except Exception as e:
            print('Cost and Usage API call is getting the following error:')
            print(e)

        if not ec2_response:
            return # Simply end this function if ec2_response did not return with a proper response
        
        region_instance_dict = dict()

        # Print the cost for each instance family and region
        for result in ec2_response['ResultsByTime']:
            for group in result['Groups']:
                instance_type = group['Keys'][0]
                region = group['Keys'][1]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])

                if instance_type == 'NoInstanceType':
                    continue

                instance_family = instance_type.split('.')[0]

                if region not in region_instance_dict:
                    region_instance_dict[region] = dict()
                
                if instance_family not in region_instance_dict[region]:
                    region_instance_dict[region][instance_family] = {'latest_gen' : True, 'cost': 0}

                region_instance_dict[region][instance_family]['cost'] += cost

        if self.region not in region_instance_dict.keys():
            return
        else:
            instance_dict = region_instance_dict.get(self.region, None)

        # Get all available instance types
        all_instance_types = []
        response = self.ec2Client.describe_instance_types()
        all_instance_types.extend(response['InstanceTypes'])

        while 'NextToken' in response:
            response = self.ec2Client.describe_instance_types(NextToken=response['NextToken'])
            all_instance_types.extend(response['InstanceTypes'])

        for instance, metadata in instance_dict.items():
            latest_gen = instance
            has_next_gen = True
            while has_next_gen:
                instance_type_to_check = get_next_gen(latest_gen)
                if instance_type_to_check in [instance_type['InstanceType'].split('.')[0] for instance_type in all_instance_types]:
                    latest_gen = instance_type_to_check
                else:
                    has_next_gen = False
        
            if latest_gen != instance:
                metadata['latest_gen'] = False
        
        formatted_instance_dict = dict()
        for instance_family, metadata in instance_dict.items():
            if metadata['latest_gen']:
                formatted_instance_dict[instance_family] = metadata['cost']
            else:
                formatted_instance_dict[f'[PREV GEN] {instance_family}'] = metadata['cost']
        self.chartGen = formatted_instance_dict

        return self.chartGen

    def advise(self):
        objs = {}
        secGroups = {}
        
        # Regional-level checks (EBS encryption by default, service quotas)
        _pi('EC2::Regional Checks')
        obj = Ec2Regional(self.ec2Client, self.compOptClient, self.rbinClient)
        obj.run(self.__class__)
        objs['EC2::Regional'] = obj.getInfo()
        
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
        instancesById = {}
        for instanceArr in instances:
            for instanceData in instanceArr['Instances']:
                instancesById[instanceData['InstanceId']] = instanceData

                _pi('EC2', instanceData['InstanceId'])
                obj = Ec2Instance(instanceData,self.ec2Client, self.cwClient)
                obj.run(self.__class__)

                objs[f"EC2::{instanceData['InstanceId']}"] = obj.getInfo()
                self.setChartData(obj.getChartData())

                ## Gather SecGroups in dict first to prevent check same sec groups multiple time
                instanceSG = self.getEC2SecurityGroups(instanceData)
                for group in instanceSG:
                    secGroups[group['GroupId']] = group


        #EBS checks
        volumes = self.getEBSResources()
        for volume in volumes:
            _pi('EBS', volume['VolumeId'])
            obj = Ec2EbsVolume(volume,self.ec2Client, self.cwClient, instancesById)
            obj.run(self.__class__)
            objs[f"EBS::{volume['VolumeId']}"] = obj.getInfo()

        #EBS Snapshots
        _pi('EBS::Snapshots')
        volume_ids = [volume['VolumeId'] for volume in volumes]
        obj = Ec2EbsSnapshot(volume_ids, self.ec2Client)

        obj.run(self.__class__)
        objs["EBS::Snapshots"] = obj.getInfo()

        selfAccount = (Config.get('stsInfo', {}) or {}).get('Account')

        # Self-owned AMIs (also used to label AMI backing snapshots)
        amiKeys = [k for k in ('ec2AmiPublic', 'ec2AmiSharedExternally') if self._ruleSelected(k)]
        images = None
        if amiKeys:
            try:
                images = self.getSelfImages()
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                _warn("Unable to list self-owned AMIs ({})".format(code))
                objs["AMI::unavailable"] = {'results': {k: [0, f"Unable to evaluate ({code})"] for k in amiKeys}, 'info': {}}
            if images:
                amiPerms = {}
                amiOrgCtx = None
                if self._ruleSelected('ec2AmiSharedExternally'):
                    amiPerms = self.getImageLaunchPermissions(images)
                    amiOrgCtx = self.getOrgContext()
                for image in images:
                    _pi('EC2::AMI', image['ImageId'])
                    obj = Ec2Ami(image, amiPerms.get(image['ImageId']), selfAccount, amiOrgCtx)
                    obj.run(self.__class__)
                    objs[f"AMI::{image['ImageId']}"] = obj.getInfo()

        # Per-snapshot checks (sharing: one describe_snapshot_attribute per
        # snapshot - only fetched when that check is selected)
        snapKeys = [k for k in ('ebsSnapshotSharedExternally', 'ebsSnapshotUnencrypted') if self._ruleSelected(k)]
        if snapKeys:
            try:
                snapshots = self.getSelfSnapshots()
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                _warn("Unable to list EBS snapshots ({})".format(code))
                objs["EBSSnapshot::unavailable"] = {'results': {k: [0, f"Unable to evaluate ({code})"] for k in snapKeys}, 'info': {}}
                snapshots = []
            if snapshots:
                permsById = {}
                orgCtx = None
                if self._ruleSelected('ebsSnapshotSharedExternally'):
                    permsById = {snap['SnapshotId']: perms for snap, perms in self.getSnapshotSharing(snapshots)}
                    orgCtx = self.getOrgContext()
                backing = {}
                for image in images or []:
                    for bdm in image.get('BlockDeviceMappings', []) or []:
                        sid = (bdm.get('Ebs') or {}).get('SnapshotId')
                        if sid:
                            backing.setdefault(sid, []).append(image['ImageId'])
                for snap in snapshots:
                    _pi('EBS::Snapshot', snap['SnapshotId'])
                    obj = Ec2EbsSnapshotSharing(snap, permsById.get(snap['SnapshotId']), selfAccount, orgCtx,
                                                backing.get(snap['SnapshotId']))
                    obj.run(self.__class__)
                    objs[f"EBSSnapshot::{snap['SnapshotId']}"] = obj.getInfo()

        # Launch template user data
        if self._ruleSelected('ec2UserDataSecrets'):
            try:
                templates = self.getLaunchTemplates()
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                _warn("Unable to list launch templates ({})".format(code))
                objs["LaunchTemplate::unavailable"] = {'results': {'ec2UserDataSecrets': [0, f"Unable to evaluate ({code})"]}, 'info': {}}
                templates = []
            for lt in templates:
                _pi('EC2::Launch Template', lt['LaunchTemplateId'])
                obj = Ec2LaunchTemplate(lt, self.ec2Client)
                obj.run(self.__class__)
                objs[f"LaunchTemplate::{lt['LaunchTemplateId']}"] = obj.getInfo()

        # VPC endpoint policies
        if self._ruleSelected('vpcEndpointPolicyFullAccess'):
            try:
                endpoints = self.getVpcEndpoints()
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                _warn("Unable to list VPC endpoints ({})".format(code))
                objs["VPCEndpoint::unavailable"] = {'results': {'vpcEndpointPolicyFullAccess': [0, f"Unable to evaluate ({code})"]}, 'info': {}}
                endpoints = []
            if endpoints:
                support, supportErr = self.getEndpointPolicySupport([ep.get('ServiceName') for ep in endpoints])
                for ep in endpoints:
                    _pi('VPC::Endpoint', ep['VpcEndpointId'])
                    obj = Ec2VpcEndpoint(ep, support.get(ep.get('ServiceName')), supportErr)
                    obj.run(self.__class__)
                    objs[f"VPCEndpoint::{ep['VpcEndpointId']}"] = obj.getInfo()

        # Internal-tier managed-service interfaces (RDS / ElastiCache / ECS) in public subnets;
        # EC2 instances are evaluated by Ec2Instance
        if self._ruleSelected('ec2InstanceInPublicSubnet'):
            try:
                enis = self.getNetworkInterfaces()
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                _warn("Unable to list network interfaces ({})".format(code))
                objs["ENI::unavailable"] = {'results': {'ec2InstanceInPublicSubnet': [0, f"Unable to evaluate ({code})"]}, 'info': {}}
                enis = []
            routing = None
            for eni in enis:
                kind = classifyEni(eni)
                if kind is None:
                    continue
                if routing is None:
                    routing = getSubnetRouting(self.ec2Client)
                _pi('EC2::Network Interface', eni['NetworkInterfaceId'])
                obj = Ec2NetworkInterface(eni, kind, routing)
                obj.run(self.__class__)
                objs[f"ENI::{eni['NetworkInterfaceId']}"] = obj.getInfo()
        
        
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
        
        
        # Key Pair Checks
        keyPairs = self.getKeyPairs()
        instanceKeyNames = self.getInstanceKeyNames(instances)
        for kp in keyPairs:
            _pi('EC2::Key Pair', kp['KeyName'])
            obj = Ec2KeyPair(kp, instanceKeyNames)
            obj.run(self.__class__)
            objs[f"KeyPair::{kp['KeyName']}"] = obj.getInfo()
        
        # SSM Managed Instance Checks
        ssmManagedSet = self.getSSMManagedInstances()
        # If the managed-instance lookup failed (getSSMManagedInstances returns
        # None) EC2SSMNotManaged is skipped to avoid false positives;
        # ec2InstanceWithKeyPair then reports "Unable to evaluate".
        if ssmManagedSet is not None or self._ruleSelected('ec2InstanceWithKeyPair'):
            for instanceArr in instances:
                for instanceData in instanceArr['Instances']:
                    if instanceData['State']['Name'] not in ('running', 'stopped'):
                        continue
                    _pi('EC2::SSM Check', instanceData['InstanceId'])
                    obj = Ec2SSM(instanceData['InstanceId'], ssmManagedSet, instanceData,
                                 getattr(self, 'ssmError', None), getattr(self, 'ssmPingStatus', None))
                    obj.run(self.__class__)
                    objs[f"SSM::{instanceData['InstanceId']}"] = obj.getInfo()
        
        if self.getChartGenCost():
            self.setChartData({"EC2 Instance Family Pricing": self.getChartGenCost()})

        return objs
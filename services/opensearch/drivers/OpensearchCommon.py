import time
import datetime

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import _warn
from utils.Tools import aws_parseInstanceFamily
from utils.Policy import Policy
from services.Evaluator import Evaluator

class OpensearchCommon(Evaluator):
    NODES_LIMIT = 200
    
    def __init__(self, bConfig, domain, attr, osClient, cwClient):
        self.results = {}
        self.clientConfig = bConfig
        self.domain = domain
        self.osClient = osClient
        self.cwClient = cwClient
        
        # self.attribute = self.osClient.describe_domain(DomainName=self.domain)
        self.attribute = {'DomainStatus': attr}
        self.cluster_config = self.attribute["DomainStatus"]["ClusterConfig"]
        self.domain_config = self.osClient.describe_domain_config(DomainName=self.domain)

        self.aos_versions = self.osClient.list_versions(MaxResults=11)
        self.latest_version = self.aos_versions["Versions"][0]
        self.engine_version = self.attribute["DomainStatus"]["EngineVersion"]
        self.instance_type_details = self.osClient.list_instance_type_details(
            EngineVersion=self.engine_version
        )
    
        # Create a list of OpenSearch instance types.
        self.instance_type_list = []
        for idx, details in enumerate(self.instance_type_details["InstanceTypeDetails"]):
            self.instance_type_list.append(details["InstanceType"])
    
        # Initialize the evaluator.
        self.init()
    
    def getCloudWatchData(self, metric, statistics=["Average"], time_ago=300, period=300):
        cw_client = self.cwClient
        
        sts_info = Config.get("stsInfo")
        client_id = sts_info["Account"]

        dimensions = [
            {"Name": "ClientId", "Value": client_id},
            {"Name": "DomainName", "Value": self.domain},
        ]

        stats = cw_client.get_metric_statistics(
            Dimensions=dimensions,
            Namespace="AWS/ES",
            MetricName=metric,
            StartTime=int(time.time())-time_ago,
            EndTime=int(time.time()),
            Period=period,
            Statistics=statistics
        )

        return stats    
        
    def _checkMasterNodes(self):
        enabled = self.cluster_config["DedicatedMasterEnabled"]
        if enabled:
            nodes = self.cluster_config["DedicatedMasterCount"]
            self.results["DedicatedMasterNodes"] = [-1, "No dedicated master nodes"]
            
            if nodes < 3:
                self.results["DedicatedMasterNodes"] = [-1, "Insufficient dedicated master nodes"]
                return
            if nodes % 2 == 0:
                self.results["DedicatedMasterNodes"] = [-1, "Wrong number of dedicated master nodes"]
                return
            self.results["DedicatedMasterNodes"] = [1, "Sufficient dedicated master nodes"]

    def _checkDataNodes(self):
        total_nodes = self.cluster_config['InstanceCount']
        master_enabled = self.cluster_config["DedicatedMasterEnabled"]
        master_nodes = 0
        if master_enabled:
            master_nodes = self.cluster_config['DedicatedMasterCount']
        warm_enabled = self.cluster_config["WarmEnabled"]
        warm_nodes = 0
        if warm_enabled:
            warm_nodes = self.cluster_config['WarmCount']
        data_nodes = total_nodes - master_nodes - warm_nodes
        
        if data_nodes < 3:
            self.results["DataNodes"] = [-1, "Insufficient data nodes"]
            return
        self.results["DataNodes"] = [1, "Sufficient data nodes"]

    def _checkAvailabilityZones(self):
        enabled = self.cluster_config["ZoneAwarenessEnabled"]
        self.results["AvailabilityZones"] = [-1, "Multi-AZ not enabled"]
        if enabled:
            self.results["AvailabilityZones"] = [1, "Multi-AZ enabled"]

    def _checkServiceSoftwareVersion(self):
        if 'DomainStatus' in self.attribute:
            if 'ServiceSoftwareOptions' in self.attribute['DomainStatus']:
                if 'UpdateAvailable' in self.attribute['DomainStatus']['ServiceSoftwareOptions']:
                    self.results["ServiceSoftwareVersion"] = [-1, "Upgrade to latest version"]

    def _checkEngineVersion(self):
        if self.engine_version != self.latest_version:
            self.results["EngineVersion"] = [-1, "Later Engine Versions Available"]

    def _checkFineGrainedAccessControl(self):
        self.results["FineGrainedAccessControl"] = [-1, "Not enabled"]
        
        if 'DomainStatus' in self.attribute:
            if 'AdvancedSecurityOptions' in self.attribute['DomainStatus']:
                if 'Enabled' in self.attribute['DomainStatus']['AdvancedSecurityOptions']:
                    self.results["FineGrainedAccessControl"] = [1, "Enabled"]

    def _checkDomainWithinVpc(self):
        self.results["DomainWithinVPC"] = [-1, "Public"]
        if "DomainStatus" in self.attribute:
            if "VPCOptions" in self.attribute["DomainStatus"]:
                self.results["DomainWithinVPC"] = [1, "Private"]

    def _checkInstanceVersion(self):
        instance_type = self.cluster_config["InstanceType"]
        self.results["LatestInstanceVersion"] = [1, instance_type]

        instance_info = aws_parseInstanceFamily(instance_type, region=self.osClient.meta.region_name)

        instance_prefix_arr = instance_info["prefixDetail"]
        instance_prefix_arr["version"] = int(instance_prefix_arr["version"]) + 1
        size = instance_info["suffix"]
        latest_instance = (
            instance_prefix_arr["family"]
            + str(instance_prefix_arr["version"])
            + instance_prefix_arr["attributes"]
            + size
            + ".search"
        )

        if latest_instance in self.instance_type_list:
            self.results["LatestInstanceVersion"] = [-1, instance_type]
            
    def _checkTSeriesForProduction(self):
        instance_type = self.cluster_config["InstanceType"]
        type_arr = instance_type.split(".")
        family = type_arr[0]
        family_char = list(family)
        if family_char[0] == "t":
            self.results["TSeriesForProduction"] = [-1, instance_type]

    def _checkEncryptionAtRest(self):
        self.results["EncyptionAtRest"] = [-1, "Disabled"]
        if 'DomainStatus' in self.attribute:
            if 'EncryptionAtRestOptions' in self.attribute['DomainStatus']:
                if 'Enabled' in self.attribute['DomainStatus']['EncryptionAtRestOptions']:
                    self.results["EncyptionAtRest"] = [1, "Enabled"]

    def _checkNodeToNodeEncryption(self):
        self.results["NodeToNodeEncryption"] = [-1, "Disabled"]
        if 'DomainStatus' in self.attribute:
            if 'NodeToNodeEncryptionOptions' in self.attribute['DomainStatus']:
                if 'Enabled' in self.attribute['DomainStatus']['NodeToNodeEncryptionOptions']:
                    self.results["NodeToNodeEncryption"] = [1, "Enabled"]
    
    def _checkTLSEnforced(self):
        self.results["TLSEnforced"] = [-1, "Disabled"]
        if 'DomainStatus' in self.attribute:
            if 'DomainEndpointOptions' in self.attribute['DomainStatus']:
                if 'EnforceHTTPS' in self.attribute['DomainStatus']['DomainEndpointOptions']:
                    self.results["TLSEnforced"] = [1, "Enabled"]
    
    def _checkSearchSlowLogs(self):
        self.results["SearchSlowLogs"] = [-1, "Disabled"]
        if 'DomainStatus' in self.attribute:
            if 'LogPublishingOptions' in self.attribute['DomainStatus']:
                if 'SEARCH_SLOW_LOGS' in self.attribute['DomainStatus']['LogPublishingOptions']:
                    self.results["SearchSlowLogs"] = [1, "Enabled"]

    def _checkApplicationLogs(self):
        self.results["ApplicationLogs"] = [-1, "Disabled"]
        if 'DomainStatus' in self.attribute:
            if 'LogPublishingOptions' in self.attribute['DomainStatus']:
                if 'ES_APPLICATION_LOGS' in self.attribute['DomainStatus']['LogPublishingOptions']:
                    self.results["SearchSlowLogs"] = [1, "Enabled"]

    def _checkAuditLogs(self):
        self.results["AuditLogs"] = [-1, "Disabled"]
        if 'DomainStatus' in self.attribute:
            if 'LogPublishingOptions' in self.attribute['DomainStatus']:
                if 'SEARCH_SLOW_LOGS' in self.attribute['DomainStatus']['LogPublishingOptions']:
                    self.results["AUDIT_LOGS"] = [1, "Enabled"]

    def _checkAutoTune(self):
        self.results["AutoTune"] = [-1, "Disabled"]
        if 'DomainStatus' in self.attribute:
            if 'AutoTuneOptions' in self.attribute['DomainStatus']:
                if 'State' in self.attribute['DomainStatus']['AutoTuneOptions']:
                    if self.attribute["DomainStatus"]["AutoTuneOptions"]["State"] == "ENABLED":
                        self.results["AutoTune"] = [1, "Enabled"]

    def _checkUltrawarmEnabled(self):
        self.results["UltrawarmEnabled"] = [-1, "Disabled"]
        if self.cluster_config["WarmEnabled"]:
            self.results["UltrawarmEnabled"] = [1, "Enabled"]

    def _checkColdStorage(self):
        self.results["ColdStorage"] = [-1, "Disabled"]
        if self.cluster_config["ColdStorageOptions"]:
            self.results["ColdStorage"] = [1, "Enabled"]
            
    def _checkEbsStorageUtilisation(self):
        metric = "FreeStorageSpace"
        stats = self.getCloudWatchData(metric)

        dp = stats.get("Datapoints")
        if len(dp) == 0:
            return
        
        free_space = dp[0]["Average"]

        try:
            ebs_vol_size = self.domain_config["DomainConfig"]["EBSOptions"]["Options"][
                "VolumeSize"
            ]
        except Exception as e:
            # print("Not EBSEnabled")
            self.results["EBSStorageUtilisation"] = [-1, "Not EBSEnabled"]
            return

        if free_space < 0.25 * (ebs_vol_size * 1000):
            self.results["EBSStorageUtilisation"] = [
                -1,
                f"{free_space} out of {ebs_vol_size * 1000} remaining",
            ]
            return
        
    def _checkClusterStatus(self):
        metrics = ["ClusterStatus.red", "ClusterStatus.yellow", "ClusterStatus.green"]

        for metric in metrics:
            stats = self.getCloudWatchData(metric)
            dp = stats.get("Datapoints")
            if dp and metric == "ClusterStatus.green":
                self.results["ClusterStatus"] = [1, metric]
            elif dp:
                self.results["ClusterStatus"] = [-1, metric]

    def _checkReplicaShard(self):
        self.results["ReplicaShard"] = [-1, None]

        active = "Shards.active"
        primary = "Shards.activePrimary"

        stats_active = self.getCloudWatchData(active)
        dp = stats_active.get("Datapoints")
        if len(dp) == 0:
            return
        
        dp_active = dp[0]["Average"]

        stats_primary = self.getCloudWatchData(primary)
        dp_primary = stats_primary.get("Datapoints")[0]["Average"]

        if dp_active - dp_primary:
            self.results["ReplicaShard"] = [1, "Enabled"]
            
    def __checkMasterNodeType(self):
        xmap = [
            {
                "instance_count": {"min": 1, "max": 10},
                "type": {"min_vcpu": 8, "min_memoryInGiB": 16},
            },
            {
                "instance_count": {"min": 11, "max": 30},
                "type": {"min_vcpu": 2, "min_memoryInGiB": 8},
            },
            {
                "instance_count": {"min": 31, "max": 75},
                "type": {"min_vcpu": 16, "min_memoryInGiB": 32},
            },
            {
                "instance_count": {"min": 76, "max": 125},
                "type": {"min_vcpu": 8, "min_memoryInGiB": 64},
            },
            {
                "instance_count": {"min": 126, "max": 200},
                "type": {"min_vcpu": 16, "min_memoryInGiB": 128},
            },
        ]

        instance_type = self.cluster_config["DedicatedMasterType"]
        instance_info = aws_parseInstanceFamily(instance_type)

        nodes = self.cluster_config["InstanceCount"]

        if nodes < 0 or nodes > self.NODES_LIMIT:
            print(_warn(f"{nodes} not within the range of 0 & {self.NODES_LIMIT}"))

        for row in xmap:
            if row["instance_count"]["min"] <= nodes <= row["instance_count"]["max"]:
                # Get instance attributes
                cpu = instance_info["specification"]["vcpu"]
                memory = instance_info["specification"]["memoryInGiB"]
                if not (
                    row["type"]["min_vcpu"] <= cpu
                    and row["type"]["min_memoryInGiB"] <= memory
                ):
                    self.results["MasterNodeType"] = [-1, instance_type]
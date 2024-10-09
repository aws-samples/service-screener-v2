import botocore
import boto3
import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd

from datetime import datetime, timedelta, time, timezone
from utils.Config import Config
from utils.Tools import _pr, _warn
from services.Service import Service
##import drivers here
from services.rds.drivers.RdsCommon import RdsCommon
from services.rds.drivers.RdsMysql import RdsMysql
from services.rds.drivers.RdsMariadb import RdsMariadb
from services.rds.drivers.RdsMysqlAurora import RdsMysqlAurora
from services.rds.drivers.RdsPostgres import RdsPostgres
from services.rds.drivers.RdsPostgresAurora import RdsPostgresAurora
from services.rds.drivers.RdsMssql import RdsMssql
from services.rds.drivers.RdsSecretsManager import RdsSecretsManager
from services.rds.drivers.RdsSecretsVsDB import RdsSecretsVsDB
from services.rds.drivers.RdsSecurityGroup import RdsSecurityGroup


class CostData:
    def __init__(
        self, costJson, startDate, endDate, regionName, serviceName, dimension
    ):
        self.costJson = costJson
        self.dimension = dimension
        self.startDate = startDate
        self.endDate = endDate
        self.regionName = regionName
        self.serviceName = serviceName

    def __str__(self):
        return self.costJson
        
        
class Rds(Service):
    def __init__(self, region):
        super().__init__(region)
        
        ssBoto = self.ssBoto
        self.rdsClient = ssBoto.client('rds', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self.ctClient = ssBoto.client('cloudtrail', config=self.bConfig)
        self.smClient = ssBoto.client('secretsmanager', config=self.bConfig)
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        self.ceClient = ssBoto.client('ce', config=self.bConfig)
        
        self.secrets = []

    engineDriver = {
        'mariadb': 'Mariadb',
        'mysql': 'Mysql',
        'aurora-mysql': 'MysqlAurora',
        'postgres': 'Postgres',
        'aurora-postgresql': 'PostgresAurora',
        'sqlserver': 'Mssql'
    }
    
    # def getCharts(self):
    #     startDate, endDate = self.getDate()
    #     rdsInstanceTypeCost = self.getCosts(
    #         startDate,
    #         endDate,
    #         self.region,
    #         "Amazon Relational Database Service",
    #         "INSTANCE_TYPE",
    #     )
    #     rdsDatabaseEngineCost = self.getCosts(
    #         startDate,
    #         endDate,
    #         self.region,
    #         "Amazon Relational Database Service",
    #         "DATABASE_ENGINE",
    #     )
    #     rdsLinkedAccountCost = self.getCosts(
    #         startDate,
    #         endDate,
    #         self.region,
    #         "Amazon Relational Database Service",
    #         "LINKED_ACCOUNT",
    #     )
    #     rdsRegionCost = self.getCosts(
    #         startDate,
    #         endDate,
    #         self.region,
    #         "Amazon Relational Database Service",
    #         "REGION",
    #     )
    #     rdsDeploymentOptionCost = self.getCosts(
    #         startDate,
    #         endDate,
    #         self.region,
    #         "Amazon Relational Database Service",
    #         "DEPLOYMENT_OPTION",
    #     )
    #     rdsUsageTypeCost = self.getCosts(
    #         startDate,
    #         endDate,
    #         self.region,
    #         "Amazon Relational Database Service",
    #         "USAGE_TYPE",
    #     )
    
        # self.plotCostByTime(rdsInstanceTypeCost)
        # self.plotCostByTime(rdsDatabaseEngineCost)
        # self.plotCostByTime(rdsLinkedAccountCost)
        # self.plotCostByTime(rdsDeploymentOptionCost)
        # self.plotCostByTime(rdsUsageTypeCost)
        # self.plotCostByTime(rdsRegionCost)
        
        # instance_details_json = self.getCurrentRdsInstanceDetails(
        #     startDate, endDate, self.region
        # )
        # categorized_instances = self.categorizeRdsInstances(instance_details_json)
        # self.plotCategorizedInstances(categorized_instances)
        
        # rdsUtilization = self.getRdsUtilization(startDate, endDate)
        # self.plotRdsUtilization(rdsUtilization)

    
    def getDate(self):
        today = datetime.now()
        endDate = today.date()
        startDate = (endDate.replace(day=1) - timedelta(days=365)).replace(day=1)
        return startDate, endDate
    
    def getCosts(self, startDate, endDate, regionName, serviceName, dimension):
        response = self.ceClient.get_cost_and_usage(
            TimePeriod={"Start": str(startDate), "End": str(endDate)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": dimension}],
            Filter={
                "And": [
                    {"Dimensions": {"Key": "SERVICE", "Values": [serviceName]}},
                    {"Dimensions": {"Key": "REGION", "Values": [regionName]}},
                ]
            },
        )
        jsonResponse = json.dumps(response["ResultsByTime"], indent=4)
        return CostData(
            jsonResponse, startDate, endDate, regionName, serviceName, dimension
        )
        
    def getCurrentRdsInstanceDetails(self, startDate, endDate, regionName):
        response = self.rdsClient.describe_db_instances()
    
        startDatetime = datetime.combine(startDate, time.min).replace(tzinfo=timezone.utc)
        endDatetime = datetime.combine(endDate, time.max).replace(tzinfo=timezone.utc)
    
        instanceDetails = []
        for instance in response["DBInstances"]:
            instanceId = instance["DBInstanceIdentifier"]
            timeDiff = (endDate - startDate).days
            period = 86400 if timeDiff > 30 else 3600
    
            try:
                cpuResponse = self.cwClient.get_metric_statistics(
                    Namespace="AWS/RDS",
                    MetricName="CPUUtilization",
                    Dimensions=[{"Name": "DBInstanceIdentifier", "Value": instanceId}],
                    StartTime=startDatetime,
                    EndTime=endDatetime,
                    Period=period,
                    Statistics=["Average"],
                )
    
                if cpuResponse["Datapoints"]:
                    avgCpu = sum(
                        point["Average"] for point in cpuResponse["Datapoints"]
                    ) / len(cpuResponse["Datapoints"])
                else:
                    avgCpu = 0
    
                instanceDetails.append(
                    {
                        "DBInstanceIdentifier": instanceId,
                        "DBInstanceClass": instance["DBInstanceClass"],
                        "Engine": instance["Engine"],
                        "AllocatedStorage": instance["AllocatedStorage"],
                        "StorageType": instance["StorageType"],
                        "AverageCPUUtilization": f"{avgCpu:.2f}%",
                    }
                )
            except Exception as e:
                print(f"Error processing instance {instanceId}: {str(e)}")
    
        return json.dumps(instanceDetails, indent=2)
        
    def categorizeRdsInstances(self, instanceDetailsJson):
        instanceDetails = json.loads(instanceDetailsJson)
        highUtilization = []
        mediumUtilization = []
        lowUtilization = []
    
        for instance in instanceDetails:
            cpuUtilization = float(instance["AverageCPUUtilization"].strip("%"))
            if cpuUtilization > 70:
                highUtilization.append(instance["DBInstanceIdentifier"])
            elif cpuUtilization < 30:
                lowUtilization.append(instance["DBInstanceIdentifier"])
            else:
                mediumUtilization.append(instance["DBInstanceIdentifier"])
    
        result = {
            "highUtilization": {
                "count": len(highUtilization),
                "instances": highUtilization,
            },
            "mediumUtilization": {
                "count": len(mediumUtilization),
                "instances": mediumUtilization,
            },
            "lowUtilization": {
                "count": len(lowUtilization),
                "instances": lowUtilization,
            },
        }
        return json.dumps(result, indent=2)
    
    def getRdsUtilization(self, startDate, endDate):
        startDate = datetime.combine(startDate, datetime.min.time()).replace(tzinfo=timezone.utc)
        endDate = datetime.combine(endDate, datetime.max.time()).replace(tzinfo=timezone.utc)
        instances = self.rdsClient.describe_db_instances()["DBInstances"]
        
        utilization_data = []
        
        for instance in instances:
            instanceId = instance["DBInstanceIdentifier"]
            creationDate = instance["InstanceCreateTime"]
            if creationDate.tzinfo is None:
                creationDate = creationDate.replace(tzinfo=timezone.utc)

            response = self.cwClient.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "cpuUtilization",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/RDS",
                                "MetricName": "CPUUtilization",
                                "Dimensions": [
                                    {
                                        "Name": "DBInstanceIdentifier",
                                        "Value": instanceId,
                                    },
                                ],
                            },
                            "Period": 86400,
                            "Stat": "Average",
                        },
                    }
                ],
                StartTime=startDate,
                EndTime=endDate,
            )

            timestamps = response["MetricDataResults"][0]["Timestamps"]
            values = response["MetricDataResults"][0]["Values"]

            if len(timestamps) > 0:
                utilization_data.append({
                    "instanceId": instanceId,
                    "timestamps": timestamps,
                    "values": values
                })
            else:
                print(f"No data points for {instanceId}")
        
        return utilization_data
        
    # def plotRdsUtilization(self, utilization_data):
    #     plt.figure(figsize=(15, 8))
    #     if len(utilization_data) == 0:
    #         plt.text(
    #             0.5,
    #             0.5,
    #             "No RDS instances running currently",
    #             horizontalalignment="center",
    #             verticalalignment="center",
    #             transform=plt.gca().transAxes,
    #             fontsize=20,
    #         )
    #     else:
    #         for data in utilization_data:
    #             plt.plot(data["timestamps"], data["values"], label=data["instanceId"])

    #     plt.title("RDS CPU Utilization Over Time")
    #     plt.xlabel("Time")
    #     plt.ylabel("Average CPU Utilization (%)")
    #     plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    #     plt.grid(True)
    #     plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    #     plt.gca().xaxis.set_major_locator(mdates.MonthLocator())
    #     plt.gcf().autofmt_xdate()
    #     plt.tight_layout()
    #     plt.savefig("RDS CPU Utilisation", dpi=300, bbox_inches="tight")
    #     plt.close()
    
    # def plotRdsUtilization(self, startDate, endDate):
    #     startDate = datetime.combine(startDate, datetime.min.time()).replace(
    #         tzinfo=timezone.utc
    #     )
    #     endDate = datetime.combine(endDate, datetime.max.time()).replace(
    #         tzinfo=timezone.utc
    #     )
    #     instances = self.rdsClient.describe_db_instances()["DBInstances"]
    
    #     plt.figure(figsize=(15, 8))
    #     if len(instances) == 0:
    #         plt.text(
    #             0.5,
    #             0.5,
    #             "No RDS instances running currently",
    #             horizontalalignment="center",
    #             verticalalignment="center",
    #             transform=plt.gca().transAxes,
    #             fontsize=20,
    #         )
    #     else:
    #         for instance in instances:
    #             instanceId = instance["DBInstanceIdentifier"]
    #             creationDate = instance["InstanceCreateTime"]
    #             if creationDate.tzinfo is None:
    #                 creationDate = creationDate.replace(tzinfo=timezone.utc)
    
    #             response = self.cwClient.get_metric_data(
    #                 MetricDataQueries=[
    #                     {
    #                         "Id": "cpuUtilization",
    #                         "MetricStat": {
    #                             "Metric": {
    #                                 "Namespace": "AWS/RDS",
    #                                 "MetricName": "CPUUtilization",
    #                                 "Dimensions": [
    #                                     {
    #                                         "Name": "DBInstanceIdentifier",
    #                                         "Value": instanceId,
    #                                     },
    #                                 ],
    #                             },
    #                             "Period": 86400,
    #                             "Stat": "Average",
    #                         },
    #                     }
    #                 ],
    #                 StartTime=startDate,
    #                 EndTime=endDate,
    #             )
    
    #             timestamps = response["MetricDataResults"][0]["Timestamps"]
    #             values = response["MetricDataResults"][0]["Values"]
    
    #             if len(timestamps) > 0:
    #                 plt.plot(timestamps, values, label=instanceId)
    #             else:
    #                 print(f"No data points for {instanceId}")
    
    #     plt.title("RDS CPU Utilization Over Time")
    #     plt.xlabel("Time")
    #     plt.ylabel("Average CPU Utilization (%)")
    #     plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    #     plt.grid(True)
    #     plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    #     plt.gca().xaxis.set_major_locator(mdates.MonthLocator())
    #     plt.gcf().autofmt_xdate()
    #     plt.tight_layout()
    #     plt.savefig("RDS CPU Utilisation", dpi=300, bbox_inches="tight")
    #     plt.close()
        
    # def plotCategorizedInstances(self, categorizedDataJson):
    #     categorizedData = json.loads(categorizedDataJson)
    #     counts = [
    #         categorizedData["highUtilization"]["count"],
    #         categorizedData["mediumUtilization"]["count"],
    #         categorizedData["lowUtilization"]["count"],
    #     ]
    #     labels = ["High Utilization", "Medium Utilization", "Low Utilization"]
    #     colors = ["#ff9999", "#66b3ff", "#99ff99"]
    
    #     plt.figure(figsize=(10, 8))
    #     if sum(counts) > 0:
    #         wedges, texts, autotexts = plt.pie(
    #             counts, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90
    #         )
    #         for i, count in enumerate(counts):
    #             if count == 0:
    #                 texts[i].set_visible(False)
    #                 autotexts[i].set_visible(False)
    #         plt.title("RDS Instance Utilization Distribution")
    #         plt.legend(
    #             wedges,
    #             labels,
    #             title="Utilization Levels",
    #             loc="center left",
    #             bbox_to_anchor=(1, 0, 0.5, 1),
    #         )
    #     else:
    #         plt.text(0.5, 0.5, "No Data Available", ha="center", va="center", fontsize=20)
    #         plt.title("RDS Instance Utilization Distribution (No Data)")
    
    #     plt.axis("equal")
    #     plt.savefig("RDS Utilisation Pie Chart.png", bbox_inches="tight")
    #     plt.close()
    
    # def plotCostByTime(self, costdata):
    #     costJson = json.loads(costdata.costJson)
    #     costData = []
    
    #     for period in costJson:
    #         startDate = datetime.strptime(period["TimePeriod"]["Start"], "%Y-%m-%d")
    #         month = startDate.strftime("%Y-%m")
    #         if "Groups" in period and period["Groups"]:
    #             for group in period["Groups"]:
    #                 usageType = group["Keys"][0]
    #                 cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
    #                 costData.append({"Month": month, "Usage Type": usageType, "Cost": cost})
    #         else:
    #             costData.append({"Month": month, "Usage Type": "No Data", "Cost": 0})
    
    #     df = pd.DataFrame(costData)
    #     dfPivot = df.pivot(index="Month", columns="Usage Type", values="Cost").fillna(0)
    
    #     allMonths = [
    #         datetime.strptime(period["TimePeriod"]["Start"], "%Y-%m-%d").strftime("%Y-%m")
    #         for period in costJson
    #     ]
    #     dfPivot = dfPivot.reindex(allMonths)
    
    #     if "No Data" in dfPivot.columns:
    #         dfPivot = dfPivot.drop("No Data", axis=1)
    
    #     ax = dfPivot.plot(kind="bar", stacked=True, figsize=(15, 8))
    #     plt.title(costdata.serviceName + " Monthly Costs Breakdown")
    #     plt.xlabel("Month")
    #     plt.ylabel("Cost (USD)")
    #     plt.legend(title=costdata.dimension, bbox_to_anchor=(1.05, 1), loc="upper left")
    #     plt.xticks(rotation=45, ha="right")
    
    #     for i, total in enumerate(dfPivot.sum(axis=1)):
    #         ax.text(i, total, f"${total:.2f}", ha="center", va="bottom")
    
    #     plt.tight_layout()
    #     # plt.show()
    #     plt.savefig(
    #         costdata.serviceName + " " + costdata.dimension, dpi=300, bbox_inches="tight"
    #     )
    #     plt.close()
    
    def getResources(self):
        p = {}
        
        results = self.rdsClient.describe_db_instances(**p)
        
        arr = results.get('DBInstances')
        while results.get('Maker') is not None:
            p['Maker'] = results.get('Maker')
            results = self.rdsClient.describe_db_instances(**p)
            arr = arr + results.get('DBInstances')
        
        for k, v in enumerate(arr):
            if v['DBInstanceStatus'].lower() in ['deleting', 'failed', 'restore-error', 'failed'] or v['DBInstanceStatus'].lower().startswith('incompatible'):
                del arr[k]
        
        if not self.tags:
            return arr
        
        finalArr = []
        for i, detail in enumerate(arr):
            if self.resourceHasTags(detail['TagList']):
                finalArr.append(arr[i])
        
        return finalArr    
        
    def getClusters(self):
        p = {}
        results = self.rdsClient.describe_db_clusters(**p)
        
        arr = results.get('DBClusters')
        while results.get('Maker') is not None:
            p['Maker'] = results.get('Maker')
            results = self.rdsClient.describe_db_clusters(**p)
            
            arr = arr + results.get('DBClusters')

        if not self.tags:
            return arr
        
        finalArr = []
        for i, detail in enumerate(arr):
            if self.resourceHasTags(detail['TagList']):
                finalArr.append(arr[i])
            
        return finalArr
            
    def getSecrets(self):
        p = {"IncludePlannedDeletion": False, "MaxResults": 10}
        
        results = self.smClient.list_secrets(**p)
        self.registerSecrets(results)
        
        NextToken = results.get('NextToken')
        while NextToken != None:
            p['NextToken'] = NextToken
            results = self.smClient.list_secrets(**p)
            NextToken = results.get('NextToken')
            
            self.registerSecrets(results)
            
    def registerSecrets(self, results):
        for secret in results.get('SecretList'):
            if self.tags:
                if not 'Tags' in secret:
                    print('Tags not supported in this region: [{}], ignoring tags filter'.format(self.region))
                    continue
                
                if self.resourceHasTags(secret['Tags']) == False:
                    continue
            
            resp = self.smClient.describe_secret(SecretId=secret['ARN'])
            self.secrets.append(resp)
        
    def advise(self):
        objs = {}
        instances = self.getResources()
        securityGroupArr = {}
        
        clusters = self.getClusters()
        
        groupedResources = instances + clusters
        
        for instance in groupedResources:
            dbKey = 'DBClusterIdentifier'
            dbInfo = 'Cluster'
            if 'DBInstanceIdentifier' in instance:
                dbInfo = 'Instance'
                dbKey = 'DBInstanceIdentifier'
            
            print('... (RDS) inspecting {}::{}'.format(dbInfo, instance[dbKey]))
            
            if 'VpcSecurityGroups' in instance:
                for sg in instance['VpcSecurityGroups']:
                    if 'Status' in sg and (sg['Status'] == 'active' or sg['Status'] == 'adding'):
                        if sg['VpcSecurityGroupId'] in securityGroupArr:
                            securityGroupArr[sg['VpcSecurityGroupId']].append(instance[dbKey])
                        else:
                            securityGroupArr[sg['VpcSecurityGroupId']] = [instance[dbKey]]
                
            engine = instance['Engine']
            
            # grouping mssql versions together
            if engine.find('sqlserver') != -1:
                engine = 'sqlserver'
            
            if engine not in self.engineDriver:
                _warn("{}, unsupported RDS Engine: [{}]".format(instance[dbKey], engine))
                continue
            
            driver_ = self.engineDriver[engine]
            driver = 'Rds' + driver_
            if driver in globals():
                obj = globals()[driver](instance, self.rdsClient, self.ctClient, self.cwClient)
                obj.setEngine(engine)
                obj.run(self.__class__)
                
                objs[instance['Engine'] + '::' + dbInfo + '=' + instance[dbKey]] = obj.getInfo()
                del obj
        
        for sg, rdsList in securityGroupArr.items():
            print('... (RDS-SG) inspecting ' + sg)
            obj = RdsSecurityGroup(sg, self.ec2Client, rdsList)
            obj.run(self.__class__)
            objs['RDS_SG::' + sg] = obj.getInfo()
            del obj

        self.getSecrets()
        for secret in self.secrets:
            print('... (SecretsManager) inspecting ' + secret['Name'])
            obj = RdsSecretsManager(secret, self.smClient, self.ctClient)
            obj.run(self.__class__)
            
            objs['SecretsManager::'+ secret['Name']] = obj.getInfo()
            del obj
        
        obj = RdsSecretsVsDB(len(self.secrets), len(instances))
        obj.run(self.__class__)
        objs['SecretsRDS::General'] = obj.getInfo()
        del obj
        
        # self.getCharts()
        
        return objs
    
if __name__ == "__main__":
    Config.init()
    o = Rds('ap-southeast-1')
    out = o.advise()

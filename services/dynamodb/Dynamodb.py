import botocore
import json
import datetime
import math

from services.Service import Service
from utils.Config import Config
from services.dynamodb.drivers.DynamoDbCommon import DynamoDbCommon
from services.dynamodb.drivers.DynamoDbGeneric import DynamoDbGeneric

from utils.Tools import _pi

class Dynamodb(Service):
    
    
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        
        self.dynamoDbClient = ssBoto.client('dynamodb', config=self.bConfig)
        self.cloudWatchClient = ssBoto.client('cloudwatch', config=self.bConfig)
        self.serviceQuotaClient = ssBoto.client('service-quotas', config=self.bConfig)
        self.appScalingPolicyClient = ssBoto.client('application-autoscaling', config=self.bConfig)
        self.backupClient = ssBoto.client('backup', config=self.bConfig)
        self.cloudTrailClient = ssBoto.client('cloudtrail', config=self.bConfig)
    
    
    def list_tables(self):
        tableArr = []
        try:
            tableNames = self.dynamoDbClient.list_tables()
            
            #append table name to array
            for tables in tableNames['TableNames']:
                tableDescription = self.dynamoDbClient.describe_table(TableName = tables)
                tableArr.append(tableDescription)
            
            #loop thru next page of results    
            while 'LastEvaluatedTableName' in tableNames:
                tableNames = self.dynamoDbClient.list_tables(ExclusiveStartTableName = tableNames['LastEvaluatedTableName'],Limit = 100)
                for tables in tableNames['TableNames']:
                    tableDescription = self.dynamoDbClient.describe_table(TableName = tables)
                    tableArr.append(tableDescription)
            
            if not self.tags:
                return tableArr 
                
            finalArr = []
            for i, detail in enumerate(tableArr):
                tableArn = detail['Table']['TableArn']
                tags = self.dynamoDbClient.list_tags_of_resource(ResourceArn=tableArn)
                if self.resourceHasTags(tags.get('Tags')):
                    finalArr.append(tableArr[i])
                
            return finalArr
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            
    def advise(self):
        
        objs = {}
        
        #Retrieve all tables with descriptions from DynamoDb
        listOfTables = self.list_tables()
        if listOfTables == None:
            return objs
        
        try:
            #Run generic checks
            _pi('Dynamodb::Generic')
            obj = DynamoDbGeneric(listOfTables, self.dynamoDbClient, self.cloudWatchClient, self.serviceQuotaClient, self.appScalingPolicyClient, self.backupClient, self.cloudTrailClient)
            obj.run(self.__class__)
            objs['DynamoDb::Generic'] = obj.getInfo()
            del obj
        
            #Run table specific checks
            for eachTable in listOfTables:
                objName = 'Dynamodb::' + eachTable['Table']['TableName']
                _pi('Dynamodb::Table', objName)
                obj = DynamoDbCommon(eachTable, self.dynamoDbClient, self.cloudWatchClient, self.serviceQuotaClient, self.appScalingPolicyClient, self.backupClient, self.cloudTrailClient)
                obj.run(self.__class__)
                objs[objName] = obj.getInfo()
                del obj
            
            #Return objs
            return objs
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            print(ecode)
        

           
if __name__ == "__main__":
    Config.init()
    o = DynamoDb('ap-southeast-1')
    out = o.advise()
    out = json.dumps(out, indent=4)
    print(out)

    

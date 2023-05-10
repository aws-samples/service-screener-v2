import boto3
import botocore
import datetime
import urllib.parse

from services.Service import Service
from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator


class DynamoDbGeneric(Evaluator):
    
    def __init__(self, tables, dynamoDbClient, cloudWatchClient, serviceQuotaClient, appScalingPolicyClient, backupClient, cloudTrailClient):
        super().__init__()
        self.tables = tables
        self.dynamoDbClient = dynamoDbClient
        self.cloudWatchClient = cloudWatchClient
        self.serviceQuotaClient = serviceQuotaClient
        self.appScalingPolicyClient = appScalingPolicyClient
        self.backupClient = backupClient
        self.cloudTrailClient = cloudTrailClient
        
    # logic to check service limits Max table / region
    def _check_service_limits_max_table_region(self):
        serviceQuotasResults = Config.get('QuotaCodeDDB', None)
        try:
            #Retrieve quota for DynamoDb = L-F98FE922
            if serviceQuotasResults == None:
                serviceQuotasResults = self.serviceQuotaClient.list_service_quotas(ServiceCode='dynamodb')['Quotas']
                Config.set('QuotaCodeDDB', serviceQuotasResults)
                
            for quotas in serviceQuotasResults:
                #Check for max table / region
                if quotas['QuotaCode'] == 'L-F98FE922':
                    y = int(80 * quotas['Value'] / 100)
                    x = len(self.tables)
                    if x >= y:
                        self.results['serviceLimitMaxTablePerRegion'] = [-1, str(x) + ' tables vs limit of ' + str(int(quotas['Value']))]
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
            
    # logic to check trail of deleteBackup
    def _check_trail_delete_backup(self):
        
        _startTime = datetime.datetime.now() - datetime.timedelta(30)
        _endTime = datetime.datetime.now()
        _deletedBackupsArr = []
        
        try:
            deleteBackupResults = self.cloudTrailClient.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey':'EventName',
                        'AttributeValue':'DeleteRecoveryPoint'
                    },
                ],
                StartTime = _startTime,
                EndTime = _endTime,
                MaxResults = 50
                )
            _deletedBackupsArr.extend(deleteBackupResults['Events'])
            
            while 'NextToken' in deleteBackupResults:
                deleteBackupResults = self.cloudTrailClient.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey':'EventName',
                            'AttributeValue':'DeleteRecoveryPoint'
                        },
                    ],
                    StartTime = _startTime,
                    EndTime = _endTime,
                    MaxResults = 50,
                    NextToken = deleteBackupResults['NextToken']
                )
                _deletedBackupsArr.extend(deleteBackupResults['Events'])
            
            numOfDeleteBackup = len(_deletedBackupsArr)
            
            
            if numOfDeleteBackup > 0:
                self.results['trailDeleteBackup'] = [-1, str(numOfDeleteBackup) + ' backup deleted in past 30 days']
            
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
        
    # logic to check trail of deleteTable
    def _check_trail_delete_table(self):
        
        _startTime = datetime.datetime.now() - datetime.timedelta(30)
        _endTime = datetime.datetime.now()
        _deletedTablesArr = []

        try:
            deleteTableResults = self.cloudTrailClient.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey':'EventName',
                        'AttributeValue':'DeleteTable'
                    },
                ],
                StartTime = _startTime,
                EndTime = _endTime,
                MaxResults = 50,
            )
            _deletedTablesArr.extend(deleteTableResults['Events'])
            
            while 'NextToken' in deleteTableResults:
                deleteTableResults = self.cloudTrailClient.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey':'EventName',
                            'AttributeValue':'DeleteTable'
                        },
                    ],
                    StartTime = _startTime,
                    EndTime = _endTime,
                    MaxResults = 50,
                    NextToken = deleteTableResults['NextToken']
                )
                _deletedTablesArr.extend(deleteTableResults['Events'])
            
            numOfDeleteTable = len(_deletedTablesArr)

            if numOfDeleteTable > 0:
                self.results['trailDeleteTable'] = [-1, str(numOfDeleteTable) + ' tables deleted in past 30 days.']

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)          
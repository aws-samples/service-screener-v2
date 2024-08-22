import boto3, botocore
from boto3.dynamodb.types import TypeDeserializer as ddbDeserializer
import os
import json
from datetime import datetime

## Environment Variables
## Should comment out in actual production

# os.environ['SSV2_S3_BUCKET'] = 'myBucket'
# os.environ['SSV2_SNSARN_PREFIX'] = 'ssv2'
# os.environ['SSV2_REGION'] = 'ap-southeast-1'
# os.environ['SSV2_EVENTBRIDGE_ROLES_ARN'] = 'arn:aws:iam::1111111111:role/AWSEventBridgeRoles'
# os.environ['SSV2_JOB_DEF'] = 'TEEHEE'
# os.environ['SSV2_JOB_QUEUE'] = 'TEEHEE'
# os.environ['SSV2_SCHEDULER_NAME'] = 'screener-scheduler-group'

## Sample Event Data 


## Initialize
region = os.environ['SSV2_REGION']
s3Bucket = os.environ['SSV2_S3_BUCKET']
snsArnPrefix = os.environ['SSV2_SNSARN_PREFIX']
ebrolesARN = os.environ['SSV2_EVENTBRIDGE_ROLES_ARN']
jobDef = os.environ['SSV2_JOB_DEF']
jobQueue = os.environ['SSV2_JOB_QUEUE']
schedulerGroupName = os.environ['SSV2_SCHEDULER_NAME']

s3 = boto3.client('s3', region_name=region)
sns = boto3.client('sns', region_name=region)
scheduler = boto3.client('scheduler', region_name=region)

successResp = {
    'statusCode': 200,
    'body': 'success'
}

##  
def lambda_handler(event, context):
    items = sanitizeEvent(event)
    for item in items:
        configId = item['configId']
        emails = item['emails']
        ssparams = item['ssparams']
        cronPattern = item['frequency']
        crossAccounts = item['crossAccounts']

        print('Patching the following Config: {}'.format(configId))
        result = updateSnsRecipient(configId, emails)
        if result == False:
            msg = 'Fail to update SNS - email recipients'
            resp = {'statusCode': 500, 'body': msg}
            return resp

        result = updateEventBridge(configId, ssparams, cronPattern, crossAccounts)
        if result == False:
            msg = 'Fail to update eventBridge Configuration for: {}'.format(configId)
            resp = {'statusCode': 500, 'body': msg}
            return resp

    return successResp

## update EventBridge
def updateEventBridge(ssv2configId, ssparams, cronPattern, crossAccounts):
    ## check if schedule exists
    inputJson = { 
        "JobDefinition": jobDef, 
        "JobName": "ssv2-" + ssv2configId, 
        "JobQueue": jobQueue, 
        "ContainerOverrides": 
            { "Environment": 
                [ 
                    { "Name": "PARAMS", "Value": ssparams }, 
                    { "Name": "S3_OUTPUT_BUCKET", "Value": s3Bucket },
                    { "Name": "CONFIG_ID", "Value": ssv2configId },
                    { "Name": "CROSSACCOUNTS", "Value": crossAccounts}
                ] 
            } 
    }

    target = {
        'Arn': 'arn:aws:scheduler:::aws-sdk:batch:submitJob',
        'RoleArn': ebrolesARN,
        'Input': json.dumps(inputJson)
    }

    flexibleTimeWindow = {
        "Mode": 'OFF'
    }

    args = {
        "Description": '[Created by SSv2] Screener Scheduler:' + ssv2configId,
        "FlexibleTimeWindow": flexibleTimeWindow,
        "Name": 'ScreenerScheduler-' + ssv2configId,
        "ScheduleExpression": cronPattern,
        "ScheduleExpressionTimezone": 'UTC',
        "StartDate": datetime.now(),
        "GroupName": schedulerGroupName,
        "Target": target
    }

    print("Attempting to update EventBridge Scheduler: ...")
    print(json.dumps(args, indent=4, default=str))
    scheduler.create_schedule(**args)

    # try:
    #     scheduler.create_schedule(**args)
    # except botocore.exceptions.ClientError as e:
    #     if(e.response['Error']['Code'] == 'ConflictException'):
    #         scheduler.update_schedule(**args)

## update SNS reciepient
def updateSnsRecipient(ssv2configId, emails):
    existingSubscriptions = []
    snsName = snsArnPrefix + '-' + ssv2configId

    #create if not exists
    resp = sns.create_topic(Name=snsName)
    snsArn = resp.get('TopicArn')

    args = {'TopicArn': snsArn}

    while(True):
        resp = sns.list_subscriptions_by_topic(**args)
        existingSubscriptions.extend(resp.get('Subscriptions'))

        NextToken = resp.get('NextToken')
        if NextToken:
            args['NextToken'] = NextToken
        else:
            break

    for existingEmail in existingSubscriptions:
        if existingEmail.get('Protocol') != 'email':
            continue

        if existingEmail.get('Endpoint') not in emails:
            if existingEmail.get('SubscriptionArn') == 'PendingConfirmation':
                print('Unable to remove {}, current status is PendingConfirmation. Amazon will delete automatically the subscription after 3 days of creation'.format(existingEmail.get('Endpoint')))
                continue

            print('Removing {}'.format(existingEmail.get('Endpoint')))
            sns.unsubscribe(SubscriptionArn=existingEmail.get('SubscriptionArn'))

        if existingEmail.get('Endpoint') in emails:
            emails.remove(existingEmail.get('Endpoint'))

    for email in emails:
        print('Adding {}'.format(email))
        sns.subscribe(
            TopicArn=snsArn,
            Protocol='email',
            Endpoint=email
        )
    
    pass    

def sanitizeEvent(event):
    records = event['Records']
    deserializer = ddbDeserializer()

    items = [] 
    for record in records:
        configId = record['dynamodb']['Keys']['name']['S']
        _sanitized = {k: deserializer.deserialize(v) for k,v in record['dynamodb']['NewImage'].items()}
        
        params = ''
        regions = list(_sanitized['regions'])
        services = list(_sanitized['services'])

        params = "--regions {}".format( ','.join(regions) )
        if services:
            params = params + " --services {}".format( ','.join(services))
        
        items.append({
            'configId': configId,
            'ssparams': params,
            'frequency': _sanitized['frequency'],
            'emails': list(_sanitized['emails']),
            'crossAccounts': _sanitized['crossAccounts']
        })

    return items



## test run 

# read a json file
# with open('sampleDDBStream.json', 'r') as f:
#    event = json.load(f)

# output = lambda_handler(event, '')
# print(output)
# print(event['Records'])

# items = sanitizeEvent(event)
# print(items)

# updateSnsRecipient('default', ['yongkue+testpp@amazon.com', 'kt.xtrik@gmail.com'])
# updateSnsRecipient('default', [])
# lambda_handler(event, '')

# updateEventBridge('ssv2default', "--regions ap-southeast-1,us-east-1 --services ec2,rds,cloudtrail")
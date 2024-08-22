import boto3
import os
import json
from botocore.exceptions import ClientError


## Environment Variables
## Test values only, should comment out in actual production
os.environ['SSV2_REGION'] = 'ap-southeast-1'
os.environ['DDB_NAME'] = 'ss-parameters'
os.environ['FREQUENCY'] = 'cron(0, 0, 1,* ,?, *)'
os.environ['REGIONS'] = 'ap-southeast-1,us-east-1'
os.environ['EMAILS'] = 'yingting@amazon.com,keatkw@amazon.com'
os.environ['SERVICES'] = 'ec2,rds'
os.environ['config_name'] = 'team_B'
os.environ['crossAccounts'] = '1'

## Initialize
deploy_region = os.environ['SSV2_REGION']
ddb_name = os.environ['DDB_NAME']
frequency = os.environ['FREQUENCY']
regions = os.environ['REGIONS']
emails = os.environ['EMAILS']
services = os.environ['SERVICES']
item_name = os.environ['config_name']
cross_accounts = os.environ['crossAccounts']

ddb = boto3.client('dynamodb', region_name=deploy_region)

def lambda_handler(event, context):
    email_list = split_string(emails)
    service_list = split_string(services)
    region_list = split_string(regions)

    # Format the item
    item = {
        "name": {"S": item_name},
        "emails": {"SS": email_list},
        "services": {"SS": service_list},
        "regions": {"SS": region_list},
        "frequency": {"S": frequency},
        "crossAccounts": {"S": cross_accounts}
    }

    # Insert the item into the table
    try:
        response = ddb.put_item(
            TableName = ddb_name,
            Item=item
        )
        return {
            'statusCode': 200,
            'body': json.dumps('Item inserted successfully'),
            'response': response
        }
    except ClientError as e:
        print(e.response['Error']['Message'])
        return {
            'statusCode': 500,
            'body': json.dumps('Error inserting item into DynamoDB')
        }

def split_string(input_string):
    # Remove any leading or trailing whitespace and split by comma
    result = [item.strip() for item in input_string.split(',')]
    return result

print(lambda_handler("",""))
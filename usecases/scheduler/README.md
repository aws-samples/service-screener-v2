# Screener Scheduler Guide
Today, you can setup scheduler to run screener automatically at fix schedule. Follow the setup guide below to deloy. 

## Architecture Components
### Components

From left to right
1. DynamoDB: 
1. Lambda - ConfigUpdater: This lambda is only triggered through DynamoDB stream. It updates the EventBridge scheduler setting, parameters, and email recipients
1. EventBridge (behind-the-scene): It is the main component to perform scheduling event. Based on the scheduler setting, EventBridge triggers AWS Batch to run Screener
1. AWS Batch: It provides compute environments to runs Screener and shutdown as soon as results are generated. It first look at Spot instance availability ...
1. ...

### Costs

## Deployment Guide (Recommend to run in Cloudshell)
### Prerequisite - Permission 
1. AWS User ID to log into AWS Console
1. [TODO] Permission required
1. 

### Prereqsuite - running at your own environment 
Note: All the following already preinstall for you in Cloudshell environment
1. Python3.12 & pip3
1. awscli & awscdk
1. Docker

### Cloudshell
The deployment requires 1/ CDK, 2/ git, 3/ docker and 4/ aws-cli. Using AWS Cloudshell is the cleanest way to deploy.
1. Login to AWS Console
1. Access Cloudshell
1. Run the following commands
```
## Perform normal Screener setup
python3 -m venv .
source bin/activate
python3 -m pip install --upgrade pip
rm -rf service-screener-v2
git clone https://github.com/aws-samples/service-screener-v2.git
cd service-screener-v2
pip install -r requirements.txt
```

```
## Deploy the architecture
export AWS_DEFAULT_REGION=<YOUR_REGION>
cd usecases/scheduler/src/infra
pip install -r requirements.txt
cdk bootstrap
cdk deploy
```

## Configuration
The configuration setup is to be done in DynamoDB, a table called: <TODO>
- name (string, key): unique configurationId
- frequency (string): cron syntax
- emails (stringset): list of recipients to receive Screener reports
- regions (stringset): valid [list of regions](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RegionsAndAvailabilityZones.html). e.g: ap-southeast-1 | us-east-1 | ALL
- services (stringset, optional): leave it empty to scan all supported services, else you can refers to [list of valid services here](https://github.com/aws-samples/service-screener-v2/tree/main/services)
- crossAccounts (string, optional): need to upload a valid crossAccounts.json here. You can refers to [this sample](https://github.com/aws-samples/service-screener-v2/blob/main/crossAccounts.sample.json) or [follows this](https://github.com/aws-samples/service-screener-v2/tree/main/usecases/accountsWithinOrganization) to generate the json if the list of accounts are within the same Organization.

## Troubleshooting
### CDK Bootstrap Failed
1. Go to cloudformation and search for "CDKToolKit", if the account previously has failed deployment on this, you have to remove it first and rerun "CDK bootstrap". 
1. Please make sure the IAM role has the permission to perform `iam:CreateRole` action

### CDK Deploy Failed
1. Make sure your CDK bootstrap `region` is same as the one used for CDK deploy. You can either 1/ export AWS_DEFAULT_REGION=<YOUR_REGION>, or 2/ cdk deploy --profile <YOUR_PROFILE>


### Invalid Cron
1. Check logs in cloudwatch in the configUpdater lambda to identify error
1. Make sure your cron is in valid format, you may tap on [this site](https://www.freeformatter.com/cron-expression-generator-quartz.html) to understand better
1. Go to dynamodb and update the *frequency*. The value should consists *cron(YOUR_PATTERN)*, e.g: cron(* * * ? * 1 *)

### Not receiving reporter email
1. Check logs in cloudwatch in the resultProcesser lambda to identify error
1. Next you can go to the S3 Bucket to check if file exists. The key should have the following pattern bucketname/dynamodbKey/YYYYMMDD/AWS_ACCOUNTID/workItem.xlsx ... if files not exists, likely AWS Batch does not run properly due to configuration or permission errros, go to next step
1. Next you can go to AWS Batch to look for any jobs' errors
1. Next you can go to AWS SNS, select topic with prefix, make sure you subscribe to the email notification

### Author
1. Ying Ting
1. Wanich Keatkajonjumroen
1. KuetTai
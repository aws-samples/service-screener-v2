import boto3
from datetime import date, timedelta, datetime
from botocore.config import Config

class Cloudwatch:
    def __init__(self, region):
        self.cwClient = boto3.client('cloudwatch', config=Config(region_name=region))
    
    def getClient(self):
        return self.cwClient

if __name__ == "__main__":
    cw = Cloudwatch('ap-southeast-1')
    cwClient = cw.getClient()
    metric = 'CPUUtilization'
    results = cwClient.get_metric_statistics(
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': 'i-0a41f4908de26670d'
            }
        ],
        Namespace='AWS/EC2',
        MetricName=metric,
        StartTime=datetime.today() - timedelta(days=7),
        EndTime=datetime.today(),
        Period=60*60*24,
        Statistics=['Maximum'],
        #Unit='None'
    )
    
    print(results)
    
# https://ap-southeast-1.console.aws.amazon.com/cloudwatch/home?region=ap-southeast-1
# metricsV2?graph=~(view~'timeSeries~stacked~false~metrics~(~(~'AWS*2fEC2~'CPUUtilization~'InstanceId~'i-0a41f4908de26670d))~region~'ap-southeast-1)
# &query=~'*7bAWS*2fEC2*2cInstanceId*7d*20EC2
import botocore
from utils.Config import Config
from services.Service import Service
from utils.Tools import _pi

from services.sqs.drivers.SqsQueueDriver import SqsQueueDriver
import json

class Sqs(Service):
    def __init__(self, region):
        super().__init__(region)
        self.region = region
        
        ssBoto = self.ssBoto
        self.sqsClient = ssBoto.client('sqs', config=self.bConfig)
        self.cloudwatchClient = ssBoto.client('cloudwatch', config=self.bConfig)
        
    def getResources(self):
        """
        Discover and return SQS queues to be checked.
        Handles pagination and tag filtering.
        """
        queues = []
        dlq_mapping = {}  # Maps DLQ ARN to source queue names
        
        try:
            # List all queues
            response = self.sqsClient.list_queues()
            queue_urls = response.get('QueueUrls', [])
            
            # First pass: collect all queues and their DLQ relationships
            for queue_url in queue_urls:
                try:
                    # Get queue attributes
                    attrs_response = self.sqsClient.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['All']
                    )
                    
                    queue_name = queue_url.split('/')[-1]
                    attributes = attrs_response.get('Attributes', {})
                    
                    queue_data = {
                        'QueueUrl': queue_url,
                        'QueueName': queue_name,
                        'Attributes': attributes
                    }
                    
                    # Extract DLQ information
                    redrive_policy = attributes.get('RedrivePolicy')
                    if redrive_policy:
                        try:
                            import json
                            policy = json.loads(redrive_policy)
                            dlq_arn = policy.get('deadLetterTargetArn')
                            if dlq_arn:
                                dlq_name = dlq_arn.split(':')[-1]
                                if dlq_name not in dlq_mapping:
                                    dlq_mapping[dlq_name] = []
                                dlq_mapping[dlq_name].append(queue_name)
                        except json.JSONDecodeError:
                            pass
                    
                    # Apply tag filtering if specified
                    if self.tags:
                        try:
                            tags_response = self.sqsClient.list_queue_tags(QueueUrl=queue_url)
                            tags = [{'Key': k, 'Value': v} for k, v in tags_response.get('Tags', {}).items()]
                            
                            if not self.resourceHasTags(tags):
                                continue
                        except botocore.exceptions.ClientError:
                            # Skip if unable to get tags
                            continue
                    
                    queues.append(queue_data)
                    
                except botocore.exceptions.ClientError as e:
                    # Skip queues we can't access
                    continue
            
            # Second pass: add DLQ usage information to each queue
            for queue in queues:
                queue_name = queue['QueueName']
                if queue_name in dlq_mapping:
                    queue['DlqUsedBy'] = dlq_mapping[queue_name]
                else:
                    queue['DlqUsedBy'] = []
                    
        except botocore.exceptions.ClientError as e:
            print(f"Error listing SQS queues: {e}")
            
        return queues
    
    def advise(self):
        """
        Main method that runs checks on discovered SQS queues.
        Returns a dictionary of check results.
        """
        objs = {}
        queues = self.getResources()
        
        for queue in queues:
            queue_name = queue['QueueName']
            _pi('SQS Queue', queue_name)
            
            # Create driver instance and run checks
            cloudtrail_client = self.ssBoto.client('cloudtrail', config=self.bConfig)
            obj = SqsQueueDriver(queue, self.sqsClient, self.cloudwatchClient, cloudtrail_client)
            obj.run(self.__class__)
            
            # Store results
            objs[f"Queue::{queue_name}"] = obj.getInfo()
            del obj
            
        return objs

# Test harness for development
if __name__ == "__main__":
    Config.init()
    service = Sqs('us-east-1')
    results = service.advise()
    print(results)
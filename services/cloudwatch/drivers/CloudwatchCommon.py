import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

###### TO DO #####
## Import modules that needed for this driver
## Example
## from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

###### TO DO #####
## Replace ServiceDriver with

class CloudwatchCommon(Evaluator):
    
    ###### TO DO #####
    ## Replace resource variable to meaningful name
    ## Modify based on your need
    def __init__(self, log, logClient):
        super().__init__()
        self.init()
        
        self.log = log
        self.logClient = logClient

        self._resourceName = log['logGroupName']

        return
    
    ###### TO DO #####
    ## Change the method name to meaningful name
    ## Check methods name must follow _check[Description]
    def _checkRetention(self):
        if self.log['retentionInDays'] == -1:
            self.results['SetRetentionDays'] = [-1, "{} MB".format(self.log['storedBytes']/1024/1024)]
        elif self.log['retentionInDays'] <= 365:
            self.results['CISRetentionAtLeast1Yr'] = [-1, self.log['retentionInDays']]
    
    def _checkTags(self):
        """
        Check if log group has required cost allocation tags
        Validates: Requirements 2.1, 2.2, 2.3, 2.5
        """
        try:
            # Retrieve tags for the log group
            response = self.logClient.list_tags_log_group(
                logGroupName=self.log['logGroupName']
            )
            
            # Get tags dict from response
            tags = response.get('tags', {})
            
            # Define required tags
            required_tags = ['Environment', 'Project', 'CostCenter']
            
            # Check which required tags are missing
            missing_tags = [tag for tag in required_tags if tag not in tags]
            
            # Flag if any required tags are missing
            if missing_tags:
                missing_tags_str = ', '.join(missing_tags)
                self.results['cloudwatchResourcesWithoutTags'] = [
                    -1, 
                    f"Missing required tags: {missing_tags_str}"
                ]
        except Exception as e:
            # Log error but don't fail the check
            print(f"Error checking tags for {self._resourceName}: {str(e)}")
    
    def _checkLogInsightsUsage(self):
        """
        Check if log group has recent Log Insights query activity
        Validates: Requirements 3.1, 3.2, 3.3, 3.4
        """
        try:
            import time
            
            # Query recent Log Insights executions
            response = self.logClient.describe_queries(
                logGroupName=self.log['logGroupName'],
                status='Complete',
                maxResults=50
            )
            
            # Get current time and 30 days ago in milliseconds
            current_time = int(time.time() * 1000)
            thirty_days_ago = current_time - (30 * 24 * 60 * 60 * 1000)
            
            # Check if any queries were executed within last 30 days
            recent_queries = [
                q for q in response.get('queries', [])
                if q.get('createTime', 0) >= thirty_days_ago
            ]
            
            # Flag if no recent query activity
            if not recent_queries:
                self.results['logGroupsWithoutLogInsightsUsage'] = [
                    -1,
                    "No Log Insights queries executed in the last 30 days"
                ]
        except Exception as e:
            # Log error but don't fail the check
            print(f"Error checking Log Insights usage for {self._resourceName}: {str(e)}")
    
    def _checkScheduledQueryFailures(self):
        """
        Check for failed scheduled queries in log group
        Validates: Requirements 12.1, 12.2, 12.3, 12.4
        """
        try:
            # Query recent query executions for failed/cancelled status
            failed_queries = []
            
            for status in ['Failed', 'Cancelled']:
                response = self.logClient.describe_queries(
                    logGroupName=self.log['logGroupName'],
                    status=status,
                    maxResults=50
                )
                failed_queries.extend(response.get('queries', []))
            
            # Flag if any failed queries are found
            if failed_queries:
                # Get first failed query details
                first_failed = failed_queries[0]
                query_id = first_failed.get('queryId', 'unknown')
                status = first_failed.get('status', 'unknown')
                
                self.results['failedScheduledQueries'] = [
                    -1,
                    f"Query {query_id} failed with status: {status}"
                ]
        except Exception as e:
            # Log error but don't fail the check
            print(f"Error checking scheduled query failures for {self._resourceName}: {str(e)}")

